"""OCI backup integrity, original-tag recovery, and injected Blob Storage behavior."""

import hashlib
import json
import tarfile
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock

import pytest

from guardian.executor.backup import (
    OCI_INDEX,
    OCI_MANIFEST,
    AzureBlobTransport,
    BlobBackup,
    LocalBlobTransport,
    lifecycle_rule,
)
from guardian.models import Image

NOW = datetime(2026, 11, 10, tzinfo=UTC)


def digest(data: bytes) -> str:
    """Calculate a real content address for a fixture blob."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def encoded(value: dict) -> bytes:
    """Serialize a deterministic fixture document."""
    return json.dumps(value, sort_keys=True).encode()


def fixture_graph(*, index: bool = False) -> tuple[list[Image], dict[str, bytes]]:
    """Build a valid OCI manifest with a real layer and optional index."""
    layer_buffer = BytesIO()
    with tarfile.open(fileobj=layer_buffer, mode="w") as archive:
        member = tarfile.TarInfo("hello.txt")
        member.size = 5
        archive.addfile(member, BytesIO(b"hello"))
    layer = layer_buffer.getvalue()
    config = encoded(
        {
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [digest(layer)]},
        }
    )
    manifest = encoded(
        {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": digest(config),
                "size": len(config),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": digest(layer),
                    "size": len(layer),
                }
            ],
        }
    )
    payloads = {digest(value): value for value in [layer, config, manifest]}
    child = Image(
        registry="demo",
        repository="app",
        digest=digest(manifest),
        tags=["old", "v1"],
        manifest_type="single",
        pushed_at=NOW - timedelta(days=100),
        size_bytes=len(manifest),
        blobs={address: len(value) for address, value in payloads.items()},
    )
    if not index:
        return [child], payloads
    document = encoded(
        {
            "schemaVersion": 2,
            "mediaType": OCI_INDEX,
            "manifests": [
                {
                    "mediaType": OCI_MANIFEST,
                    "digest": child.digest,
                    "size": len(manifest),
                    "platform": {"architecture": "amd64", "os": "linux"},
                }
            ],
        }
    )
    root = Image(
        registry="demo",
        repository="app",
        digest=digest(document),
        tags=["v-index", "v2"],
        manifest_type="index",
        child_digests=[child.digest],
        pushed_at=NOW - timedelta(days=100),
        size_bytes=len(document),
        blobs={digest(document): len(document)},
    )
    payloads[root.digest] = document
    return [root, child], payloads


def stored_path(directory: Path, backup_id: str) -> Path:
    """Locate a content-addressed test archive."""
    return directory / "guardian" / (backup_id.removeprefix("sha256:") + ".tar")


def replace_member(data: bytes, name: str, replacement: bytes) -> bytes:
    """Build a modified archive to exercise semantic validation after rehashing."""
    output = BytesIO()
    with tarfile.open(fileobj=BytesIO(data), mode="r:") as source:
        with tarfile.open(fileobj=output, mode="w") as target:
            for member in source:
                content = source.extractfile(member).read()
                if member.name == name:
                    content = replacement
                info = tarfile.TarInfo(member.name)
                info.size = len(content)
                target.addfile(info, BytesIO(content))
    return output.getvalue()


@pytest.mark.parametrize("index", [False, True])
def test_verified_backup_restores_all_tags_and_graph(tmp_path: Path, index: bool) -> None:
    graph, payloads = fixture_graph(index=index)
    reader = Mock(side_effect=payloads.__getitem__)
    backup = BlobBackup(LocalBlobTransport(tmp_path))
    backup_id = backup.save("demo", graph, reader, NOW)
    assert len(reader.call_args_list) == len(payloads)  # shared descriptors read only once
    imported = Mock()
    backup.restore(backup_id, "demo", "app", graph[0].digest, imported, NOW + timedelta(days=1))
    restored, blobs = imported.call_args.args
    assert [image.model_dump() for image in restored] == [image.model_dump() for image in graph]
    assert blobs == payloads
    with tarfile.open(stored_path(tmp_path, backup_id)) as archive:
        assert archive.getnames() == sorted(archive.getnames())
        assert json.load(archive.extractfile("oci-layout")) == {"imageLayoutVersion": "1.0.0"}
        index_document = json.load(archive.extractfile("index.json"))
        assert {
            item["annotations"]["org.opencontainers.image.ref.name"]
            for item in index_document["manifests"]
        } == set(graph[0].tags)
        assert all(member.isfile() for member in archive)


def test_bad_source_blob_blocks_backup(tmp_path: Path) -> None:
    graph, payloads = fixture_graph()
    payloads[graph[0].digest] = b"corrupted"
    with pytest.raises(ValueError, match="digest mismatch"):
        BlobBackup(LocalBlobTransport(tmp_path)).save("demo", graph, payloads.__getitem__, NOW)
    assert not list(tmp_path.rglob("*.tar"))


def test_missing_graph_and_descriptor_mismatch_fail(tmp_path: Path) -> None:
    graph, payloads = fixture_graph(index=True)
    backup = BlobBackup(LocalBlobTransport(tmp_path))
    with pytest.raises(ValueError, match="incomplete"):
        backup.save("demo", graph[:1], payloads.__getitem__, NOW)
    graph[1].blobs[next(d for d in graph[1].blobs if d != graph[1].digest)] += 1
    with pytest.raises(ValueError, match="size mismatch"):
        backup.save("demo", graph, payloads.__getitem__, NOW)


def test_corrupt_stored_copy_blocks_backup_and_restore(tmp_path: Path) -> None:
    graph, payloads = fixture_graph()
    transport = Mock()
    transport.get.return_value = b"corrupted"
    with pytest.raises(ValueError, match="integrity"):
        BlobBackup(transport).save("demo", graph, payloads.__getitem__, NOW)
    with pytest.raises(ValueError, match="integrity"):
        BlobBackup(transport).restore(digest(b"real"), "demo", "app", graph[0].digest, Mock(), NOW)
    transport.put.assert_called_once()
    assert transport.put.call_args.kwargs == {"tier": "Cool", "retention_days": 30}


@pytest.mark.parametrize("scope", [("other", "app"), ("demo", "mirror")])
def test_restore_refuses_wrong_scope_without_importing(
    tmp_path: Path,
    scope: tuple[str, str],
) -> None:
    graph, payloads = fixture_graph()
    backup = BlobBackup(LocalBlobTransport(tmp_path))
    backup_id = backup.save("demo", graph, payloads.__getitem__, NOW)
    importer = Mock()
    with pytest.raises(ValueError, match="identity"):
        backup.restore(backup_id, *scope, graph[0].digest, importer, NOW)
    importer.assert_not_called()


def test_restore_expiration_and_future_backup_refused(tmp_path: Path) -> None:
    graph, payloads = fixture_graph()
    backup = BlobBackup(LocalBlobTransport(tmp_path), retention_days=0.1)
    backup_id = backup.save("demo", graph, payloads.__getitem__, NOW)
    for moment in [NOW - timedelta(seconds=1), NOW + timedelta(days=0.1)]:
        with pytest.raises(ValueError, match="retention"):
            backup.restore(backup_id, "demo", "app", graph[0].digest, Mock(), moment)


def test_rehashed_corrupted_manifest_and_index_are_refused(tmp_path: Path) -> None:
    graph, payloads = fixture_graph()
    transport = LocalBlobTransport(tmp_path)
    backup = BlobBackup(transport)
    backup_id = backup.save("demo", graph, payloads.__getitem__, NOW)
    data = stored_path(tmp_path, backup_id).read_bytes()
    for name, replacement in [
        ("index.json", b"{}"),
        ("blobs/sha256/" + graph[0].digest.removeprefix("sha256:"), b"{}"),
        ("oci-layout", b"{}"),
    ]:
        altered = replace_member(data, name, replacement)
        identifier = digest(altered)
        transport.put(
            "guardian/" + identifier.removeprefix("sha256:") + ".tar",
            altered,
            tier="Cool",
            retention_days=30,
        )
        with pytest.raises(ValueError):
            backup.restore(identifier, "demo", "app", graph[0].digest, Mock(), NOW)


def test_injected_azure_transport_configures_scoped_lifecycle_and_tier() -> None:
    client, configure = Mock(), Mock()
    client.download_blob.return_value.readall.return_value = b"archive"
    transport = AzureBlobTransport(client, "acr-backups", configure)
    transport.put("guardian/test.tar", b"archive", tier="Cool", retention_days=0.1)
    client.upload_blob.assert_called_once_with(
        "guardian/test.tar", b"archive", standard_blob_tier="Cool", overwrite=True
    )
    assert configure.call_args.args[0] == lifecycle_rule("acr-backups", 0.1)
    rule = configure.call_args.args[0]["definition"]
    assert rule["filters"]["prefixMatch"] == ["acr-backups/guardian/"]
    assert rule["actions"]["baseBlob"]["delete"]["daysAfterCreationGreaterThan"] == 1
    assert transport.get("guardian/test.tar") == b"archive"


@pytest.mark.parametrize("retention", [0, -1, float("inf"), float("nan"), True])
def test_invalid_retention_refused(retention: float, tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        BlobBackup(LocalBlobTransport(tmp_path), retention_days=retention)


def test_local_transport_rejects_path_escape_and_bad_tier(tmp_path: Path) -> None:
    transport = LocalBlobTransport(tmp_path)
    with pytest.raises(ValueError):
        transport.get("../escape")
    with pytest.raises(ValueError):
        transport.put("guardian/" + "a" * 64 + ".tar", b"archive", tier="Hot", retention_days=30)


def test_graph_scope_incompleteness_duplicates_and_invalid_digest(tmp_path: Path) -> None:
    graph, payloads = fixture_graph()
    backup = BlobBackup(LocalBlobTransport(tmp_path))
    for invalid in [
        [],
        [graph[0], graph[0]],
        [graph[0].model_copy(update={"registry": "other"})],
        [graph[0].model_copy(update={"inventory_complete": False})],
        [graph[0].model_copy(update={"digest": "sha256:invalid"})],
    ]:
        with pytest.raises(ValueError):
            backup.save("demo", invalid, payloads.__getitem__, NOW)
