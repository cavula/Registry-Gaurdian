"""Persistent registry transaction, index, and restore-conflict behavior."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from guardian.executor.fixture_registry import FixtureRegistryStore, fixture_image
from guardian.models import Image


def record(label: str, *, repository: str = "app", tags: list[str] | None = None) -> Image:
    """Create a seed record whose label becomes content in its valid OCI manifest."""
    return Image(
        registry="demo",
        repository=repository,
        digest=label,
        tags=tags or [],
        pushed_at=datetime(2020, 1, 1, tzinfo=UTC),
    )


def test_real_oci_image_bytes_and_persistent_reads(tmp_path: Path) -> None:
    image, payloads = fixture_image(record("one", tags=["v1", "old"]))
    store = FixtureRegistryStore(tmp_path / "registry.db", "demo")
    store.seed([image], payloads)
    restored = FixtureRegistryStore(store.path, "demo")
    assert restored.list_repositories() == ["app"]
    assert restored.list_images("missing") == []
    observed = restored.list_images("app")[0]
    assert observed == image
    observed.tags.append("local-only")
    assert restored.list_images("app")[0].tags == ["v1", "old"]
    manifest = json.loads(restored.read_blob(image.digest))
    assert manifest["schemaVersion"] == 2
    assert manifest["mediaType"] == "application/vnd.oci.image.manifest.v1+json"
    assert manifest["layers"] == []
    for digest, data in payloads.items():
        assert digest == "sha256:" + hashlib.sha256(data).hexdigest()
    with pytest.raises(ValueError, match="different registry"):
        FixtureRegistryStore(store.path, "other")


def test_changed_tag_or_lock_refuses_conditional_delete(tmp_path: Path) -> None:
    image, payloads = fixture_image(record("one", tags=["old"]))
    store = FixtureRegistryStore(tmp_path / "registry.db", "demo")
    store.seed([image], payloads)
    other_client = FixtureRegistryStore(store.path, "demo")
    other_client.seed([image.model_copy(update={"tags": ["old", "prod"]})], payloads)
    with pytest.raises(ValueError, match="changed"):
        store.delete_image("app", image.digest, expected=[image])
    other_client.seed([image.model_copy(update={"locked": True})], payloads)
    with pytest.raises(ValueError, match="locked"):
        store.delete_image("app", image.digest, expected=[image])
    assert len(store.list_images("app")) == 1


def test_rechecked_evidence_does_not_change_physical_comparison(tmp_path: Path) -> None:
    image, payloads = fixture_image(record("one", tags=["old"]))
    store = FixtureRegistryStore(tmp_path / "registry.db", "demo")
    store.seed([image], payloads)
    reviewed = image.model_copy(update={"vulns": {"HIGH": 2}, "scan_source": "trivy"})
    store.delete_image("app", image.digest, expected=[reviewed])
    assert store.list_images("app") == []
    with pytest.raises(KeyError):
        store.read_blob(image.digest)
    with pytest.raises(ValueError, match="no longer present"):
        store.delete_image("app", image.digest, expected=[reviewed])


def test_index_root_removal_preserves_children_and_shared_blob_bytes(tmp_path: Path) -> None:
    child, child_blobs = fixture_image(record("arm-child"))
    parent, parent_blobs = fixture_image(record("index", tags=["v0"]), children=[child])
    mirror = parent.model_copy(update={"repository": "mirror", "tags": ["prod"]})
    store = FixtureRegistryStore(tmp_path / "registry.db", "demo")
    store.seed([child, parent, mirror], child_blobs | parent_blobs)
    with pytest.raises(ValueError, match="child"):
        store.delete_image("app", child.digest, expected=[child])
    store.delete_image("app", parent.digest, expected=[parent, child])
    assert store.list_images("app") == [child]
    assert store.list_images("mirror") == [mirror]
    assert store.read_blob(parent.digest) == parent_blobs[parent.digest]
    assert store.read_blob(child.digest) == child_blobs[child.digest]


def test_restore_conflict_is_atomic_and_preserves_current_tag(tmp_path: Path) -> None:
    original, original_blobs = fixture_image(record("original", tags=["v1", "old"]))
    newer, newer_blobs = fixture_image(record("newer", tags=["v1"]))
    store = FixtureRegistryStore(tmp_path / "registry.db", "demo")
    store.seed([newer], newer_blobs)
    with pytest.raises(ValueError, match="Tag conflict"):
        store.import_graph([original], original_blobs)
    assert store.list_images("app") == [newer]
    with pytest.raises(KeyError):
        store.read_blob(original.digest)


def test_restore_merges_existing_same_digest_tags_and_graph(tmp_path: Path) -> None:
    child, child_blobs = fixture_image(record("arm-child"))
    parent, parent_blobs = fixture_image(record("index", tags=["v0", "release"]), children=[child])
    store = FixtureRegistryStore(tmp_path / "registry.db", "demo")
    store.seed([child.model_copy(update={"tags": ["child-tag"]})], child_blobs)
    store.import_graph([parent, child], parent_blobs | child_blobs)
    images = {item.digest: item for item in store.list_images("app")}
    assert images[parent.digest].tags == ["v0", "release"]
    assert images[child.digest].tags == ["child-tag"]


def test_invalid_inventory_or_bytes_refuse_atomic_seed(tmp_path: Path) -> None:
    image, payloads = fixture_image(record("one", tags=["old"]))
    store = FixtureRegistryStore(tmp_path / "registry.db", "demo")
    for records, blobs in [
        ([image, image], payloads),
        ([image.model_copy(update={"registry": "other"})], payloads),
        ([image], {**payloads, image.digest: b"corrupted"}),
        ([image.model_copy(update={"blobs": {image.digest: 1}})], payloads),
    ]:
        with pytest.raises(ValueError):
            store.seed(records, blobs)
        assert store.list_repositories() == []
    with pytest.raises(KeyError):
        store.seed([image], {})
    with pytest.raises(ValueError, match="root"):
        store.import_graph([], {})
    with pytest.raises(ValueError, match="graph"):
        store.import_graph([image, image], payloads)
    with pytest.raises(ValueError, match="children"):
        fixture_image(image, children=[])
