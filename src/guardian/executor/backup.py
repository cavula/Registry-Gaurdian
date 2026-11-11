"""Content-verified OCI archive backup through injected Blob Storage transports."""

import hashlib
import json
import math
import re
import tarfile
from collections.abc import Callable
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Protocol

from pydantic import BaseModel, Field, StrictInt

from guardian.config import utc
from guardian.models import Image
from guardian.policy.engine import descendants, key

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
MEDIA_TYPES = {
    "single": {OCI_MANIFEST, "application/vnd.docker.distribution.manifest.v2+json"},
    "index": {OCI_INDEX, "application/vnd.docker.distribution.manifest.list.v2+json"},
}
DEFAULT_MEDIA_TYPE = {"single": OCI_MANIFEST, "index": OCI_INDEX}
OCI_LAYOUT = {"imageLayoutVersion": "1.0.0"}
METADATA_FILE = "guardian-backup.json"


class BlobTransport(Protocol):
    """Store and retrieve whole archives in the configured storage container."""

    def put(self, key: str, data: bytes, *, tier: str, retention_days: float) -> None:
        """Persist an archive using the given access tier and lifecycle retention."""
        ...

    def get(self, key: str) -> bytes:
        """Read the stored archive bytes."""
        ...


class LocalBlobTransport:
    """Filesystem-backed Blob Storage stand-in for the local test registry."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory.resolve()

    def _path(self, key: str) -> Path:
        if not re.fullmatch(r"guardian/[a-f0-9]{64}\.tar", key):
            raise ValueError("Invalid backup object key")
        path = (self.directory / key).resolve()
        if not path.is_relative_to(self.directory):
            raise ValueError("Backup object path escapes its container")
        return path

    def put(self, key: str, data: bytes, *, tier: str, retention_days: float) -> None:
        """Atomically publish an archive to the local container directory."""
        if tier != "Cool" or not math.isfinite(retention_days) or retention_days <= 0:
            raise ValueError("Backup requires Cool storage and positive retention")
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(dir=path.parent, delete=False) as pending:
            temporary_path = Path(pending.name)
            try:
                pending.write(data)
                pending.close()
                temporary_path.replace(path)
            finally:
                temporary_path.unlink(missing_ok=True)

    def get(self, key: str) -> bytes:
        """Read the local archive."""
        return self._path(key).read_bytes()


class AzureContainer(Protocol):
    """Blob container client operations needed by the injected transport."""

    def upload_blob(
        self, name: str, data: bytes, *, standard_blob_tier: str, overwrite: bool
    ) -> Any:
        """Upload a block blob with its access tier."""
        ...

    def download_blob(self, blob: str) -> Any:
        """Return a downloader exposing readall()."""
        ...


def lifecycle_rule(container: str, retention_days: float) -> dict[str, Any]:
    """Describe expiration for Guardian archives in one Blob container."""
    if (
        not container
        or "/" in container
        or not math.isfinite(retention_days)
        or retention_days <= 0
    ):
        raise ValueError("Backup requires a container and positive retention")
    return {
        "name": "GuardianBackupRetention",
        "enabled": True,
        "type": "Lifecycle",
        "definition": {
            "filters": {"blobTypes": ["blockBlob"], "prefixMatch": [f"{container}/guardian/"]},
            "actions": {
                "baseBlob": {"delete": {"daysAfterCreationGreaterThan": math.ceil(retention_days)}}
            },
        },
    }


class AzureBlobTransport:
    """Blob adapter whose container client and lifecycle policy updater are injected."""

    def __init__(
        self,
        client: AzureContainer,
        container: str,
        configure_lifecycle: Callable[[dict[str, Any]], None],
    ) -> None:
        self.client = client
        self.container = container
        self.configure_lifecycle = configure_lifecycle

    def put(self, key: str, data: bytes, *, tier: str, retention_days: float) -> None:
        """Apply the archive-specific lifecycle rule and upload in the Cool tier."""
        self.configure_lifecycle(lifecycle_rule(self.container, retention_days))
        self.client.upload_blob(key, data, standard_blob_tier=tier, overwrite=True)

    def get(self, key: str) -> bytes:
        """Retrieve the original archive bytes through the injected client."""
        return self.client.download_blob(key).readall()


class _Descriptor(BaseModel):
    digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    size: StrictInt = Field(ge=0)
    media_type: str = Field(alias="mediaType", min_length=1)


class _Metadata(BaseModel):
    format_version: int = 1
    created_at: datetime
    expires_at: datetime
    graph: list[Image] = Field(min_length=1)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _hex(digest: str) -> str:
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("Expected a SHA-256 digest")
    return digest.removeprefix("sha256:")


def _object_key(backup_id: str) -> str:
    return f"guardian/{_hex(backup_id)}.tar"


def _blob_path(digest: str) -> str:
    return f"blobs/sha256/{_hex(digest)}"


def _json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _graph_members(registry: str, graph: list[Image]) -> dict[str, Image]:
    if not graph:
        raise ValueError("Backup graph has no root")
    root = graph[0]
    inventory = {key(image): image for image in graph}
    for image in graph:
        if (
            image.registry != registry
            or image.repository != root.repository
            or not image.inventory_complete
            or not image.children_complete
        ):
            raise ValueError("Backup graph scope or inventory is incomplete")
    reachable, complete = descendants(root, inventory)
    if not complete or len(graph) != len(reachable):
        raise ValueError("Backup graph is incomplete, cyclic, or contains extra manifests")
    return {image.digest: image for image in graph}


def _manifest(data: bytes, image: Image) -> tuple[str, list[_Descriptor]]:
    manifest = json.loads(data)
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
        raise ValueError("Unsupported image manifest schema")
    media_type = manifest.get("mediaType", DEFAULT_MEDIA_TYPE[image.manifest_type])
    if media_type not in MEDIA_TYPES[image.manifest_type]:
        raise ValueError("Manifest media type differs from the inventory")
    if image.manifest_type == "index":
        if not isinstance(manifest.get("manifests"), list) or not manifest["manifests"]:
            raise ValueError("Image index has no child descriptors")
        descriptors = [_Descriptor.model_validate(item) for item in manifest["manifests"]]
        if {item.digest for item in descriptors} != set(image.child_digests):
            raise ValueError("Index child descriptors differ from the inventory")
    else:
        if image.child_digests or not isinstance(manifest.get("layers"), list):
            raise ValueError("Invalid single-image manifest")
        descriptors = [_Descriptor.model_validate(manifest.get("config"))]
        descriptors.extend(_Descriptor.model_validate(item) for item in manifest["layers"])
    return media_type, descriptors


def _verified_content(
    registry: str, graph: list[Image], read_blob: Callable[[str], bytes]
) -> tuple[dict[str, bytes], dict[str, str]]:
    members = _graph_members(registry, graph)
    content: dict[str, bytes] = {}
    media_types: dict[str, str] = {}
    child_descriptors: list[_Descriptor] = []

    def read(digest: str, size: int | None = None) -> bytes:
        _hex(digest)
        if digest not in content:
            data = read_blob(digest)
            if _digest(data) != digest:
                raise ValueError(f"Blob digest mismatch for {digest}")
            content[digest] = data
        data = content[digest]
        if size is not None and len(data) != size:
            raise ValueError(f"Blob descriptor size mismatch for {digest}")
        return data

    for image in graph:
        media_type, descriptors = _manifest(read(image.digest), image)
        media_types[image.digest] = media_type
        for descriptor in descriptors:
            read(descriptor.digest, descriptor.size)
        if image.manifest_type == "index":
            child_descriptors.extend(descriptors)
        for digest, size in image.blobs.items():
            # ACR manifest size can describe the image total rather than raw manifest bytes.
            read(digest, size if digest not in members else None)
    for descriptor in child_descriptors:
        if media_types[descriptor.digest] != descriptor.media_type:
            raise ValueError("Index child media type differs from the child manifest")
    return content, media_types


def _index(root: Image, data: bytes, media_type: str) -> dict[str, Any]:
    descriptor = {"mediaType": media_type, "digest": root.digest, "size": len(data)}
    manifests = [
        {**descriptor, "annotations": {"org.opencontainers.image.ref.name": tag}}
        for tag in root.tags
    ]
    return {"schemaVersion": 2, "mediaType": OCI_INDEX, "manifests": manifests or [descriptor]}


def _pack(files: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, BytesIO(data))
    return buffer.getvalue()


def _unpack(data: bytes) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=BytesIO(data), mode="r:") as archive:
        for member in archive:
            if not member.isfile() or member.name in files:
                raise ValueError("Archive has an invalid or duplicate entry")
            content = archive.extractfile(member)
            if content is None:
                raise ValueError("Archive entry is unreadable")
            files[member.name] = content.read()
    return files


class BlobBackup:
    """Create verified OCI archives and hand validated restores to an atomic importer."""

    def __init__(self, transport: BlobTransport, retention_days: float = 30) -> None:
        if (
            isinstance(retention_days, bool)
            or not math.isfinite(retention_days)
            or retention_days <= 0
        ):
            raise ValueError("Backup retention must be a finite positive duration in days")
        self.transport = transport
        self.retention_days = retention_days

    def save(
        self, registry: str, graph: list[Image], read_blob: Callable[[str], bytes], now: datetime
    ) -> str:
        """Upload a complete archive and confirm its content by reading it back."""
        content, media_types = _verified_content(registry, graph, read_blob)
        root = graph[0]
        now = utc(now)
        metadata = _Metadata(
            graph=graph, created_at=now, expires_at=now + timedelta(days=self.retention_days)
        )
        files = {_blob_path(digest): data for digest, data in content.items()}
        files.update(
            {
                "oci-layout": _json(OCI_LAYOUT),
                "index.json": _json(_index(root, content[root.digest], media_types[root.digest])),
                METADATA_FILE: metadata.model_dump_json().encode(),
            }
        )
        archive = _pack(files)
        backup_id = _digest(archive)
        object_key = _object_key(backup_id)
        self.transport.put(object_key, archive, tier="Cool", retention_days=self.retention_days)
        if _digest(self.transport.get(object_key)) != backup_id:
            raise ValueError("Stored backup failed its integrity check")
        return backup_id

    def restore(
        self,
        backup_id: str,
        registry: str,
        repository: str,
        digest: str,
        import_graph: Callable[[list[Image], dict[str, bytes]], None],
        now: datetime,
    ) -> None:
        """Validate the saved graph and restore through a single atomic import call.

        The importer must check all original tags for conflicts inside its transaction.
        """
        archive = self.transport.get(_object_key(backup_id))
        if _digest(archive) != backup_id:
            raise ValueError("Stored backup failed its integrity check")
        files = _unpack(archive)
        metadata = _Metadata.model_validate_json(files[METADATA_FILE])
        root = metadata.graph[0]
        now = utc(now)
        if metadata.format_version != 1 or json.loads(files["oci-layout"]) != OCI_LAYOUT:
            raise ValueError("Unsupported backup layout")
        if not utc(metadata.created_at) <= now < utc(metadata.expires_at):
            raise ValueError("Backup is outside its retention window")
        if (root.registry, root.repository, root.digest) != (registry, repository, digest):
            raise ValueError("Backup identity does not match the requested manifest")
        content, media_types = _verified_content(
            registry, metadata.graph, lambda digest: files[_blob_path(digest)]
        )
        if json.loads(files["index.json"]) != _index(root, content[digest], media_types[digest]):
            raise ValueError("Backup index does not match its manifest")
        if set(files) != {
            "oci-layout",
            "index.json",
            METADATA_FILE,
            *(_blob_path(item) for item in content),
        }:
            raise ValueError("Archive contains unexpected entries")
        import_graph(metadata.graph, content)
