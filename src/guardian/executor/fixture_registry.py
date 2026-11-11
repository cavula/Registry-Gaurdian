"""Persistent, local registry fixture for conditional purge and restore tests."""

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from guardian.executor.registry import manifest_signature
from guardian.models import Image
from guardian.policy.engine import Key, descendants, key

INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _json_blob(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def fixture_image(
    image: Image, *, children: list[Image] | None = None
) -> tuple[Image, dict[str, bytes]]:
    """Build OCI bytes for a fixture, using its input digest as a unique content label.

    For an index, pass the generated child records and combine their blob mappings
    with the returned index blobs when seeding the registry.
    """
    document: dict[str, Any] = {
        "schemaVersion": 2,
        "annotations": {"org.opencontainers.image.title": image.digest},
    }
    payloads: dict[str, bytes] = {}
    if children is None:
        config = _json_blob(
            {"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}}
        )
        config_digest = _digest(config)
        payloads[config_digest] = config
        document.update(
            mediaType=MANIFEST_MEDIA_TYPE,
            config={"mediaType": CONFIG_MEDIA_TYPE, "digest": config_digest, "size": len(config)},
            layers=[],
        )
    else:
        if not children or any(
            child.registry != image.registry or child.repository != image.repository
            for child in children
        ):
            raise ValueError("Fixture index requires children from its repository")
        document.update(
            mediaType=INDEX_MEDIA_TYPE,
            manifests=[
                {
                    "mediaType": INDEX_MEDIA_TYPE
                    if child.manifest_type == "index"
                    else MANIFEST_MEDIA_TYPE,
                    "digest": child.digest,
                    "size": child.size_bytes,
                }
                for child in children
            ],
        )
    payload = _json_blob(document)
    digest = _digest(payload)
    payloads[digest] = payload
    return image.model_copy(
        update={
            "digest": digest,
            "manifest_type": "single" if children is None else "index",
            "child_digests": [child.digest for child in children or []],
            "size_bytes": len(payload),
            "blobs": {name: len(data) for name, data in payloads.items()},
        }
    ), payloads


class FixtureRegistryStore:
    """Keep repository-qualified manifest records and shared OCI bytes in SQLite."""

    def __init__(self, path: Path, registry: str) -> None:
        if not registry:
            raise ValueError("Fixture registry name is required")
        self.path = path
        self.registry = registry
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "CREATE TABLE IF NOT EXISTS fixture_registry "
                "(id INTEGER PRIMARY KEY CHECK(id=1), name TEXT NOT NULL)"
            )
            db.execute("INSERT OR IGNORE INTO fixture_registry VALUES (1,?)", (registry,))
            stored_name = db.execute("SELECT name FROM fixture_registry WHERE id=1").fetchone()[0]
            if stored_name != registry:
                raise ValueError("Fixture database belongs to a different registry")
            db.execute(
                "CREATE TABLE IF NOT EXISTS fixture_manifests "
                "(repo TEXT, digest TEXT, payload TEXT NOT NULL, PRIMARY KEY (repo,digest))"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS fixture_blobs "
                "(digest TEXT PRIMARY KEY, payload BLOB NOT NULL)"
            )

    def list_repositories(self) -> list[str]:
        """Return current fixture repository names in deterministic order."""
        with closing(sqlite3.connect(self.path)) as db:
            return [
                row[0]
                for row in db.execute("SELECT DISTINCT repo FROM fixture_manifests ORDER BY repo")
            ]

    def list_images(self, repo: str) -> list[Image]:
        """Return independent copies of the persisted repository records."""
        with closing(sqlite3.connect(self.path)) as db:
            return [
                Image.model_validate_json(row[0])
                for row in db.execute(
                    "SELECT payload FROM fixture_manifests WHERE repo=? ORDER BY digest", (repo,)
                )
            ]

    def read_blob(self, digest: str) -> bytes:
        """Read a manifest, config, or layer by its OCI content digest."""
        with closing(sqlite3.connect(self.path)) as db:
            return self._blob(db, digest)

    @staticmethod
    def _blob(db: sqlite3.Connection, digest: str) -> bytes:
        row = db.execute("SELECT payload FROM fixture_blobs WHERE digest=?", (digest,)).fetchone()
        if row is None:
            raise KeyError(digest)
        return row[0]

    @staticmethod
    def _inventory(db: sqlite3.Connection) -> dict[Key, Image]:
        images = (
            Image.model_validate_json(row[0])
            for row in db.execute("SELECT payload FROM fixture_manifests")
        )
        return {key(image): image for image in images}

    @staticmethod
    def _blob_sizes(image: Image) -> dict[str, int]:
        if image.digest in image.blobs and image.blobs[image.digest] != image.size_bytes:
            raise ValueError("Fixture manifest size disagrees with its descriptor")
        return {**image.blobs, image.digest: image.size_bytes}

    def seed(self, images: list[Image], blobs: dict[str, bytes]) -> None:
        """Insert or replace fixture records without allowing conflicting tag ownership."""
        self._write(images, blobs, restoring=False)

    def import_graph(self, images: list[Image], blobs: dict[str, bytes]) -> None:
        """Restore all original tags atomically and preserve existing tag assignments."""
        if not images:
            raise ValueError("Restore requires a root image")
        graph, complete = descendants(images[0], {key(image): image for image in images})
        if not complete or len(graph) != len(images):
            raise ValueError("Restore graph must contain only the root and all of its children")
        self._write(images, blobs, restoring=True)

    def _write(self, images: list[Image], blobs: dict[str, bytes], *, restoring: bool) -> None:
        incoming = {key(image): image for image in images}
        if len(incoming) != len(images) or any(image.registry != self.registry for image in images):
            raise ValueError("Invalid or duplicate fixture manifest identity")
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            existing = self._inventory(db)
            if restoring:
                for image_key, image in incoming.items():
                    if current := existing.get(image_key):
                        incoming[image_key] = current.model_copy(
                            update={"tags": sorted(set(current.tags) | set(image.tags))}
                        )
            self._check_tags(existing | incoming)
            required: dict[str, bytes] = {}
            for image in incoming.values():
                for digest, size in self._blob_sizes(image).items():
                    payload = blobs[digest] if digest in blobs else self._blob(db, digest)
                    if len(payload) != size or _digest(payload) != digest:
                        raise ValueError("Fixture blob digest or size mismatch")
                    required[digest] = payload
            db.executemany("INSERT OR REPLACE INTO fixture_blobs VALUES (?,?)", required.items())
            db.executemany(
                "INSERT OR REPLACE INTO fixture_manifests VALUES (?,?,?)",
                [
                    (image.repository, image.digest, image.model_dump_json())
                    for image in incoming.values()
                ],
            )

    @staticmethod
    def _check_tags(inventory: dict[Key, Image]) -> None:
        owners: dict[tuple[str, str], str] = {}
        for image in inventory.values():
            for tag in image.tags:
                if owners.setdefault((image.repository, tag), image.digest) != image.digest:
                    raise ValueError(f"Tag conflict: {image.repository}:{tag}")

    def delete_image(self, repo: str, digest: str, *, expected: list[Image]) -> None:
        """Conditionally remove a root after checking the graph under the write lock."""
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            inventory = self._inventory(db)
            root = inventory.get((repo, digest))
            if root is None:
                raise ValueError("Manifest is no longer present")
            if any(
                image.repository == repo and digest in image.child_digests
                for image in inventory.values()
            ):
                raise ValueError("Cannot delete an index child on its own")
            graph, complete = descendants(root, inventory)
            if not complete or any(
                image.locked or not image.inventory_complete or not image.children_complete
                for image in graph
            ):
                raise ValueError("Manifest graph is locked or incomplete")
            observed = {key(image): manifest_signature(image) for image in graph}
            reviewed = {key(image): manifest_signature(image) for image in expected}
            if len(reviewed) != len(expected) or observed != reviewed:
                raise ValueError("Manifest graph changed before deletion")
            db.execute("DELETE FROM fixture_manifests WHERE repo=? AND digest=?", (repo, digest))
            del inventory[(repo, digest)]
            referenced = {
                name
                for image in inventory.values()
                for name in (image.digest, *image.blobs, *image.child_digests)
            }
            db.executemany(
                "DELETE FROM fixture_blobs WHERE digest=?",
                [(name,) for name in self._blob_sizes(root).keys() - referenced],
            )
