"""Executor-only registry mutation contract."""

from typing import Protocol

from guardian.models import Image


def manifest_signature(image: Image) -> tuple[object, ...]:
    """Compare inventory and lock metadata independently of refreshed policy evidence."""
    return (
        image.registry,
        image.repository,
        image.digest,
        tuple(sorted(image.tags)),
        image.manifest_type,
        tuple(sorted(image.child_digests)),
        image.pushed_at,
        image.size_bytes,
        tuple(sorted(image.blobs.items())),
        image.locked,
        image.inventory_complete,
        image.children_complete,
    )


class RegistryDeleter(Protocol):
    """Registry operations reserved for the executor."""

    def read_blob(self, digest: str) -> bytes:
        """Read the exact content-addressed blob for backup."""
        ...

    def delete_image(self, repo: str, digest: str, *, expected: list[Image]) -> None:
        """Atomically verify the expected graph and delete only its root."""
        ...

    def import_graph(self, images: list[Image], blobs: dict[str, bytes]) -> None:
        """Atomically restore all manifests and tags after checking conflicts."""
        ...
