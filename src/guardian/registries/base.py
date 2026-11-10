"""Scanning interfaces intentionally contain no deletion capability."""

from typing import Protocol

from guardian.models import Image


class RegistryReader(Protocol):
    """Read registry inventory for review."""

    def list_repositories(self) -> list[str]:
        """Return all repository names."""
        ...

    def list_images(self, repo: str) -> list[Image]:
        """Return every manifest, including untagged and child manifests."""
        ...


class UnsupportedRegistry:
    """Extension point for registries deferred beyond v1."""

    def list_repositories(self) -> list[str]:
        """Fail explicitly until this registry is supported."""
        raise NotImplementedError("Registry implementation is out of scope for v1")

    def list_images(self, repo: str) -> list[Image]:
        """Fail explicitly until this registry is supported."""
        raise NotImplementedError("Registry implementation is out of scope for v1")


class DockerHubReader(UnsupportedRegistry):
    """Docker Hub extension point."""


class GHCRReader(UnsupportedRegistry):
    """GHCR extension point."""
