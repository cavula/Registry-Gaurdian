"""Read-only ACR SDK wrapper; development uses injected clients exclusively."""

from typing import Any

from guardian.models import Image


class ACRReader:
    """Normalize the SDK's lazy paged inventory; never expose its mutations."""

    def __init__(self, registry: str, client: Any) -> None:
        self.registry = registry
        self._client = client

    def list_repositories(self) -> list[str]:
        """Exhaust SDK paging; inventory failures propagate to the caller."""
        return sorted(self._client.list_repository_names())

    def list_images(self, repo: str) -> list[Image]:
        """Read all tags, manifest metadata, child descriptors and blobs."""
        properties = list(self._client.list_manifest_properties(repo))
        tags: dict[str, list[str]] = {}
        tag_locks: set[str] = set()
        try:
            for tag in self._client.list_tag_properties(repo):
                tags.setdefault(tag.digest, []).append(tag.name)
                if not tag.can_delete:
                    tag_locks.add(tag.digest)
            tags_complete = True
        except Exception:
            tags_complete = False
        result = []
        for prop in properties:
            if not prop.digest:
                raise ValueError("ACR returned a manifest without a digest")
            image = Image(
                registry=self.registry,
                repository=repo,
                digest=prop.digest,
                tags=sorted(set((prop.tags or []) + tags.get(prop.digest, []))),
                pushed_at=prop.created_on,
                size_bytes=prop.size_in_bytes or 0,
                locked=not prop.can_delete or prop.digest in tag_locks,
                inventory_complete=tags_complete and prop.created_on is not None,
            )
            try:
                manifest = self._client.get_manifest(repo, prop.digest).manifest
                image.manifest_type = "index" if "manifests" in manifest else "single"
                image.child_digests = [item["digest"] for item in manifest.get("manifests", [])]
                descriptors = list(manifest.get("layers", []))
                if manifest.get("config"):
                    descriptors.append(manifest["config"])
                image.blobs = {item["digest"]: item["size"] for item in descriptors}
                image.blobs[prop.digest] = image.size_bytes
                if manifest.get("schemaVersion") != 2:
                    image.inventory_complete = False
            except Exception:
                image.inventory_complete = False
                image.children_complete = False
            result.append(image)
        known = {image.digest for image in result}
        for image in result:
            if any(child not in known for child in image.child_digests):
                image.children_complete = False
        return result


def create_acr_reader(registry: str) -> ACRReader:
    """Wire read-only SDK authentication; not invoked by offline commands."""
    from azure.containerregistry import ContainerRegistryClient
    from azure.identity import DefaultAzureCredential

    client = ContainerRegistryClient(
        f"https://{registry}.azurecr.io", credential=DefaultAzureCredential()
    )
    return ACRReader(registry, client)
