"""Usage sources and repository-aware image reference resolution."""

from collections.abc import Callable
from typing import Any, Protocol

from pydantic import BaseModel, Field

from guardian.models import Evidence, Image


class UsageResult(BaseModel):
    """Digest references are scoped to repository."""

    in_use: set[tuple[str, str]] = Field(default_factory=set)
    unresolved_repositories: set[str] = Field(default_factory=set)


class UsageSource(Protocol):
    """Injected source of running or referenced digests."""

    def get_images_in_use(self, images: list[Image]) -> UsageResult:
        """Resolve configured references against inventory."""
        ...


def image_references(value: Any) -> list[str]:
    """Extract Kubernetes image strings and static Helm image mappings recursively."""
    result: list[str] = []
    if isinstance(value, dict):
        image = value.get("image")
        if isinstance(image, str):
            result.append(image)
        elif isinstance(image, dict) and isinstance(image.get("repository"), str):
            reference = image["repository"]
            if image.get("registry"):
                reference = str(image["registry"]).rstrip("/") + "/" + reference
            if image.get("digest"):
                reference += "@" + str(image["digest"])
            else:
                reference += ":" + str(image.get("tag", "latest"))
            result.append(reference)
        for key, item in value.items():
            if key != "image":
                result.extend(image_references(item))
    elif isinstance(value, list):
        for item in value:
            result.extend(image_references(item))
    return result


def resolve_references(references: list[str], images: list[Image]) -> UsageResult:
    """Unresolved references in the configured registry protect affected repositories."""
    result = UsageResult()
    if not images:
        return result
    registries = {image.registry for image in images}
    for reference in references:
        reference = reference.removeprefix("docker-pullable://")
        if "/" not in reference:
            continue
        server, location = reference.split("/", 1)
        if server not in registries and server.removesuffix(".azurecr.io") not in registries:
            continue
        if "@" in location:
            repo, digest = location.rsplit("@", 1)
            matches = [i for i in images if i.repository == repo and i.digest == digest]
        else:
            repo, sep, tag = location.rpartition(":")
            if not sep:
                repo, tag = location, "latest"
            matches = [i for i in images if i.repository == repo and tag in i.tags]
        if matches:
            result.in_use.update((i.repository, i.digest) for i in matches)
        else:
            result.unresolved_repositories.add(repo)
    return result


def collect_usage(
    sources: list[UsageSource],
    images: list[Image],
    evidence: Evidence,
    log: Callable[..., None],
) -> None:
    """A failed configured source protects the whole run."""
    for source in sources:
        try:
            result = source.get_images_in_use(images)
            for image in images:
                image.in_use |= (image.repository, image.digest) in result.in_use
            evidence.affected_repositories.update(result.unresolved_repositories)
            for repo in result.unresolved_repositories:
                log("unresolved_reference", repository=repo)
                evidence.alerts.append(f"Unresolved image reference in {repo}; repository kept")
        except Exception:
            evidence.usage_failed = True
            evidence.alerts.append("Usage source failed; all candidates kept")
            log("usage_failure", source=type(source).__name__)
