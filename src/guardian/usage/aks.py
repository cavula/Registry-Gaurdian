"""AKS discovery through injected clients only."""

from collections.abc import Callable
from typing import Any

from guardian.models import Image
from guardian.usage.base import UsageResult, image_references, resolve_references


class AKSSource:
    """Read serialized workloads from a fake or injected Kubernetes client."""

    def __init__(self, list_workloads: Callable[[], Any]) -> None:
        self._list_workloads = list_workloads

    def get_images_in_use(self, images: list[Image]) -> UsageResult:
        """Include regular, init, and ephemeral containers."""
        return resolve_references(image_references(self._list_workloads()), images)
