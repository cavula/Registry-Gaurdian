"""Local static YAML discovery; no rendering or Git network calls."""

from pathlib import Path

import yaml

from guardian.models import Image
from guardian.usage.base import UsageResult, image_references, resolve_references


class GitManifestSource:
    """Read explicitly configured local YAML files."""

    def __init__(self, paths: list[Path]) -> None:
        self.paths = paths

    def get_images_in_use(self, images: list[Image]) -> UsageResult:
        """Invalid or unrendered YAML fails closed."""
        references = []
        for path in self.paths:
            text = path.read_text()
            if "{{" in text or "{%" in text:
                raise ValueError("Rendered Helm templates are not supported")
            for document in yaml.safe_load_all(text):
                references.extend(image_references(document))
        return resolve_references(references, images)
