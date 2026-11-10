"""Offline registry loaded from JSON, with no service calls."""

import json
from pathlib import Path

from guardian.models import Image


class FixtureRegistry:
    """Read a registry fixture containing an images array."""

    def __init__(self, path: Path) -> None:
        self.images = [
            Image.model_validate(item) for item in json.loads(path.read_text())["images"]
        ]

    def list_repositories(self) -> list[str]:
        """Return unique repository names."""
        return sorted({image.repository for image in self.images})

    def list_images(self, repo: str) -> list[Image]:
        """Return independent copies of repository records."""
        return [image.model_copy(deep=True) for image in self.images if image.repository == repo]
