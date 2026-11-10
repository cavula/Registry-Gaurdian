"""Defender fixture provider; no production ARG query is hard-coded."""

import json
from pathlib import Path

from guardian.models import Image
from guardian.scanning.base import ScanResult


class DefenderFixtures:
    """Load normalized bulk scan data once; emulate provider failures."""

    source = "defender"

    def __init__(self, path: Path) -> None:
        self.data = json.loads(path.read_text())

    def results(self, images: list[Image]) -> dict[tuple[str, str], ScanResult]:
        """Return repository/digest results, never call an external scanner."""
        if self.data.get("failed"):
            raise RuntimeError("fixture scan provider failure")
        requested = {(i.repository, i.digest) for i in images}
        return {
            (row["repository"], row["digest"]): ScanResult(
                source=self.source, vulns=row.get("vulns", {}), scanned_at=row.get("scanned_at")
            )
            for row in self.data.get("results", [])
            if (row["repository"], row["digest"]) in requested
        }
