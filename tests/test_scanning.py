"""Scan freshness, per-image fallback, and unknown evidence."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from guardian.models import Image
from guardian.scanning.base import ScanResult, fresh, scan_images
from guardian.scanning.defender import DefenderFixtures
from guardian.scanning.trivy import TrivyFixtures

NOW = datetime(2026, 11, 10, tzinfo=UTC)


@pytest.mark.parametrize(
    "age,counts,expected",
    [
        (1, {"HIGH": 6}, True),
        (7, {}, False),
        (30, {}, False),
        (-1, {}, False),
        (1, {"UNKNOWN": 1}, False),
        (1, {"HIGH": -1}, False),
    ],
)
def test_freshness(age: int, counts: dict[str, int], expected: bool) -> None:
    assert (
        fresh(ScanResult(source="fake", scanned_at=NOW - timedelta(days=age), vulns=counts), NOW, 7)
        == expected
    )
    assert not fresh(ScanResult(source="missing"), NOW, 7)


def test_30_day_defender_falls_back_per_image(tmp_path: Path) -> None:
    primary, fallback = tmp_path / "defender.json", tmp_path / "trivy.json"
    row = {
        "repository": "app",
        "digest": "a",
        "vulns": {"CRITICAL": 1},
        "scanned_at": (NOW - timedelta(days=30)).isoformat(),
    }
    primary.write_text(json.dumps({"results": [row]}))
    row["scanned_at"] = NOW.isoformat()
    fallback.write_text(json.dumps({"results": [row]}))
    images = [Image(registry="demo", repository="app", digest=d) for d in ["a", "b"]]
    alerts = scan_images(images, DefenderFixtures(primary), TrivyFixtures(fallback), NOW, 7)
    assert images[0].scan_source == "trivy" and not images[0].security_unknown
    assert images[1].security_unknown
    assert alerts == ["Needs scanning: app@b"]


def test_provider_errors_become_unknown(tmp_path: Path) -> None:
    path = tmp_path / "failed.json"
    path.write_text('{"failed": true}')
    images = [Image(registry="demo", repository="app", digest="a")]
    assert scan_images(images, DefenderFixtures(path), TrivyFixtures(path), NOW, 7)
    assert images[0].security_unknown


def test_fresh_defender_avoids_fallback() -> None:
    image = Image(registry="demo", repository="app", digest="a")
    primary = Mock()
    primary.results.return_value = {("app", "a"): ScanResult(source="defender", scanned_at=NOW)}
    fallback = Mock()
    assert scan_images([image], primary, fallback, NOW, 7) == []
    fallback.results.assert_not_called()
