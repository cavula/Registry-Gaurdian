"""Provider-neutral security evidence and strict freshness."""

from datetime import datetime, timedelta
from typing import Protocol

from pydantic import BaseModel, Field, field_validator

from guardian.config import utc
from guardian.models import Image


class ScanResult(BaseModel):
    """A timestamped scan, not a policy verdict."""

    vulns: dict[str, int] = Field(default_factory=dict)
    scanned_at: datetime | None = None
    source: str

    @field_validator("scanned_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime | None) -> datetime | None:
        """Normalize provider timestamps."""
        return utc(value) if value else None


class ScanProvider(Protocol):
    """Bulk scan input contract; keys are repository and digest."""

    def results(self, images: list[Image]) -> dict[tuple[str, str], ScanResult]:
        """Return available results or raise a provider failure."""
        ...


def fresh(result: ScanResult | None, now: datetime, max_age_days: float) -> bool:
    """Count only results strictly newer than the freshness cutoff."""
    if result is None or result.scanned_at is None:
        return False
    known = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"}
    return now - timedelta(days=max_age_days) < result.scanned_at <= now and all(
        key in known and count >= 0 for key, count in result.vulns.items()
    )


def scan_images(
    images: list[Image],
    defender: ScanProvider,
    trivy: ScanProvider,
    now: datetime,
    max_age_days: float,
) -> list[str]:
    """Try fresh Defender then Trivy; UNKNOWN protects only the affected image."""
    now = utc(now)
    try:
        primary = defender.results(images)
    except Exception:
        primary = {}
    missing = [
        i for i in images if not fresh(primary.get((i.repository, i.digest)), now, max_age_days)
    ]
    try:
        fallback = trivy.results(missing) if missing else {}
    except Exception:
        fallback = {}
    alerts = []
    for image in images:
        key = (image.repository, image.digest)
        result = primary.get(key)
        if not fresh(result, now, max_age_days):
            result = fallback.get(key)
        if not fresh(result, now, max_age_days):
            image.security_unknown = True
            image.vulns = {}
            image.scanned_at = None
            image.scan_source = None
            alerts.append(f"Needs scanning: {image.repository}@{image.digest}")
        else:
            image.security_unknown = False
            image.vulns = result.vulns.copy()
            image.scanned_at = result.scanned_at
            image.scan_source = result.source
    return alerts
