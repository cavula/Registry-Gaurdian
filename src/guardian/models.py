"""Typed internal inventory and policy evidence."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, field_validator

from guardian.config import utc


class Verdict(StrEnum):
    """Exclusive deterministic policy verdicts."""

    KEEP = "KEEP"
    STALE = "STALE"
    INSECURE = "INSECURE"
    STALE_AND_INSECURE = "STALE_AND_INSECURE"
    UNTAGGED = "UNTAGGED"


class Image(BaseModel):
    """Manifest record including evidence completeness and physical blob sizes."""

    registry: str
    repository: str
    tags: list[str] = Field(default_factory=list)
    digest: str
    manifest_type: str = "single"
    child_digests: list[str] = Field(default_factory=list)
    pushed_at: datetime | None = None
    last_pulled_at: datetime | None = None
    size_bytes: int = Field(default=0, ge=0)
    blobs: dict[str, int] = Field(default_factory=dict)
    in_use: bool = False
    locked: bool = False
    inventory_complete: bool = True
    children_complete: bool = True
    pull_history_incomplete: bool = False
    vulns: dict[str, int] = Field(default_factory=dict)
    scan_source: str | None = None
    scanned_at: datetime | None = None
    security_unknown: bool = True
    verdict: Verdict = Verdict.KEEP
    reasons: list[str] = Field(default_factory=list)

    @field_validator("pushed_at", "last_pulled_at", "scanned_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime | None) -> datetime | None:
        """Normalize all evidence dates."""
        return utc(value) if value else None

    @field_validator("blobs")
    @classmethod
    def nonnegative_blob_sizes(cls, value: dict[str, int]) -> dict[str, int]:
        """Reject invalid physical storage evidence."""
        if any(size < 0 for size in value.values()):
            raise ValueError("Blob sizes must be nonnegative")
        return value

    @field_validator("manifest_type")
    @classmethod
    def valid_manifest_type(cls, value: str) -> str:
        """Unsupported formats cannot be silently considered single manifests."""
        if value not in {"single", "index"}:
            raise ValueError("manifest_type must be single or index")
        return value


class Evidence(BaseModel):
    """Run-wide and repository-scoped failure signals."""

    usage_failed: bool = False
    pull_failed: bool = False
    affected_repositories: set[str] = Field(default_factory=set)
    history_started_at: datetime | None = None
    alerts: list[str] = Field(default_factory=list)

    @field_validator("history_started_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime | None) -> datetime | None:
        """Normalize the history coverage start."""
        return utc(value) if value else None
