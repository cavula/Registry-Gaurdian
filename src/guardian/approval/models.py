"""Durable approval snapshots with per-image lifecycle."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from guardian.config import utc


class Status(StrEnum):
    """Approval states specified by the service contract."""

    PENDING = "PENDING"
    SCHEDULED = "SCHEDULED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    DELETED = "DELETED"


class ApprovalItem(BaseModel):
    """One repository-qualified approved snapshot."""

    repository: str
    digest: str
    tags: list[str]
    verdict: str
    reasons: list[str]
    size_bytes: int
    snapshot: dict[str, Any]
    graph_snapshots: list[dict[str, Any]] = Field(default_factory=list)
    status: Status = Status.PENDING
    outcome: str | None = None
    outcome_reason: str | None = None
    processing: bool = False
    backup_id: str | None = None
    cancelled_by: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        """Return the indivisible candidate identity."""
        return self.repository, self.digest


class Batch(BaseModel):
    """A batch retains its origin run and approver for the executor audit."""

    approval_id: str
    run_id: str
    registry: str
    fingerprint: str
    items: list[ApprovalItem]
    status: Status = Status.PENDING
    requested_at: datetime
    expires_at: datetime
    decided_by: str | None = None
    decided_at: datetime | None = None
    scheduled_delete_at: datetime | None = None
    cancelled_by: str | None = None
    final_notified: bool = False
    activity_id: str | None = None

    @field_validator("requested_at", "expires_at", "decided_at", "scheduled_delete_at")
    @classmethod
    def utc_timestamps(cls, value: datetime | None) -> datetime | None:
        """Normalize persisted lifecycle timestamps."""
        return utc(value) if value else None

    def aggregate(self) -> None:
        """Reflect per-item cancellation without losing still-scheduled items."""
        states = {item.status for item in self.items}
        if len(states) == 1:
            self.status = next(iter(states))
        elif Status.PENDING in states:
            self.status = Status.PENDING
        elif Status.SCHEDULED in states:
            self.status = Status.SCHEDULED
        elif Status.DELETED in states:
            self.status = Status.DELETED
        else:
            self.status = Status.CANCELLED


class OutboxEvent(BaseModel):
    """A durable notification snapshot."""

    event_id: str
    kind: str
    batch: Batch
    delivered: bool = False
    attempts: int = 0
    details: dict[str, Any] = Field(default_factory=dict)
