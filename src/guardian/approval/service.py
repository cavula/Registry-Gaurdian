"""Approver membership and approval/grace/cancellation state machine."""

from collections.abc import Callable
from datetime import datetime, timedelta
from uuid import uuid4

from guardian.approval.models import ApprovalItem, Batch, Status
from guardian.approval.store import ApprovalStore
from guardian.audit.log import AuditLog
from guardian.config import Config, utc
from guardian.models import Evidence, Image, Verdict
from guardian.policy.engine import descendants, evaluate, key
from guardian.state import fingerprint


class ApprovalService:
    """Code-enforced lifecycle independent of model output and Teams presentation."""

    def __init__(
        self,
        store: ApprovalStore,
        config: Config,
        membership: Callable[[str, str], bool],
        audit: AuditLog,
    ) -> None:
        self.store = store
        self.config = config
        self.membership = membership
        self.audit = audit

    def request(
        self, images: list[Image], evidence: Evidence, items: list[tuple[str, str]], now: datetime
    ) -> Batch:
        """Re-evaluate proposed snapshots; persist all original tags and verdicts."""
        now = utc(now)
        if any(image.registry != self.config.registry.name for image in images):
            raise ValueError("Approval inventory belongs to a different registry")
        evaluated = {key(i): i for i in evaluate(images, self.config, evidence, now)}
        if (
            not items
            or len(set(items)) != len(items)
            or any(
                pair not in evaluated or evaluated[pair].verdict == Verdict.KEEP for pair in items
            )
        ):
            raise ValueError("Approval items must be unique eligible policy candidates")
        candidates = [evaluated[pair] for pair in sorted(items)]
        value = fingerprint([(i.repository, i.digest, i.verdict.value) for i in candidates])
        batch = Batch(
            approval_id=str(uuid4()),
            run_id=self.audit.run_id,
            registry=self.config.registry.name,
            fingerprint=value,
            requested_at=now,
            expires_at=now + timedelta(hours=self.config.approval_ttl_hours),
            items=[
                ApprovalItem(
                    repository=i.repository,
                    digest=i.digest,
                    tags=i.tags,
                    verdict=i.verdict.value,
                    reasons=i.reasons,
                    size_bytes=i.size_bytes,
                    snapshot=i.model_dump(mode="json"),
                    graph_snapshots=[
                        member.model_dump(mode="json") for member in descendants(i, evaluated)[0]
                    ],
                )
                for i in candidates
            ],
        )
        batch, created = self.store.create(batch)
        if created:
            self.audit.write(
                "approval_requested",
                approval_id=batch.approval_id,
                items=[item.key for item in batch.items],
            )
        return batch

    def authorised(self, actor: str) -> bool:
        """Fail closed on missing group settings or any Graph failure."""
        group = getattr(self.config, "approvers_group_id", None)
        try:
            return bool(actor and isinstance(group, str) and group) and (
                self.membership(actor, group) is True
            )
        except Exception:
            return False

    def decide(
        self,
        action: str,
        approval_id: str,
        actor: str,
        now: datetime,
        items: list[tuple[str, str]] | None = None,
    ) -> Batch:
        """Authorize every click, then apply only a valid current-state transition."""
        now = utc(now)
        if not self.authorised(actor):
            self.audit.write("approval_refused", approval_id=approval_id, actor=actor)
            raise PermissionError("not authorised")
        if action not in {"approve", "reject", "cancel"}:
            raise ValueError("Unsupported approval action")

        def change(batch: Batch) -> list[str]:
            if batch.registry != self.config.registry.name:
                raise PermissionError("not authorised")
            if batch.status == Status.PENDING and now >= batch.expires_at:
                batch.status = Status.EXPIRED
                for item in batch.items:
                    if item.status == Status.PENDING:
                        item.status = Status.EXPIRED
                return ["expired"]
            selected = set(items) if items is not None else {i.key for i in batch.items}
            if not selected or not selected.issubset({i.key for i in batch.items}):
                raise ValueError("Unknown or empty cancellation selection")
            if action in {"approve", "reject"}:
                if items is not None:
                    raise ValueError("Approve and reject operate on the whole batch")
                if batch.status != Status.PENDING:
                    return []  # repeated clicks never restart the grace clock
                batch.decided_by, batch.decided_at = actor, now
                if action == "approve":
                    batch.status = Status.SCHEDULED
                    batch.scheduled_delete_at = now + timedelta(
                        hours=self.config.grace_period_hours
                    )
                else:
                    batch.status = Status.REJECTED
                for item in batch.items:
                    if item.status == Status.PENDING:
                        item.status = batch.status
                return ["scheduled" if action == "approve" else "rejected"]
            changed = False
            for item in batch.items:
                if item.key not in selected:
                    continue
                if item.processing or item.outcome is not None:
                    continue
                cancellable = item.status == Status.PENDING or (
                    item.status == Status.SCHEDULED
                    and batch.scheduled_delete_at is not None
                    and now < batch.scheduled_delete_at
                )
                if cancellable:
                    item.status = Status.CANCELLED
                    item.cancelled_by = actor
                    item.outcome_reason = "Cancelled by approver"
                    changed = True
            if changed:
                batch.cancelled_by = actor
                batch.aggregate()
            return ["cancelled"] if changed else []

        try:
            batch = self.store.mutate(approval_id, change)
        except PermissionError:
            self.audit.write("approval_refused", approval_id=approval_id, actor=actor)
            raise
        self.audit.write(
            "approval_action",
            approval_id=approval_id,
            action=action,
            actor=actor,
            status=batch.status,
            scheduled_delete_at=batch.scheduled_delete_at,
        )
        return batch

    def tick(self, now: datetime) -> None:
        """Expire pending requests and enqueue refreshed countdown cards."""
        now = utc(now)
        for existing in self.store.list_batches():
            if existing.registry != self.config.registry.name:
                continue

            def change(batch: Batch) -> list[str]:
                if batch.status == Status.PENDING and now >= batch.expires_at:
                    batch.status = Status.EXPIRED
                    for item in batch.items:
                        if item.status == Status.PENDING:
                            item.status = Status.EXPIRED
                    self.audit.write("approval_expired", approval_id=batch.approval_id)
                    return ["expired"]
                if (
                    batch.status == Status.SCHEDULED
                    and batch.scheduled_delete_at
                    and (now < batch.scheduled_delete_at)
                ):
                    return ["countdown"]
                return []

            self.store.mutate(existing.approval_id, change)
