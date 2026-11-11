"""Guarded, repository-qualified execution of scheduled approval items."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from guardian.approval.models import ApprovalItem, Batch, Status
from guardian.approval.store import ApprovalStore
from guardian.audit.log import AuditLog
from guardian.config import Config, utc
from guardian.executor.backup import BlobBackup
from guardian.executor.registry import RegistryDeleter, manifest_signature
from guardian.models import Evidence, Image, Verdict
from guardian.policy.engine import Key, descendants, evaluate, key


@dataclass(frozen=True)
class PurgeResult:
    """Outcome of a single repository and digest operation."""

    repository: str
    digest: str
    outcome: str
    reason: str


class UnsafeImage(ValueError):
    """A refreshed inventory or policy decision prevents deletion."""


def due(batch: Batch, now: datetime, registry: str) -> bool:
    """Require a valid approval decision and an ended grace period."""
    return (
        batch.registry == registry
        and batch.status == Status.SCHEDULED
        and bool(batch.decided_by)
        and batch.decided_at is not None
        and batch.scheduled_delete_at is not None
        and batch.requested_at <= batch.decided_at < batch.expires_at
        and batch.decided_at <= batch.scheduled_delete_at <= now
    )


def available(item: ApprovalItem) -> bool:
    """Return whether a scheduled item still needs processing."""
    return item.status == Status.SCHEDULED and item.outcome is None and not item.processing


def signature(graph: list[Image]) -> dict[Key, tuple[object, ...]]:
    """Index physical signatures by repository and digest."""
    return {key(image): manifest_signature(image) for image in graph}


class PurgeExecutor:
    """Recheck policy and verify a backup before conditional registry deletion."""

    def __init__(
        self,
        store: ApprovalStore,
        config: Config,
        registry: RegistryDeleter,
        backup: BlobBackup,
        refresh: Callable[[datetime], tuple[list[Image], Evidence]],
        audit: AuditLog,
        alert: Callable[[str, str], None] | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self.registry = registry
        self.backup = backup
        self.refresh = refresh
        self.audit = audit
        self.alert = alert

    def run(self, now: datetime) -> list[PurgeResult]:
        """Process due items, or preview them with zero mutations in dry run."""
        now = utc(now)
        results: list[PurgeResult] = []
        self.audit.write("purge_started", dry_run=self.config.dry_run)
        for batch in self.store.list_batches():
            if not due(batch, now, self.config.registry.name):
                continue
            for item in batch.items:
                if not available(item):
                    continue
                if self.config.dry_run:
                    results.append(PurgeResult(*item.key, "DRY_RUN", "Scheduled item is due"))
                    continue
                if not self.store.scheduled_notice_delivered(batch.approval_id):
                    results.append(
                        PurgeResult(*item.key, "DEFERRED", "Scheduled notification is pending")
                    )
                    continue
                claim = self._claim(batch.approval_id, item.key, now)
                if claim:
                    results.append(self._purge_item(*claim, now))
        self.audit.write("purge_finished", items=len(results))
        return results

    def _claim(
        self, approval_id: str, identity: Key, now: datetime
    ) -> tuple[Batch, ApprovalItem] | None:
        claimed = False

        def change(batch: Batch) -> list[str]:
            nonlocal claimed
            if not due(batch, now, self.config.registry.name):
                return []
            for item in batch.items:
                if item.key == identity and available(item):
                    item.processing = True
                    claimed = True
                    break
            return []

        batch = self.store.mutate(approval_id, change)
        return (
            (batch, next(item for item in batch.items if item.key == identity)) if claimed else None
        )

    def _fresh_graph(self, approved: ApprovalItem, now: datetime) -> list[Image]:
        try:
            images, evidence = self.refresh(now)
            if len({key(i) for i in images}) != len(images) or any(
                image.registry != self.config.registry.name for image in images
            ):
                raise ValueError("Inventory identity mismatch")
            inventory = {key(i): i for i in evaluate(images, self.config, evidence, now)}
            original = [Image.model_validate(image) for image in approved.graph_snapshots]
        except Exception:
            raise UnsafeImage("Could not refresh inventory and policy evidence") from None

        current = inventory.get(approved.key)
        if current is None:
            raise UnsafeImage("Approved image is missing")
        if current.verdict == Verdict.KEEP or current.verdict.value != approved.verdict:
            raise UnsafeImage(
                f"Verdict changed to {current.verdict.value}: {'; '.join(current.reasons)}"
            )
        graph, complete = descendants(current, inventory)
        if not complete or not original or signature(graph) != signature(original):
            raise UnsafeImage("Approved manifest graph or tag set changed")
        return graph

    def _purge_item(self, batch: Batch, item: ApprovalItem, now: datetime) -> PurgeResult:
        audit = AuditLog(self.audit.path, batch.run_id)
        context = {
            "approval_id": batch.approval_id,
            "approver": batch.decided_by,
            "repository": item.repository,
            "digest": item.digest,
            "purge_run_id": self.audit.run_id,
        }
        backup_id: str | None = None
        outcome, reason = "DELETED", "Verified backup and deleted the approved manifest"
        try:
            graph = self._fresh_graph(item, now)
            try:
                backup_id = self.backup.save(batch.registry, graph, self.registry.read_blob, now)
            except Exception:
                raise UnsafeImage("Backup failed or could not be verified") from None
            if not backup_id:
                raise UnsafeImage("Backup returned no verified identifier")
            audit.write("backup", **context, backup_id=backup_id)
            expected = self._fresh_graph(item, now)

            def record_backup(current: Batch) -> list[str]:
                target = next(candidate for candidate in current.items if candidate.key == item.key)
                if (
                    not due(current, now, batch.registry)
                    or target.status != Status.SCHEDULED
                    or not target.processing
                    or target.outcome is not None
                ):
                    raise UnsafeImage("Approval is no longer scheduled")
                target.backup_id = backup_id
                return []

            self.store.mutate(batch.approval_id, record_backup)
            try:
                self.registry.delete_image(item.repository, item.digest, expected=expected)
            except Exception:
                outcome, reason = "FAILED", "Registry refused deletion or its outcome is uncertain"
        except UnsafeImage as exc:
            outcome, reason = "SKIPPED", str(exc)
        except Exception:
            outcome, reason = "SKIPPED", "Could not record the verified backup or approval claim"

        def finish(current: Batch) -> list[str]:
            target = next(candidate for candidate in current.items if candidate.key == item.key)
            target.processing = False
            target.outcome, target.outcome_reason = outcome, reason
            if outcome == "DELETED":
                target.status = Status.DELETED
            current.aggregate()
            unfinished = any(
                candidate.status == Status.SCHEDULED and candidate.outcome is None
                for candidate in current.items
            )
            if not unfinished and not current.final_notified:
                current.final_notified = True
                return ["final"]
            return []

        self.store.mutate(batch.approval_id, finish)
        event = {"DELETED": "deletion", "SKIPPED": "purge_skipped", "FAILED": "purge_failed"}[
            outcome
        ]
        audit.write(event, **context, reason=reason, backup_id=backup_id)
        if outcome != "DELETED":
            audit.write("alert", **context, reason=reason)
            if self.alert is not None:
                try:
                    self.alert(item.digest, f"{item.repository}@{item.digest}: {reason}")
                except Exception:
                    audit.write("purge_alert_failed", **context)
        return PurgeResult(*item.key, outcome, reason)

    def restore(
        self, digest: str, actor: str, now: datetime, *, repository: str | None = None
    ) -> PurgeResult:
        """Verify and restore an approved deletion with its original tags."""
        if not actor.strip():
            raise ValueError("A restore actor is required")
        records = [
            (batch, item)
            for batch in reversed(self.store.list_batches())
            for item in batch.items
            if batch.registry == self.config.registry.name
            and item.status == Status.DELETED
            and item.backup_id is not None
            and item.digest == digest
            and (repository is None or item.repository == repository)
        ]
        if not records:
            raise ValueError("No verified backup for this deleted image")
        if len({item.repository for _, item in records}) > 1:
            raise ValueError("Digest occurs in multiple repositories. Specify the repository.")
        batch, item = records[0]
        assert item.backup_id is not None

        def preview(_: list[Image], __: dict[str, bytes]) -> None:
            """Validate the archive without modifying the test registry."""

        self.backup.restore(
            item.backup_id,
            batch.registry,
            item.repository,
            digest,
            preview if self.config.dry_run else self.registry.import_graph,
            utc(now),
        )
        outcome = "DRY_RUN" if self.config.dry_run else "RESTORED"
        AuditLog(self.audit.path, batch.run_id).write(
            "restore_preview" if self.config.dry_run else "restore",
            approval_id=batch.approval_id,
            actor=actor,
            repository=item.repository,
            digest=digest,
            backup_id=item.backup_id,
            restore_run_id=self.audit.run_id,
        )
        return PurgeResult(*item.key, outcome, "Verified archive and original tags")
