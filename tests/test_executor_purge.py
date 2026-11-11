"""Purge guardrails, races, backup ordering, and restore audit."""

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from test_policy import NOW, config, image

from guardian.approval.models import Batch, Status
from guardian.approval.service import ApprovalService
from guardian.approval.store import ApprovalStore
from guardian.audit.log import AuditLog
from guardian.executor.backup import BlobBackup, LocalBlobTransport
from guardian.executor.fixture_registry import FixtureRegistryStore, fixture_image
from guardian.executor.purge import PurgeExecutor
from guardian.models import Evidence, Image
from guardian.policy.engine import key

DUE = NOW + timedelta(hours=0.1)


def environment(
    tmp_path: Path, *, index: bool = False
) -> tuple[
    PurgeExecutor,
    ApprovalService,
    FixtureRegistryStore,
    Batch,
    Image,
    list[Image],
    dict[str, bytes],
]:
    settings = config(dry_run=False, grace_period_hours=0.1, approvers_group_id="group")
    registry = FixtureRegistryStore(tmp_path / "registry.sqlite", "demo")
    root, blobs = fixture_image(image())
    graph = [root]
    if index:
        child = root.model_copy(update={"tags": []})
        root, root_blobs = fixture_image(
            image(digest="index", tags=["v0"], pushed_at=NOW - timedelta(days=150)),
            children=[child],
        )
        blobs.update(root_blobs)
        graph = [root, child]
    registry.seed(graph, blobs)
    evidence = Evidence(history_started_at=NOW - timedelta(days=200))
    audit = AuditLog(tmp_path / "audit.jsonl", "original-run")
    store = ApprovalStore(tmp_path / "approval.sqlite")
    approvals = ApprovalService(store, settings, lambda actor, _: actor == "alice", audit)
    batch = approvals.request(graph, evidence, [key(root)], NOW)
    approvals.decide("approve", batch.approval_id, "alice", NOW)
    for event in store.pending_events():
        store.delivered(event)

    def refresh(now: datetime) -> tuple[list[Image], Evidence]:
        return [
            i for repo in registry.list_repositories() for i in registry.list_images(repo)
        ], evidence

    backup = BlobBackup(LocalBlobTransport(tmp_path / "blobs"))
    alert = Mock()
    executor = PurgeExecutor(store, settings, registry, backup, refresh, audit, alert)
    return executor, approvals, registry, batch, root, graph, blobs


def test_no_delete_before_grace_and_dry_run_is_default(tmp_path: Path) -> None:
    executor, approvals, registry, batch, root, _, _ = environment(tmp_path)
    assert executor.run(NOW) == []
    executor.config = executor.config.model_copy(update={"dry_run": True})
    assert executor.run(DUE)[0].outcome == "DRY_RUN"
    assert registry.list_images("app")
    item = approvals.store.get(batch.approval_id).items[0]
    assert item.status == Status.SCHEDULED and item.backup_id is None and not item.processing


@pytest.mark.parametrize(
    "status", [Status.CANCELLED, Status.EXPIRED, Status.REJECTED, Status.PENDING]
)
def test_refuses_non_scheduled_items(tmp_path: Path, status: Status) -> None:
    executor, approvals, registry, batch, _, _, _ = environment(tmp_path)

    def change(current: Batch) -> list[str]:
        current.status = current.items[0].status = status
        return []

    approvals.store.mutate(batch.approval_id, change)
    assert executor.run(DUE) == []
    assert registry.list_images("app")


@pytest.mark.parametrize(
    "updates",
    [
        {"tags": ["prod"]},
        {"in_use": True},
        {"locked": True},
        {"security_unknown": True},
        {"children_complete": False},
        {"vulns": {"CRITICAL": 1}},
        {"tags": ["retagged"]},
    ],
)
def test_changed_policy_or_metadata_skips(tmp_path: Path, updates: dict[str, object]) -> None:
    executor, approvals, registry, batch, _, graph, _ = environment(tmp_path)
    executor.refresh = lambda now: (
        [graph[0].model_copy(update=updates)],
        Evidence(history_started_at=NOW - timedelta(days=200)),
    )
    result = executor.run(DUE)[0]
    assert result.outcome == "SKIPPED"
    assert registry.list_images("app")
    assert approvals.store.get(batch.approval_id).items[0].outcome == "SKIPPED"
    executor.alert.assert_called_once()


@pytest.mark.parametrize("evidence", [Evidence(usage_failed=True), Evidence(pull_failed=True)])
def test_source_failures_keep_and_alert(tmp_path: Path, evidence: Evidence) -> None:
    executor, _, registry, _, _, graph, _ = environment(tmp_path)
    executor.refresh = lambda now: (graph, evidence)
    assert executor.run(DUE)[0].outcome == "SKIPPED"
    assert registry.list_images("app")
    executor.alert.assert_called_once()


def test_backup_failure_blocks_delete(tmp_path: Path) -> None:
    executor, approvals, registry, batch, _, _, _ = environment(tmp_path)
    executor.backup = Mock()
    executor.backup.save.side_effect = OSError("blob unavailable")
    assert executor.run(DUE)[0].outcome == "SKIPPED"
    assert registry.list_images("app")
    assert approvals.store.get(batch.approval_id).items[0].backup_id is None
    executor.alert.assert_called_once()


def test_policy_rechecked_after_backup(tmp_path: Path) -> None:
    executor, _, registry, _, root, graph, blobs = environment(tmp_path)
    save = executor.backup.save

    def lock_after_backup(
        registry_name: str, images: list[Image], read_blob: Callable[[str], bytes], now: datetime
    ) -> str:
        identifier = save(registry_name, images, read_blob, now)
        registry.seed([root.model_copy(update={"locked": True})], blobs)
        return identifier

    executor.backup.save = lock_after_backup
    assert executor.run(DUE)[0].outcome == "SKIPPED"
    assert registry.list_images("app")[0].locked


def test_success_audit_restore_and_idempotent_repeat(tmp_path: Path) -> None:
    executor, approvals, registry, batch, root, _, _ = environment(tmp_path)
    assert executor.run(DUE)[0].outcome == "DELETED"
    assert registry.list_images("app") == []
    assert executor.run(DUE) == []
    item = approvals.store.get(batch.approval_id).items[0]
    assert item.backup_id and item.status == Status.DELETED
    assert executor.restore(root.digest, "operator", DUE).outcome == "RESTORED"
    assert registry.list_images("app")[0].tags == root.tags
    rows = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    deletion = next(row for row in rows if row["event"] == "deletion")
    assert deletion["run_id"] == "original-run"
    assert deletion["approval_id"] == batch.approval_id and deletion["approver"] == "alice"
    assert deletion["digest"] == root.digest
    assert any(row["event"] == "restore" and row["actor"] == "operator" for row in rows)


def test_index_deletes_root_only_and_restores_graph(tmp_path: Path) -> None:
    executor, _, registry, _, root, graph, _ = environment(tmp_path, index=True)
    assert executor.run(DUE)[0].outcome == "DELETED"
    remaining = registry.list_images("app")
    assert [i.digest for i in remaining] == [graph[1].digest]
    assert executor.restore(root.digest, "operator", DUE).outcome == "RESTORED"
    assert {i.digest for i in registry.list_images("app")} == {i.digest for i in graph}


def test_atomic_claim_prevents_two_workers_deleting_twice(tmp_path: Path) -> None:
    executor, _, registry, _, _, _, _ = environment(tmp_path)
    with ThreadPoolExecutor(max_workers=2) as pool:
        result = list(pool.map(executor.run, [DUE, DUE]))
    assert sum(item.outcome == "DELETED" for group in result for item in group) == 1
    assert registry.list_images("app") == []


def test_partial_pending_cancellation_is_never_rescheduled(tmp_path: Path) -> None:
    settings = config(approvers_group_id="group")
    approvals = ApprovalService(
        ApprovalStore(tmp_path / "state"),
        settings,
        lambda *_: True,
        AuditLog(tmp_path / "audit", "run"),
    )
    batch = approvals.request(
        [image(), image(digest="b")], Evidence(), [("app", "a"), ("app", "b")], NOW
    )
    approvals.decide("cancel", batch.approval_id, "alice", NOW, [("app", "a")])
    scheduled = approvals.decide("approve", batch.approval_id, "alice", NOW)
    assert [item.status for item in scheduled.items] == [Status.CANCELLED, Status.SCHEDULED]


def test_backup_record_failure_finishes_claim_without_deleting(tmp_path: Path) -> None:
    executor, approvals, registry, batch, _, _, _ = environment(tmp_path)
    mutate = approvals.store.mutate
    calls = 0

    def fail_checkpoint(approval_id: str, change: Callable[[Batch], list[str]]) -> Batch:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("checkpoint failed")
        return mutate(approval_id, change)

    approvals.store.mutate = fail_checkpoint
    assert executor.run(DUE)[0].outcome == "SKIPPED"
    assert registry.list_images("app")
    item = approvals.store.get(batch.approval_id).items[0]
    assert not item.processing and item.outcome == "SKIPPED"
