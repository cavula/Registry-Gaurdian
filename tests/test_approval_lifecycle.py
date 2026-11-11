"""T8 approval, cancellation, authorization and notification safety."""

from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient
from test_policy import NOW, config, image

from guardian.approval.cancel import build_cancel_app
from guardian.approval.models import Status
from guardian.approval.service import ApprovalService
from guardian.approval.store import ApprovalStore
from guardian.approval.teams import GraphMembership, TeamsBot
from guardian.audit.log import AuditLog
from guardian.models import Evidence
from guardian.notify.email import GraphMailer


def setup(tmp_path: Path, **updates: object) -> tuple[ApprovalService, TeamsBot, Mock, Mock]:
    settings = config(
        approvers_group_id="approvers", grace_period_hours=0.1, approval_ttl_hours=0.2, **updates
    )
    service = ApprovalService(
        ApprovalStore(tmp_path / "state.sqlite"),
        settings,
        lambda actor, group: actor in {"alice", "bob"},
        AuditLog(tmp_path / "audit.jsonl", "approval-run"),
    )
    send, mail = Mock(return_value="activity-1"), Mock()
    bot = TeamsBot(
        service,
        send,
        Mock(),
        GraphMailer(mail, "sender@example.test", "group@example.test"),
        "channel-1",
        "https://portal.azure.com/#resource/fixture",
        "https://guardian.example.test/cancel",
    )
    return service, bot, send, mail


def request(service: ApprovalService):
    return service.request(
        [image(), image(digest="b")], Evidence(), [("app", "a"), ("app", "b")], NOW
    )


def test_approve_only_schedules_and_duplicate_does_not_reset(tmp_path: Path) -> None:
    service, bot, send, mail = setup(tmp_path)
    batch = request(service)
    same = request(service)
    assert same.approval_id == batch.approval_id
    bot.flush(NOW)
    send.assert_called_once()
    result = service.decide("approve", batch.approval_id, "alice", NOW)
    assert result.status == Status.SCHEDULED
    assert result.scheduled_delete_at == NOW + timedelta(hours=0.1)
    result2 = service.decide("approve", batch.approval_id, "bob", NOW + timedelta(minutes=1))
    assert result2.scheduled_delete_at == result.scheduled_delete_at
    bot.flush(NOW)
    mail.assert_called_once()
    assert service.store.scheduled_notice_delivered(batch.approval_id)
    assert all(item.outcome is None for item in result.items)


def test_every_action_checks_membership_and_graph_failure_denies(tmp_path: Path) -> None:
    service, bot, _, _ = setup(tmp_path)
    batch = request(service)
    for action in ["approve", "reject", "cancel"]:
        assert bot.action(action, batch.approval_id, "outsider", now=NOW) == "not authorised"
    assert service.store.get(batch.approval_id).status == Status.PENDING
    service.membership = Mock(side_effect=RuntimeError("Graph unavailable"))
    with pytest.raises(PermissionError):
        service.decide("approve", batch.approval_id, "alice", NOW)
    graph = Mock(return_value={"value": ["approvers"]})
    assert GraphMembership(graph)("alice", "approvers")
    assert graph.call_args.args == ("/users/alice/checkMemberGroups", {"groupIds": ["approvers"]})


def test_expiry_boundary_reject_and_cancel_per_item(tmp_path: Path) -> None:
    service, _, _, _ = setup(tmp_path)
    batch = request(service)
    expired = service.decide("approve", batch.approval_id, "alice", NOW + timedelta(hours=0.2))
    assert expired.status == Status.EXPIRED
    service, _, _, _ = setup(tmp_path / "second")
    batch = request(service)
    service.decide("approve", batch.approval_id, "alice", NOW)
    part = service.decide(
        "cancel", batch.approval_id, "bob", NOW + timedelta(minutes=1), [("app", "a")]
    )
    assert [i.status for i in part.items] == [Status.CANCELLED, Status.SCHEDULED]
    at_deadline = service.decide(
        "cancel", batch.approval_id, "alice", part.scheduled_delete_at, [("app", "b")]
    )
    assert at_deadline.items[1].status == Status.SCHEDULED
    with pytest.raises(ValueError):
        service.decide("cancel", batch.approval_id, "alice", NOW, [("mirror", "a")])
    service, _, _, _ = setup(tmp_path / "third")
    batch = request(service)
    rejected = service.decide("reject", batch.approval_id, "alice", NOW)
    assert rejected.status == Status.REJECTED


def test_scheduler_and_outbox_retry_no_repeat_email(tmp_path: Path) -> None:
    service, bot, send, mail = setup(tmp_path)
    batch = request(service)
    bot.flush(NOW)
    service.decide("approve", batch.approval_id, "alice", NOW)
    bot.update.side_effect = RuntimeError("Teams down")
    bot.flush(NOW)
    assert not service.store.scheduled_notice_delivered(batch.approval_id)
    mail.assert_called_once()
    bot.update.side_effect = None
    bot.flush(NOW)
    mail.assert_called_once()
    assert service.store.scheduled_notice_delivered(batch.approval_id)
    service.tick(NOW + timedelta(minutes=1))
    bot.flush(NOW + timedelta(minutes=1))
    assert not service.store.pending_events()
    bot.alert("a", "Critical in-use image")
    assert send.call_count == 2


def test_cancel_link_authentication_and_get_does_not_mutate(tmp_path: Path) -> None:
    service, _, _, _ = setup(tmp_path)
    batch = request(service)
    app = build_cancel_app(
        service, lambda token: "alice" if token == "Bearer valid" else "", clock=lambda: NOW
    )
    client = TestClient(app)
    assert client.get("/cancel", params={"approval_id": batch.approval_id}).status_code == 200
    assert service.store.get(batch.approval_id).status == Status.PENDING
    body = {"approval_id": batch.approval_id}
    assert client.post("/cancel", json=body).status_code == 401
    assert (
        client.post(
            "/cancel", json={**body, "items": []}, headers={"Authorization": "Bearer valid"}
        ).status_code
        == 422
    )
    assert (
        client.post("/cancel", json=body, headers={"Authorization": "Bearer valid"}).status_code
        == 200
    )
    assert service.store.get(batch.approval_id).status == Status.CANCELLED


def test_request_refuses_keep_and_unknown_items(tmp_path: Path) -> None:
    service, _, _, _ = setup(tmp_path)
    with pytest.raises(ValueError):
        service.request([image(tags=["prod"])], Evidence(), [("app", "a")], NOW)
    with pytest.raises(ValueError):
        service.request([image()], Evidence(), [("mirror", "a")], NOW)
