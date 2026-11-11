"""Adaptive Card/email fixtures preserve all affected tags and action security data."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest

from guardian.approval.cards import alert_card, approval_card, cancel_url, final_card
from guardian.notify.email import GraphMailer, final_email, scheduled_email

NOW = datetime(2026, 11, 10, tzinfo=UTC)
PORTAL = "https://portal.azure.com/#resource/registry"
CANCEL = "https://guardian.example.test/cancel?route=mail"


def batch(status: str = "SCHEDULED") -> SimpleNamespace:
    """Return a fixture with shared tags and grouped but independently qualified orphans."""

    def item(repository: str, digest: str, tags: list[str], size: int) -> SimpleNamespace:
        return SimpleNamespace(
            repository=repository,
            digest=digest,
            tags=tags,
            verdict="STALE" if tags else "UNTAGGED",
            reasons=["unused", "old <unsafe>"],
            size_bytes=size,
            status=status,
            outcome=None,
        )

    return SimpleNamespace(
        approval_id="approval-1",
        run_id="run-1",
        registry="fixture",
        items=[
            item("app", "sha256:same", ["old", "archive"], 100),
            item("app", "sha256:orphan1", [], 20),
            item("app", "sha256:orphan2", [], 30),
            item("mirror", "sha256:orphan3", [], 40),
        ],
        status=status,
        requested_at=NOW - timedelta(hours=1),
        decided_by="approver-1",
        scheduled_delete_at=NOW + timedelta(hours=0.1) if status == "SCHEDULED" else None,
    )


def test_scheduled_card_has_all_tags_countdown_and_qualified_cancellation() -> None:
    card = approval_card(batch(), PORTAL, CANCEL, NOW)
    encoded = json.dumps(card)
    assert card["type"] == "AdaptiveCard"
    assert "All tags: old, archive" in encoded
    assert "app: 2 untagged manifests, 50 bytes" in encoded
    assert "mirror: 1 untagged manifests, 40 bytes" in encoded
    assert "00:06:00" in encoded and "2026-11-10T00:06:00+00:00" in encoded
    assert "sha256:orphan1" in encoded and "sha256:orphan2" in encoded
    assert "user_id" not in encoded
    cancel = card["actions"][0]
    assert cancel["type"] == "Action.Execute"
    assert cancel["data"] == {"approval_id": "approval-1", "action": "cancel"}
    item_actions = [block["actions"][0] for block in card["body"] if block["type"] == "ActionSet"]
    assert item_actions[0]["data"]["items"] == [{"repository": "app", "digest": "sha256:same"}]
    assert "repository" not in item_actions[0]["data"]
    assert "digest" not in item_actions[0]["data"]


def test_pending_actions_and_deadline_gate() -> None:
    pending = approval_card(batch("PENDING"), PORTAL, CANCEL, NOW)
    assert [action["data"]["action"] for action in pending["actions"][:-1]] == [
        "approve",
        "reject",
        "cancel",
    ]
    expired = approval_card(batch(), PORTAL, CANCEL, NOW + timedelta(minutes=6))
    assert len(expired["actions"]) == 1
    assert expired["actions"][0]["type"] == "Action.OpenUrl"
    assert "00:00:00" in json.dumps(expired)


def test_alert_and_final_cards_do_not_offer_deletion_actions() -> None:
    alert = alert_card("CRITICAL image is in use; KEEP", "sha256:same", PORTAL)
    assert "CRITICAL" in json.dumps(alert)
    assert all(action["type"] == "Action.OpenUrl" for action in alert["actions"])
    record = batch()
    record.items[0].status = "DELETED"
    record.items[0].outcome = "Deleted after successful backup"
    record.items[1].status = "CANCELLED"
    record.items[1].outcome = "Cancelled by approver"
    record.items[2].status = "SCHEDULED"
    record.items[2].outcome = "SKIPPED"
    record.items[2].outcome_reason = "Backup failed before deletion"
    card = final_card(record, PORTAL)
    output = json.dumps(card)
    for value in [
        "DELETED",
        "CANCELLED",
        "SKIPPED",
        "Backup failed before deletion",
        "old, archive",
    ]:
        assert value in output
    assert len(card["actions"]) == 1


def test_cancel_link_preserves_route_and_encodes_repository_identity() -> None:
    url = cancel_url(CANCEL, "approval&1", "nested/app", "sha256:same")
    assert parse_qs(urlsplit(url).query) == {
        "route": ["mail"],
        "approval_id": ["approval&1"],
        "repository": ["nested/app"],
        "digest": ["sha256:same"],
    }


def test_scheduled_email_has_graph_shape_escaped_facts_and_utc_deadline() -> None:
    payload = scheduled_email(batch(), "sender@example.test", "group@example.test", PORTAL, CANCEL)
    assert payload["saveToSentItems"] is True
    assert payload["message"]["toRecipients"] == [
        {"emailAddress": {"address": "group@example.test"}}
    ]
    content = payload["message"]["body"]["content"]
    assert payload["message"]["body"]["contentType"] == "HTML"
    assert "old, archive" in content and "approver-1" in content
    assert "old &lt;unsafe&gt;" in content and "<unsafe>" not in content
    assert "2026-11-10T00:06:00+00:00" in content
    assert "app: 2 untagged manifests, 50 bytes" in content
    assert "sha256:orphan1" in content and "sha256:orphan2" in content
    assert "Cancel batch" in content and "Open in Azure portal" in content
    with pytest.raises(ValueError, match="deadline"):
        scheduled_email(batch("PENDING"), "sender", "group", PORTAL, CANCEL)


def test_final_email_and_mailer_use_only_injected_graph_route() -> None:
    record = batch()
    record.items[0].status = "DELETED"
    record.items[0].outcome = "Successful backup and deletion"
    record.items[1].outcome = "SKIPPED"
    record.items[1].outcome_reason = "Fresh policy changed to KEEP"
    payload = final_email(record, "sender@example.test", "group@example.test", PORTAL)
    assert "Successful backup and deletion" in payload["message"]["body"]["content"]
    assert "Fresh policy changed to KEEP" in payload["message"]["body"]["content"]
    send = Mock()
    mailer = GraphMailer(send, "sender@example.test", "group@example.test")
    mailer.scheduled(record, PORTAL, CANCEL)
    mailer.final(record, PORTAL)
    assert send.call_count == 2
    assert all(
        call.args[0] == "/users/sender%40example.test/sendMail" for call in send.call_args_list
    )
    assert send.call_args.args[1] == payload
    with pytest.raises(ValueError):
        GraphMailer(send, "", "group@example.test")


def test_item_cancel_card_round_trips_through_actual_sdk_handler() -> None:
    import asyncio

    from microsoft_teams.api import AdaptiveCardInvokeActivity

    from guardian.approval.sdk import create_card_handler

    card = approval_card(batch(), PORTAL, CANCEL, NOW)
    action = next(block["actions"][0] for block in card["body"] if block["type"] == "ActionSet")
    invoke = AdaptiveCardInvokeActivity.model_validate(
        {
            "id": "invoke-item-cancel",
            "type": "invoke",
            "name": "adaptiveCard/action",
            "from": {"id": "teams-user", "aadObjectId": "trusted-approver"},
            "recipient": {"id": "bot"},
            "conversation": {"id": "dedicated-channel"},
            "value": {"action": action},
        }
    )
    callback = Mock(return_value="cancelled selected item")
    response = asyncio.run(create_card_handler(callback)(SimpleNamespace(activity=invoke)))
    assert response.value == "cancelled selected item"
    callback.assert_called_once_with(
        "cancel", "approval-1", "trusted-approver", [("app", "sha256:same")]
    )
