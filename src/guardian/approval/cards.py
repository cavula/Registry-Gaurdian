"""Adaptive Card payloads without SDK or service dependencies."""

from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


class ApprovalItemView(Protocol):
    """Read-only approval item shape consumed by notification builders."""

    repository: str
    digest: str
    tags: list[str]
    verdict: str
    reasons: list[str]
    size_bytes: int
    status: str
    outcome: str | None
    outcome_reason: str | None


class BatchView(Protocol):
    """Read-only approval batch shape consumed by notification builders."""

    approval_id: str
    run_id: str
    registry: str
    status: str
    requested_at: datetime
    decided_by: str | None
    scheduled_delete_at: datetime | None

    @property
    def items(self) -> Sequence[ApprovalItemView]:
        """Return all qualified manifest approval snapshots."""
        ...


def utc_time(value: datetime) -> datetime:
    """Normalize timestamps for rendering without consulting the clock."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def cancel_url(
    base_url: str,
    approval_id: str,
    repository: str | None = None,
    digest: str | None = None,
) -> str:
    """Build an authenticated cancellation-route URL with qualified optional item identity."""
    parts = urlsplit(base_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["approval_id"] = approval_id
    if repository is not None:
        query["repository"] = repository
    if digest is not None:
        query["digest"] = digest
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _text(value: str, **extra: Any) -> dict[str, Any]:
    return {"type": "TextBlock", "text": value, "wrap": True, **extra}


def _execute(
    batch: BatchView,
    title: str,
    action: str,
    items: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {"approval_id": batch.approval_id, "action": action}
    if items is not None:
        data["items"] = items
    return {
        "type": "Action.Execute",
        "title": title,
        "verb": action,
        "data": data,
    }


def _shell(body: list[dict[str, Any]], actions: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "$schema": "https://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.5",
        "body": body,
        "actions": actions,
    }


def _item_text(item: ApprovalItemView, *, final: bool = False) -> str:
    tags = ", ".join(item.tags) if item.tags else "(untagged)"
    value = (
        f"{item.repository}@{item.digest}\n"
        f"All tags: {tags}\nVerdict: {item.verdict}\n"
        f"Reason: {'; '.join(item.reasons)}"
    )
    if final:
        value += f"\nStatus: {item.status}\nOutcome: {item.outcome or 'No outcome recorded'}"
        reason = getattr(item, "outcome_reason", None)
        if reason:
            value += f"\nOutcome reason: {reason}"
    return value


def _items(batch: BatchView, *, final: bool = False) -> list[dict[str, Any]]:
    tagged = [item for item in batch.items if item.tags]
    untagged: dict[str, list[ApprovalItemView]] = defaultdict(list)
    for item in batch.items:
        if not item.tags:
            untagged[item.repository].append(item)
    body = [_text(_item_text(item, final=final)) for item in tagged]
    for repository, members in sorted(untagged.items()):
        total = sum(item.size_bytes for item in members)
        body.append(
            _text(
                f"{repository}: {len(members)} untagged manifests, {total} bytes", weight="Bolder"
            )
        )
        body.extend(_text(_item_text(item, final=final)) for item in members)
    return body


def approval_card(
    batch: BatchView, portal_url: str, cancel_base_url: str, now: datetime
) -> dict[str, Any]:
    """Show every affected manifest/tag and only locally compute the grace countdown."""
    body = [
        _text("Registry Guardian approval", weight="Bolder", size="Large"),
        _text(f"Registry: {batch.registry}\nApproval: {batch.approval_id}\nStatus: {batch.status}"),
    ]
    actions: list[dict[str, Any]] = []
    if batch.status == "PENDING":
        actions.extend(
            [
                _execute(batch, "Approve", "approve"),
                _execute(batch, "Reject", "reject"),
                _execute(batch, "Cancel", "cancel"),
            ]
        )
    deadline = batch.scheduled_delete_at
    can_cancel = batch.status == "PENDING"
    if deadline is not None:
        deadline = utc_time(deadline)
        seconds = max(0, int((deadline - utc_time(now)).total_seconds()))
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        body.append(
            _text(
                f"Scheduled deletion (UTC): {deadline.isoformat()}\n"
                f"Countdown: {hours:02d}:{minutes:02d}:{seconds:02d}\n"
                f"Approver: {batch.decided_by or '(not recorded)'}"
            )
        )
        can_cancel = batch.status == "SCHEDULED" and utc_time(now) < deadline
        if can_cancel:
            actions.append(_execute(batch, "Cancel", "cancel"))
            body.append(_text("Cancellation also requires an authenticated approver."))
            body.append(
                {
                    "type": "Container",
                    "items": [_text("Open authenticated cancellation page")],
                    "selectAction": {
                        "type": "Action.OpenUrl",
                        "url": cancel_url(cancel_base_url, batch.approval_id),
                    },
                }
            )
    body.extend(_items(batch))
    if can_cancel:
        for item in batch.items:
            if item.status not in {"PENDING", "SCHEDULED"}:
                continue
            body.append(
                {
                    "type": "ActionSet",
                    "actions": [
                        _execute(
                            batch,
                            f"Cancel {item.repository}@{item.digest}",
                            "cancel",
                            items=[{"repository": item.repository, "digest": item.digest}],
                        )
                    ],
                }
            )
    actions.append({"type": "Action.OpenUrl", "title": "Open in Azure portal", "url": portal_url})
    return _shell(body, actions)


def alert_card(message: str, digest: str, portal_url: str) -> dict[str, Any]:
    """Render a security/safety alert without any deletion action."""
    return _shell(
        [
            _text("Registry Guardian alert", weight="Bolder", size="Large"),
            _text(f"Digest: {digest}"),
            _text(message),
        ],
        [{"type": "Action.OpenUrl", "title": "Open in Azure portal", "url": portal_url}],
    )


def final_card(batch: BatchView, portal_url: str) -> dict[str, Any]:
    """Show every final deletion, skip, cancellation or restore result and its reason."""
    body = [
        _text("Registry Guardian final results", weight="Bolder", size="Large"),
        _text(f"Registry: {batch.registry}\nApproval: {batch.approval_id}\nStatus: {batch.status}"),
        *_items(batch, final=True),
    ]
    return _shell(
        body, [{"type": "Action.OpenUrl", "title": "Open in Azure portal", "url": portal_url}]
    )
