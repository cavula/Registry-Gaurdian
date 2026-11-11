"""Microsoft Graph sendMail payloads through an injected transport only."""

from collections import defaultdict
from collections.abc import Callable
from html import escape
from typing import Any
from urllib.parse import quote

from guardian.approval.cards import ApprovalItemView, BatchView, cancel_url, utc_time


def _details(item: ApprovalItemView, *, final: bool) -> str:
    values = [
        ("Image", f"{item.repository}@{item.digest}"),
        ("All tags", ", ".join(item.tags) or "(untagged)"),
        ("Verdict", item.verdict),
        ("Reason", "; ".join(item.reasons)),
    ]
    if final:
        values.extend([("Status", item.status), ("Outcome", item.outcome or "No outcome recorded")])
        reason = getattr(item, "outcome_reason", None)
        if reason:
            values.append(("Outcome reason", reason))
    return (
        "<dl>"
        + "".join(f"<dt>{escape(label)}</dt><dd>{escape(value)}</dd>" for label, value in values)
        + "</dl>"
    )


def _images(batch: BatchView, *, final: bool, cancel_base_url: str | None = None) -> str:
    sections: list[str] = []
    untagged: dict[str, list[ApprovalItemView]] = defaultdict(list)
    for item in batch.items:
        if not item.tags:
            untagged[item.repository].append(item)
        else:
            sections.append(_details(item, final=final))
        if cancel_base_url and item.status in {"PENDING", "SCHEDULED"}:
            url = cancel_url(cancel_base_url, batch.approval_id, item.repository, item.digest)
            sections.append(
                f'<p><a href="{escape(url, quote=True)}">'
                f"Cancel {escape(item.repository)}@{escape(item.digest)}</a></p>"
            )
    for repository, members in sorted(untagged.items()):
        total = sum(item.size_bytes for item in members)
        sections.append(
            f"<h3>{escape(repository)}: {len(members)} untagged manifests, {total} bytes</h3>"
        )
        sections.extend(_details(item, final=final) for item in members)
    return "".join(sections)


def _payload(subject: str, content: str, distribution: str) -> dict[str, Any]:
    return {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": content},
            "toRecipients": [{"emailAddress": {"address": distribution}}],
        },
        "saveToSentItems": True,
    }


def scheduled_email(
    batch: BatchView,
    sender: str,
    distribution: str,
    portal_url: str,
    cancel_base_url: str,
) -> dict[str, Any]:
    """Render the scheduled approval snapshot, deadline and authenticated cancel links."""
    if batch.scheduled_delete_at is None:
        raise ValueError("Scheduled email requires a deletion deadline")
    deadline = utc_time(batch.scheduled_delete_at).isoformat()
    cancel = cancel_url(cancel_base_url, batch.approval_id)
    content = (
        "<h1>Registry Guardian: deletion scheduled</h1>"
        f"<p>Registry: {escape(batch.registry)}</p>"
        f"<p>Approval: {escape(batch.approval_id)}; Run: {escape(batch.run_id)}</p>"
        f"<p>Service mailbox: {escape(sender)}</p>"
        f"<p>Approver: {escape(batch.decided_by or '(not recorded)')}</p>"
        f"<p>Scheduled deletion (UTC): {escape(deadline)}</p>"
        f'<p><a href="{escape(cancel, quote=True)}">Cancel batch</a> '
        f'| <a href="{escape(portal_url, quote=True)}">Open in Azure portal</a></p>'
        "<p>Cancellation requires authentication and approver group membership.</p>"
        + _images(batch, final=False, cancel_base_url=cancel_base_url)
    )
    return _payload(f"Registry Guardian: {batch.approval_id} scheduled", content, distribution)


def final_email(
    batch: BatchView,
    sender: str,
    distribution: str,
    portal_url: str,
) -> dict[str, Any]:
    """Render final per-item outcomes after the purge/restore workflow."""
    content = (
        "<h1>Registry Guardian: final results</h1>"
        f"<p>Registry: {escape(batch.registry)}</p>"
        f"<p>Approval: {escape(batch.approval_id)}; Run: {escape(batch.run_id)}</p>"
        f"<p>Service mailbox: {escape(sender)}</p>"
        f"<p>Batch status: {escape(batch.status)}</p>"
        f'<p><a href="{escape(portal_url, quote=True)}">Open in Azure portal</a></p>'
        + _images(batch, final=True)
    )
    return _payload(f"Registry Guardian: {batch.approval_id} final results", content, distribution)


class GraphMailer:
    """Send Graph-shaped payloads through an explicitly injected fake/SDK callable."""

    def __init__(
        self,
        send: Callable[[str, dict[str, Any]], None],
        sender: str,
        distribution: str,
    ) -> None:
        if not sender or not distribution:
            raise ValueError("Sender and distribution list are required")
        self._send = send
        self.sender = sender
        self.distribution = distribution

    def scheduled(self, batch: BatchView, portal: str, cancelbase: str) -> None:
        """Queue the scheduled message against the service mailbox's Graph sendMail route."""
        payload = scheduled_email(batch, self.sender, self.distribution, portal, cancelbase)
        self._send(f"/users/{quote(self.sender, safe='')}/sendMail", payload)

    def final(self, batch: BatchView, portal: str) -> None:
        """Queue final results through the same injected transport."""
        payload = final_email(batch, self.sender, self.distribution, portal)
        self._send(f"/users/{quote(self.sender, safe='')}/sendMail", payload)
