"""Injected Teams/Graph notification delivery and authenticated action boundary."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from guardian.approval.cards import alert_card, approval_card, final_card
from guardian.approval.models import Batch
from guardian.approval.service import ApprovalService
from guardian.notify.email import GraphMailer


class GraphMembership:
    """Transitive security-group membership via an injected Graph callable."""

    def __init__(self, call: Callable[[str, dict[str, Any]], dict[str, Any]]) -> None:
        self.call = call

    def __call__(self, actor: str, group: str) -> bool:
        """A group must appear explicitly in Graph's successful response."""
        result = self.call(
            f"/users/{quote(actor, safe='')}/checkMemberGroups", {"groupIds": [group]}
        )
        return group in result.get("value", [])


class TeamsBot:
    """Deliver only to a configured dedicated channel through injected SDK methods."""

    def __init__(
        self,
        service: ApprovalService,
        send: Callable[[str, dict[str, Any]], str],
        update: Callable[[str, str, dict[str, Any]], None],
        mailer: GraphMailer,
        channel: str,
        portal_url: str,
        cancel_base_url: str,
    ) -> None:
        if (
            not channel
            or not portal_url.startswith("https://")
            or not cancel_base_url.startswith("https://")
        ):
            raise ValueError("Dedicated channel and HTTPS links are required")
        self.service = service
        self.send = send
        self.update = update
        self.mailer = mailer
        self.channel = channel
        self.portal_url = portal_url
        self.cancel_base_url = cancel_base_url

    def action(
        self,
        action: str,
        approval_id: str,
        actor: str,
        items: list[tuple[str, str]] | None = None,
        now: datetime | None = None,
    ) -> str:
        """Identity comes from authenticated transport, never Adaptive Card data."""
        try:
            self.service.decide(action, approval_id, actor, now or datetime.now(UTC), items)
        except PermissionError:
            return "not authorised"
        self.flush(now or datetime.now(UTC))
        return "Decision recorded"

    def alert(self, digest: str, message: str) -> None:
        """Send an immediate alert through the configured dedicated-channel fake."""
        self.send(self.channel, alert_card(message, digest, self.portal_url))
        self.service.audit.write("alert", digest=digest, message=message)

    def flush(self, now: datetime) -> None:
        """Retry undelivered outbox records; never acknowledge failed delivery."""
        for event in self.service.store.pending_events():
            batch = self.service.store.get(event.batch.approval_id)
            try:
                if event.kind == "scheduled" and not event.details.get("email"):
                    self.mailer.scheduled(event.batch, self.portal_url, self.cancel_base_url)
                    self.service.store.mark_step(event, "email")
                elif event.kind == "final" and not event.details.get("email"):
                    self.mailer.final(event.batch, self.portal_url)
                    self.service.store.mark_step(event, "email")
                card = (
                    final_card(batch, self.portal_url)
                    if event.kind == "final"
                    else approval_card(batch, self.portal_url, self.cancel_base_url, now)
                )
                if batch.activity_id:
                    self.update(self.channel, batch.activity_id, card)
                else:
                    activity_id = self.send(self.channel, card)

                    def remember(current: Batch, identifier: str = activity_id) -> list[str]:
                        current.activity_id = identifier
                        return []

                    self.service.store.mutate(batch.approval_id, remember)
                self.service.store.delivered(event)
                self.service.audit.write(
                    "notification_delivered", kind=event.kind, approval_id=batch.approval_id
                )
            except Exception:
                self.service.audit.write(
                    "notification_failed", kind=event.kind, approval_id=batch.approval_id
                )
