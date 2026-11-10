"""One bulk pull-history query through an injected fixture client."""

import json
from collections.abc import Callable
from datetime import datetime
from typing import Any

from guardian.config import utc
from guardian.models import Evidence, Image


def pull_query(login_server: str) -> str:
    """Build a protective query using verified Microsoft columns."""
    return (
        "ContainerRegistryRepositoryEvents\n"
        f"| where LoginServer == {json.dumps(login_server)}\n"
        '| where OperationName contains "Pull"\n'
        "| summarize last_pulled_at=max(TimeGenerated) by Repository, Digest"
    )


class PullHistory:
    """Distinguish absent history from errors."""

    def __init__(
        self,
        query: Callable[[str], list[dict[str, Any]]],
        enabled_on: datetime | None,
        configured: bool = True,
    ) -> None:
        self._query = query
        self.enabled_on = utc(enabled_on) if enabled_on else None
        self.configured = configured

    def apply(self, images: list[Image], evidence: Evidence, login_server: str) -> None:
        """Fetch once per run; errors protect every candidate."""
        if not self.configured or self.enabled_on is None:
            return
        evidence.history_started_at = self.enabled_on
        try:
            latest: dict[tuple[str, str], datetime] = {}
            for row in self._query(pull_query(login_server)):
                stamp = utc(datetime.fromisoformat(row["last_pulled_at"]))
                key = (row["Repository"], row["Digest"])
                latest[key] = max(stamp, latest.get(key, stamp))
            for image in images:
                image.last_pulled_at = latest.get((image.repository, image.digest))
        except Exception:
            evidence.pull_failed = True
            evidence.alerts.append("Pull history query failed; all candidates kept")
