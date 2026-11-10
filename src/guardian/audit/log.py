"""Append-only JSON-lines audit events with secret redaction."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SENSITIVE = ("secret", "password", "token", "api_key", "authorization")


def redact(value: Any) -> Any:
    """Redact sensitive named fields recursively."""
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if any(s in key.lower() for s in SENSITIVE) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


class AuditLog:
    """Write one JSON record per event with immutable run identity."""

    def __init__(self, path: Path, run_id: str) -> None:
        self.path = path
        self.run_id = run_id

    def write(self, event: str, **details: Any) -> None:
        """Append a sanitized event without accepting caller-supplied identity."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            **redact(details),
            "event": event,
            "run_id": self.run_id,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        with self.path.open("a") as stream:
            stream.write(json.dumps(record, default=str) + "\n")
