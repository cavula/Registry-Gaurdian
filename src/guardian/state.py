"""SQLite state for idempotent local simulated notifications."""

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path


def fingerprint(items: list[tuple[str, str]]) -> str:
    """Hash the sorted unique digest/verdict pairs."""
    return hashlib.sha256(json.dumps(sorted(set(items))).encode()).hexdigest()


class StateStore:
    """Persist the most recent fingerprint per notification scope."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with closing(sqlite3.connect(path)) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS notices "
                "(scope TEXT PRIMARY KEY, fingerprint TEXT, simulated_id TEXT)"
            )

    def record(self, scope: str, value: str) -> tuple[str, bool]:
        """Return a stable simulated ID; emit only on a changed fingerprint."""
        with closing(sqlite3.connect(self.path)) as db, db:
            row = db.execute(
                "SELECT fingerprint, simulated_id FROM notices WHERE scope=?", (scope,)
            ).fetchone()
            if row and row[0] == value:
                return row[1], False
            simulated_id = "simulated-" + value[:16]
            db.execute(
                "INSERT OR REPLACE INTO notices VALUES (?, ?, ?)", (scope, value, simulated_id)
            )
            return simulated_id, True
