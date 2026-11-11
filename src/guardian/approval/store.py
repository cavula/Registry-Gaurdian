"""SQLite approval transitions and transactional notification outbox."""

import sqlite3
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from uuid import uuid4

from guardian.approval.models import Batch, OutboxEvent


class ApprovalStore:
    """Serialize approval/cancel/purge transitions with SQLite write transactions."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with closing(sqlite3.connect(path)) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS approvals "
                "(id TEXT PRIMARY KEY, registry TEXT, payload TEXT)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS approval_outbox "
                "(id TEXT PRIMARY KEY, payload TEXT, delivered INTEGER DEFAULT 0)"
            )

    def get(self, approval_id: str) -> Batch:
        """Read an independent batch snapshot."""
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute("SELECT payload FROM approvals WHERE id=?", (approval_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown approval")
        return Batch.model_validate_json(row[0])

    def list_batches(self) -> list[Batch]:
        """Read batches in insertion order."""
        with closing(sqlite3.connect(self.path)) as db:
            return [
                Batch.model_validate_json(row[0])
                for row in db.execute("SELECT payload FROM approvals ORDER BY rowid")
            ]

    @staticmethod
    def _queue(db: sqlite3.Connection, batch: Batch, kind: str) -> None:
        event = OutboxEvent(event_id=str(uuid4()), kind=kind, batch=batch)
        db.execute(
            "INSERT INTO approval_outbox(id,payload) VALUES (?,?)",
            (event.event_id, event.model_dump_json()),
        )

    def create(self, batch: Batch) -> tuple[Batch, bool]:
        """Create only after the registry's last candidate fingerprint changes."""
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT payload FROM approvals WHERE registry=? ORDER BY rowid DESC LIMIT 1",
                (batch.registry,),
            ).fetchone()
            if row:
                previous = Batch.model_validate_json(row[0])
                if previous.fingerprint == batch.fingerprint:
                    return previous, False
            db.execute(
                "INSERT INTO approvals VALUES (?,?,?)",
                (batch.approval_id, batch.registry, batch.model_dump_json()),
            )
            self._queue(db, batch, "requested")
        return batch, True

    def mutate(self, approval_id: str, change: Callable[[Batch], list[str]]) -> Batch:
        """Atomically apply a guarded transition and enqueue its notifications."""
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT payload FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if not row:
                raise ValueError("Unknown approval")
            batch = Batch.model_validate_json(row[0])
            kinds = change(batch)
            db.execute(
                "UPDATE approvals SET payload=? WHERE id=?", (batch.model_dump_json(), approval_id)
            )
            for kind in kinds:
                self._queue(db, batch, kind)
        return batch

    def pending_events(self) -> list[OutboxEvent]:
        """Return notifications still awaiting successful delivery."""
        with closing(sqlite3.connect(self.path)) as db:
            return [
                OutboxEvent.model_validate_json(row[0])
                for row in db.execute(
                    "SELECT payload FROM approval_outbox WHERE delivered=0 ORDER BY rowid"
                )
            ]

    def delivered(self, event: OutboxEvent) -> None:
        """Acknowledge only a successfully delivered notification."""
        event.delivered = True
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                "UPDATE approval_outbox SET delivered=1,payload=? WHERE id=?",
                (event.model_dump_json(), event.event_id),
            )

    def mark_step(self, event: OutboxEvent, step: str) -> None:
        """Persist a successful subdelivery before attempting the next transport."""
        event.details[step] = True
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute(
                "UPDATE approval_outbox SET payload=? WHERE id=?",
                (event.model_dump_json(), event.event_id),
            )

    def scheduled_notice_delivered(self, approval_id: str) -> bool:
        """Do not purge until the scheduled notification has been acknowledged."""
        with closing(sqlite3.connect(self.path)) as db:
            events = [
                OutboxEvent.model_validate_json(row[0])
                for row in db.execute("SELECT payload FROM approval_outbox")
            ]
        return any(
            e.batch.approval_id == approval_id and e.kind == "scheduled" and e.delivered
            for e in events
        )
