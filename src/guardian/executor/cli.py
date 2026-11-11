"""Wire purge and restore to the local test registry and fixture evidence."""

from argparse import Namespace
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from guardian.approval.store import ApprovalStore
from guardian.audit.log import AuditLog
from guardian.config import Config
from guardian.executor.backup import BlobBackup, LocalBlobTransport
from guardian.executor.fixture_registry import FixtureRegistryStore
from guardian.executor.purge import PurgeExecutor
from guardian.models import Evidence, Image
from guardian.offline import collect_fixture_evidence


class BackupSettings(BaseModel):
    """Backup options supported by the fixture executor."""

    model_config = ConfigDict(allow_inf_nan=False)
    mode: Literal["blob"] = "blob"
    retention_days: float = Field(default=30, gt=0)

    @field_validator("retention_days", mode="before")
    @classmethod
    def numeric_retention(cls, value: Any) -> Any:
        """Reject boolean retention while preserving fractional durations."""
        if isinstance(value, bool):
            raise ValueError("retention_days must be a number")
        return value


def execute_command(args: Namespace, config: Config) -> int:
    """Run the requested executor command with fixture-only dependencies."""
    try:
        backup_settings = BackupSettings.model_validate(getattr(config, "backup", {}))
    except ValueError:
        print("Invalid backup configuration. This release supports blob mode only.")
        return 2
    if not args.registry_db.is_file() or not args.fixtures.is_dir():
        print("An existing test registry database and fixture directory are required.")
        return 2
    if args.command == "restore" and not args.actor.strip():
        print("A restore actor is required.")
        return 2

    now = datetime.now(UTC)
    audit = AuditLog(config.audit_path, str(uuid4()))
    audit.write("executor_started", command=args.command, dry_run=config.dry_run)
    try:
        registry = FixtureRegistryStore(args.registry_db, config.registry.name)
        backup = BlobBackup(
            LocalBlobTransport(args.backup_dir), retention_days=backup_settings.retention_days
        )

        def refresh(at: datetime) -> tuple[list[Image], Evidence]:
            return collect_fixture_evidence(args.fixtures, config, audit, at, registry)

        def alert(digest: str, message: str) -> None:
            audit.write("alert", digest=digest, message=message, simulated=True)

        executor = PurgeExecutor(
            ApprovalStore(config.state_path), config, registry, backup, refresh, audit, alert
        )
        if args.command == "purge":
            results = executor.run(now)
        else:
            results = [executor.restore(args.digest, args.actor, now, repository=args.repository)]
    except Exception:
        audit.write("executor_failed", command=args.command)
        print("Fixture executor failed. Check the audit log.")
        return 1

    for result in results:
        print(f"{result.outcome} {result.repository}@{result.digest} {result.reason}")
    if not results:
        print("No scheduled items are due.")
    audit.write("executor_finished", command=args.command, count=len(results))
    return int(any(result.outcome == "FAILED" for result in results))
