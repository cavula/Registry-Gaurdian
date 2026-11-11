"""Public executor commands against the local registry and injected notification fakes."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest
from test_policy import config, image

from guardian.approval.models import Batch, Status
from guardian.approval.service import ApprovalService
from guardian.approval.store import ApprovalStore
from guardian.approval.teams import TeamsBot
from guardian.audit.log import AuditLog
from guardian.config import Config
from guardian.executor.fixture_registry import FixtureRegistryStore, fixture_image
from guardian.main import main
from guardian.models import Image
from guardian.notify.email import GraphMailer


def _prepare(tmp_path: Path) -> tuple[Config, FixtureRegistryStore, Image, Batch, TeamsBot, Mock]:
    approved_at = datetime.now(UTC) - timedelta(hours=1)
    settings = config(
        approvers_group_id="approvers",
        grace_period_hours=0.1,
        state_path=tmp_path / "approvals.db",
        audit_path=tmp_path / "audit.jsonl",
        report_dir=tmp_path / "reports",
    )
    registry = FixtureRegistryStore(tmp_path / "registry.db", settings.registry.name)
    candidate, blobs = fixture_image(
        image(
            tags=["v1", "v1.0"],
            pushed_at=approved_at - timedelta(days=120),
            scanned_at=approved_at,
        )
    )
    registry.seed([candidate], blobs)
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "run.json").write_text(json.dumps({"now": approved_at.isoformat()}))
    (fixtures / "usage.json").write_text('{"aks": []}')
    start = approved_at - timedelta(days=180)
    (fixtures / "pulls.json").write_text(json.dumps({"enabled_on": start.isoformat()}))
    (fixtures / "defender.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "repository": candidate.repository,
                        "digest": candidate.digest,
                        "scanned_at": approved_at.isoformat(),
                        "vulns": {},
                    }
                ]
            }
        )
    )
    (fixtures / "trivy.json").write_text("{}")
    calls = [
        ("list_repositories", {"registry": "demo"}),
        ("list_images", {"registry": "demo", "repo": candidate.repository}),
        ("evaluate_policy", {"digest": candidate.digest}),
        (
            "request_approval",
            {
                "summary": "Stale fixture manifest",
                "items": [{"repository": candidate.repository, "digest": candidate.digest}],
            },
        ),
    ]
    (fixtures / "llm.json").write_text(
        json.dumps(
            {
                "responses": [
                    {
                        "tool_calls": [
                            {"id": str(index), "name": name, "arguments": arguments}
                            for index, (name, arguments) in enumerate(calls)
                        ]
                    },
                    {"text": "The fixture manifest is stale."},
                ]
            }
        )
    )

    approvals = ApprovalService(
        ApprovalStore(settings.state_path),
        settings,
        lambda actor, group: actor == "alice" and group == "approvers",
        AuditLog(settings.audit_path, "fixture-review"),
    )
    mail = Mock()
    bot = TeamsBot(
        approvals,
        Mock(return_value="activity-1"),
        Mock(),
        GraphMailer(mail, "guardian@example.test", "approvers@example.test"),
        "registry-guardian",
        "https://portal.azure.com/#resource/fixture",
        "https://guardian.example.test/cancel",
    )
    (tmp_path / "config.yaml").write_text(json.dumps(settings.model_dump(mode="json")))
    run = _arguments(tmp_path, "run")
    assert main(run) == 0
    (batch,) = approvals.store.list_batches()
    assert batch.status == Status.PENDING
    assert main(run) == 0
    assert [b.approval_id for b in approvals.store.list_batches()] == [batch.approval_id]
    assert len(approvals.store.pending_events()) == 1
    assert bot.action("approve", batch.approval_id, "alice", now=approved_at) == "Decision recorded"
    return settings, registry, candidate, batch, bot, mail


def _arguments(tmp_path: Path, command: str) -> list[str]:
    args = [
        command,
        "--config",
        str(tmp_path / "config.yaml"),
        "--fixtures",
        str(tmp_path / "fixtures"),
        "--registry-db",
        str(tmp_path / "registry.db"),
    ]
    if command != "run":
        args.extend(["--backup-dir", str(tmp_path / "backups")])
    return args


def test_cli_dry_run_purge_restore_and_final_notifications(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    settings, registry, candidate, batch, bot, mail = _prepare(tmp_path)
    assert capsys.readouterr().out.count(f"Approval ID: {batch.approval_id}") == 2
    config_file = tmp_path / "config.yaml"
    payload = settings.model_dump(mode="json", exclude={"dry_run"})
    config_file.write_text(json.dumps(payload))
    purge = _arguments(tmp_path, "purge")

    assert main(purge) == 0
    assert registry.list_images("app")[0].digest == candidate.digest
    assert bot.service.store.get(batch.approval_id).items[0].status == Status.SCHEDULED
    assert not list((tmp_path / "backups").glob("*.tar"))
    assert "DRY_RUN" in capsys.readouterr().out

    config_file.write_text(json.dumps({**payload, "dry_run": False}))
    assert main(purge) == 0
    assert not registry.list_images("app")
    completed = bot.service.store.get(batch.approval_id)
    assert completed.items[0].status == Status.DELETED
    assert completed.items[0].backup_id
    bot.flush(datetime.now(UTC))
    assert mail.call_count == 2
    assert candidate.digest in str(mail.call_args)

    restore = [
        *_arguments(tmp_path, "restore"),
        candidate.digest,
        "--repository",
        candidate.repository,
        "--actor",
        "alice",
    ]
    config_file.write_text(json.dumps(payload))
    assert main(restore) == 0
    assert not registry.list_images("app")
    assert "DRY_RUN" in capsys.readouterr().out
    config_file.write_text(json.dumps({**payload, "dry_run": False}))
    assert main(restore) == 0
    assert registry.list_images("app")[0].tags == candidate.tags


def test_cli_purge_reloads_usage_and_rejects_soft_delete(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    settings, registry, candidate, batch, bot, _ = _prepare(tmp_path)
    config_file = tmp_path / "config.yaml"
    payload = {**settings.model_dump(mode="json"), "dry_run": False}
    purge = _arguments(tmp_path, "purge")
    config_file.write_text(json.dumps({**payload, "backup": {"mode": "soft_delete"}}))
    assert main(purge) == 2
    assert "blob mode only" in capsys.readouterr().out

    config_file.write_text(json.dumps(payload))
    (tmp_path / "fixtures" / "usage.json").write_text(
        json.dumps({"aks": [{"image": f"demo/{candidate.repository}@{candidate.digest}"}]})
    )
    assert main(purge) == 0
    assert registry.list_images("app")[0].digest == candidate.digest
    assert bot.service.store.get(batch.approval_id).items[0].outcome == "SKIPPED"
    assert "SKIPPED" in capsys.readouterr().out


def test_cli_restore_refuses_existing_tag_owner(tmp_path: Path) -> None:
    settings, registry, candidate, _, _, _ = _prepare(tmp_path)
    (tmp_path / "config.yaml").write_text(
        json.dumps({**settings.model_dump(mode="json"), "dry_run": False})
    )
    assert main(_arguments(tmp_path, "purge")) == 0
    other, blobs = fixture_image(
        candidate.model_copy(update={"digest": "other-content", "tags": candidate.tags[:1]})
    )
    registry.seed([other], blobs)
    assert main([*_arguments(tmp_path, "restore"), candidate.digest, "--actor", "alice"]) == 1
    assert registry.list_images(candidate.repository) == [other]
