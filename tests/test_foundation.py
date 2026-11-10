"""Configuration, audit, CLI, and state contracts."""

import json
from datetime import UTC
from pathlib import Path

import pytest
from pydantic import ValidationError

from guardian.audit.log import AuditLog
from guardian.config import Config, load_config
from guardian.main import main, parser
from guardian.state import StateStore, fingerprint


def test_defaults_and_decimal_values(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(
        "registry: {name: test}\ngrace_period_hours: 0.1\nstale_days: 0.5\n"
        "pull_logs_enabled_on: 2026-01-01\nbackup: anything\n"
    )
    config = load_config(path)
    assert config.dry_run is True
    assert config.grace_period_hours == 0.1
    assert config.stale_days == 0.5
    assert config.pull_logs_enabled_on.tzinfo == UTC
    assert config.audit_path == Path("out/audit.jsonl")
    assert config.report_dir == Path("out/reports")


@pytest.mark.parametrize(
    "field,value",
    [
        ("keep_last_n", 1.1),
        ("max_high", True),
        ("stale_days", -1),
        ("scan_max_age_days", float("nan")),
        ("grace_period_hours", True),
        ("dry_run", "false"),
        ("untagged_days", float("inf")),
    ],
)
def test_invalid_config(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Config.model_validate({"registry": {"name": "test"}, field: value})


def test_mapping_and_registry_required(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("[]")
    with pytest.raises(ValueError, match="mapping"):
        load_config(path)
    with pytest.raises(ValidationError):
        Config.model_validate({})


def test_audit_redacts_and_has_identity(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "audit.jsonl"
    log = AuditLog(path, "run-1")
    log.write("start", nested={"api_key": "do-not-log", "value": 2})
    log.write("end", run_id="spoof")
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert rows[0]["nested"] == {"api_key": "[REDACTED]", "value": 2}
    assert rows[1]["run_id"] == "run-1"
    assert rows[0]["timestamp"].endswith("+00:00")
    assert "do-not-log" not in path.read_text()


def test_state_survives_reopen_and_changes(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    value = fingerprint([("b", "STALE"), ("a", "INSECURE")])
    assert value == fingerprint([("a", "INSECURE"), ("b", "STALE")])
    first, emitted = StateStore(path).record("request", value)
    assert emitted
    assert StateStore(path).record("request", value) == (first, False)
    assert StateStore(path).record("request", fingerprint([("a", "STALE")]))[1]


def test_cli_requires_offline_fixtures() -> None:
    with pytest.raises(SystemExit):
        parser().parse_args(["run"])
    args = parser().parse_args(["run", "--fixtures", "demo"])
    assert args.fixtures == Path("demo")
    assert args.config == Path("config.yaml")
    with pytest.raises(SystemExit, match="pending"):
        main(["run", "--fixtures", "demo"])
