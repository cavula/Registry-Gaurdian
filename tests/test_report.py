"""End-to-end offline reports, snapshots, safety and benchmark acceptance."""

import json
import shutil
import time
from pathlib import Path

import pytest
from test_policy import NOW, image

from guardian.agent.runner import RunResult
from guardian.audit.log import AuditLog
from guardian.config import Config
from guardian.main import main
from guardian.offline import execute, fixture_path, prepare
from guardian.report.markdown import reclaimable_bytes, render_report

DEMO = Path("tests/fixtures/demo")


def settings(tmp_path: Path) -> Config:
    return Config.model_validate(
        {
            "registry": {"name": "demo"},
            "audit_path": tmp_path / "audit.jsonl",
            "report_dir": tmp_path / "reports",
            "state_path": tmp_path / "state.db",
        }
    )


def test_demo_full_review_and_repeat_idempotency(tmp_path: Path) -> None:
    config = settings(tmp_path)
    path, result = execute(DEMO, config)
    assert result.complete and result.tool_calls == 8
    report = path.read_text()
    assert "Deletion candidates: 5" in report
    assert "sha256:unknown" in report and "Needs scanning" in report
    assert "| sha256:shared | v1.2, prod | KEEP" in report
    assert "| sha256:index | v-index | KEEP" in report
    path2, result2 = execute(DEMO, config)
    assert result2.complete and path != path2
    assert "Local alerts recorded this run: 0" in path2.read_text()
    rows = [json.loads(line) for line in config.audit_path.read_text().splitlines()]
    assert sum(row["event"] == "approval" for row in rows) == 1
    assert sum(row["event"] == "pull_history_query" for row in rows) == 2
    assert all("run_id" in row and "timestamp" in row for row in rows)
    assert not any(row["event"] == "deletion" for row in rows)


def test_report_snapshot(tmp_path: Path) -> None:
    from guardian.agent.runner import run_agent
    from guardian.llm.client import FixtureLLM

    config = settings(tmp_path)
    service, warnings = prepare(DEMO, config, AuditLog(config.audit_path, "snapshot"), NOW)
    result = run_agent(FixtureLLM.from_path(DEMO / "llm.json"), service, NOW)
    content = render_report(service, result, "snapshot", NOW, warnings)
    assert content == Path("tests/snapshots/demo.md").read_text()


def test_unique_and_retained_blob_accounting() -> None:
    a = image(digest="a", blobs={"shared": 100, "only-a": 50})
    b = image(digest="b", blobs={"shared": 100, "only-b": 70})
    assert reclaimable_bytes([a, b], {"a", "b"}) == 220
    assert reclaimable_bytes([a, b], {"a"}) == 50
    parent = image(digest="idx", manifest_type="index", child_digests=["a"], blobs={"idx": 10})
    a.tags = []
    assert reclaimable_bytes([parent, a], {"idx"}) == 160


@pytest.mark.parametrize(
    "failure_file,patch",
    [
        ("pulls.json", {"failed": True, "enabled_on": "2026-01-01T00:00:00Z"}),
        ("usage.json", {"aks_failed": True}),
        ("defender.json", {"failed": True}),
        ("registry.json", {"images": [{"invalid": "record"}]}),
        ("llm.json", {"tool_calling": False}),
    ],
)
def test_failure_reports_propose_nothing(
    tmp_path: Path,
    failure_file: str,
    patch: dict,
) -> None:
    fixtures = tmp_path / "fixtures"
    shutil.copytree(DEMO, fixtures)
    (fixtures / failure_file).write_text(json.dumps(patch))
    # Prevent successful Trivy fallback except for the dedicated fallback case in other tests.
    (fixtures / "trivy.json").write_text('{"failed": true}')
    path, _ = execute(fixtures, settings(tmp_path))
    assert "Deletion candidates: 0" in path.read_text()
    assert "Status: incomplete" in path.read_text() or "| KEEP | 14 |" in path.read_text()


def test_public_cli_and_config_false_still_offline(tmp_path: Path) -> None:
    config = settings(tmp_path).model_dump(mode="json")
    config["dry_run"] = False
    path = tmp_path / "config.yaml"
    path.write_text(json.dumps(config))
    assert main(["run", "--fixtures", str(DEMO), "--config", str(path)]) == 0
    assert len(list((tmp_path / "reports").glob("*.md"))) == 1
    assert "offline dry run" in next((tmp_path / "reports").glob("*.md")).read_text()


def test_fixture_path_cannot_escape(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        fixture_path(tmp_path, "../escape.yaml")


def test_1000_images_complete_benchmark(tmp_path: Path) -> None:
    started = time.monotonic()
    path, result = execute(Path("tests/fixtures/benchmark"), settings(tmp_path))
    elapsed = time.monotonic() - started
    assert result.complete and result.tool_calls == 4
    assert "Deletion candidates: 997" in path.read_text()
    assert elapsed < 600
    print(f"1000-image offline benchmark: {elapsed:.3f}s")


def test_incomplete_report_never_counts_candidates(tmp_path: Path) -> None:
    config = settings(tmp_path)
    service, warnings = prepare(DEMO, config, AuditLog(config.audit_path, "incomplete"), NOW)
    service.requested = ["sha256:stale"]
    report = render_report(
        service,
        RunResult(complete=False, tool_calls=200, narrative="", failure="Tool call cap reached"),
        "incomplete",
        NOW,
        warnings,
    )
    assert "Deletion candidates: 0" in report
    assert "Reclaimable storage estimate (decimal GB): 0.000000000" in report


def test_safety_alerts_survive_failed_model(tmp_path: Path) -> None:
    fixtures = tmp_path / "fixtures"
    shutil.copytree(DEMO, fixtures)
    (fixtures / "llm.json").write_text('{"tool_calling": false}')
    config = settings(tmp_path)
    path, result = execute(fixtures, config)
    assert not result.complete and "Deletion candidates: 0" in path.read_text()
    assert "In-use image exceeds the security threshold; kept." in path.read_text()
    rows = [json.loads(line) for line in config.audit_path.read_text().splitlines()]
    assert any(row["event"] == "alert" and row.get("digest") == "sha256:live" for row in rows)
    assert not any(row["event"] == "approval" for row in rows)
