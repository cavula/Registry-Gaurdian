"""Fixture orchestration. This module cannot construct live service clients."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from guardian.agent.mcp_server import ToolService
from guardian.agent.runner import RunResult, required_security_alerts, run_agent
from guardian.audit.log import AuditLog
from guardian.config import Config, utc
from guardian.llm.client import FixtureLLM, ResilientClient
from guardian.models import Evidence, Image
from guardian.registries.fixtures import FixtureRegistry
from guardian.report.markdown import render_report, write_report
from guardian.scanning.base import scan_images
from guardian.scanning.defender import DefenderFixtures
from guardian.scanning.trivy import TrivyFixtures
from guardian.state import StateStore
from guardian.usage.aks import AKSSource
from guardian.usage.base import UsageSource, collect_usage
from guardian.usage.git_manifests import GitManifestSource
from guardian.usage.pull_history import PullHistory


def read_json(path: Path) -> dict[str, Any]:
    """Load a fixture mapping, refusing non-object roots."""
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("Fixture must be a JSON object")
    return data


def fixture_path(root: Path, relative: str) -> Path:
    """Keep local fixture references inside the selected fixture directory."""
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("Fixture reference escapes fixture directory")
    return path


def prepare(
    fixtures: Path, config: Config, audit: AuditLog, now: datetime
) -> tuple[ToolService, list[str]]:
    """Gather complete offline evidence before the model can request a review."""
    registry = FixtureRegistry(fixtures / "registry.json")
    images: list[Image] = []
    for repo in registry.list_repositories():
        images.extend(registry.list_images(repo))
    if any(i.registry != config.registry.name for i in images):
        raise ValueError("Fixture registry differs from configured registry")
    if len({(i.repository, i.digest) for i in images}) != len(images):
        raise ValueError("Duplicate repository/digest inventory records")
    audit.write("inventory", image_count=len(images))
    evidence = Evidence()
    usage = read_json(fixtures / "usage.json")
    sources: list[UsageSource] = []
    for source in config.usage_sources:
        if config.usage_sources[source] and source not in usage:
            evidence.usage_failed = True
            evidence.alerts.append(f"Configured usage source missing from fixtures: {source}")
    if usage.get("aks_failed"):
        evidence.usage_failed = True
        evidence.alerts.append("AKS usage source failed; all candidates kept")
    elif "aks" in usage:
        sources.append(AKSSource(lambda: usage["aks"]))
    if "git_manifests" in usage:
        sources.append(
            GitManifestSource([fixture_path(fixtures, name) for name in usage["git_manifests"]])
        )
    unsupported = set(usage) - {"aks", "aks_failed", "git_manifests"}
    if unsupported:
        evidence.usage_failed = True
        evidence.alerts.append("Unsupported Phase 1 usage source; all candidates kept")
    collect_usage(sources, images, evidence, audit.write)
    pulls = read_json(fixtures / "pulls.json")

    def query(_: str) -> list[dict[str, Any]]:
        audit.write("pull_history_query")
        if pulls.get("failed"):
            raise RuntimeError("Scripted pull query failure")
        return pulls.get("rows", [])

    started = pulls.get("enabled_on")
    PullHistory(
        query, datetime.fromisoformat(started) if started else None, pulls.get("configured", True)
    ).apply(images, evidence, config.registry.name)
    evidence.alerts += scan_images(
        images,
        DefenderFixtures(fixtures / "defender.json"),
        TrivyFixtures(fixtures / "trivy.json"),
        now,
        config.scan_max_age_days,
    )
    for warning in evidence.alerts:
        audit.write("safety_fact", message=warning, simulated=True)
    service = ToolService(
        registry, images, config, evidence, now, audit, StateStore(config.state_path)
    )
    for warning in evidence.alerts:
        identifier = "safety-" + hashlib.sha256(warning.encode()).hexdigest()[:16]
        service.safety_alerts[identifier] = warning
    for digest in required_security_alerts(service, now):
        service.safety_alerts[digest] = "In-use image exceeds the security threshold; kept."
    return service, evidence.alerts


def execute(fixtures: Path, config: Config) -> tuple[Path, RunResult]:
    """Run the entire offline review and write a report even for runtime failures."""
    run_id = str(uuid4())
    stamp = datetime.now(UTC)
    audit = AuditLog(config.audit_path, run_id)
    audit.write("run_started", dry_run=True, transport="fixtures")
    # This phase never enables mutations, including when config requests dry_run=false.
    warnings: list[str] = []
    try:
        run_data = read_json(fixtures / "run.json")
        now = utc(datetime.fromisoformat(run_data["now"])) if run_data.get("now") else stamp
        service, warnings = prepare(fixtures, config, audit, now)
        primary = read_json(fixtures / "llm.json")
        providers = [(config.llm.provider, FixtureLLM(primary))]
        for entry in config.llm.fallback:
            label = str(entry["provider"])
            providers.append((label, FixtureLLM(primary.get("fallbacks", {}).get(label, {}))))
        result = run_agent(ResilientClient(providers, audit.write), service, now)
    except Exception:
        # Never put raw validation/transport exception strings into logs or reports.
        warnings.append("Offline fixture preparation failed; nothing proposed")
        audit.write("preparation_failed", candidates_discarded=True)
        registry = None
        # Do not reparse potentially malformed data to produce a failure report.
        service = ToolService(
            registry, [], config, Evidence(), stamp, audit, StateStore(config.state_path)
        )
        result = RunResult(
            complete=False, tool_calls=0, narrative="", failure="Offline fixture preparation failed"
        )
    content = render_report(service, result, run_id, stamp, warnings)
    path = write_report(config.report_dir, content, stamp, run_id)
    audit.write(
        "run_finished", complete=result.complete, report=str(path), tool_calls=result.tool_calls
    )
    return path, result
