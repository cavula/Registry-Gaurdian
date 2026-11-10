"""Authoritative offline reports with graph-aware, deduplicated storage estimates."""

from collections import Counter
from datetime import datetime
from pathlib import Path

from guardian.agent.mcp_server import ToolService
from guardian.agent.runner import RunResult
from guardian.models import Image, Verdict
from guardian.policy.engine import descendants, key


def text(value: str) -> str:
    """Keep untrusted fixture labels inside a single Markdown table cell."""
    return value.replace("\n", " ").replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def reclaimable_bytes(images: list[Image], selected: set[str]) -> int:
    """Count unique candidate graph blobs, excluding blobs retained by other roots."""
    inventory = {key(image): image for image in images}
    child_keys = {(i.repository, d) for i in images for d in i.child_digests}
    proposed: dict[str, int] = {}
    retained: set[str] = set()
    for image in images:
        graph, complete = descendants(image, inventory)
        if not complete:
            continue
        blobs = {
            digest: size
            for member in graph
            for digest, size in (member.blobs or {member.digest: member.size_bytes}).items()
        }
        if image.digest in selected:
            for digest, size in blobs.items():
                proposed[digest] = min(size, proposed.get(digest, size))
        elif key(image) not in child_keys:
            retained.update(blobs)
    return sum(size for digest, size in proposed.items() if digest not in retained)


def render_report(
    service: ToolService, result: RunResult, run_id: str, timestamp: datetime, warnings: list[str]
) -> str:
    """Render policy facts independently of the model's narrative."""
    selected = set(service.requested) if result.complete else set()
    counts = Counter(i.verdict.value for i in service.images)
    storage = reclaimable_bytes(service.images, selected) / 1_000_000_000
    emitted_alerts = sum(n["kind"] == "alert" and n["emitted"] for n in service.notifications)
    lines = [
        "# Registry Guardian report",
        "",
        f"Run: {run_id}",
        f"UTC: {timestamp.isoformat()}",
        f"Status: {'complete' if result.complete else 'incomplete'}",
        "Mode: offline dry run; notifications and approvals are simulated.",
        f"Tool calls: {result.tool_calls}",
        "",
        "## Counts by verdict",
        "",
        "| Verdict | Count |",
        "| --- | ---: |",
        *[f"| {v.value} | {counts[v.value]} |" for v in Verdict],
        "",
        f"Reclaimable storage estimate (decimal GB): {storage:.9f}",
        f"Deletion candidates: {len(selected)}",
        f"Local alerts recorded this run: {emitted_alerts}",
        "External alerts sent: 0",
        "",
        "## Top risks and findings",
        "",
        "| Repository | Digest | All tags | Verdict | Reasons |",
        "| --- | --- | --- | --- | --- |",
    ]
    priority = {
        Verdict.STALE_AND_INSECURE: 0,
        Verdict.INSECURE: 1,
        Verdict.STALE: 2,
        Verdict.UNTAGGED: 3,
        Verdict.KEEP: 4,
    }
    ordered = sorted(
        service.images,
        key=lambda i: (
            0 if i.in_use and i.vulns.get("CRITICAL", 0) else 1,
            priority[i.verdict],
            i.repository,
            i.digest,
        ),
    )
    lines.extend(
        f"| {text(i.repository)} | {text(i.digest)} | "
        f"{text(', '.join(i.tags) or '(untagged)')} | {i.verdict.value} | "
        f"{text('; '.join(i.reasons))} |"
        for i in ordered
    )
    lines += ["", "## Items awaiting simulated approval", ""]
    if selected:
        lines += [
            f"- {text(i.repository)}@{text(i.digest)} "
            f"(all tags: {text(', '.join(i.tags) or '(untagged)')})"
            for i in ordered
            if i.digest in selected and i.tags
        ]
        groups = Counter(i.repository for i in ordered if i.digest in selected and not i.tags)
        for repo, count in sorted(groups.items()):
            members = [
                i for i in ordered if i.repository == repo and not i.tags and i.digest in selected
            ]
            size = reclaimable_bytes(members, {i.digest for i in members})
            lines.append(
                f"- {text(repo)}: {count} untagged manifests, {size} bytes; "
                f"digests: {', '.join(text(i.digest) for i in members)}"
            )
    else:
        lines.append("None.")
    lines += ["", "## Pull history incomplete", ""]
    lines += [
        f"- {text(i.repository)}@{text(i.digest)}" for i in ordered if i.pull_history_incomplete
    ] or ["None."]
    lines += ["", "## Needs scanning", ""]
    lines += [
        f"- {text(i.repository)}@{text(i.digest)}"
        for i in ordered
        if i.security_unknown or "security UNKNOWN; needs scanning" in i.reasons
    ] or ["None."]
    lines += ["", "## Local alerts and warnings", ""]
    notices = [
        n["message"] + (" (already recorded)" if not n["emitted"] else "")
        for n in service.notifications
        if n["kind"] == "alert"
    ]
    lines += [f"- {text(warning)}" for warning in dict.fromkeys(warnings + notices)] or ["None."]
    if result.failure:
        lines += ["", f"Incomplete reason: {text(result.failure)}"]
    lines += [
        "",
        "## Agent explanation (advisory)",
        "",
        text(result.narrative) or "Unavailable.",
        "",
        "Storage is an estimate of unique candidate graph blobs not retained by another "
        "root; no image is deleted in Phase 1.",
        "",
    ]
    return "\n".join(lines)


def write_report(directory: Path, content: str, timestamp: datetime, run_id: str) -> Path:
    """Write a unique timestamp-and-run-ID report."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{timestamp.strftime('%Y%m%dT%H%M%S%fZ')}-{run_id}.md"
    path.write_text(content)
    return path
