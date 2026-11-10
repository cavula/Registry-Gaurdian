"""Safety decisions only: no network, filesystem, or clock access."""

from datetime import datetime, timedelta
from fnmatch import fnmatchcase

from guardian.config import Config, utc
from guardian.models import Evidence, Image, Verdict
from guardian.scanning.base import ScanResult, fresh

Key = tuple[str, str]


def key(image: Image) -> Key:
    """Identify a digest within a repository."""
    return image.repository, image.digest


def security_known(image: Image, config: Config, now: datetime) -> bool:
    """Require explicitly successful and fresh scan evidence."""
    return not image.security_unknown and fresh(
        ScanResult(
            source=image.scan_source or "unknown", scanned_at=image.scanned_at, vulns=image.vulns
        ),
        utc(now),
        config.scan_max_age_days,
    )


def insecure(image: Image, config: Config, now: datetime) -> bool:
    """Security facts survive a KEEP verdict and can drive alerts."""
    return security_known(image, config, now) and (
        image.vulns.get("CRITICAL", 0) > 0 or image.vulns.get("HIGH", 0) > config.max_high
    )


def newest_keys(images: list[Image], count: int) -> set[Key]:
    """Rank tags by manifest push time descending, then digest and tag ascending."""
    repos = {image.repository for image in images}
    result: set[Key] = set()
    for repo in repos:
        entries = [
            (image, tag)
            for image in images
            if image.repository == repo and image.pushed_at
            for tag in image.tags
        ]
        entries.sort(key=lambda entry: (-entry[0].pushed_at.timestamp(), entry[0].digest, entry[1]))
        result.update(key(image) for image, _ in entries[:count])
    return result


def descendants(image: Image, inventory: dict[Key, Image]) -> tuple[list[Image], bool]:
    """Walk indexes without duplicates; missing nodes and cycles are incomplete."""
    visited: set[Key] = set()
    active: set[Key] = set()
    found: list[Image] = []
    complete = True

    def visit(node: Image) -> None:
        nonlocal complete
        node_key = key(node)
        if node_key in active:
            complete = False
            return
        if node_key in visited:
            return
        visited.add(node_key)
        active.add(node_key)
        found.append(node)
        for digest in node.child_digests:
            child = inventory.get((node.repository, digest))
            if child is None:
                complete = False
            else:
                visit(child)
        active.remove(node_key)

    visit(image)
    return found, complete


def keep_reasons(
    image: Image, config: Config, evidence: Evidence, now: datetime, newest: set[Key], window: float
) -> list[str]:
    """Return non-overridable protection reasons for a graph member."""
    reasons: list[str] = []
    if evidence.usage_failed:
        reasons.append("usage source failed")
    if evidence.pull_failed:
        reasons.append("pull history query failed")
    if image.repository in evidence.affected_repositories:
        reasons.append("unresolved usage reference")
    if not image.inventory_complete or not image.children_complete:
        reasons.append("incomplete inventory or child data")
    if image.locked:
        reasons.append("locked")
    if image.in_use:
        reasons.append("in use")
    if any(fnmatchcase(tag, pattern) for tag in image.tags for pattern in config.protected_tags):
        reasons.append("protected tag")
    if key(image) in newest:
        reasons.append("among newest tags")
    if image.pushed_at is None or image.pushed_at > now:
        reasons.append("missing or future push timestamp")
    if image.last_pulled_at and image.last_pulled_at > now:
        reasons.append("future pull timestamp")
    elif image.last_pulled_at and image.last_pulled_at >= now - timedelta(days=window):
        reasons.append("recent pull")
    if not security_known(image, config, now):
        reasons.append("security UNKNOWN; needs scanning")
    if evidence.history_started_at and evidence.history_started_at > now:
        reasons.append("future pull history start")
    return reasons


def evaluate(images: list[Image], config: Config, evidence: Evidence, now: datetime) -> list[Image]:
    """Return evaluated copies; only this module assigns authoritative verdicts."""
    now = utc(now)
    inventory = {key(image): image for image in images}
    newest = newest_keys(images, config.keep_last_n)
    children = {(image.repository, digest) for image in images for digest in image.child_digests}
    output = []
    for original in images:
        image = original.model_copy(deep=True)
        graph, complete = descendants(original, inventory)
        window = config.stale_days if image.tags else config.untagged_days
        history_complete = evidence.history_started_at is not None and (
            evidence.history_started_at <= now - timedelta(days=window)
        )
        image.pull_history_incomplete = not history_complete
        reasons = []
        if key(image) in children:
            reasons.append("child referenced by an index; never propose alone")
        if not complete:
            reasons.append("incomplete or cyclic index graph")
        for member in graph:
            member_reasons = keep_reasons(member, config, evidence, now, newest, window)
            if member is not original and (member.pushed_at is None or not history_complete):
                member_reasons.append("missing child push timestamp or incomplete pull history")
            reasons.extend(member_reasons)
        if not image.tags:
            if not history_complete:
                reasons.append("untagged pull history incomplete")
            if image.pushed_at is None or image.pushed_at >= now - timedelta(days=window):
                reasons.append("untagged age threshold not met")
        if reasons:
            image.verdict = Verdict.KEEP
            image.reasons = list(dict.fromkeys(reasons))
        else:
            stale = bool(image.tags and image.pushed_at < now - timedelta(days=config.stale_days))
            risky = any(insecure(member, config, now) for member in graph)
            if stale and risky:
                image.verdict = Verdict.STALE_AND_INSECURE
                image.reasons = ["unused, old, no recent pull", "fresh security threshold exceeded"]
            elif stale:
                image.verdict = Verdict.STALE
                image.reasons = ["unused, old, no recent pull"]
            elif risky:
                image.verdict = Verdict.INSECURE
                image.reasons = ["fresh security threshold exceeded"]
            elif not image.tags:
                image.verdict = Verdict.UNTAGGED
                image.reasons = ["orphan untagged manifest older than threshold; no recent pull"]
            else:
                image.verdict = Verdict.KEEP
                image.reasons = ["no deletion policy matched"]
        if image.pull_history_incomplete and image.tags:
            image.reasons.append("pull history incomplete")
        output.append(image)
    return output
