"""Policy acceptance cases and graph safety boundaries."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from guardian.config import Config
from guardian.models import Evidence, Image, Verdict
from guardian.policy.engine import descendants, evaluate, insecure

NOW = datetime(2026, 11, 10, tzinfo=UTC)


def config(**updates: Any) -> Config:
    return Config.model_validate({"registry": {"name": "demo"}, "keep_last_n": 0, **updates})


def image(**updates: Any) -> Image:
    return Image.model_validate(
        {
            "registry": "demo",
            "repository": "app",
            "digest": "a",
            "tags": ["v1"],
            "pushed_at": NOW - timedelta(days=120),
            "scanned_at": NOW,
            "security_unknown": False,
            "vulns": {},
            **updates,
        }
    )


def verdict(item: Image, evidence: Evidence | None = None, **settings: Any) -> Image:
    return evaluate(
        [item],
        config(**settings),
        evidence or Evidence(history_started_at=NOW - timedelta(days=200)),
        NOW,
    )[0]


@pytest.mark.parametrize(
    "updates,expected",
    [
        ({}, Verdict.STALE),
        ({"tags": ["prod", "v1"]}, Verdict.KEEP),
        ({"tags": ["release-2020"]}, Verdict.KEEP),
        ({"tags": ["Prod"]}, Verdict.STALE),
        ({"in_use": True, "vulns": {"CRITICAL": 1}}, Verdict.KEEP),
        ({"vulns": {"CRITICAL": 1}}, Verdict.STALE_AND_INSECURE),
        ({"pushed_at": NOW - timedelta(days=10), "vulns": {"HIGH": 6}}, Verdict.INSECURE),
        ({"pushed_at": NOW - timedelta(days=10), "vulns": {"HIGH": 5}}, Verdict.KEEP),
        ({"pushed_at": NOW - timedelta(days=90)}, Verdict.KEEP),
        ({"pushed_at": NOW - timedelta(days=90, microseconds=1)}, Verdict.STALE),
        ({"pushed_at": NOW + timedelta(seconds=1)}, Verdict.KEEP),
        ({"pushed_at": None}, Verdict.KEEP),
        ({"last_pulled_at": NOW - timedelta(days=90)}, Verdict.KEEP),
        ({"last_pulled_at": NOW + timedelta(seconds=1)}, Verdict.KEEP),
        ({"last_pulled_at": NOW - timedelta(days=91)}, Verdict.STALE),
        ({"locked": True}, Verdict.KEEP),
        ({"inventory_complete": False}, Verdict.KEEP),
        ({"children_complete": False}, Verdict.KEEP),
        ({"security_unknown": True}, Verdict.KEEP),
        ({"scanned_at": NOW - timedelta(days=7)}, Verdict.KEEP),
        ({"vulns": {"UNKNOWN": 1}}, Verdict.KEEP),
        ({"tags": [], "pushed_at": NOW - timedelta(days=10)}, Verdict.UNTAGGED),
        ({"tags": [], "pushed_at": NOW - timedelta(days=7)}, Verdict.KEEP),
        (
            {"tags": [], "pushed_at": NOW - timedelta(days=10), "vulns": {"CRITICAL": 1}},
            Verdict.INSECURE,
        ),
    ],
)
def test_verdict_table(updates: dict[str, Any], expected: Verdict) -> None:
    original = image(**updates)
    assert verdict(original).verdict == expected
    assert original.verdict == Verdict.KEEP  # inputs stay unchanged


@pytest.mark.parametrize(
    "evidence",
    [
        Evidence(usage_failed=True),
        Evidence(pull_failed=True),
        Evidence(affected_repositories={"app"}),
        Evidence(history_started_at=NOW + timedelta(days=1)),
    ],
)
def test_failure_overrides(evidence: Evidence) -> None:
    assert verdict(image(vulns={"CRITICAL": 1}), evidence).verdict == Verdict.KEEP


def test_warmup_and_untagged_coverage() -> None:
    warm = Evidence(history_started_at=NOW - timedelta(days=10))
    result = verdict(image(), warm)
    assert result.verdict == Verdict.STALE and result.pull_history_incomplete
    assert verdict(image(last_pulled_at=NOW - timedelta(days=5)), warm).verdict == Verdict.KEEP
    untagged = image(tags=[], pushed_at=NOW - timedelta(days=10))
    assert verdict(untagged, Evidence()).verdict == Verdict.KEEP
    assert verdict(untagged, warm).verdict == Verdict.UNTAGGED
    assert verdict(untagged, Evidence(history_started_at=NOW - timedelta(days=6))).verdict == "KEEP"


def test_newest_tags_ties_and_shared_digest() -> None:
    images = [image(digest="b"), image(digest="a", tags=["v1", "v2"]), image(digest="c", tags=[])]
    result = evaluate(images, config(keep_last_n=2), Evidence(), NOW)
    assert result[0].verdict == Verdict.STALE
    assert result[1].verdict == Verdict.KEEP
    result = evaluate([image(tags=["v1", "prod"])], config(), Evidence(), NOW)
    assert result[0].verdict == Verdict.KEEP


@pytest.mark.parametrize(
    "child_updates",
    [
        {"in_use": True},
        {"last_pulled_at": NOW - timedelta(days=1)},
        {"tags": ["prod"]},
        {"locked": True},
        {"security_unknown": True},
        {"pushed_at": None},
    ],
)
def test_index_child_protection(child_updates: dict[str, Any]) -> None:
    parent = image(digest="idx", manifest_type="index", child_digests=["child"])
    child = image(
        digest="child",
        tags=[],
        last_pulled_at=NOW - timedelta(days=150),
        **{k: v for k, v in child_updates.items() if k not in {"tags", "last_pulled_at"}},
    )
    if "tags" in child_updates:
        child.tags = child_updates["tags"]
    if "last_pulled_at" in child_updates:
        child.last_pulled_at = child_updates["last_pulled_at"]
    result = evaluate(
        [parent, child], config(), Evidence(history_started_at=NOW - timedelta(days=200)), NOW
    )
    assert all(item.verdict == Verdict.KEEP for item in result)


def test_missing_cyclic_and_shared_children() -> None:
    parent = image(digest="idx", manifest_type="index", child_digests=["child", "child"])
    child = image(digest="child", tags=[], last_pulled_at=NOW - timedelta(days=150))
    graph, complete = descendants(parent, {("app", "idx"): parent, ("app", "child"): child})
    assert complete and len(graph) == 2
    evidence = Evidence(history_started_at=NOW - timedelta(days=200))
    result = evaluate([parent, child], config(), evidence, NOW)
    assert result[0].verdict == Verdict.STALE
    assert result[1].verdict == Verdict.KEEP
    assert evaluate([parent], config(), evidence, NOW)[0].verdict == Verdict.KEEP
    child.child_digests = ["idx"]
    assert all(
        item.verdict == Verdict.KEEP for item in evaluate([parent, child], config(), evidence, NOW)
    )


def test_parent_pull_and_security_alert_facts() -> None:
    parent = image(digest="idx", manifest_type="index", child_digests=["child"], last_pulled_at=NOW)
    child = image(digest="child", tags=[], last_pulled_at=NOW - timedelta(days=150))
    result = evaluate([parent, child], config(), Evidence(), NOW)
    assert all(item.verdict == Verdict.KEEP for item in result)
    live = image(in_use=True, vulns={"CRITICAL": 1})
    assert verdict(live).verdict == Verdict.KEEP and insecure(live, config(), NOW)


def test_index_child_never_pulled_with_complete_history_is_stale() -> None:
    parent = image(
        digest="idx",
        tags=["v0"],
        manifest_type="index",
        child_digests=["child"],
        pushed_at=NOW - timedelta(days=150),
    )
    child = image(digest="child", tags=[], pushed_at=NOW - timedelta(days=150), last_pulled_at=None)
    full = Evidence(history_started_at=NOW - timedelta(days=200))
    result = evaluate([parent, child], config(), full, NOW)
    assert result[0].verdict == Verdict.STALE
    assert result[1].verdict == Verdict.KEEP
    assert evaluate([parent, child], config(), Evidence(), NOW)[0].verdict == Verdict.KEEP
    child.pushed_at = None
    assert evaluate([parent, child], config(), full, NOW)[0].verdict == Verdict.KEEP
