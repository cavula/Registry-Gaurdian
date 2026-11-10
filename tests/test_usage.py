"""Fixture-only source resolution and failure safety."""

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock

from guardian.models import Evidence, Image
from guardian.usage.aks import AKSSource
from guardian.usage.base import collect_usage, resolve_references
from guardian.usage.git_manifests import GitManifestSource
from guardian.usage.pull_history import PullHistory, pull_query


def inventory() -> list[Image]:
    return [Image(registry="demo", repository="app", digest="sha256:a", tags=["v1"])]


def test_aks_and_static_helm(tmp_path: Path) -> None:
    images = inventory()
    aks = AKSSource(
        lambda: {
            "items": [
                {
                    "spec": {
                        "containers": [{"image": "elsewhere/app:v1"}],
                        "initContainers": [{"image": "demo.azurecr.io/app:v1"}],
                    }
                }
            ]
        }
    )
    assert aks.get_images_in_use(images).in_use == {("app", "sha256:a")}
    path = tmp_path / "values.yaml"
    path.write_text("image:\n  registry: demo.azurecr.io\n  repository: app\n  digest: sha256:a\n")
    assert GitManifestSource([path]).get_images_in_use(images).in_use == {("app", "sha256:a")}


def test_unresolved_is_repository_scoped_and_logged() -> None:
    images, evidence, log = inventory(), Evidence(), Mock()
    source = AKSSource(lambda: {"image": "demo/app:missing"})
    collect_usage([source], images, evidence, log)
    assert evidence.affected_repositories == {"app"}
    assert not evidence.usage_failed
    log.assert_called_once()
    assert resolve_references(["demo/app@sha256:a"], images).in_use
    assert resolve_references(["demo/app"], images).unresolved_repositories == {"app"}
    assert not resolve_references(["ubuntu", "external/app:v1"], images).in_use


def test_source_failure_protects_whole_run(tmp_path: Path) -> None:
    path = tmp_path / "template.yaml"
    path.write_text("image: '{{ .Values.image }}'")
    evidence = Evidence()
    collect_usage([GitManifestSource([path])], inventory(), evidence, Mock())
    assert evidence.usage_failed
    assert evidence.alerts


def test_pull_query_bulk_scoped_and_latest() -> None:
    images, evidence = inventory(), Evidence()
    query = Mock(
        return_value=[
            {"Repository": "app", "Digest": "sha256:a", "last_pulled_at": "2026-10-10T00:00:00Z"},
            {"Repository": "app", "Digest": "sha256:a", "last_pulled_at": "2026-11-01T00:00:00Z"},
        ]
    )
    PullHistory(query, datetime(2026, 1, 1, tzinfo=UTC)).apply(images, evidence, "demo")
    query.assert_called_once_with(pull_query("demo"))
    assert images[0].last_pulled_at == datetime(2026, 11, 1, tzinfo=UTC)
    assert evidence.history_started_at.year == 2026
    assert "by Repository, Digest" in pull_query("demo")


def test_disabled_history_vs_query_failure() -> None:
    query = Mock(side_effect=RuntimeError("query failed"))
    evidence = Evidence()
    PullHistory(query, None).apply(inventory(), evidence, "demo")
    assert evidence.history_started_at is None and not evidence.pull_failed
    query.assert_not_called()
    PullHistory(query, datetime(2026, 1, 1)).apply(inventory(), evidence, "demo")
    assert evidence.pull_failed and evidence.alerts
