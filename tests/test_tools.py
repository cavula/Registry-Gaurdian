"""Tool schema, side-effect staging, and policy guardrails."""

from datetime import timedelta
from pathlib import Path

import pytest
from jsonschema import ValidationError, validate
from test_policy import NOW, config, image

from guardian.agent.mcp_server import INPUTS, OUTPUTS, ToolService, build_mcp_server
from guardian.audit.log import AuditLog
from guardian.models import Evidence
from guardian.registries.base import RegistryReader
from guardian.state import StateStore


def service(tmp_path: Path) -> ToolService:
    return ToolService(
        RegistryReader,
        [image()],
        config(),
        Evidence(history_started_at=NOW - timedelta(days=200)),
        NOW,
        AuditLog(tmp_path / "audit.jsonl", "r1"),
        StateStore(tmp_path / "state.db"),
    )


def test_all_eight_schemas_and_local_shapes(tmp_path: Path) -> None:
    tools = service(tmp_path)
    calls = [
        ("list_repositories", {"registry": "demo"}),
        ("list_images", {"registry": "demo", "repo": "app"}),
        ("get_images_in_use", {}),
        ("get_pull_history", {}),
        ("get_scan_results", {"digest": "a"}),
        ("evaluate_policy", {"digest": "a"}),
        ("request_approval", {"digests": ["a"], "summary": "Old image"}),
        ("send_alert", {"digest": "a", "message": "Test"}),
    ]
    assert len(tools.definitions()) == 8
    for name, arguments in calls:
        validate(tools.call(name, arguments), OUTPUTS[name])
    assert not tools.notifications
    tools.finalize(True)
    assert all(n["emitted"] for n in tools.notifications)
    repeated = service(tmp_path)
    repeated.call("list_images", {"registry": "demo", "repo": "app"})
    repeated.call("evaluate_policy", {"digest": "a"})
    repeated.call("request_approval", {"digests": ["a"], "summary": "Old image"})
    repeated.call("send_alert", {"digest": "a", "message": "Test"})
    repeated.finalize(True)
    assert all(not n["emitted"] for n in repeated.notifications)
    assert build_mcp_server(tools).name == "registry-guardian"


def test_no_delete_or_unsafe_requests(tmp_path: Path) -> None:
    tools = service(tmp_path)
    assert not any("delete" in name or "purge" in name for name in INPUTS)
    with pytest.raises(ValueError):
        tools.call("delete_image", {"digest": "a"})
    with pytest.raises(ValueError, match="Every image"):
        tools.call("request_approval", {"digests": ["a"], "summary": "too early"})
    with pytest.raises(ValidationError):
        tools.call("get_images_in_use", {"extra": True})
    with pytest.raises(ValueError):
        tools.call("list_images", {"registry": "other", "repo": "app"})
    with pytest.raises(ValueError):
        tools.call("list_images", {"registry": "demo", "repo": "missing"})
    with pytest.raises(ValueError):
        tools.call("get_scan_results", {"digest": "missing"})
    tools.images[0].locked = True
    # A fresh service evaluates the locked image; LLM cannot override its KEEP verdict.
    guarded = ToolService(
        RegistryReader, tools.images, config(), Evidence(), NOW, tools.audit, tools.state
    )
    guarded.call("evaluate_policy", {"digest": "a"})
    with pytest.raises(ValueError, match="eligible"):
        guarded.call("request_approval", {"digests": ["a"], "summary": "unsafe"})


def test_incomplete_discards_staged_notifications(tmp_path: Path) -> None:
    tools = service(tmp_path)
    tools.call("evaluate_policy", {"digest": "a"})
    tools.call("request_approval", {"digests": ["a"], "summary": "test"})
    tools.finalize(False)
    assert not tools.requested and not tools.notifications


def test_mcp_protocol_handler_has_structured_output(tmp_path: Path) -> None:
    import asyncio

    from mcp.types import CallToolRequest, CallToolRequestParams

    server = build_mcp_server(service(tmp_path))
    request = CallToolRequest(
        method="tools/call",
        params=CallToolRequestParams(name="list_repositories", arguments={"registry": "demo"}),
    )
    response = asyncio.run(server.request_handlers[CallToolRequest](request))
    assert not response.root.isError
    assert response.root.structuredContent == {"repositories": ["app"]}


def test_alert_resolution_then_reappearance_changes_fingerprint(tmp_path: Path) -> None:
    first = service(tmp_path)
    first.alerts["a"] = "insecure"
    first.finalize(True)
    cleared = service(tmp_path)
    cleared.finalize(True)
    returned = service(tmp_path)
    returned.alerts["a"] = "insecure"
    returned.finalize(True)
    assert returned.notifications[0]["emitted"]


def test_cross_repository_keep_never_enters_batch(tmp_path: Path) -> None:
    from guardian.models import Evidence

    tools = service(tmp_path)
    images = [image(), image(repository="protected", tags=["prod"])]
    guarded = ToolService(None, images, config(), Evidence(), NOW, tools.audit, tools.state)
    guarded.call("evaluate_policy", {"digests": ["a"]})
    with pytest.raises(ValueError, match="eligible"):
        guarded.call("request_approval", {"digests": ["a"], "summary": "ambiguous"})
