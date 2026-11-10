"""Scripted provider equivalence, fallback, cap and safety checks."""

from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest
from test_policy import NOW
from test_tools import service

from guardian.agent.runner import run_agent
from guardian.config import LLMConfig
from guardian.llm.client import FixtureLLM, LiteLLMClient, ResilientClient, Response, probe


def script(extra: list[dict] | None = None) -> dict:
    calls = [
        {"id": "1", "name": "list_repositories", "arguments": {"registry": "demo"}},
        {"id": "2", "name": "list_images", "arguments": {"registry": "demo", "repo": "app"}},
        {"id": "3", "name": "evaluate_policy", "arguments": {"digests": ["a"]}},
        {
            "id": "4",
            "name": "request_approval",
            "arguments": {
                "items": [{"repository": "app", "digest": "a"}],
                "summary": "Unused old image",
            },
        },
    ]
    return {"responses": [{"tool_calls": calls + (extra or [])}, {"text": "Old image: stale."}]}


@pytest.mark.parametrize("provider", ["anthropic", "openai", "azure_openai"])
def test_provider_equivalent_run(provider: str, tmp_path: Path) -> None:
    tools = service(tmp_path)
    settings = LLMConfig(provider=provider)
    client = ResilientClient([(settings.provider, FixtureLLM(script()))], tools.audit.write)
    result = run_agent(client, tools, NOW)
    assert result.complete and result.tool_calls == 4
    assert tools.requested == [("app", "a")]


def test_unsafe_and_incomplete_models(tmp_path: Path) -> None:
    for data in [
        {"tool_calling": False},
        {"responses": [{"text": "done without reviewing"}]},
        script([{"id": "bad", "name": "delete_image", "arguments": {"digest": "a"}}]),
    ]:
        tools = service(tmp_path)
        result = run_agent(FixtureLLM(data), tools, NOW)
        assert not result.complete
        assert not tools.requested and not tools.notifications


def test_cap_discards_previously_staged_candidates(tmp_path: Path) -> None:
    tools = service(tmp_path)
    data = script(
        [{"id": str(i), "name": "get_images_in_use", "arguments": {}} for i in range(210)]
    )
    result = run_agent(FixtureLLM(data), tools, NOW)
    assert not result.complete and result.tool_calls == 200
    assert result.failure == "Tool call cap reached"
    assert not tools.requested and not tools.notifications


def test_retries_then_fallback_and_all_fail() -> None:
    first, second, log = Mock(), Mock(), Mock()
    first.chat.side_effect = TimeoutError("sensitive exception")
    second.chat.return_value = Response(text="ok")
    client = ResilientClient([("first", first), ("second", second)], log)
    assert client.chat([], []).text == "ok"
    assert first.chat.call_count == 3 and second.chat.call_count == 1
    assert "sensitive exception" not in str(log.call_args_list)
    second.chat.side_effect = RuntimeError()
    with pytest.raises(RuntimeError, match="All configured"):
        client.chat([], [])
    with pytest.raises(ValueError):
        ResilientClient([], log)


@pytest.mark.parametrize(
    "provider,prefix",
    [
        ("anthropic", "anthropic"),
        ("openai", "openai"),
        ("azure_openai", "azure"),
        ("openai_compatible", "openai"),
        ("gemini", "gemini"),
        ("ollama", "ollama"),
    ],
)
def test_litellm_translation_with_mocked_completion(
    provider: str,
    prefix: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_MODEL_KEY", "fixture-not-a-secret")
    completion = Mock(
        return_value=NS(
            choices=[
                NS(
                    message=NS(
                        content=None,
                        tool_calls=[NS(id="1", function=NS(name="dummy", arguments="{}"))],
                    )
                )
            ],
            usage=NS(model_dump=lambda: {"total_tokens": 12}),
        )
    )
    client = LiteLLMClient(
        LLMConfig(provider=provider, model="test", api_key_env="TEST_MODEL_KEY"), completion
    )
    probe(client)
    assert completion.call_args.kwargs["model"] == prefix + "/test"
    assert completion.call_args.kwargs["timeout"] == 60
    assert completion.call_args.kwargs["num_retries"] == 0


def test_probe_rejects_non_tool_model() -> None:
    with pytest.raises(ValueError, match="does not support"):
        probe(FixtureLLM({"tool_calling": False}))


def test_llm_cli_helper_uses_fixture_only(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    import json

    from guardian.main import main

    (tmp_path / "llm.json").write_text(json.dumps({"tool_calling": True}))
    config_path = tmp_path / "config.yaml"
    config_path.write_text("registry: {name: demo}")
    assert main(["llm", "test", "--fixtures", str(tmp_path), "--config", str(config_path)]) == 0
    output = capsys.readouterr().out
    assert "tool_calling=true" in output and "transport=fixture" in output
