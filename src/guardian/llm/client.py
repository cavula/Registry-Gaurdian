"""Typed model responses, scripted offline models, and injectable LiteLLM adapter."""

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, Field

from guardian.config import LLMConfig


class ToolCall(BaseModel):
    """Normalized provider-independent tool invocation."""

    id: str
    name: str
    arguments: dict[str, Any]


class Response(BaseModel):
    """Normalized model output."""

    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    token_usage: dict[str, int] = Field(default_factory=dict)


class LLMClient(Protocol):
    """The runner depends only on this interface."""

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Response:
        """Return text, tool calls and token usage."""
        ...


class FixtureLLM:
    """Replay a file-backed script; tool calling is probed independently."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        self.cursor = 0

    @classmethod
    def from_path(cls, path: Path) -> "FixtureLLM":
        """Load the scripted model from JSON."""
        return cls(json.loads(path.read_text()))

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Response:
        """Replay responses without any external transport."""
        if messages[0]["content"] == "TOOL_CALLING_PROBE":
            if not self.data.get("tool_calling", True):
                return Response(text="Tool calling unsupported")
            return Response(tool_calls=[ToolCall(id="probe", name="dummy", arguments={})])
        responses = self.data.get("responses", [])
        if self.cursor >= len(responses):
            return Response(text="Script ended")
        row = responses[self.cursor]
        self.cursor += 1
        if row.get("error"):
            raise TimeoutError("Scripted provider failure")
        return Response.model_validate(row)


class LiteLLMClient:
    """Translate the neutral contract into an injected LiteLLM completion callable.

    Phase 1 deliberately requires injection and never binds a live API callable.
    Production transport activation is deferred.
    """

    def __init__(self, settings: LLMConfig, completion: Callable[..., Any]) -> None:
        self.settings = settings
        self._completion = completion

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Response:
        """Use LiteLLM-compatible arguments and normalize its response."""
        provider = {"azure_openai": "azure", "openai_compatible": "openai", "gemini": "gemini"}.get(
            self.settings.provider, self.settings.provider
        )
        model = f"{provider}/{self.settings.model}"
        reply = self._completion(
            model=model,
            messages=messages,
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": tool["name"],
                        "description": tool.get("description", ""),
                        "parameters": tool["inputSchema"],
                    },
                }
                for tool in tools
            ],
            api_key=os.environ.get(self.settings.api_key_env),
            api_base=self.settings.base_url,
            api_version=self.settings.api_version,
            temperature=self.settings.temperature,
            timeout=60,
            num_retries=0,
        )
        message = reply.choices[0].message
        calls = [
            ToolCall(
                id=call.id, name=call.function.name, arguments=json.loads(call.function.arguments)
            )
            for call in (message.tool_calls or [])
        ]
        usage = reply.usage.model_dump() if reply.usage else {}
        return Response(
            text=message.content or "",
            tool_calls=calls,
            token_usage={k: v for k, v in usage.items() if isinstance(v, int)},
        )


class ResilientClient:
    """Retry twice per provider, then try fallbacks in configured order."""

    def __init__(self, providers: list[tuple[str, LLMClient]], log: Callable[..., None]) -> None:
        if not providers:
            raise ValueError("At least one provider is required")
        self.providers = providers
        self.log = log

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Response:
        """Avoid logging exception strings, messages, credentials or model payloads."""
        for label, client in self.providers:
            for attempt in range(3):
                try:
                    response = client.chat(messages, tools)
                    self.log(
                        "llm_response",
                        provider=label,
                        attempt=attempt + 1,
                        token_usage=response.token_usage,
                    )
                    return response
                except Exception:
                    self.log("llm_retry", provider=label, attempt=attempt + 1)
        raise RuntimeError("All configured LLM providers failed")


def probe(client: LLMClient) -> None:
    """Fail fast when the fake/model cannot produce the dummy tool call."""
    response = client.chat(
        [{"role": "system", "content": "TOOL_CALLING_PROBE"}],
        [{"name": "dummy", "inputSchema": {"type": "object", "properties": {}}}],
    )
    if len(response.tool_calls) != 1 or response.tool_calls[0].name != "dummy":
        raise ValueError("Chosen model does not support tool calling")
