"""Exercise the public stdio MCP command through the SDK client."""

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def test_stdio_round_trip(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        json.dumps(
            {
                "registry": {"name": "demo"},
                "audit_path": str(tmp_path / "audit.jsonl"),
                "state_path": str(tmp_path / "state.db"),
            }
        )
    )

    async def check() -> None:
        parameters = StdioServerParameters(
            command=str(Path(sys.executable).parent / "guardian"),
            args=["mcp", "--fixtures", "tests/fixtures/demo", "--config", str(config)],
        )
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert len(tools.tools) == 8
                result = await session.call_tool("list_repositories", {"registry": "demo"})
                assert not result.isError
                assert result.structuredContent == {"repositories": ["app"]}
                result = await session.call_tool(
                    "evaluate_policy", {"digests": ["sha256:protected", "sha256:stale"]}
                )
                assert not result.isError
                assert result.structuredContent["results"][0]["verdict"] == "KEEP"

    asyncio.run(check())
