"""Command-line entry point; no production service calls are enabled."""

import argparse
import time
from pathlib import Path


def parser() -> argparse.ArgumentParser:
    """Build the offline Guardian command parser."""
    root = argparse.ArgumentParser(prog="guardian")
    sub = root.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Review a registry offline")
    run.add_argument("--config", type=Path, default=Path("./config.yaml"))
    run.add_argument("--fixtures", type=Path, required=True)
    run.add_argument("--registry-db", type=Path, help="Existing SQLite test registry")
    mcp = sub.add_parser("mcp", help="Serve the eight offline tools over stdio")
    mcp.add_argument("--config", type=Path, default=Path("./config.yaml"))
    mcp.add_argument("--fixtures", type=Path, required=True)
    llm = sub.add_parser("llm", help="Probe an offline model fixture")
    helper = llm.add_subparsers(dest="llm_command", required=True).add_parser("test")
    helper.add_argument("--fixtures", type=Path, required=True)
    helper.add_argument("--config", type=Path, default=Path("./config.yaml"))
    purge = sub.add_parser("purge", help="Process approved items in the local test registry")
    restore = sub.add_parser("restore", help="Restore a saved image to the local test registry")
    for command in (purge, restore):
        command.add_argument("--config", type=Path, default=Path("./config.yaml"))
        command.add_argument("--fixtures", type=Path, required=True)
        command.add_argument("--registry-db", type=Path, required=True)
        command.add_argument("--backup-dir", type=Path, required=True)
    restore.add_argument("digest")
    restore.add_argument("--repository", help="Required when a digest spans repositories")
    restore.add_argument("--actor", required=True, help="Fixture operator identity for audit")
    return root


def main(argv: list[str] | None = None) -> int:
    """Dispatch offline commands."""
    args = parser().parse_args(argv)
    if args.command == "llm":
        from guardian.config import load_config
        from guardian.llm.client import FixtureLLM, probe

        config = load_config(args.config)
        started = time.monotonic()
        probe(FixtureLLM.from_path(args.fixtures / "llm.json"))
        print(
            f"provider={config.llm.provider} model={config.llm.model} "
            f"latency_ms={(time.monotonic() - started) * 1000:.2f} "
            "tool_calling=true transport=fixture"
        )
        return 0
    from guardian.config import load_config
    from guardian.offline import execute

    try:
        config = load_config(args.config)
    except Exception:
        print("Invalid or missing configuration")
        return 2
    if args.command in {"purge", "restore"}:
        from guardian.executor.cli import execute_command

        return execute_command(args, config)
    if args.command == "mcp":
        import asyncio
        from datetime import UTC, datetime
        from uuid import uuid4

        from guardian.agent.mcp_server import serve_stdio
        from guardian.audit.log import AuditLog
        from guardian.offline import prepare, read_json

        data = read_json(args.fixtures / "run.json")
        now = datetime.fromisoformat(data["now"]) if data.get("now") else datetime.now(UTC)
        service, _ = prepare(args.fixtures, config, AuditLog(config.audit_path, str(uuid4())), now)
        asyncio.run(serve_stdio(service))
        return 0
    if args.registry_db is not None and not args.registry_db.is_file():
        print("An existing test registry database is required.")
        return 2
    path, result = execute(args.fixtures, config, registry_db=args.registry_db)
    print(f"Report: {path} (status={'complete' if result.complete else 'incomplete'})")
    if result.approval_id is not None:
        print(f"Approval ID: {result.approval_id}")
    return 0 if result.complete else 1
