"""Command-line entry point; no production service calls are enabled."""

import argparse
import time
from pathlib import Path


def parser() -> argparse.ArgumentParser:
    """Build the Phase 1 command parser."""
    root = argparse.ArgumentParser(prog="guardian")
    sub = root.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Review a registry offline")
    run.add_argument("--config", type=Path, default=Path("./config.yaml"))
    run.add_argument("--fixtures", type=Path, required=True)
    llm = sub.add_parser("llm", help="Probe an offline model fixture")
    helper = llm.add_subparsers(dest="llm_command", required=True).add_parser("test")
    helper.add_argument("--fixtures", type=Path, required=True)
    helper.add_argument("--config", type=Path, default=Path("./config.yaml"))
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
    raise SystemExit("Offline pipeline is pending T2–T7 and T10.")
