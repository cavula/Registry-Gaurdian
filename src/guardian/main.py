"""Command-line entry point; no production service calls are enabled."""

import argparse
from pathlib import Path


def parser() -> argparse.ArgumentParser:
    """Build the Phase 1 command parser."""
    root = argparse.ArgumentParser(prog="guardian")
    sub = root.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="Review a registry offline")
    run.add_argument("--config", type=Path, default=Path("./config.yaml"))
    run.add_argument("--fixtures", type=Path, required=True)
    return root


def main(argv: list[str] | None = None) -> int:
    """Dispatch offline commands."""
    parser().parse_args(argv)
    raise SystemExit("Offline pipeline is pending T2–T7 and T10.")
