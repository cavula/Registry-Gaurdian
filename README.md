# Registry Guardian

Registry Guardian reviews container registry images with deterministic safety policy and an advisory LLM tool loop. **v0.1 is an offline dry-run release:** every registry, usage, pull-history, scanner, and model interaction comes from local fixtures. Alerts and approval IDs are simulated. There is no deletion interface or purge command in this phase.

Requires Python 3.11 or newer.

## Install and run the demo

Create a virtual environment using your Python 3.11+ executable, then:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
guardian run --fixtures tests/fixtures/demo
```

The demo reviews 14 manifests, proposes five eligible digests locally, and records a security alert for a running vulnerable image. Protected tags, shared protected digests, the index with an in-use arm64 child, recent pulls, and incomplete scan evidence are kept. An old Defender result falls back to a fresh fixture Trivy result.

Defaults are config at ./config.yaml, JSONL audit at ./out/audit.jsonl, SQLite notification state at ./out/state.sqlite, and per-run Markdown reports under ./out/reports/. Output files are ignored by Git. All timestamps are UTC. Each report filename contains its timestamp and unique run ID.

```sh
guardian run --fixtures tests/fixtures/demo --config config.yaml
guardian llm test --fixtures tests/fixtures/demo
guardian mcp --fixtures tests/fixtures/demo
ruff check .
pytest --cov=guardian
```

The MCP command serves eight tools over stdio. The evaluate_policy tool accepts a single digest or a digests batch, as approved in Q17. Approval/alert tools stage local fake records; the normal agent runner finalizes them after validating completion. No MCP tool can delete images.

## Configuration and fixture contracts

Only Phase 1 settings are required. Counts are integers; ages and durations accept decimals. dry_run defaults to true. The offline CLI remains read-only even if config sets it false. Later-phase settings are optional.

A fixture directory contains:

| File | Content |
| --- | --- |
| run.json | Optional fixed evaluation time in now (UTC); empty object uses the current time |
| registry.json | images array with repository/digest identity, all tags, timestamps, index children, locks and completeness flags |
| usage.json | Serialized aks workloads and git_manifests paths relative to the fixture directory; aks_failed simulates failure |
| pulls.json | enabled_on, configured, rows with Repository, Digest and last_pulled_at; failed simulates a query error |
| defender.json | Normalized results containing repository, digest, vulns and scanned_at; failed simulates failure |
| trivy.json | The same normalized result format for per-image fallback |
| llm.json | tool_calling flag and scripted responses with text/tool_calls; optional provider-keyed fallbacks |

Static Helm values support image.repository, image.registry, image.tag or image.digest. Kubernetes image fields are discovered recursively, including init containers. Templates are not rendered, and configured references cannot escape the fixture directory. Local registry references that cannot resolve protect the affected repository. Usage-source or pull-query failure protects all candidates; missing/stale/failed scans protect affected images with UNKNOWN security status.

The registry record's blobs mapping identifies physical blobs and their byte sizes. Reclaimable storage uses decimal GB, deduplicates blobs, and excludes blobs retained by another root. If blob detail is absent, the manifest's size_bytes is the conservative available estimate. This is an offline estimate, not a measured production storage saving.

The injected ACR SDK wrapper implements RegistryReader and supports DefaultAzureCredential wiring, but the CLI never constructs it. Defender and Trivy are fixture-only. The LiteLLM adapter requires an injected completion callable; live transport activation is deferred. Optional extras azure, mcp, and llm describe integration dependencies. Tests use mocks and reject outbound socket connections.

## Validation and phase boundary

The demo's expected Markdown output is checked in at tests/snapshots/demo.md. The 1,000-image fixture under tests/fixtures/benchmark performs a complete review in four tool calls using batch evaluation. Run its benchmark with:

```sh
pytest -s tests/test_report.py::test_1000_images_complete_benchmark
```

The model is limited to 200 individual tool calls. Cap exhaustion, unsafe calls, and incomplete review produce an incomplete report with zero candidates. Deterministic local safety alerts survive model failure. SQLite fingerprints suppress unchanged simulated requests and alerts across repeated runs.

Phase 1 includes T1–T7 and the Markdown-report portion of T10. Phase 2 (Teams approvals, Graph email, grace periods, executor, backup and restore) and Phase 3 (additional usage sources, weekly metrics, workflow/container deployment and full production setup documentation) remain unbuilt. Current Microsoft schema/SDK verification gates and unresolved production decisions are in OPEN_QUESTIONS.md. See PROGRESS.md for task evidence and the release review gate.
