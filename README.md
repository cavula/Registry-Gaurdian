# Registry Guardian

Registry Guardian reviews container registry images with deterministic safety policy and an advisory LLM tool loop. **v0.2 runs the review and approval workflow against fixtures and a local test registry.** Registry, usage, pull history, scan, model, and notification interactions use fixtures or injected fakes.

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

Counts are integers. Ages and durations accept decimals. The review command is read-only, and purge and restore default to dry run. The test-registry workflow uses the approval and backup settings below.

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

## Test-registry approval and purge

The test-registry workflow uses a SQLite registry seeded with OCI fixtures. The fixture directory supplies usage, pull and scan evidence and scripted model responses. Run the complete workflow with:

```bash
pytest -q tests/test_executor_cli.py
```

Use the same registry database and configuration throughout the workflow:

```bash
guardian run --fixtures ./fixtures --registry-db ./registry.db --config ./config.yaml
guardian purge --fixtures ./fixtures --registry-db ./registry.db --backup-dir ./backups --config ./config.yaml
guardian restore sha256:DIGEST --repository app --actor alice --fixtures ./fixtures --registry-db ./registry.db --backup-dir ./backups --config ./config.yaml
```

A successful review with candidates prints the approval ID. Approvals and the notification outbox use the configured `state_path`. An injected Teams worker delivers the approval card and checks approver group membership when handling decisions. After the grace period, purge refreshes evidence, verifies a Cool-tier OCI archive, and removes the approved repository and digest from the test registry. The worker delivers the final results from the outbox.

Set `dry_run: false` in the test configuration to apply purge or restore. The backup configuration accepts `mode: blob` and `retention_days` (default 30). A restore verifies the archive and checks all original tags before writing. A conflict refuses the entire restore and preserves existing tags. Pass `--repository` when the digest occurs in more than one repository.

Production deployment and Phase 3 coverage work are tracked in [OPEN_QUESTIONS.md](OPEN_QUESTIONS.md). Task verification and release gates are in [PROGRESS.md](PROGRESS.md).
