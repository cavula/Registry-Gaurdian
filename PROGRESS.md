# Progress

## Phase 1 — v0.1 planning (2026-11-10)

Read AGENTS.md and SPEC.md in full. The initial plan was documentation only. Implementation is now authorized for Phase 1. SPEC.md remains the source of truth. Q01–Q16 are resolved in OPEN_QUESTIONS.md by the user's decisions. Tasks begin sequentially below.

### Scope and execution rules

Implement one task at a time in this order: T1, T2, the Phase 1 subset of T3, T4, T5, T6, T7, then the Markdown report subset of T10. Only AKS, Git manifests, and pull history belong to T3 in this phase. Teams posts, approvals, emails, purge, backup/restore, other usage sources, weekly summaries, metrics.json, deployment workflow, and the full T12 README are deferred to their specified phases.

Use mocks, fixtures, and fakes for all Azure, Microsoft Graph, Teams, and LLM interactions. The Phase 1 outcome is a single command reviewing a fixture-backed test registry and writing a Markdown report, with nothing posted or deleted. Default dry_run to true everywhere. Resolve blocking questions before implementing dependent behavior; move to independent work when possible.

Before coding each task, review and refine its plan here. After each implementation task, run `ruff check .` and `pytest --cov=guardian`, fix failures, commit with the task ID prefix, then tick its checkbox and add a one-line result. Do not mark a task complete with failing tests. Policy coverage must reach at least 80%; executor coverage becomes applicable when that module is built in Phase 2.

### Task plans

- [x] **T1 — Scaffold, configuration, audit, CLI.** Set up Python 3.11+ packaging, typed modules, ruff/pytest configuration, validated config loading, JSON-lines audit logging with run IDs and timestamps, and the CLI entry point. Keep credentials in environment variables and redact sensitive values. Test defaults, invalid config, decimal thresholds (including grace_period_hours), audit shape, and CLI validation. Follow resolved Q01/Q02.
- [x] **T2 — Registry interface and ACR inventory.** Define the adapter interface and implement ACR inventory using injected/mock Azure SDK clients and DefaultAzureCredential wiring. Normalize all tags per digest, manifest type, children, timestamps, size, and lock status; provide Docker Hub/GHCR stubs raising NotImplementedError. Test pagination, shared digests, indexes, locks, and SDK failures without live calls. Follow Q03/Q04: no deletion interface in Phase 1; expose no delete tool to the agent.
- [x] **T3 — Phase 1 usage sources and pull history.** Define UsageSource and implement AKS and configured Git manifest/Helm-value discovery with tag-to-digest resolution. Aggregate one pull-history query per run by repository and digest; carry warm-up completeness and failure state into policy/report inputs. Test fixtures for referenced images, children, recent pulls, warm-up, and failures that force KEEP and record a local alert. Defer remaining FR15 sources to Phase 3. Follow resolved Q05–Q07.
- [x] **T4 — Defender and Trivy scanning.** Verify current Microsoft documentation and record the supported Resource Graph schema before production; use the ScanProvider interface and Defender fixtures only in Phase 1. Normalize digest results, severity counts, and timestamps; use mocked Trivy fallback for missing/stale Defender data. Test freshness boundaries, failed scans, UNKNOWN reporting, and fail-safe KEEP. Follow Q08/Q09: fixture-only Defender and per-image fallback.
- [x] **T5 — Pure policy engine.** Implement deterministic, typed pure functions with an explicit evaluation time and no network/file access. Cover FR4, FR14, FR16, FR17, and scan freshness inputs: KEEP overrides, newest tags, shared digests, index/child protections, locks, staleness, vulnerability counts, untagged rules, incomplete history, and failed evidence. Keep in-use security alert facts separate from the KEEP verdict. Use table-driven edge/boundary tests and enforce at least 80% policy coverage. Follow resolved Q09–Q12.
- [x] **T6 — MCP tools.** Expose the eight documented tool names with validated inputs and documented result shapes; keep evaluation authoritative in policy code. For Phase 1, approval/alert calls must use local recording fakes with no Teams/Graph side effects. Test each shape, invalid inputs, guardrails against KEEP proposals, and absence of any delete tool. Follow Q13: local fakes and MCP stdio.
- [x] **T7 — LLM layer and agent loop.** Implement the provider-neutral LLMClient interface, LiteLLM wiring behind injected fakes, config-driven providers/fallbacks, startup tool-calling validation, and the CLI helper without making real LLM calls. Implement the prescribed prompt and bounded loop reviewing every repository/image and producing one local candidate batch/report input. Test scripted tool calls with anthropic, openai, and azure_openai configurations, fallback/timeouts, no delete capability, and the 200-call limit. Follow resolved Q14/Q15 and Q17 batch evaluation.
- [x] **T10 (Phase 1 subset) — Markdown report.** Generate counts by verdict, reclaimable GB, local alert outcomes, simulated items awaiting approval, incomplete pull history, and needs-scanning sections. Include reasons and all affected tags while avoiding double-counting shared/index storage. Add snapshots and an offline end-to-end single-command acceptance scenario exercising all Phase 1 policy rules. Defer metrics.json and weekly Teams cards to Phase 3. Follow resolved Q12–Q16.

### Phase exit requirements

After all Phase 1 tasks are complete, run lint and all tests, confirm policy coverage and the offline command outcome, record a phase summary here, commit it, and tag v0.1. STOP for human review before Phase 2. Use the exact tag v0.1 per Q16. The planning update created no tag; the implementation release is recorded below.

## Execution log

### T1 — active plan

Implement typed validated Phase 1 configuration (decimal ages, integer counts, UTC paths/defaults), safe JSONL audit output, and argparse CLI scaffolding for offline runs. Add local SQLite fingerprint state foundation. No live API clients or deletion interfaces. Test invalid inputs, defaults, audit redaction and CLI behavior. Later tasks will connect the fixture pipeline.

T1 complete: validated config, UTC audit with redaction, offline CLI scaffold and SQLite state. Lint and all 12 tests pass; 99% total coverage.

### T2 — active plan

Build RegistryReader, normalized image/evidence/blob models, JSON fixture reader, and an ACR wrapper accepting only injected SDK clients. A separate explicit factory wires DefaultAzureCredential without contacting Azure during tests. Inventory all tags/digests and parse index/child and blob metadata; partial metadata sets evidence incomplete. Verify pagination, lock, shared tags, index and failure behavior. No deleter is built.

T2 complete: read-only readers, fixture inventory, ACR normalization and future registry stubs. Lint and all 17 tests pass. No deletion interface exists.

### T3 — active plan

Implement injectable AKS and local Git YAML/static Helm sources, scoped reference resolution, aggregation failures and pull-history fixtures. Query once in bulk using documented table columns; treat disabled/missing history separately from errors. Carry coverage start and latest parent/child pulls to pure policy inputs. Test init containers, static values, unresolved tags, source failure and query failure.

T3 complete: AKS/static Git usage, unresolved-reference safety, and one bulk pull query with absent/error evidence. Lint and all 22 tests pass.

### T4 — active plan

Build ScanProvider with bulk fixture Defender data and per-image fixture Trivy fallback. Freshness is strict; reject future/missing scan times and unknown/negative severity data. UNKNOWN forces that image KEEP and creates a local alert fact. Production Defender query is intentionally deferred by Q08. Test the 30-day-old fallback scenario and both-provider failures.

T4 complete: fixture ScanProvider, strict freshness and per-image Trivy fallback with UNKNOWN alerts. Lint and all 31 tests pass.

### T5 — active plan

Implement pure policy evaluation over immutable copies with explicit UTC time. Enforce KEEP overrides before verdict precedence; independently expose fresh insecurity facts for alerts. Rank tag entries by push time with deterministic digest ties. Traverse same-repository index graphs with deduplication and fail closed on cycles, missing children or child timestamps. Untagged eligibility requires coverage of its own window. Table-driven tests will cover all verdicts, exact boundaries, shared tags, newest tags, failures and graph protections, with at least 80% policy coverage.

T5 complete: pure policy with all KEEP guardrails, precedence, warm-up and graph rules. Lint and all 70 tests pass; policy engine coverage 100%.

### T6 — active plan

Define strict input/output JSON schemas for exactly eight tools. Dispatch against read-only registry/evidence/pure policy snapshots. Stage simulated approvals and alerts locally, validate every requested digest against policy and all images reviewed, and persist only on successful finalization so interrupted agent runs cannot create candidates. Expose MCP via the installed v1 SDK over stdio. Test every documented shape, invalid arguments and forbidden mutation tools.

T6 complete: eight schema-validated MCP tools, stdio server, policy-checked simulated requests and local notification staging. Lint and all 74 tests pass, including MCP structured-output handling.

### T7 — active plan

Build typed LLM response/tool-call contracts, file-backed scripted fake/probe, and an injectable LiteLLM adapter with provider mapping, environment-key lookup, 60s timeout, two retries and ordered fallback. Wire a bounded agent runner that verifies full inventory/evaluation and safe batched candidates before finalizing local notifications. Implement batch evaluate_policy under Q17 so the benchmark can complete within 200 calls. Connect fixture preparation for the future CLI/report; test provider-equivalent scripts, invalid tool calls, incomplete reviews and exact cap behavior. No real LLM calls.

T7 complete: neutral LLM interface, injected LiteLLM translation, fixture probe/helper, retries/fallback and bounded runner with batch evaluation. Lint and all 88 tests pass; cap/unsafe/incomplete runs discard candidates.

### T10 (Phase 1 subset) — active plan

Connect fixture-only preparation, agent execution and one Markdown report per run. Add deterministic demo and 1,000-image benchmark fixtures with batched policy evaluation. Report authoritative counts, unique/exclusively reclaimable blob estimates in decimal GB, local simulated notifications, untagged repository groups, incomplete pull history and needs scanning. Incomplete runs show zero candidates. Snapshot reports and test the public CLI twice for idempotency, failure safety, cap, fallback, all policy examples, and a full 1,000-image review under 10 minutes. Add Phase 1 usage documentation; leave full T12 deployment docs deferred.

T10 Phase 1 subset complete: per-run Markdown report, offline pipeline and public CLI, demo/snapshot, 1,000-image fixture benchmark and stdio MCP round trip. Final safety review ensured deterministic local alerts survive failed/incomplete model runs and unchanged fingerprints suppress repeated notifications. README documents this release; full production T12 remains deferred.

## Phase 1 summary — v0.1 (2026-11-10)

Completed T1, T2, the Phase 1 subset of T3, T4, T5, T6, T7, and the Markdown-report subset of T10, each with a task-ID commit. Q01–Q16 and the approved Q17 batch-evaluation amendment are recorded as resolved. Q18 (cross-repository bare-digest tool ambiguity) remains open with conservative batch refusal; production Defender mapping, pull operation enumeration, and Phase 2 SDK/soft-delete checks remain explicit gates.

Built: validated decimal-aware configuration, UTC JSONL audit, SQLite fingerprint state, read-only ACR/inventory abstractions, offline AKS and static Git sources, bulk pull history, fixture Defender/Trivy freshness fallback, pure policy rules with graph safety, eight schema-validated MCP tools over stdio, provider-neutral scripted LLM review and injected LiteLLM translation, bounded tool loop, and authoritative Markdown reports. No RegistryDeleter, purge, restore, Teams/Graph transport, weekly metrics, or deployment workflow was built.

Validation at phase exit:
- Python 3.13.17; project minimum Python 3.11.
- ruff check and ruff format --check pass.
- pytest --cov=guardian: 104 passed, 96% overall coverage.
- Policy engine coverage: 100%; explicit 80% coverage gate passes. Executor coverage is not applicable until Phase 2.
- Public demo command completed: guardian run --fixtures tests/fixtures/demo. Fourteen manifests reviewed; five simulated candidates; protected/shared/in-use/index/unknown images kept.
- Public guardian llm test fixture probe passed.
- Real stdio MCP client/server round trip passed, with exactly eight tools and structured results.
- Complete 1,000-image fixture review: 0.226 seconds, four individual tool calls, 997 simulated candidates and three newest tagged digests kept. This is an offline benchmark, not a production Azure/LLM performance claim.
- Repeated runs produce no duplicate simulated approvals/alerts; cap exhaustion and unsafe/incomplete review yield zero candidates. Safety alerts survive model failure.
- Tests prohibit outbound socket connections; no real Azure, Microsoft Graph, Teams, or LLM API calls were made.

Release: tag exactly v0.1 after this summary is committed. STOPPED for human review at the Phase 1 boundary. Do not start Phase 2 until human approval.
