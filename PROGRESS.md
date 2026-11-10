# Progress

## Phase 1 — v0.1 planning (2026-11-10)

Read AGENTS.md and SPEC.md in full. The initial plan was documentation only. Implementation is now authorized for Phase 1. SPEC.md remains the source of truth. Q01–Q16 are resolved in OPEN_QUESTIONS.md by the user's decisions. Tasks begin sequentially below.

### Scope and execution rules

Implement one task at a time in this order: T1, T2, the Phase 1 subset of T3, T4, T5, T6, T7, then the Markdown report subset of T10. Only AKS, Git manifests, and pull history belong to T3 in this phase. Teams posts, approvals, emails, purge, backup/restore, other usage sources, weekly summaries, metrics.json, deployment workflow, and the full T12 README are deferred to their specified phases.

Use mocks, fixtures, and fakes for all Azure, Microsoft Graph, Teams, and LLM interactions. The Phase 1 outcome is a single command reviewing a fixture-backed test registry and writing a Markdown report, with nothing posted or deleted. Default dry_run to true everywhere. Resolve blocking questions before implementing dependent behavior; move to independent work when possible.

Before coding each task, review and refine its plan here. After each implementation task, run `ruff check .` and `pytest --cov=guardian`, fix failures, commit with the task ID prefix, then tick its checkbox and add a one-line result. Do not mark a task complete with failing tests. Policy coverage must reach at least 80%; executor coverage becomes applicable when that module is built in Phase 2.

### Task plans

- [x] **T1 — Scaffold, configuration, audit, CLI.** Set up Python 3.11+ packaging, typed modules, ruff/pytest configuration, validated config loading, JSON-lines audit logging with run IDs and timestamps, and the CLI entry point. Keep credentials in environment variables and redact sensitive values. Test defaults, invalid config, decimal thresholds (including grace_period_hours), audit shape, and CLI validation. Resolve Q01 and Q02 before finalizing relevant behavior.
- [x] **T2 — Registry interface and ACR inventory.** Define the adapter interface and implement ACR inventory using injected/mock Azure SDK clients and DefaultAzureCredential wiring. Normalize all tags per digest, manifest type, children, timestamps, size, and lock status; provide Docker Hub/GHCR stubs raising NotImplementedError. Test pagination, shared digests, indexes, locks, and SDK failures without live calls. Resolve Q03 and Q04 before implementing the deletion interface or inventory failure behavior; expose no delete tool to the agent.
- [ ] **T3 — Phase 1 usage sources and pull history.** Define UsageSource and implement AKS and configured Git manifest/Helm-value discovery with tag-to-digest resolution. Aggregate one pull-history query per run by repository and digest; carry warm-up completeness and failure state into policy/report inputs. Test fixtures for referenced images, children, recent pulls, warm-up, and failures that force KEEP and record a local alert. Defer remaining FR15 sources to Phase 3. Resolve Q05–Q07 before dependent parsing and query behavior.
- [ ] **T4 — Defender and Trivy scanning.** Verify current Microsoft documentation and record the supported Resource Graph schema before production; use the ScanProvider interface and Defender fixtures only in Phase 1. Normalize digest results, severity counts, and timestamps; use mocked Trivy fallback for missing/stale Defender data. Test freshness boundaries, failed scans, UNKNOWN reporting, and fail-safe KEEP. Resolve Q08 and Q09 before encoding query and fallback semantics.
- [ ] **T5 — Pure policy engine.** Implement deterministic, typed pure functions with an explicit evaluation time and no network/file access. Cover FR4, FR14, FR16, FR17, and scan freshness inputs: KEEP overrides, newest tags, shared digests, index/child protections, locks, staleness, vulnerability counts, untagged rules, incomplete history, and failed evidence. Keep in-use security alert facts separate from the KEEP verdict. Use table-driven edge/boundary tests and enforce at least 80% policy coverage. Resolve Q09–Q12 before choosing ambiguous precedence or time rules.
- [ ] **T6 — MCP tools.** Expose the eight documented tool names with validated inputs and documented result shapes; keep evaluation authoritative in policy code. For Phase 1, approval/alert calls must use local recording fakes with no Teams/Graph side effects. Test each shape, invalid inputs, guardrails against KEEP proposals, and absence of any delete tool. Resolve Q13 before finalizing local approval semantics and MCP transport.
- [ ] **T7 — LLM layer and agent loop.** Implement the provider-neutral LLMClient interface, LiteLLM wiring behind injected fakes, config-driven providers/fallbacks, startup tool-calling validation, and the CLI helper without making real LLM calls. Implement the prescribed prompt and bounded loop reviewing every repository/image and producing one local candidate batch/report input. Test scripted tool calls with anthropic, openai, and azure_openai configurations, fallback/timeouts, no delete capability, and the 200-call limit. Resolve Q14 and Q15 before dependent persistence and call-cap behavior.
- [ ] **T10 (Phase 1 subset) — Markdown report.** Generate counts by verdict, reclaimable GB, local alert outcomes, simulated items awaiting approval, incomplete pull history, and needs-scanning sections. Include reasons and all affected tags while avoiding double-counting shared/index storage. Add snapshots and an offline end-to-end single-command acceptance scenario exercising all Phase 1 policy rules. Defer metrics.json and weekly Teams cards to Phase 3. Resolve Q12–Q16 before finalizing report semantics.

### Phase exit (future; not performed by this planning update)

After all Phase 1 tasks are complete, run lint and all tests, confirm policy coverage and the offline command outcome, record a phase summary here, commit it, and tag v0.1. STOP for human review before Phase 2. Confirm the release tag convention in Q16 before tagging. No release tag is created during planning.

## Execution log

### T1 — active plan

Implement typed validated Phase 1 configuration (decimal ages, integer counts, UTC paths/defaults), safe JSONL audit output, and argparse CLI scaffolding for offline runs. Add local SQLite fingerprint state foundation. No live API clients or deletion interfaces. Test invalid inputs, defaults, audit redaction and CLI behavior. Later tasks will connect the fixture pipeline.

T1 complete: validated config, UTC audit with redaction, offline CLI scaffold and SQLite state. Lint and all 12 tests pass; 99% total coverage.

### T2 — active plan

Build RegistryReader, normalized image/evidence/blob models, JSON fixture reader, and an ACR wrapper accepting only injected SDK clients. A separate explicit factory wires DefaultAzureCredential without contacting Azure during tests. Inventory all tags/digests and parse index/child and blob metadata; partial metadata sets evidence incomplete. Verify pagination, lock, shared tags, index and failure behavior. No deleter is built.

T2 complete: read-only readers, fixture inventory, ACR normalization and future registry stubs. Lint and all 17 tests pass. No deletion interface exists.
