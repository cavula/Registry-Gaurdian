# AGENTS.md

## Source of truth
SPEC.md is the source of truth. If code and spec disagree, the spec wins.
If anything is unclear or missing, do not guess. Add it to OPEN_QUESTIONS.md
with the task ID and your best options, then move to the next task you can do.
Things the spec asks you to verify (Defender Resource Graph fields, ACR soft
delete support, Teams SDK fit) must be checked against current Microsoft docs
and recorded in OPEN_QUESTIONS.md, never assumed.

## Phases
1. Build in the three phases defined in SPEC.md: v0.1, v0.2, v1.0.
2. Phase order takes precedence over task numbers.
3. At the end of each phase: all tests green, tag the release, write a phase
   summary in PROGRESS.md, then STOP and wait for human review before
   starting the next phase.

## How to work
1. One task at a time, in phase order.
2. Before coding a task, write a short plan for it in PROGRESS.md.
3. After each task: run lint and all tests, fix failures, then commit
   with a message starting with the task ID, for example "T5: policy engine".
4. Tick the task off in PROGRESS.md with a one line summary.
5. Never mark a task done while any test is failing.

## Safety rules (never break these)
- Never call real Azure, Microsoft Graph, Teams, or LLM APIs. Use mocks and fakes.
- Never write secrets or keys in code, tests, or commits. Read them from env vars.
- The agent must have no delete tool. Deletion lives only in `guardian purge`.
- dry_run defaults to true everywhere.
- Nothing is deleted without approval, an ended grace period, and a successful backup.
- Protected tags, in use images, shared digests, and approver checks are
  enforced in code, not prompts.
- Never delete a child manifest of a multi architecture image on its own.
- If any usage source, pull history query, or scan fails, fail safe: KEEP and alert.

## Code standards
- Python 3.11+, type hints everywhere, formatted and linted with ruff.
- Tests with pytest. Policy and executor modules need 80% coverage or more.
- Keep policy/engine.py pure: no network or file access.
- Small functions, clear names, docstrings on public functions.
- Numeric config values such as grace_period_hours must accept decimals.

## Commands
- Install: pip install -e ".[dev]"
- Lint: ruff check .
- Test: pytest --cov=guardian

## When finished
Update README.md per T12, list anything unresolved in OPEN_QUESTIONS.md,
and summarise what was built in PROGRESS.md.
