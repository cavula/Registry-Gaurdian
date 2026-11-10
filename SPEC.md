# Registry Guardian: Specification

This spec is the source of truth for building Registry Guardian. Read it in full before starting. Build in the order set by Delivery phases, then the task list.

## Instructions to the coding agent

1. Treat this spec as the source of truth. If code and spec disagree, the spec wins. If the spec is unclear, write the question in OPEN_QUESTIONS.md instead of guessing.
2. Work one task at a time, in phase order. After each task, run all tests and commit with a message naming the task ID.
3. Never call real delete APIs in tests. Use mocks and a test registry.
4. Default every run to dry run mode. Deletion requires dry run off, a valid approval, and an expired grace period.
5. Keep secrets out of code. Read them from environment variables or Azure Key Vault.

## Overview

Registry Guardian is a Python service that reviews container images in Azure Container Registry (ACR) on a schedule. It flags stale images, untagged leftovers, and images that fail security policy. An LLM agent explains the findings in plain English. Nothing is deleted without approval in Microsoft Teams, a 72 hour grace period, and a backup. The registry layer must be pluggable so Docker Hub and GitHub Container Registry (GHCR) can be added later.

## Functional requirements

**FR1 Inventory.** List all repositories and manifests in the configured ACR, capturing repository, tags, digest, manifest type (single or index), push time, and size. Last pull time comes from FR14.

**FR2 Usage check.** Mark a digest as in use if any configured usage source (FR15) reports it running or referenced. Resolve tags to digests before comparing.

**FR3 Security scan.** Get vulnerability results from Microsoft Defender for Containers in bulk with one Azure Resource Graph query per run (the securityresources table, container registry vulnerability assessments and their sub assessments), filtered to the configured registry and mapped to digests. Verify the current table and field names against Microsoft documentation and record them in OPEN_QUESTIONS.md if they differ. The agent identity needs Reader on the subscription. If Defender is unavailable, fall back to a local Trivy scan. Freshness rules are in FR20.

**FR4 Policy evaluation.** Each digest gets one verdict: KEEP, STALE, INSECURE, STALE_AND_INSECURE, or UNTAGGED. Rules:

- STALE: meets the FR14 staleness rules (unused, older than `stale_days`, default 90, and no recent pull).
- INSECURE: one or more CRITICAL vulnerabilities, or more than `max_high` (default 5) HIGH vulnerabilities, from a fresh scan (FR20).
- UNTAGGED: see FR17.
- Always KEEP: any digest with a tag matching `protected_tags` (default: latest, prod, release*), any digest among the newest `keep_last_n` (default 3) tags per repository, any digest in use, and any rule in FR16 that forces KEEP.
- Policy code is the only thing that sets verdicts.

**FR5 Agent review.** An LLM agent calls the read only tools, reviews the verdicts, and writes a plain English report with the top risks first and a reason for each flagged image. The agent can recommend, never decide.

**FR6 Alerts.** INSECURE images that are in use trigger an immediate Teams alert. They are never proposed for deletion.

**FR7 Approval request.** Digests proposed for deletion are sent to Teams as one Adaptive Card listing each digest, all its tags, its verdict, and its reason. Requests with no decision expire after `approval_ttl_hours` (default 72). Only approvers can act on them (FR11).

**FR8 Purge.** When the grace period (FR12) ends, the executor handles only digests still SCHEDULED. For each one it rechecks policy, backs up (FR18), then deletes. Any digest whose verdict changed, or whose backup failed, is skipped and logged.

**FR9 Audit.** Every run, tool call, verdict, approval, cancellation, backup, deletion, and restore is written as a JSON log line with run ID and timestamp.

**FR10 Report.** Each run produces a Markdown report: counts by verdict, storage reclaimable in GB, alerts sent, items awaiting approval, images with incomplete pull history, and images that need scanning.

**FR11 Approver guardrail.** Only members of a configured Entra ID security group (`approvers_group_id`) can Approve, Reject, or Cancel. The bot checks the clicking user's group membership through Microsoft Graph before acting. Clicks from anyone else are refused, logged, and answered with a short "not authorised" reply in Teams.

**FR12 Grace period and rollback.** Approval does not delete anything. It moves the batch to SCHEDULED with `scheduled_delete_at` set to `grace_period_hours` later (default 72; must accept decimal values such as 0.1 for testing). Then:

- An email goes to the distribution list (`notify_distribution_list`) through Microsoft Graph sendMail from a service mailbox (`sender_mailbox`). It lists each image, its tags, verdict, reason, approver, and scheduled deletion time, with a Cancel link and an Open in Azure portal link.
- The Teams card updates to show the countdown and a Cancel button.
- Any approver can cancel the whole batch or single digests before the deadline. Cancelled digests become CANCELLED and are never deleted in this run.
- After the purge, a final email and Teams update list what was deleted, what was skipped, and why.

**FR13 Teams bot.** Notifications use a bot built with the Microsoft Teams SDK for Python, registered in Azure Bot Service. Do not use the retired Bot Framework SDK. The Microsoft 365 Agents SDK for Python is an acceptable alternative if the Teams SDK lacks a needed feature; record that choice in OPEN_QUESTIONS.md. Host the bot on Azure Functions; if the SDK does not run cleanly there, use Azure Container Apps and note the choice. Cards have Approve, Reject, Cancel, and Open in Azure portal buttons. The portal button links to the registry resource. All alerts and approvals go to one dedicated channel (`teams_channel`).

**FR14 Pull history (hybrid staleness).** ACR does not store a last pull time, so staleness uses two layers:

- **Layer 1, always on:** a digest is a stale candidate only if it is not in use, its push time is older than `stale_days`, and it is not among the newest `keep_last_n` tags in its repository.
- **Layer 2, pull logs:** the registry's diagnostic setting sends only the `ContainerRegistryRepositoryEvents` category to a Log Analytics workspace (`log_analytics_workspace_id`). Get the latest Pull event per repository and digest with one KQL query per run, not one per image.
- **Warm up rule:** until logs have existed for at least `stale_days` (tracked by `pull_logs_enabled_on`), any digest with a recorded pull inside `stale_days` is KEEP; others follow Layer 1 and the report labels them "pull history incomplete".
- **After warm up:** a digest is STALE only if Layer 1 is true and it has no Pull event within `stale_days`.
- **Failure mode:** if the Log Analytics query fails, mark every candidate KEEP, send a Teams alert, and propose nothing for deletion.
- **Setup:** the README must include the az CLI command to create the diagnostic setting with only that category, and note the Log Analytics Reader role needed by the agent identity.

**FR15 Usage sources.** Each usage source is a pluggable `UsageSource` class returning digests in use. Build: AKS, Azure Container Apps, Azure App Service and Function Apps running containers, Azure Container Instances, and deployment manifests or Helm values in configured Git repos. Sources are listed under `usage_sources` in config. If any configured source fails, mark every candidate KEEP and alert in Teams. Acceptance: an image running only on Container Apps is KEEP.

**FR16 Shared digests and multi architecture images.** The unit of deletion is the manifest digest, not the tag.

- Before proposing a digest, list every tag pointing to it. If any of those tags is protected, newest, or in use, the digest is KEEP.
- Approval cards and emails show all tags that disappear with each digest.
- For a multi architecture image (manifest list or OCI index), in use and pull checks apply to the index and every child manifest. If any child is in use or recently pulled, the whole index is KEEP. Never delete a child manifest on its own.
- Respect ACR locks: digests with delete disabled are skipped and reported, never forced.
- Acceptance: a digest tagged both `v1.2` and `prod` is KEEP; an index whose arm64 child is in use is KEEP.

**FR17 Untagged manifests.** Manifests with no tags get the verdict UNTAGGED when older than `untagged_days` (default 7), not in use, not a child of a tagged index, and not pulled in that window. They go through the same approval and grace period, grouped as one line per repository with a count and total size. Acceptance: a dangling manifest 10 days old appears in the batch; a child of a tagged index never does.

**FR18 Backup and restore.** Before deleting any digest, the executor saves a copy.

- Default (`backup.mode: blob`): export the image as an OCI archive to Azure Blob Storage (`backup.storage_account`, `backup.container`) in the Cool tier, with a lifecycle rule removing backups after `backup.retention_days` (default 30).
- If the registry has ACR soft delete enabled, `backup.mode: soft_delete` may rely on it instead, recording the recovery window in the audit log. Verify current ACR soft delete support and note findings in OPEN_QUESTIONS.md; do not assume it.
- If the backup fails, that digest is not deleted and an alert is sent.
- `guardian restore <digest>` pushes the image back with its original tags and logs who restored it.
- Acceptance: a deleted image can be restored with all its tags; a failed backup blocks its deletion.

**FR19 Weekly Teams summary.** On `summary.cron` (default Mondays 09:00), the bot posts one Adaptive Card with: storage reclaimed this week and in total (GB), images deleted, cancelled, and restored, open security alerts by severity, top five repositories by reclaimable storage, and a four week trend for each figure. The same numbers are written to `metrics.json`. Acceptance: the card renders from fixture data and its numbers match the audit log.

**FR20 Scan freshness.** A scan result counts only if newer than `scan_max_age_days` (default 7). Images with missing or stale Defender results get a local Trivy scan in the same run. If neither succeeds, security status is UNKNOWN: the image is never treated as secure, cannot be called INSECURE, and is listed in the report under "needs scanning". Acceptance: an image with a 30 day old Defender result is rescanned by Trivy.

## Non functional requirements

- **Safety:** no deletion without approval, grace period, and backup. Protected and in use images are blocked in code, not by prompt.
- **Least privilege:** the scanning identity is read only. Only the executor identity can delete.
- **Idempotent:** running twice in a row produces no duplicate approvals or alerts.
- **Performance:** a registry of 1,000 images completes a run in under 10 minutes.
- **Testability:** at least 80% unit test coverage on policy and executor modules.
- **Configurable:** all thresholds live in `config.yaml`.

## Design

### Project structure

```
registry-guardian/
  config.yaml
  src/guardian/
    registries/base.py      # RegistryAdapter interface
    registries/acr.py       # ACR implementation
    usage/base.py           # UsageSource interface
    usage/aks.py
    usage/container_apps.py
    usage/app_service.py
    usage/container_instances.py
    usage/git_manifests.py
    usage/pull_history.py   # Log Analytics pull query (FR14)
    scanning/defender.py
    scanning/trivy.py
    policy/engine.py        # pure functions, no I/O
    llm/client.py           # provider agnostic LLM layer
    agent/mcp_server.py     # exposes read only tools over MCP
    agent/runner.py         # LLM loop with tool calling
    approval/teams.py       # Teams bot, cards, approver check
    notify/email.py         # Graph sendMail (FR12)
    executor/purge.py
    executor/backup.py      # FR18 backup and restore
    audit/log.py
    report/markdown.py
    report/summary.py       # FR19 weekly summary, metrics.json
    main.py                 # CLI: guardian run | purge | restore | llm test | summary
  tests/
  .github/workflows/daily.yml
```

### Data model

Image record: `registry`, `repository`, `tags` (list), `digest`, `manifest_type`, `child_digests`, `pushed_at`, `last_pulled_at`, `size_bytes`, `in_use` (bool), `vulns` (counts by severity), `scan_source`, `scanned_at`, `verdict`, `reasons` (list of strings).

Approval record: `approval_id`, `run_id`, `digests`, `status` (PENDING, SCHEDULED, CANCELLED, REJECTED, EXPIRED, DELETED), `requested_at`, `decided_by`, `decided_at`, `scheduled_delete_at`, `cancelled_by`. Store approvals in Azure Table Storage, or a local SQLite file in dev.

### RegistryAdapter interface

Every registry implements `list_repositories()`, `list_images(repo)`, `delete_image(repo, digest)`. ACR is built now. Docker Hub and GHCR adapters are stubs that raise NotImplementedError.

### MCP tools exposed to the agent

| Tool | Input | Output | Side effects |
| --- | --- | --- | --- |
| list_repositories | registry | list of repo names | none |
| list_images | registry, repo | list of image records | none |
| get_images_in_use | none | list of digests | none |
| get_pull_history | none | latest Pull time per digest (FR14) | none |
| get_scan_results | digest | vuln counts by severity, source, scan date | none |
| evaluate_policy | digest | verdict and reasons | none |
| request_approval | list of digests, summary | approval_id | posts to Teams |
| send_alert | digest, message | ok | posts to Teams |

The agent gets NO delete tool. Deletion only happens in `guardian purge`, which reads SCHEDULED records whose grace period has ended and runs outside the LLM.

### Agent behaviour

Model: any provider supported by the LLM provider layer, chosen in config. The system prompt must state: review every repository, call evaluate_policy for each image, never propose an image whose verdict is KEEP, alert on in use insecure images, group all deletion candidates into one approval request, then write the report. Cap the loop at 200 tool calls per run.

### LLM provider layer

The agent must not depend on any single LLM vendor. All model calls go through one interface in `src/guardian/llm/`.

- **Interface:** `LLMClient.chat(messages, tools) -> response`, returning text, a list of tool calls (name, arguments), and token usage. The agent runner only uses this interface.
- **Implementation:** LiteLLM under the hood, covering Anthropic, OpenAI, Azure OpenAI, Google Gemini, Ollama, and any OpenAI compatible endpoint.
- **Selection:** provider, model, key env var, base URL, and API version come from the `llm` block in `config.yaml`. Switching providers needs a config change only.
- **Keys:** read from the env var named in `api_key_env`, or from Azure Key Vault in production. Never log keys.
- **Custom providers:** OpenAI compatible endpoints work with `provider: openai_compatible` and `base_url`. For anything else, add a class implementing `LLMClient` and register it by name.
- **Fallback:** if the primary provider errors or times out, try each `fallback` entry in order and log which one answered.
- **Tool calling check:** on startup, fail fast with a clear error if the chosen model does not support tool calling.
- **CLI helper:** `guardian llm test` sends one test prompt with one dummy tool and prints provider, model, latency, and whether tool calling worked.
- **Tests:** a fake `LLMClient` replays scripted tool calls. Acceptance: the same scripted run passes with provider set to anthropic, openai, and azure_openai using mocked responses.

### Run flow

1. The scheduler starts `guardian run`.
2. The agent inventories, checks usage, pull history, and scans, and evaluates policy.
3. The agent sends alerts and one approval request, and writes the report.
4. An approver clicks Approve or Reject in Teams. The bot checks the approver group, sets the batch to SCHEDULED, and emails the distribution list.
5. After the grace period with no cancellation, the scheduler runs `guardian purge`, which rechecks policy, backs up, and deletes digests still SCHEDULED.
6. Everything is written to the audit log.

### Configuration (config.yaml)

```yaml
registry: { type: acr, name: "<registry name>", resource_group: "<resource group>" }
stale_days: 90
max_high: 5
keep_last_n: 3
protected_tags: [latest, prod, "release*"]
untagged_days: 7
scan_max_age_days: 7
usage_sources:
  aks: [{ resource_group: "<resource group>", name: "<cluster name>" }]
  container_apps: { subscriptions: ["<subscription ID>"] }
  app_service: { subscriptions: ["<subscription ID>"] }
  container_instances: { subscriptions: ["<subscription ID>"] }
  git_manifests: [{ repo: "<org/repo>", paths: ["deploy/"] }]
dry_run: true
approval_ttl_hours: 72
grace_period_hours: 72          # decimals allowed, e.g. 0.1 for testing
log_analytics_workspace_id: "<workspace ID>"
pull_logs_enabled_on: "<YYYY-MM-DD>"
approvers_group_id: "<Entra ID group object ID>"
notify_distribution_list: "<distribution list email>"
sender_mailbox: "<service mailbox email>"
teams_channel: "registry-guardian"
backup:
  mode: blob                    # blob | soft_delete
  storage_account: "<storage account name>"
  container: "acr-backups"
  retention_days: 30
summary:
  cron: "0 9 * * MON"
llm:
  provider: openai              # anthropic | openai | azure_openai | gemini | ollama | openai_compatible
  model: "<model name>"
  api_key_env: LLM_API_KEY      # name of the env var holding the key, never the key itself
  base_url: null                # Azure OpenAI, Ollama, or any OpenAI compatible endpoint
  api_version: null             # Azure OpenAI only
  temperature: 0
  fallback:                     # optional, tried in order if the primary fails
    - { provider: anthropic, model: "<model name>", api_key_env: ANTHROPIC_API_KEY }
```

## Delivery phases

Build in three phases. Finish and tag each phase before starting the next, and stop after each phase for human review. Phase order takes precedence over task numbers.

**Phase 1: Working agent in dry run (tag v0.1).** T1 to T7, plus the Markdown report from T10. In T3, build only the AKS and Git manifest usage sources plus pull history. Outcome: one command reviews a test registry, applies all policy rules including FR14, FR16, FR17, and FR20, and writes a report. Nothing is posted or deleted.

**Phase 2: Safe approvals and purge (tag v0.2).** T8 and T9. Teams bot, approver group, grace period, emails, backup and restore, and the purge executor. Outcome: the full approve, cancel, back up, delete, restore loop works against mocks and a test registry.

**Phase 3: Coverage and visibility (tag v1.0).** The remaining FR15 usage sources, the FR19 weekly summary and metrics.json from T10, T11, and T12.

## Tasks

- [ ] **T1** Scaffold the project, config loader with validation, audit logger, CLI entry point. Tests for config validation.
- [ ] **T2** RegistryAdapter interface and ACR adapter using the Azure SDK with DefaultAzureCredential, including tags per digest, manifest type, child manifests, and lock status. Tests with mocked SDK responses.
- [ ] **T3** UsageSource classes for every FR15 source, plus the FR14 pull history query with warm up and failure handling. Tests with fixtures.
- [ ] **T4** Defender client through Resource Graph and Trivy fallback, with FR20 freshness rules. Tests with fixture scan outputs.
- [ ] **T5** Policy engine as pure functions. Table driven tests for every rule in FR4, FR14, FR16, and FR17, including edge cases: protected tag that is also stale, in use image that is insecure, digest exactly `stale_days` old, shared digest with a protected tag, index with an in use child.
- [ ] **T6** MCP server exposing the eight read only tools. Tests that each tool returns the documented shape and that no delete tool exists.
- [ ] **T7** LLM provider layer and agent runner with the system prompt, tool loop, and call cap. Test with a fake LLM that replays a scripted tool sequence.
- [ ] **T8** Teams bot per FR13 with alert and approval cards, the FR11 approver check, the FR12 grace period scheduler, cancel handling, and Graph email notifications. Tests with mocked Teams and Graph clients.
- [ ] **T9** Purge executor with FR18 backup and restore, FR16 digest, multi architecture, and lock handling, and FR17 untagged batches. Tests proving it refuses expired, rejected, cancelled, or changed images, blocks deletion on failed backup, and does nothing in dry run.
- [ ] **T10** Markdown report generator, metrics.json, and the FR19 weekly Teams summary. Snapshot tests.
- [ ] **T11** GitHub Actions workflow: daily `guardian run`, lint, tests. Dockerfile for the service.
- [ ] **T12** README with setup steps, the diagnostic setting command, required Azure roles and Graph permissions, an architecture diagram, and a demo walkthrough.

## Acceptance criteria

1. A protected tag older than 90 days is KEEP.
2. An in use image with a CRITICAL vulnerability triggers an alert and is never in an approval request.
3. An unused image not pulled for 120 days, after warm up, is STALE and appears in the approval request with its reason.
4. With dry run on, `guardian purge` deletes nothing even with a scheduled record.
5. A request with no decision after `approval_ttl_hours` is EXPIRED and nothing is deleted.
6. An approved batch is not deleted before the grace period ends; a cancelled digest is never deleted; a click from a non approver is refused.
7. If a verdict changes to KEEP after approval, purge skips it and logs why.
8. A failed backup blocks deletion of that digest; a deleted image can be restored with all its tags.
9. Running `guardian run` twice in a row creates only one approval request.
10. Every deletion has a matching audit line with run ID, approval ID, approver, and digest.
11. The agent has no tool that can delete an image.
12. All tests pass in CI and policy plus executor coverage is at least 80%.

## Out of scope for v1

Docker Hub and GHCR implementations, image signing checks, a chat interface, multi tenant support, and a web dashboard. Leave clean extension points for each.
