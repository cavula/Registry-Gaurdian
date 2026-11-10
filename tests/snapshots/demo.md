# Registry Guardian report

Run: snapshot
UTC: 2026-11-10T00:00:00+00:00
Status: complete
Mode: offline dry run; notifications and approvals are simulated.
Tool calls: 8

## Counts by verdict

| Verdict | Count |
| --- | ---: |
| KEEP | 9 |
| STALE | 2 |
| INSECURE | 1 |
| STALE_AND_INSECURE | 1 |
| UNTAGGED | 1 |

Reclaimable storage estimate (decimal GB): 5.000000500
Deletion candidates: 5
Local alerts recorded this run: 2
External alerts sent: 0

## Top risks and findings

| Repository | Digest | All tags | Verdict | Reasons |
| --- | --- | --- | --- | --- |
| app | sha256:live | v-live | KEEP | in use |
| app | sha256:both | v-both | STALE_AND_INSECURE | unused, old, no recent pull; fresh security threshold exceeded |
| app | sha256:insecure | v-risk | INSECURE | fresh security threshold exceeded |
| app | sha256:fallback | v-fallback | STALE | unused, old, no recent pull |
| app | sha256:stale | v-stale | STALE | unused, old, no recent pull |
| app | sha256:untagged | (untagged) | UNTAGGED | orphan untagged manifest older than threshold; no recent pull |
| app | sha256:arm | (untagged) | KEEP | child referenced by an index; never propose alone; in use |
| app | sha256:boundary | v-boundary | KEEP | no deletion policy matched |
| app | sha256:index | v-index | KEEP | in use |
| app | sha256:newest | new1, new2, new3 | KEEP | among newest tags |
| app | sha256:protected | prod | KEEP | protected tag |
| app | sha256:recent | v-recent | KEEP | recent pull |
| app | sha256:shared | v1.2, prod | KEEP | protected tag |
| app | sha256:unknown | v-unknown | KEEP | security UNKNOWN; needs scanning |

## Items awaiting simulated approval

- app@sha256:both (all tags: v-both)
- app@sha256:insecure (all tags: v-risk)
- app@sha256:fallback (all tags: v-fallback)
- app@sha256:stale (all tags: v-stale)
- app: 1 untagged manifests, 1000000100 bytes; digests: sha256:untagged

## Pull history incomplete

None.

## Needs scanning

- app@sha256:unknown

## Local alerts and warnings

- Needs scanning: app@sha256:unknown
- In-use image exceeds the security threshold; kept.

## Agent explanation (advisory)

Top risk: the running live image has a CRITICAL vulnerability and is kept. The both image is stale and insecure; insecure exceeds the HIGH limit. Stale and fallback are unused and old, and untagged is an old orphan. The unknown image needs scanning. All requests and alerts are simulated.

Storage is an estimate of unique candidate graph blobs not retained by another root; no image is deleted in Phase 1.
