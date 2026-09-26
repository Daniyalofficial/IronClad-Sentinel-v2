# Upgrade validation — 2026-09-25

This records **what was actually exercised**, not a percentage-complete or
"perfect" certification. The upgrade is on
`arena/01a0d7c0-ironclad-sentinel-v2`, based on `main` at
`c4a814d692efe4a95644c698c3e24c6522428566`. The earlier unpushed
checkout identified by the requester was not available here; these are new
improvements to the checkout that was available, **not a recovery of the
missing files**. Nothing under `.github/workflows/` was changed.

## Changes tied to reproduced behavior

- A FIFO could stall a scan and a file symlink (including one swapped in
  after discovery) could make it read outside the target. Discovery now skips
  non-regular files; readers open without following the final link, reject
  non-regular descriptors and do not block on FIFOs. See
  `tests/test_file_safety.py`. A writable parent-directory race remains;
  mount untrusted repositories read-only.
- Competing workers could both claim a running job. The queue now checks
  the runnable/stale predicate again in its conditional update; concurrent
  PostgreSQL tests cover both one- and two-job races. A worker failure is
  recorded on the scan after rolling back partial findings, and the job's
  attempt/backoff state remains durable.
- `POST /scan` with `wait: true` previously had a cancelled job with no
  recovery path if the API died immediately after committing the request.
  The API now claims that job before committing, finishes it with a successful
  inline scan, and leaves it reclaimable after a crash. Inline scanner
  exceptions persist a failed scan with a generic HTTP error and a retryable
  job. SQLite and PostgreSQL API/worker tests assert live claims, normal
  completion, stale recovery, and retry. The stale timeout defaults to
  **15 minutes**; job delivery is at-least-once, not exactly-once.
- Repository-controlled `.ironclad.yml` could disable server engines or
  request outbound advisory egress. Server scans now ignore that file;
  local CLI scans keep their project-config behavior. A hostile-config API
  probe detected an attempted request before the fix, and the regression
  tests verify it is absent afterward.
- An uninitialized or wrong-working-directory SQLite database previously
  appeared healthy until login failed. `/health` now reports degraded
  bootstrap state; `/ready` returns 503 until an organization exists.
  Operator-only local `server unlock` and `server reset-password` provide
  recovery without SMTP; password reset revokes existing sessions, API
  tokens and unused reset links. SQLite and PostgreSQL recovery tests cover
  the account and credential state.
- A **zero-day audit-retention purge deleted its own audit record**. A
  second purge could delete the first purge's record. The purge now uses the
  exact preview cutoff and excludes all `audit.purged` entries from both
  previews and deletions. Real API/SQLite and PostgreSQL tests cover single
  and repeated zero-day purges. This is not protection against a database
  administrator changing rows directly.
- The local verifier counted network benchmarks that printed `SKIP:` and
  exited 0 as passing measurements. It now reports those as **skipped**;
  a regression test checks pass, fail and self-skip classification.

## Validation on the upgraded checkout

| Check | Observed result | Scope |
|---|---|---|
| Full suite with a **disposable live PostgreSQL** database (`IRONCLAD_TEST_POSTGRES_URL` set, `python -m pytest -q --disable-warnings --tb=short`) | **1,465 passed, 354 warnings, 0 skipped**; 191.23 s | Includes SQLite, PostgreSQL, API, file-safety, queue, auth and retention regressions. The PostgreSQL test module drops tables: never point it at production. |
| `bash scripts/verify_all.sh --keep-venv` | **33 passed, 0 failed, 4 skipped** | Installs, wheel, local HTTP API/dashboard and worker, migrations, reports, SBOM, policy gate, labelled corpus, scale smoke test and demo passed. Docker runtime was unavailable. The other three skips are described below. |
| Labelled corpus (`python benchmarks/corpus_metrics.py --fail-below 0.95`) | **26 files; 12 true positives, 0 false negatives, 0 false positives, 0 crashes; precision/recall 1.00** | Hand-written fixtures, not an estimate of misses in production repositories. |
| 10,000-file synthetic scale run (`python benchmarks/scale_benchmark.py --tiers 10000`) | **8.807 s; 1,135.472 files/s; 71.633 MB peak RSS; 1,424 findings** | Python 3.11.2/Linux, one run on this sandbox. No speed-up is established. |
| Hostile behavior probes and mutations | **New regression tests failed before their fixes and passed afterward** | Included API-death job recovery, invalid source retries, untrusted config egress, and retention `N=0`. Restoring cancellation, cancelling a completed inline job, recomputing the purge cutoff, dropping the purge-record exclusion, or treating an explicit benchmark skip as a pass was caught by the corresponding tests. |

The old 10,000-file reference measurement in this investigation was
**7.523 s**; other upgraded runs measured **7.530 s** and **8.147 s**.
Together with the final **8.807 s** result, these are noisy single-machine
runs, not a controlled speed comparison. We do **not** claim a throughput
improvement. The change prioritizes avoiding hangs, data loss, duplicate
work and misleading results over making a new speed claim.

Earlier in this investigation, while GitHub was reachable, the optional
network benchmarks observed **24 dependency findings and 0 false positives
under that benchmark's narrow criteria** on six repositories, **114/114**
for the bundled-feed parse/normalize/lookup pipeline, and **105/105** across
four pinned revisions against a PyPA advisory checkout at `a2fd0cfa1972`.
The PyPA result is partly circular because PyPA contributes to the bundled
feed; none of these establishes complete detection or a current live feed.
**The final attempts were not measurements:** GitHub was unreachable, so the
real-world corpus and pipeline-recall scripts printed `SKIP:`. The PyPA
benchmark also could not clone its target revisions even when given the
local PyPA source; the verifier invocation had no PyPA source configured.
The verifier now counts all three as skipped rather than passing.

## Remaining limits and operational cautions

- Docker build/runtime was not exercised in this environment (no usable
  Docker daemon). The PostgreSQL tests and HTTP/worker checks did execute.
- Remote GitHub-dependent detection checks need rerunning when network
  access is available; a self-skipped script exiting 0 is not evidence.
- An inline scan taking longer than the stale timeout can be reclaimed by a
  worker while still running. Use queued mode for large trees, monitor jobs,
  and keep the scanned repository read-only and available to API and worker.
- The bundled advisory database is a snapshot, not a real-time vulnerability
  feed. Taint analysis is intra-procedural and deep only for Python; other
  languages are mostly pattern based. No completion percentage or guarantee
  of zero false negatives can be inferred from the test totals.
- A source-code ZIP is **not** a database, scanned-repository, signing-key or
  integration-secret backup. Follow [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md)
  for state backups and off-host audit evidence.

For setup and recovery commands see [QUICKSTART.md](../QUICKSTART.md); for the
request semantics and the audit-retention exception see [API.md](API.md).
