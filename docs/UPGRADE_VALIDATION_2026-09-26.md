# PostgreSQL scan cancellation and worker-claim upgrade — 2026-09-26

This report records **observed behavior**, not a project-completion percentage. The previously mentioned unpushed checkout was unavailable; this is an upgrade to the available branch, `arena/01a0d7c0-ironclad-sentinel-v2`, not a recovery of those files. No file under `.github/workflows/` was changed. Earlier results remain in [the 2026-09-25 report](UPGRADE_VALIDATION_2026-09-25.md).

## Reproduced problems and repairs

Real PostgreSQL sessions and HTTP requests were paused at defined barriers to control the ordering; each regression failed before the relevant repair:

| Reproduced interleaving | Incorrect prior result | Guard now exercised |
|---|---|---|
| Worker loads scan; API cancels; worker resumes | Scan became `succeeded` with findings despite accepted cancellation | Conditional scan reservation before reading files; no completion event or findings after cancellation |
| API reads queued scan; worker finishes; API resumes | Completed scan became `cancelled` and returned HTTP 200 | Cancellation conditionally updates only unfinished scans; HTTP 409 if completion won |
| Failure handler reads scan; API cancels; failure handler writes | Cancelled scan became `failed` and emitted a failure event | Conditional failure marker; no failure event if cancellation won |
| Worker finishes or retries a job after another session cancels it | Cancelled job became `succeeded` or `queued` | Job finishing requires `running` and the worker's own attempt number; job cancellation cannot undo success |
| Another worker reclaims a stale job; older worker finishes | Older attempt completed or retried the newer claim | Immutable attempt number is saved **outside the ORM object** before handler work and retained across rollback/reload; both worker and inline error paths are tested |
| Inline request is delayed after its job claim; worker reclaims or finishes | Inline request adopted the newer claim, scanned or returned an unexpected error | Inline path refreshes scan/job identity-map rows and checks its original attempt before doing work |
| Inline request is cancelled before its helper starts | Stale ORM scan/job state produced an unexpected error | Refresh before deciding whether to run; returns the cancelled scan |

The PostgreSQL job claim also disables SQLAlchemy's Python-side synchronization for its timestamp predicate and refreshes the claimed row afterward. Repeated retries previously raised `TypeError: can't compare offset-naive and offset-aware datetimes` once a PostgreSQL-aware timestamp entered the session's identity map. The existing PostgreSQL retry test detects reintroducing that bug.

The cancellation is **not a preemptive kill** of an executing scanner. A running transaction holds the scan row lock: a cancel request can wait until it completes, then return 409 if it finished first. If cancellation wins before the scan reserves the row, the worker does not persist scan results.

## Verification on the upgraded code

| Check | Observed result | Scope and caveat |
|---|---|---|
| Full suite with a disposable live PostgreSQL database (`IRONCLAD_TEST_POSTGRES_URL` set, `python -m pytest -q --disable-warnings --tb=short --show-capture=no`) | **1,479 passed, 370 warnings, 0 skipped** in 186.20 s | Includes SQLite, PostgreSQL, FastAPI, concurrent API/worker, migrations and security regressions. The PostgreSQL test fixture **drops every table** in its designated test database; never point it at production. The warnings were not treated as test failures. |
| `IRONCLAD_PYPA_VULNS=<temporary PyPA checkout>/vulns bash scripts/verify_all.sh --keep-venv` | **36 passed, 0 failed, 1 skipped** | Installs, SQLite and PostgreSQL tests, API/dashboard over real HTTP, worker, wheel, SBOM, policy, local integrations, source-code scans, benchmarks and demo passed. Docker build/runtime was **not exercised**: no usable Docker daemon. The PyPA source was a separate temporary checkout, not committed to this repository. |
| Real-world dependency probe (`benchmarks/real_world_corpus.py`) | **24 findings, 0 false positives** in its narrow checks across six cloned repositories | Does **not** measure recall or a production false-positive rate. |
| Pinned-revision pipeline probe (`benchmarks/pipeline_recall.py`) | **114/114 found** | Ground truth comes from the bundled advisory database, so this cannot measure feed completeness. |
| PyPA advisory probe (`benchmarks/independent_recall.py --source .../vulns`) | **105/105 found** at PyPA checkout `bf401288956a` | The bundled database incorporates PyPA; this score is partly circular and is a regression guard, not a universal recall claim. |
| Synthetic 10,000-file scale run (`benchmarks/scale_benchmark.py --tiers 10000`) | **7.686 s**, 1,301.098 files/s, 71.648 MB peak RSS, 1,424 findings | One local run; earlier runs were noisy, so no speed-up is asserted. |

For the independent-feed check, the temporary source was cloned with `git clone --depth 1 --filter=blob:none --sparse https://github.com/pypa/advisory-database /tmp/pypa` and `git -C /tmp/pypa sparse-checkout set vulns` (the actual temporary checkout path had a randomized suffix). Point `IRONCLAD_PYPA_VULNS` at its `vulns` directory to reproduce the verifier invocation; the observed checkout was `bf401288956a`.

The pre-change full-suite baseline on this checkout was **1,465 passed, 354 warnings** with live PostgreSQL. Counts describe executed tests, **not** percent completeness.

### Regression sensitivity

The concurrency tests failed on the original implementation before repairs. Afterward, deliberate local mutations were individually reverted: allowing cancelled scans through reservation, letting late cancellation overwrite success, allowing failure markers after cancellation, removing job status or attempt predicates, letting terminal job cancellation overwrite success, using refreshed `job.attempts` after rollback, omitting the worker/inline attempt token, and skipping the inline scan/job identity-map refresh or ownership check **each caused its corresponding test to fail**. Restored code passed the targeted and full suites. No tests were skipped or weakened to make the suite green.

## Remaining limits and the “100%” request

There is no agreed definition or measurement establishing either 97% or 100% whole-project completion. Passing tests does not certify zero bugs or zero false negatives. In particular:

- Docker build and runtime were not tested here. The checked-in CI workflow is only staged at `deploy/ci/verify.yml`; no `.github/workflows/` file was edited or installed.
- A scan taking longer than the stale-job timeout can be reclaimed while the original process still runs. The database guards prevent stale attempts from overwriting terminal results, **not** duplicated CPU work, instantaneous interruption, or waiting on a scan row lock. Prefer queued mode for large scans and read-only source mounts.
- A scan already marked `failed` can still have a queued retry; the scan cancellation endpoint currently returns **409** for that status rather than cancelling the pending retry. This is an outstanding behavioral limitation, not something these tests establish as solved.
- The bundled advisory database is a snapshot. Deep taint analysis is mostly Python/intra-procedural; other languages and the small synthetic corpus cannot establish universal detection accuracy. Neither the recall probes nor the absence of false positives in six repositories is a 100% security guarantee.
- The [source ZIP](https://github.com/Daniyalofficial/IronClad-Sentinel-v2/archive/refs/heads/arena/01a0d7c0-ironclad-sentinel-v2.zip) is a code snapshot, **not** a backup of the database, scanned repositories, signing keys, or integration secrets. Follow [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md) for state backups.

A specific acceptance checklist (supported scanners, accuracy and freshness targets, operating environments, and security/operational SLOs) is needed to measure further progress toward the user's 100% aspiration.
