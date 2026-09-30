# Enterprise release gate — 2026-09-30

**Decision: BLOCKED.** The project cannot honestly be called 100% complete,
production-certified or competition-ready under the agreed acceptance gates.
This is an evidence report, not a final enterprise release or a readiness
percentage. The 2026-09-27 [gate review](ENTERPRISE_RELEASE_GATE_2026-09-27.md)
is historical; its measurements are not the current results.

The agreed scope is a running Docker Compose deployment with PostgreSQL,
generic enterprise OIDC, independent precision **≥95%** and recall **≥90%**
for currently shipped scanners, and an offline advisory snapshot no more than
24 hours old and still at both upstream heads **when promoted**. Deep
multi-language data flow and dependency reachability are deferred. No
threshold or third-party label has been loosened to produce a passing result.

| Gate | Evidence from this checkout | Result |
|---|---|---|
| Independent scanner accuracy | Pinned RealVuln human-authored Python corpus, **26/26 repositories**, original third-party scorer and unchanged 703 positive labels: **124 TP / 119 FP / 579 FN / 119 TN** = **51.03% precision / 17.64% recall** for `ast-python` + `rule-engine`. Other shipped engines still lack adequate independent ground-truth measurements. | **FAIL** (required ≥95% / ≥90%) |
| Docker Compose + PostgreSQL | A live local PostgreSQL server, real TCP API and separate worker were exercised, but no `docker`/`podman`/`nerdctl` executable or container daemon is available here; package mirror/registry access also failed. The built Compose image was **not** started. | **UNVERIFIED** |
| Generic enterprise OIDC | Authorization-code/PKCE, signed ID token, state/nonce, local preprovisioned users and PostgreSQL replay protections are covered by tests. An authorized live enterprise IdP with actual TLS redirect was **not** available or tested. | **Implemented locally; integration unverified** |
| Offline advisory freshness | Rebuilt on **2026-09-30T10:06:19Z** from GitHub Advisory Database `6669d604e3bd` and PyPA Advisory Database `4eab9bee0c16`: **13,527 packages / 46,732 advisories**. Online age and both upstream heads matched at the time of this review; this must be repeated at promotion. | **Time-dependent; last checked PASS** |

## What was actually improved and verified

- Checked the latest remote session branch and restored the identical saved
  worktree before making changes; **no merge into `main`**. Nothing under
  `.github/workflows/` was modified.
- A malformed benchmark setup had a pinned `HEAD` but an unpopulated
  `--no-checkout` worktree. It falsely *appeared* to reach 77.19% precision
  while scanning many repositories with zero files. This was reproduced,
  **invalidated**, and never counted as an improvement. The benchmark now
  refuses dirty, incomplete or sparse target checkouts. Clean clones at all
  26 pinned commits reproduce the earlier 117 TP / 118 FP / 586 FN baseline.
- Red-first, mutation-verified scanner changes model archive/compressed-file
  openers, bounded HTTP URL placeholders, non-injected FastAPI endpoint
  parameters and Jinja `Environment.from_string` receivers. They avoid
  confusing an archive mode with its filename, FastAPI dependency injection
  with HTTP input, an arbitrary parser with Jinja, or one HTML-escaped value
  with a different unescaped value. Actual FastAPI request binding was also
  checked. The full, unchanged independent scorer then measured **124 TP /
  119 FP / 579 FN**, an improvement of seven matched cases and one additional
  unmatched alert relative to the earlier revision — **not** a passing score.
- The current complete Python test run used a disposable **live PostgreSQL**
  database throughout: **1,572 passed, 439 warnings, 0 skipped**. The CLI
  self-scan returned zero findings. A PostgreSQL-backed API and worker ran on
  real sockets: **38/38** HTTP checks passed and the worker persisted five
  expected hostile-source findings. A foreign tenant received 404, an
  anonymous client 401, an oversized identifier 422, and both symlink
  escape and path traversal requests 400. The test API was stopped afterward.
  This is not evidence of a running Compose image or a real IdP.
- Bundled-data pipeline regression: **112/112**, measured *against the
  bundled snapshot itself*, not an independent completeness claim. An
  additional feed-derived PyPA probe returned **103/105, exit 1**: two
  `cryptography==37.0.4` cases still disagree between upstream ranges.
  These failures have **not** been suppressed or called passing.
- A Python wheel built successfully and its archive integrity, scanner,
  refreshed advisory snapshot and template rule pack were checked. This does
  not demonstrate a running Compose image or an installed customer system.

### Independent scorer provenance and reproduction

RealVuln Benchmark **v3.1.0**, commit
`3aa5a1069685cce00b472defcde1a94499418673`, manifest ground-truth hash
`sha256:0754363572503562e692414f826aad6f135f254851b8d12f70148bd235d23585`.
Every selected repository's checked-out source, commit and cleanliness were
verified before scanning. The original scorer's file + acceptable CWE +
±10-line matcher counts *every* unmatched SAST alert as an FP under that
published protocol. The [machine-readable per-repository result](INDEPENDENT_SAST_RESULTS_2026-09-30.json)
and [`benchmarks/realvuln_probe.py`](../benchmarks/realvuln_probe.py) make
this reproducible. Unmatched benchmark alerts are not necessarily adjudicated
real-world false positives. A generous declared-CWE-only sensitivity view is
still **51.03% precision / 29.88% recall** (124 TP / 119 FP / 291 FN); it
cannot replace the agreed full-corpus measurement.

## Release blockers, not waived

1. Improve the shipped scanners enough to meet **both** independent
   thresholds on full, intact, third-party corpora, without manipulating
   labels, selecting only favorable targets or substituting the internal
   regression corpus. Independently measure the remaining shipped engines.
2. Build and boot the actual **Docker Compose** API/worker/PostgreSQL stack on
   a suitable host; exercise health, migrations, security boundaries,
   read-only mounts, scan/retry and restore over its deployed network.
3. Validate generic OIDC end-to-end against an authorized HTTPS IdP with
   preprovisioned users and tested deactivation/session-revocation operations.
4. At the actual release instant, rerun complete no-skips testing, check CI
   for the exact candidate SHA, and recheck/rebuild the offline advisory
   snapshot against **both** live upstream heads and the ≤24-hour limit.

An earlier green GitHub workflow or a passing local test suite does not
certify production operation, independent scanner accuracy, or whole-product
completion. A source ZIP is not a database, keys, repository, or operational
state backup. **No final enterprise ZIP is approved.**
