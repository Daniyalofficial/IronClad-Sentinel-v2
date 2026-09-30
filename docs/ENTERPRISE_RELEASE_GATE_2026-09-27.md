# Enterprise release gate — 2026-09-27

> **Historical review.** The latest evidence and release decision are in
> [ENTERPRISE_RELEASE_GATE_2026-09-30.md](ENTERPRISE_RELEASE_GATE_2026-09-30.md).

**Status: BLOCKED. This is not a 100% or competition-ready certification. No
final enterprise ZIP is approved.** The older project-status report records
historical estimates, not an overriding accuracy measurement.

## Agreed release scope and evidence

| Acceptance item | Requirement | Evidence as of this review | Gate |
|---|---|---|---|
| Deployment | Docker Compose + PostgreSQL running together | PostgreSQL migrations, concurrent operations, and direct HTTP requests to a PostgreSQL-backed server were exercised locally. The Compose image could not be built or booted here: `docker`, `podman`, and `nerdctl` are unavailable; package-mirror, release-asset, and registry connections also failed. Static Compose tests and direct HTTP/PostgreSQL tests do not substitute for a running container. | **Unverified** |
| Enterprise sign-in | Generic OIDC, preprovisioned local users | Optional HTTPS authorization-code + PKCE flow; signed ID token, browser-bound single-use state, issuer/audience/nonce checks and local tenant/role binding exercised against a protocol mock and in a concurrent PostgreSQL replay test. SSO-only users can issue limited-scope, one-time-display dashboard tokens with CSRF checks. No authorized customer's live IdP was available. No IdP back-channel logout, SCIM or push deprovisioning: operators can now deactivate accounts and revoke their sessions/API tokens through the API. | **Implemented locally; live IdP integration unverified** |
| Independently benchmarked currently shipped scanners | Precision ≥95% and recall ≥90% | Full **26/26** independently labelled RealVuln human-authored Python repositories for shipped `ast-python` + `rule-engine`: **49.79% precision**, **16.64% recall** (see below). Other shipped scanners have not been independently measured against suitable third-party ground truth. | **FAIL** |
| Offline advisory database freshness | Snapshot age ≤24 h **and** still at both upstream Git heads when promoted | Generated 2026-09-27T09:46:47Z from GitHub Advisory Database `47313c6163ca` and PyPA Advisory Database `bf401288956a`: **13,523 packages / 46,634 advisories**. The online checker passed at measurement time; it must be rerun and, if necessary, rebuilt immediately before any future release. | **Time-dependent; last checked PASS** |
| Complete product readiness | Only claim completion with objective evidence for all in-scope gates | Accuracy fails by a large margin and Compose/runtime certification and other independent benchmarks remain open. | **BLOCKED** |

The agreed release deliberately defers **deep multi-language data flow and
dependency reachability**. Deferral does not turn the measured accuracy failure
of the *currently shipped* Python scanners into a pass.

### Independent accuracy, not the internal corpus

Pinned RealVuln Benchmark **v3.1.0**, release commit
`3aa5a1069685cce00b472defcde1a94499418673`. The benchmark manifest and
independently computed ground-truth content hash both equal
`sha256:0754363572503562e692414f826aad6f135f254851b8d12f70148bd235d23585`.
All 26 target repositories were checked out at their manifest-pinned commits.
The original scorer's file + acceptable CWE + ±10-line matching was used.

| Scoring view | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Full Python-human benchmark | 117 | 118 | 586 | 119 | **49.79%** | **16.64%** |
| Generous *declared-CWE-only* sensitivity analysis | 117 | 118 | 298 | — | **49.79%** | **28.19%** |

The declared-CWE view is derived from scanner source independently of which
benchmark cases passed; it **does not replace** the full-corpus score.
Before the narrowly scoped Python SQL/data-source fixes, the same full
benchmark produced 83 TP, 112 FP, 620 FN (42.56% precision, 11.81% recall).
The previously pushed SQL/data-source fixes matched eight more labels
(91 TP / 112 FP / 612 FN). The latest independently scored HTML-response and
template changes raised the count to **117 TP / 118 FP / 586 FN**, while the
full 26-repository gate still fails both thresholds by a wide margin. The
benchmark counts unmatched findings as FPs by its published protocol; some
`|safe` expressions are genuinely exploitable even inside HTML comments.
No label or matcher was changed to fit the score.
Unmatched findings are false positives *under the benchmark's published
protocol*, not evidence that a human would always reject them. Likewise, an
internal 26-file synthetic regression corpus that reports 1.00/1.00 cannot
establish third-party scanner accuracy. The independent Python result remains
well below both user-selected thresholds in either view. Reproduce with
[`benchmarks/realvuln_probe.py`](../benchmarks/realvuln_probe.py) against the
pinned release and read the saved per-repository result at
[`INDEPENDENT_SAST_RESULTS_2026-09-27.json`](INDEPENDENT_SAST_RESULTS_2026-09-27.json).
The benchmark's later HEAD has a stale manifest after its ground truth
changed; do **not** waive that integrity check to get a number.

### Separate advisory-feed disagreement (not an accuracy-gate waiver)

With the **same pinned PyPA advisory source** as the snapshot, the optional
feed-derived dependency regression probe (`benchmarks/independent_recall.py`)
returned **103/105 = 98.10%, exit 1** against four pinned repositories. It
was not counted as a pass. Both unmatched PyPA labels concern
`cryptography==37.0.4`: CVE-2026-69249 / PYSEC-2026-3553 and CVE-2026-69248 /
PYSEC-2026-3554. Those advisories **are present** in the bundle, but their
ranges exclude version 37. PyPA says `>=0, <49.0.0`, while the corresponding
GitHub Reviewed advisories say [`>=42.0.0, <49.0.0`](https://github.com/advisories/GHSA-jwv3-5hgf-82ww)
and [`>=45.0.0, <49.0.0`](https://github.com/advisories/GHSA-m2h6-j472-rp4c),
respectively. Cryptography's own [X.509 verification documentation](https://cryptography.io/en/latest/x509/verification/)
marks the verifier as **added in 42.0.0**. Thus the raw two-feed disagreement
must not silently be called two confirmed scanner false negatives, nor
silently dropped to make the probe green. The tool now distinguishes absent
advisories from range disagreements while **preserving its failing score and
threshold**. An operator should reconcile the upstream labels; freshness
alone does not certify advisory correctness. This feed-derived probe is also
partly circular because the bundled snapshot incorporates PyPA, and it does
**not** change the separately failing independent RealVuln SAST measurement.

### Verification actually performed

- API/dashboard and OIDC tests exercise hostile CSRF tokens, foreign tenants,
  forged/replayed OIDC state, incorrect ID-token signature/nonce, API-token
  privilege boundaries, account deactivation and last-owner protection.
  Regressions were reproduced before changes and deliberately disabled to
  check that the tests detect the missing guards.
- A disposable **live PostgreSQL** test database exercises migrations,
  job/cancellation races, single-use OIDC state across API replicas, and
  concurrent owner deactivation with transactional session/API-token
  revocation. PostgreSQL tests **must not** be silently skipped: set
  `IRONCLAD_TEST_POSTGRES_URL` to a disposable database whose name contains
  `test`, `verify`, `ci`, `scratch`, `tmp` or `temp`; these tests DROP its tables.
- A **real HTTP socket** (`uvicorn` bound to 0.0.0.0 with a disposable
  PostgreSQL database, not TestClient or Docker) was probed with valid and
  hostile requests. Readiness, auth, tenant isolation, a scan, traversal and
  oversized IDs, idempotency, cross-session dashboard CSRF, narrow-token
  authorization, revocation, logout, and local user deactivation all behaved
  as asserted. The previously pushed SQL fix was also verified through a
  real-HTTP scan: PostgreSQL stored the finding at the interpolated query, a bound
  parameter produced no SQL injection finding, and a foreign tenant and
  anonymous client could not read the findings. A new live PostgreSQL/HTTP
  scan of hostile Flask and Jinja sources returned **five exact expected
  findings** (including two HTML-comment breakout expressions), with no
  Jinja-comment or properly escaped HTML alerts. The live request probe passed
  **38/38** checks, including traversal and idempotency; a separate worker
  completed the queued scan and PostgreSQL persisted its findings. This is
  **not** a Compose or real-IdP result.
- New scanner tests first reproduced missing Flask JSON and GraphQL SQL
  injections, a false alarm on bound SQL values, a shadowed SQLAlchemy name,
  and deduplication of distinct queries. The current upgrade additionally
  reproduced unsafe Flask route/JSON-to-HTML and `|safe` template flows,
  verified that Jinja (not browser HTML) comment semantics govern whether
  expressions are rendered, and mutation-verified the new rule and source
  handling. Deliberately disabling the fixes caused their tests to fail; the
  source was restored afterward. Real Jinja rendering demonstrated a `|safe`
  payload that escaped an HTML comment into a `<script>` element.
- Complete suite with `.venv/bin` on `PATH` and a disposable live PostgreSQL
  server kept alive throughout pytest (after scanner changes):
  **1,551 passed, 440 warnings, 0 skipped**. A passing test suite
  demonstrates only the behaviors it tests, not release completion.
  `.github/workflows/` was not modified; a fuller example is at
  `deploy/ci/verify.yml` and must be installed by an authorized maintainer
  if CI coverage is expanded.
- The local `scripts/verify_all.sh --quick --keep-venv` completed **33 passed,
  0 failed, 2 explicitly skipped**: the optional feed-derived PyPA recall
  probe lacked a checkout, and Docker build/runtime could not run. The
  script's own 0.95 threshold checks a *project-written* corpus, not the
  failing independent RealVuln accuracy gate. The skipped optional PyPA
  probe was subsequently run with the pinned feed; its **103/105 result
  failed** and its two contradictory ranges are detailed above. The prior
  pushed branch commit `114e8fd` received **3/3 successful** GitHub Actions
  jobs ([run](https://github.com/Daniyalofficial/IronClad-Sentinel-v2/actions/runs/36308545737));
  that run predates the HTML/template changes documented here. Neither local
  nor remote tests certify running Compose or independent scanner accuracy.

The online freshness check is `python scripts/check_advisory_freshness.py`
(no `--offline`). Refresh with `bash scripts/build_advisory_db.sh` if the age
exceeds 24 hours or either upstream head changes. A feed match at one point
in time does not prove it will match at the later release instant.

## Remaining release work (not waived)

1. Reach **both** independent accuracy thresholds on the pinned full scope
   without tuning the scorer, selecting only passing repositories, or
   replacing the independent corpus with project-written fixtures. Define
   third-party labelled corpora and measure the remaining shipped scanners.
2. Run the **built Compose image** with PostgreSQL, API and worker on a
   Docker-enabled host; exercise TLS/reverse proxy, migration, auth/SSO,
   scanning, permissions, restore and failure/retry paths with hostile inputs.
3. Test with an authorized enterprise IdP and document its deprovision/logout
   integration or accept and enforce the operator-driven local deactivation
   procedure and session TTL as a scoped limitation.
4. Re-run the complete no-skips PostgreSQL test suite and release-time online
   advisory checker **again at actual promotion** (their earlier results
   are not perpetual). Measure any required real integration and
   operational SLOs separately. Only then reconsider whether a **final** ZIP
   is justified; a source archive is never a database/key/repository backup.

No weighted completion percentage is inferred from these checks, file counts
or test counts. Failing an explicit gate means the enterprise release is
**not ready** regardless of how many other tests pass.
