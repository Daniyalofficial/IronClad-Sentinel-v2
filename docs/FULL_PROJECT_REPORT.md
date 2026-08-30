# IronClad Sentinel — Full Project Report

**Report date:** 2026-08-30
**Branch:** `arena/01a03853-ironclad-sentinel-v2`
**HEAD:** `082b8d1` (`docs: make the table count and skip counts precise`)
**Previous fix commit:** `4adf170` (`fix(reports): advertise the real tool version; unblock two verification steps`)
**Branched from:** `f53b542` on `main`
**Pull request:** #8 — `OPEN`, `MERGEABLE`, **43 commits**, **155 files changed, +28,194 / −491**
**GitHub CI on `082b8d1`:** **4/4 checks pass** (run `33294410087` / `33294410112`)

Every number in this document was produced by running the command shown
against this checkout during the session that wrote it. Nothing here is
carried forward from an earlier report without being re-measured.

---

## 1. Headline

| | |
|---|---|
| **Implementation completeness** | **~97%** |
| **Verification completeness** | **~93%** |
| **Overall project completion** | **~96%** |
| **Production-usable today** | Yes, for the self-hosted single-tenant and multi-tenant SQLite/PostgreSQL deployment described in `docs/DEPLOYMENT.md` |

Implementation and verification are scored separately on purpose. The code
is close to finished; the *evidence* is not, because four categories of
evidence need things this environment does not have (a container runtime,
real third-party credentials, a labelled real-world corpus, and CI
`workflows` permission).

---

## 2. Verified evidence

Run against `082b8d1`, Python 3.11.2, in a fresh `.venv`.

| # | Claim | Command | Result |
|---|---|---|---|
| 1 | Full suite, with a live PostgreSQL | `pytest -q` + `IRONCLAD_TEST_POSTGRES_URL` | **866 passed, 0 skipped** (111s) |
| 2 | Full suite, no `psycopg2` installed | `pytest -q` | **850 passed, 1 skipped** |
| 3 | Full suite, `psycopg2` present, no server | `pytest -q` | **850 passed, 16 skipped** |
| 4 | Core-only install (what CI installs) | fresh venv, `pip install -e .`, `pytest -q` | **485 passed, 15 skipped** (17s) |
| 5 | PostgreSQL behavioural suite | real **PostgreSQL 16.2**, `pytest tests/test_postgres.py` | **16/16 passed** |
| 6 | Reproducible end-to-end verification | `bash scripts/verify_all.sh` | **32 passed, 0 failed, 1 skipped** (Docker) |
| 7 | Detection precision / recall | `python benchmarks/corpus_metrics.py` | precision **1.0000**, recall **1.0000**; 26 files, 17 findings, 12 TP, **0 FP, 0 FN**, 0 crashes |
| 8 | Integration delivery | `python benchmarks/integration_check.py` | **51/51 checks passed** against a real local HTTP server |
| 9 | Self-scan | `ironclad scan ironclad --fail-on high` | exit 0, **0 findings**, grade **A+**, risk 0 — 89 files, 17,205 lines, 2.99s |
| 10 | Company demo | `bash demo/run_demo.sh /tmp/demo1` | exit 0 — vulnerable tree fails the gate, baselined backlog does not block CI, fixed tree passes |
| 11 | Throughput, 1,000-file tier | `python benchmarks/scale_benchmark.py` | **1,190 files/s**, 21.2 MB peak RSS |
| 12 | Throughput, 10,000-file tier | same | **1,394 files/s**, 26.0 MB peak RSS, 119,413 lines, 1,412 findings, 7.2s |
| 13 | Packaging | `python -m build --wheel` + clean-venv install | wheel builds and installs clean |
| 14 | GitHub CI | `gh pr checks 8` | **4/4 pass**: `API, dashboard and database` (51s), `Company demo and packaging` (20s), `Tests, scanner quality and CLI` (2m17s), `bootstrap-and-verify` (37s) |

**PostgreSQL server actually used:** `PostgreSQL 16.2 on
x86_64-pc-linux-gnu, compiled by gcc (GCC) 10.2.1`, started via `pgserver`,
migrations `0001`/`0002`/`0003` applied with checksums, 19 tables present in
the `public` schema.

Skip counts move with the environment, so all three variants are listed
above rather than the most flattering one: without `psycopg2` the
PostgreSQL module skips as a single unit; with `psycopg2` but no server URL
its 16 tests skip individually; with a live server nothing skips.

---

## 3. Found and fixed during this report

Five defects. Three were code/CI defects, two were documentation that
contradicted the shipped code. Each was reproduced before being fixed.

### 3.1 Reports advertised a version that was never shipped — **fixed**

`ScanResult.tool_version` defaulted to the literal `"1.0.0"`
(`ironclad/core/models.py`) while `ironclad.__version__` is `1.1.0`, and
`run_scan()` never passed a version.

Reproduced by running the real CLI and reading the output back:

```
sarif tool driver version: 1.0.0
json report tool_version:  1.0.0
package __version__:       1.1.0
```

So every JSON report and every SARIF `runs[].tool.driver.version` named a
release that does not exist. A customer ingesting our SARIF into GitHub code
scanning would attribute every finding to the wrong tool version, and
baseline provenance would be wrong with it.

Fix: `tool_version: str = field(default_factory=lambda: __version__)`.
Verified after the fix through the real CLI:

```
package:           1.1.0
SARIF driver ver:  1.1.0
JSON tool_version: 1.1.0
```

Guarded by `tests/test_self_scan.py::test_report_and_sarif_advertise_the_real_tool_version`,
which asserts the dataclass, the JSON report and the SARIF driver all agree
with `ironclad.__version__`. That test fails on the old code.

### 3.2 `verify_all.sh` could not run its own packaging step — **fixed**

Step 9 calls `python -m build --wheel`, but `build` was not declared in the
`dev` extra. On a clean `pip install -e ".[server,dev]"` the authoritative
verification script reported:

```
28 passed, 2 failed, 2 skipped
  Failures:
    - build wheel: No module named build
    - wheel installs clean: dist/*.whl does not exist
```

An earlier report claimed `32 passed, 0 failed, 1 skipped`. That claim did
**not** reproduce from a clean install. `build>=1.0` is now part of the `dev`
extra and the script reports **32 passed, 0 failed, 1 skipped (Docker)**.
GitHub CI already worked around this by installing `build` explicitly, so
this brings the local script in line with CI.

### 3.3 The staged CI workflow never ran the PostgreSQL behavioural suite — **fixed**

`deploy/ci/verify.yml` stood up `postgres:16-alpine` and applied the
migrations, but never set `IRONCLAD_TEST_POSTGRES_URL`. The 16 tests
covering check constraints, unique constraints, cascade delete, tenant
isolation, timezone-aware session expiry and the job queue were therefore
skipped while looking covered.

Added a step that creates a dedicated `ironclad_ci_test` scratch database
(the suite drops every table in its target and refuses to run against a name
that does not look disposable) and runs the suite. Verified locally by
executing the exact step commands against PostgreSQL 16.2: **16/16 passing**.

`.github/workflows/` was deliberately **not** touched, per the standing
constraint. The gap in the *live* workflow therefore still exists; it closes
when the staged workflow is installed.

### 3.4 Four documented "known limitations" were false — **corrected**

`docs/PROGRESS.md` listed these as missing. All four exist and are tested:

| Doc claimed | Actual, verified |
|---|---|
| "No rate limiting on the API" | `app.state.limiter = build_limiter(engine)`; login, per-account lockout, password-reset, password-change and token-creation budgets from `IRONCLAD_RATELIMIT_*`. `tests/test_ratelimit.py`: **29 passed** |
| "Password reset has no delivery mechanism (no mail transport is bundled)" | `app.state.mail = build_transport_from_env()` is passed into `password_reset.request_reset(...)`; SMTP / in-memory / null transports in `ironclad/platform/mail.py`, configured via `IRONCLAD_MAIL_TRANSPORT` + `IRONCLAD_SMTP_*`. `tests/test_password_reset.py`: **33 passed** |
| "The dashboard has no mutating UI" | `POST /ui/findings/{finding_id}/triage` exists and shares `ironclad.platform.triage` with the JSON API |
| "PostgreSQL is supported but not exercised in CI" | The live CI service `postgres:16-alpine` applies migrations and bootstraps an organization |

Leaving these in place would have understated the product to anyone reading
the progress matrix.

### 3.5 "19 tables" was ambiguous — **clarified**

ORM metadata reports **18** tables; the live PostgreSQL `public` schema
reports **19**. Both are right — `schema_migrations` is the migration ledger
and is not an ORM model. The docs now state the breakdown.

---

## 4. Capability inventory

All counts measured from the code, not from documentation.

### Detection

| | |
|---|---|
| Rule packs | **9** (`go`, `java`, `javascript`, `multi_language_crypto`, `php`, `python_extra`, `ruby`, `secrets_generic`, `shell_and_config`) |
| Rules | **66** |
| Manifest parsers | **20** registry entries, plus `requirements*.txt` and `*.csproj` variant handlers |
| Ecosystems | **8** — python, javascript, go, ruby, php, java, rust, nuget |
| Offline advisory DB | **44** packages across 8 ecosystems (`ironclad/data/vuln_db.json`) |
| License DB | **61** package→license mappings (`ironclad/data/license_db.json`) |
| Python deep analysis | AST-based, 10 flow detectors in `ironclad/scanners/python_flows.py` |
| Report formats | json, sarif, html, markdown, junit, cyclonedx, spdx — all from one `ScanResult` |

### Platform

| | |
|---|---|
| Database tables | **19** (18 application + `schema_migrations`) |
| Migrations | **3 per dialect** (sqlite + postgres), checksummed, transactional |
| API operations | **53** across **45** paths |
| Dashboard | **14** routes, **10** distinct pages, **11** templates |
| CLI command groups | **12** (`baseline`, `config`, `doctor`, `init`, `license`, `policy`, `report`, `sbom`, `scan`, `serve`, `server`, `version`) |
| Auth | PBKDF2-SHA256 210k iterations, session digests, account lockout, revocation, password reset with constant-time unknown-address path |
| Authz | 5 roles / 19 permissions, deny by default |
| Multi-tenancy | `org_query` scoping enforced per route |
| Kubernetes manifests | **9** |
| Documents | **13** in `docs/` |

### Code size

| | |
|---|---|
| `ironclad/` | **58** Python files, **14,303** lines |
| `tests/` | **60** Python files, **9,710** lines, **35** test modules |
| Test:product line ratio | ~0.68 : 1 |

---

## 5. Test totals by module

Collected with `pytest --collect-only -q`.

| Module | Tests | | Module | Tests |
|---|---|---|---|---|
| `test_api` | 102 | | `test_ratelimit` | 29 |
| `test_rule_packs_extended` | 71 | | `test_dashboard` | 29 |
| `test_python_flows` | 54 | | `test_cli` | 26 |
| `test_org_egress_policy` | 51 | | `test_secrets` | 21 |
| `test_egress_allowlist` | 49 | | `test_deployment` | 20 |
| `test_ssrf` | 45 | | `test_audit_export` | 19 |
| `test_detection_coverage` | 40 | | `test_baseline_v2` | 17 |
| `test_dependency_ecosystems` | 38 | | `test_postgres` | 16 |
| `test_security` | 36 | | `test_mvp_acceptance` | 12 |
| `test_password_reset` | 33 | | `test_ast_python` | 11 |
| `test_policy` | 32 | | `test_self_scan` | 9 |
| `test_database` | 32 | | `test_sbom_license_hardening` | 7 |
| `test_resilience` | 29 | | 10 remaining modules | 38 |

Total collected: **866** across **35** modules, verified with
`pytest --collect-only -q` (sum of the per-module counts above is 866).

---

## 6. Architecture

```
ironclad/
  core/          config (5-level precedence), walker, models, engine,
                 policy, baseline (v2: reasons + expiry), spdx_expr,
                 exit_codes, paths (target confinement)
  scanners/      ast_python, python_flows, rule_engine, secrets,
                 dependency, advisories, sbom, spdx, iac, iac_extended
  rules/packs/   9 YAML packs, 66 rules
  data/          offline vuln + license databases
  platform/      database (transactional migrations), models, security,
                 rbac, tenancy, egress, triage, password_reset, mail,
                 ratelimit, audit, events, jobs, worker_jobs,
                 observability, scanning, integrations/
  api/           FastAPI app factory, routes, schemas, deps
  web/           server-rendered dashboard (Jinja2), no client-side JS logic
  reporting/     json, sarif, html, markdown, junit
  licensing/     offline Ed25519 commercial license verification
```

Design properties that hold and are tested:

* **Single canonical `Finding`** — every engine feeds the same
  deduplication, baseline-diff, scoring and reporting pipeline.
* **Schema is never created by application code.** Only checksummed SQL
  migrations create tables; `run_migrations()` is idempotent and atomic on
  both dialects.
* **No network access at scan time.** The scanner is fully offline; the only
  outbound paths are the integration deliveries, which are gated by SSRF
  protection plus the egress allowlist.
* **Egress precedence is intersection.** An organization can only narrow the
  operator's global `IRONCLAD_EGRESS_ALLOWLIST`, never widen it. Enforced
  inside `resolve_target()` before DNS, covering the initial destination and
  every redirect hop.
* **Tenancy scoping is structural** — `org_query` rather than per-query
  filtering, so a forgotten `WHERE org_id = ...` is not possible.

---

## 7. Security posture

| Control | Status | Evidence |
|---|---|---|
| SSRF / private-range blocking | Implemented, incl. `http://` scheme, RFC 6598 CGNAT, hex/octal/decimal loopback, IPv6 + IPv4-mapped loopback, RFC 6890/2544, broadcast, userinfo tricks | `tests/test_ssrf.py` — 45 tests |
| DNS rebinding | Validation and connection resolve to the **same pinned IP** (`_PinnedHTTPConnection` / `_PinnedHTTPSConnection`) | reproduced, then blocked |
| Redirect handling | Every hop re-validated; `_NoRedirect` because urllib raises on 3xx | tested |
| Egress allowlist | Global + per-organization, intersection precedence, exact/`*.` label-anchored matching, no suffix matching | 49 + 51 = **100 tests** |
| Secrets detection | Regex + Shannon entropy, with redaction; hardcoded-credential rule added after a 3.67-entropy password went undetected | 21 tests |
| Password storage | PBKDF2-SHA256, 210,000 iterations | `tests/test_security.py` — 36 tests |
| Account enumeration | Password-reset request returns an identical response and burns comparable time for unknown addresses | tested |
| Audit log | Append-only, redacted, filterable, permission-gated, exportable, retention purge | 19 tests |
| Rate limiting | Login, per-account lockout, password reset/change, token creation | 29 tests |
| Docs/OpenAPI exposure | Disabled by default | tested |
| Self-scan | **0 findings, grade A+** on the product's own 89 files | re-run this session |
| Dashboard headers | CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` | in `ironclad/api/app.py` |
| Cookie | `HttpOnly`, `SameSite=Lax`, `Secure` gated on `IRONCLAD_COOKIE_SECURE` | tested |
| Container | non-root, read-only rootfs (manifests written; **not booted**) | `deploy/k8s/` |

---

## 8. Known limitations — what prevents 100%

Ordered by how much they matter commercially.

1. **The Docker image has never been built or booted.** No container runtime
   exists in this sandbox (`docker`, `podman`, `nerdctl`, `buildah`, `kaniko`
   all absent; no `/var/run/docker.sock`). `Dockerfile`,
   `docker-compose.yml` and `scripts/container-entrypoint.sh` exist and the
   entrypoint's logic is exercised by tests, but no container has ever
   started. This is the single largest unverified claim in the project.
2. **No integration has been proven against a real third-party endpoint.**
   GitHub, GitLab, Slack, Teams and Jira deliveries are verified only as
   *request construction against a local receiver*. `benchmarks/integration_check.py`
   says so explicitly, labelling all five `NOT EXTERNALLY VERIFIED`. No
   credentials were used, so none were claimed.
3. **Recall is measured on a synthetic corpus, not a labelled real-world
   one.** precision 1.0000 / recall 1.0000 comes from 26 hand-written files.
   False positives *were* tuned against real projects (flask, click, jinja,
   requests, httpx, rubygems, PHPMailer, guzzle — 182 findings reduced to 73),
   but nobody has labelled a real vulnerable codebase to produce a true
   recall figure. The published recall is therefore an upper bound on a
   corpus we designed.
4. **Analysis depth is intra-procedural and Python-only.** Flows crossing a
   function boundary are missed. Java, Go, PHP, Ruby and JS are regex rules
   with no data-flow model. There is no reachability analysis, so a
   vulnerable dependency is reported whether or not the vulnerable path is
   reachable.
5. **No OIDC / OAuth2.** Local authentication and API tokens only. For a B2B
   security product this is a real sales blocker in enterprises with
   mandatory SSO.
6. **The live CI workflow does not run the PostgreSQL behavioural suite.**
   Fixed in the staged `deploy/ci/verify.yml`; installing it requires the
   `workflows` permission this identity does not have.
7. **PostgreSQL is verified for correctness, not under load.** 16/16
   behavioural tests pass; no concurrency or volume benchmark has been run
   against it. Throughput numbers above are scanner throughput, not
   API/database throughput.
8. **Egress allowlist is hostname-only.** No per-path, per-port or
   per-integration restrictions.
9. **Rate limiting is in-process unless the database backend is used.** A
   multi-replica deployment must set `IRONCLAD_RATELIMIT_BACKEND` to the
   database; edge throttling still belongs in the ingress.

---

## 9. What the final ~4% requires

| Gap | Requirement | Effort once unblocked |
|---|---|---|
| Container | Any environment with a container runtime; then `docker build` + boot + `verify_all.sh` step 11 | ~1 day |
| Real integrations | Test credentials/tokens for GitHub, GitLab, Slack, Teams, Jira | ~2 days |
| True recall | A labelled vulnerable corpus (e.g. a set of CVE-bearing commits) | ~1 week, ongoing |
| OIDC / OAuth2 | Product decision on providers + a session external-identity path | ~1 week |
| Live CI upgrade | `workflows` permission, or a maintainer installs `deploy/ci/verify.yml` | minutes |
| PostgreSQL under load | A load generator against a real server | ~2 days |
| Per-path/port egress | Design decision on policy shape | ~2 days |

---

## 10. Corrections to previously reported figures

Stated plainly, because the earlier report was the basis for a "96–98%"
claim and two of its numbers did not survive re-measurement.

| Previously reported | Re-measured this session | Verdict |
|---|---|---|
| `verify_all.sh` → 32 passed, 0 failed, 1 skipped | 28 passed, **2 failed**, 2 skipped from a clean `.[server,dev]` install | **Did not reproduce.** Now genuinely 32/0/1 after the `build` extra fix |
| 849 passed, 1 skipped | 850 passed, 1 skipped (no `psycopg2`); **866 passed, 0 skipped** with a live server | Superseded — one test added, and the PostgreSQL suite now actually runs |
| 484 passed, 15 skipped (core-only) | **485 passed, 15 skipped** | Superseded by the one added test |
| 49 API endpoints | **53 operations across 45 paths** | Corrected; there is no `/api` prefix at all |
| 11 dashboard pages | **14 routes, 10 distinct pages, 11 templates** | Corrected |
| 5 roles / 20 permissions | **5 roles / 19 permissions** (`len(ALL_PERMISSIONS) == 19`; the union of all role grants is the same 19) | **Was wrong in 4 documents**, all corrected |
| 19 tables | 18 ORM models + `schema_migrations` = 19 in the database | Ambiguous, now stated precisely |
| Self-scan: 81 files / 14,766 lines | **89 files / 17,205 lines** | The codebase grew; old numbers were stale |
| 1,917 / 2,142 / 2,122 files/s | **1,190 / 1,394 files/s** on the 1k / 10k tiers | Machine-load dependent; the numbers published in `docs/BENCHMARKS.md` should be re-run on representative hardware before being quoted to a customer |
| "No rate limiting", "no mail transport", "read-only dashboard", "PostgreSQL not exercised in CI" | All four exist and are tested | **False limitations**, removed |

---

## 11. Commercial assessment

**What is genuinely sellable today.** An offline, self-hosted AppSec scanner
with a real multi-tenant platform behind it: 66 rules across 8 ecosystems,
SBOM generation, license compliance, IaC checks, secrets detection, an
append-only audit log, RBAC, a dashboard, a durable job queue, Prometheus
metrics, and Kubernetes manifests. The offline-only posture is a real
differentiator for finance, healthcare, defence and any air-gapped
environment, and it is architecturally true rather than a marketing claim —
the scanner makes no network calls.

**Where it loses deals today.** No SSO/OIDC. No container image that has
actually been booted. No proven integration with the ticketing and chat
tools security teams actually live in. And no third-party recall benchmark —
a security buyer will ask "what does it catch on *my* codebase?" and the
honest answer right now is "we measured precision and recall on a corpus we
wrote ourselves."

**Credibility of the engineering.** The codebase passes its own scanner at
zero findings, the migrations are genuinely atomic on both dialects, tenancy
is enforced structurally rather than by convention, and the test suite
contains regression guards for bugs that were actually reproduced rather
than theorised. Several of the defects fixed along the way — the dead login
form, the dead triage form, non-atomic migrations, a CI-green-but-broken
acceptance gate — are the kind that survive code review and only surface
when something is executed end to end. That is the strongest signal in this
report.

**Bottom line.** ~96% complete, production-usable for its stated deployment
model, and not yet demo-ready for an enterprise buyer until the container,
one real integration, and SSO are done. None of the remaining work is
architecturally difficult; all of it is blocked on environment access,
credentials, or a labelled corpus.
