# Changelog

All notable changes. Format follows [Keep a Changelog](https://keepachangelog.com/);
versioning is [SemVer](https://semver.org/).

## [Unreleased]

Verification-driven hardening. Every fix below was found by *executing* the
system in a way it had not been executed before, not by reading it.

### Added

- **Rate limiting** (`ironclad/platform/ratelimit.py`). Account lockout alone
  was not brute-force protection — it is per account, so an attacker got
  `MAX_FAILED_LOGINS` guesses against *every* address with nothing limiting
  the rate. Measured before this change: 25 credential guesses across 5
  accounts in 1.9s (~13/sec), no `429` ever returned.

  Sliding-window limiter with three layers on `/auth/login`: per-IP
  (10/60s), per-account volume (5/300s), and the existing account lockout.
  Also 10/300s on API-token creation and 5/300s on password change. The same
  attack now yields 10 guesses from one IP, then `429` with `Retry-After` and
  `X-RateLimit-Limit`/`X-RateLimit-Remaining`.

  Storage is pluggable: `InMemoryStore` (default, per process) and
  `DatabaseStore` (`IRONCLAD_RATELIMIT_BACKEND=database`, shares counters
  across processes at the cost of a write per checked request). Every limit
  is operator-tunable via `IRONCLAD_RATELIMIT_*` as `LIMIT:WINDOW_SECONDS`,
  with `0` disabling that check. Fails **open** on a store error and counts
  it — a limiter that takes the API down when its backend hiccups is worse
  than no limiter. `X-Forwarded-For` is honoured only with
  `IRONCLAD_TRUST_PROXY=1`.

### Fixed

- **Migrations were not atomic.** pysqlite implicitly commits before DDL, so
  `engine.begin()` never wrapped a migration in a transaction. A migration
  that failed partway left all 19 tables behind while recording nothing as
  applied, and a retry died on "table already exists" — a single bad
  migration could brick a fresh install. Transaction control is now handed
  to SQLAlchemy (DBAPI autocommit plus an explicit `BEGIN`).
- **Two SSRF bypasses.** RFC 6598 CGNAT (`100.64.0.0/10`) passed the guard
  because Python's `ipaddress` reports `is_private=False` for it; and
  `http://localhost.localdomain/` was not recognised as local. Both now
  blocked, along with the hex/octal/decimal loopback encodings, IPv6 and
  IPv4-mapped loopback, RFC 6890/2544, broadcast and userinfo tricks.
- **The WAL/foreign-key pragmas** moved to the connect event, since
  `journal_mode` cannot be changed from inside a transaction once DDL is
  transactional.
- **Rate-limit fallback loop** — an unrecognised `IRONCLAD_RATELIMIT_BACKEND`
  was caught and then re-raised, because the fallback called `build_limiter()`
  again, which re-read the same bad environment value. Now falls back to the
  in-memory store explicitly and logs a warning.
- **Pre-auth rate limiting must not write a tenant-scoped audit row.**
  `audit_events.org_id` is a foreign key and there is no tenant before
  authentication; the first implementation inserted `org_id=0` and failed the
  constraint on every throttled request. Volume rejections are now counted in
  `ironclad_rate_limited_total` instead.

### Added

- `scripts/verify_all.sh` — one reproducible verification entry point (11
  stages) for as long as the comprehensive GitHub workflow cannot be
  installed. 32 checks pass; anything unavailable is reported SKIPPED with
  the reason.
- `tests/test_deployment.py` (20 tests) — the container entrypoint is now
  *executed* for every role rather than inspected, and the Kubernetes/compose
  hardening claims are assertions: non-root, `readOnlyRootFilesystem`, all
  capabilities dropped, resource limits, probes on the right paths, read-only
  scan volume, fail-fast on missing secrets.
- `tests/test_resilience.py` (29 tests) — migration failure recovery,
  edited-migration refusal, stale-job reclaim (and an in-flight job *not*
  being stolen), duplicate-finding rejection, retry exhaustion, cancelled
  jobs never executing, queued work surviving a restart, reconnection after
  dispose, expired/revoked sessions, deactivated users, the lockout matrix,
  malformed payloads, no stack-trace leakage, cross-tenant 404s, invalid
  scan paths, token narrowing.
- 18 parameterised SSRF bypass regression tests.
- A version-consistency test covering `pyproject.toml`, `__init__.py`,
  `SBOM_TOOL_VERSION`, the Kubernetes image tags and the changelog.

### Documented

- `SECURITY.md` now states the SSRF threat surface explicitly, including
  that **DNS rebinding is not defended** (the host is resolved at validation
  time, not at connect time).

### Known limitation added

- The container image has still never been built or run: no container runtime
  exists in the verification environment. The entrypoint logic is executed,
  but in-container behaviour is not verified.

## [1.1.0] - 2026-08-27

The release that turns IronClad Sentinel from a scanner into a platform:
persistent storage, authentication, authorization, multi-tenancy, an HTTP
API, a dashboard, a job queue, events, audit and deployment artifacts.

### Added

**Policy engine**
- `policy.yaml` with severity gates, `fail_on`, composite risk cap, license
  allow/warn/block, blocked packages, confidence floor, rule severity
  overrides, path and engine restrictions.
- Validation reports **every** problem at once, not just the first.
- Evaluation is deterministic: same scan + same policy → byte-identical
  decision (asserted in tests).
- CLI: `ironclad policy validate|show|init`, `ironclad scan --policy`.

**Baseline v2**
- Entries carry rule id, file, line, severity, reason, author, creation
  time and **expiry**, instead of a bare fingerprint list.
- Expired entries stop suppressing, so a baseline is a runway rather than a
  permanent waiver.
- Refuses to baseline critical findings without `--reason` unless `--force`.
- CLI: `baseline create|list|diff|prune`.

**CLI**
- New commands: `version`, `doctor`, `init`, `config show|init`,
  `report convert`, `sbom --format spdx`, `license verify`,
  `server init`, `server worker`, `serve`.
- Published exit-code contract in `ironclad/core/exit_codes.py`.

**Scanning**
- Flow detectors: path traversal, SSRF, XSS, open redirect, template
  injection, XXE, unsafe YAML loader, weak TLS protocol, insecure random,
  disabled TLS verification — each with source → sanitizer → sink reasoning
  and an explicit sanitizer list.
- Import-alias resolution so `import xml.etree.ElementTree as ET` matches
  rules written against the canonical module path.
- Dependency coverage grows from 4 manifests to **8 ecosystems / 20
  parsers**: Python, npm, Go, Rust, Java (Maven + Gradle), PHP, Ruby, NuGet.
- Pluggable advisory sources: `bundled` (default, offline), `directory`
  (organization overlay), `remote` (opt-in, https-only, hard timeout).
- Rule packs grow from 40 to **66 rules** across 9 packs (new: java, go,
  php, ruby, python_extra).
- New detector `SECRETS-HARDCODED-CREDENTIAL` for literal credential
  assignments below the entropy bar, with redacted output.
- Malformed manifests produce `DEP-MANIFEST-*` findings instead of being
  silently skipped.

**SBOM and licensing**
- CycloneDX 1.5 with deterministic `serialNumber`, `bom-ref`s, a dependency
  graph and a structural validator.
- New SPDX 2.3 builder sharing one component model, plus its own validator.
- New `cyclonedx` report format carrying findings as CycloneDX
  vulnerabilities.
- SPDX license expression parsing (`OR` / `AND` / `WITH`); unknown licenses
  are never assumed permissive.

**Platform**
- Storage: numbered, checksummed SQL migrations for SQLite **and**
  PostgreSQL; 19 tables; schema never created by application code.
- Authentication: PBKDF2-HMAC-SHA256 (210k iterations), session and API
  tokens stored as digests, time-based self-clearing lockout.
- Authorization: 5 roles, 20 permissions, deny by default.
- Multi-tenancy: `org_query()` refuses a model with no `org_id`; foreign
  rows return 404, never 403.
- Jobs: durable queue with at-least-once delivery, retry with exponential
  backoff, stale-claim recovery.
- Events: 15 typed event contracts, validated at publish time.
- Audit: append-only with recursive credential redaction.
- Observability: JSON structured logs with request/correlation ids,
  Prometheus metrics at `/metrics`.

**API and dashboard**
- Full REST API (see `docs/API.md`) with Pydantic validation
  (`extra="forbid"`, bounded lengths, capped page sizes).
- Server-rendered dashboard under `/ui` — no JavaScript build step, every
  number read from the database.

**Integrations**
- Real HTTPS deliveries for webhook (HMAC-SHA256 signed), GitHub (SARIF
  upload + repository dispatch), GitLab, Slack/Teams, Jira.
- Bounded retries, hard timeout, 4xx not retried, SSRF guard rejecting
  private/link-local hosts.

**Deployment**
- Multi-stage Dockerfile, non-root, read-only scan root, healthcheck.
- `docker-compose.yml` with PostgreSQL + API + worker.
- Kubernetes manifests: namespace with restricted pod-security, ConfigMap,
  Secret template, API/worker Deployments with probes and limits, HPA,
  ingress, read-only PVC, migration job.

**Quality**
- `benchmarks/scale_benchmark.py` — measured 1k / 10k / 100k file tiers.
- `benchmarks/corpus_metrics.py` — precision/recall against the labelled
  corpus, with `--fail-below` for CI.
- `demo/run_demo.sh` — reproducible end-to-end story that asserts its own
  outcome via exit codes.
- Test suite grows from 61 to **452 tests**.

**Real-world accuracy measurement**
- Measured against five real OSS projects (flask, click, jinja, requests,
  httpx — 671 files) rather than only the synthetic corpus. Found and fixed
  five false-positive classes; total findings fell **182 → 73 (−60%)** and
  production-source findings **47 → 25 (−47%)** with no loss of detection.
  Documented with method, per-class fixes and limitations in
  `docs/REAL_WORLD_CORPUS.md`.

**Documentation**
- New: `API.md`, `DEPLOYMENT.md`, `SECURITY.md`, `THREAT_MODEL.md`,
  `DISASTER_RECOVERY.md`, `BENCHMARKS.md`, `CONTRIBUTING.md`,
  `PROGRESS.md`, `CORPUS_RESULTS.json`.

### Fixed

- **The "MVP acceptance gate" never ran.** `tests/mvp_acceptance.py` does
  not match pytest's default `test_*.py` pattern, so it was silently
  skipped while CI stayed green — and when run directly it failed, because
  it referenced `ironclad/scanners/dependencies.py`, which does not exist.
  Renamed to `test_mvp_acceptance.py` and parametrised per required file.
- **Baselines did not actually gate.** `--fail-on` and policy evaluation
  scored *all* findings, so an accepted (baselined) finding still failed
  CI. Gating now uses `ScanResult.gating_findings()`.
- **`postgresql+psycopg2://` URLs were rejected.** `detect_dialect()` used a
  string prefix check, so the driver-qualified form this project tells
  people to deploy with failed outright. Now parsed with SQLAlchemy's URL
  parser via `get_backend_name()`.
- **Absolute SQLite paths were broken.** `url.split("///")[-1].lstrip("/")`
  turned `/abs/path` into `abs/path`, created the directory in the wrong
  place, and failed with "unable to open database file".
- **The scanner reported its own rule packs.** Three false positives
  (`YAML-K8S-PRIVILEGED-CONTAINER`, `YAML-K8S-HOST-NETWORK`) matched
  pattern/message text inside `shell_and_config.yml`. Rule packs are now
  detected and their definition lines skipped; the key regex requires a
  real YAML key so prose like "hostNetwork:true removes network namespace
  isolation" is not mistaken for a mapping.
- **API-token scopes granted nothing.** Scopes used `scan:read` while
  permissions use `scan.read`, so the intersection was empty and every
  token got 403. Scopes are now normalised and validated at creation.
- **Dashboard pages returned JSON.** `/projects` and friends collided with
  API routes; the dashboard moved under `/ui`.
- **An always-failing job retried forever.** `run_pending` rolled back the
  claim, so `attempts` never advanced. The claim is now committed before
  the handler runs.
- **`ironclad server worker --max-jobs N` hung** on an idle queue; it now
  drains and exits.
- **A deleted scan target reported success** with zero findings.
  `perform_scan` re-validates the target at execution time.
- **`GET /audit` returned 500** — `AuditOut` rejected the `org_id` key.
- **`RequestContext.audit()` wrote to a `None` session**, crashing logout
  and any route that audited. `get_db` now binds one session per request to
  the context.
- Three broken rule patterns: `RUBY-SYSTEM-INTERPOLATION` could not match
  past the opening quote, `PHP-SUPERGLOBAL-IN-SQL` matched prepared
  statements, `JWT-ALGORITHM-NONE` required no quote before the colon.
- `ScanResult.from_dict` now rejects non-IronClad JSON instead of returning
  an empty report.

### Changed

- **Breaking:** CycloneDX components now include `ironclad:ecosystem` and
  `ironclad:manifest` properties before `ironclad:license-status`. Tests
  that indexed `properties[0]` must look the property up by name.
- **Breaking:** an unmapped license is reported as `LICENSE-REVIEW-REQUIRED`
  (weak copyleft) or `LICENSE-COPYLEFT-DEPENDENCY` (blocked) rather than a
  single copyleft rule. `LICENSE-COPYLEFT-DEPENDENCY` keeps its id so
  existing baselines and CI ignore-lists still match.
- Configuration precedence is now documented and implemented:
  CLI → `IRONCLAD_*` env → project `.ironclad.yml` →
  `~/.ironclad/config.yml` → defaults.
- Server dependencies moved to the `[server]` extra so an air-gapped,
  scan-only install does not need a web stack.
- `LGPL-2.1` / `LGPL-3.0` default to **blocked** (their linking obligations
  are what legal teams actually reject); move them to `licenses.warning` in
  `policy.yaml` if you have a standing approval.
- Advisory database grows from 22 to 44 packages with an explicit
  provenance note; license database from 31 to 61 mappings.

## [1.0.0] - previous

Offline scanner: Python AST + taint analysis, multi-language rule engine,
secrets detection, dependency CVE matching, IaC scanning, CycloneDX SBOM,
license compliance, five report formats, baselines, CI integrations,
Ed25519 offline licensing.
