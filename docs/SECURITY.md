# Security

This document describes how IronClad Sentinel itself is secured, how to
report a vulnerability, and what the product does **not** protect against.

## Reporting a vulnerability

Email `security@ironclad.local` (replace with the maintainer address for
your fork) with:

* what you found and the version affected
* a minimal reproduction
* whether it is already public

Please do not open a public issue for an unpatched security bug. We aim to
acknowledge within 3 working days and to ship a fix or a documented
mitigation within 30 days for High/Critical findings.

## Threat model summary

Full version: [THREAT_MODEL.md](THREAT_MODEL.md).

The single most important property: **the scanner parses code, it never
executes it.** There is no `eval`, no `exec`, no `subprocess` anywhere in
the scanning path. A malicious repository cannot achieve code execution
through a scan.

## Trust boundaries

| Boundary | Attacker controls | Defence |
|---|---|---|
| Scanned repository | File contents, filenames, directory structure, manifest contents | Static parsing only; per-file size cap; parser exceptions contained to one file; binary extensions skipped |
| `POST /scan` target path | A path string | Confined to `IRONCLAD_SCAN_ROOT` via `realpath`; traversal and symlink escape rejected (`400`); re-validated at execution time |
| HTTP request body | JSON | Pydantic models with `extra="forbid"`, bounded lengths, constrained ints, enumerated choices |
| Webhook URL | An administrator-supplied URL | https required; private/link-local hosts rejected unless explicitly allowed; bounded retries; hard timeout |
| Advisory feed | Advisory records | `remote` is opt-in; https only; 10 s timeout; failure degrades to the bundled database with a recorded warning |
| License file | A signed JSON document | Ed25519 signature verified against a bundled public key; expiry enforced locally |

## Authentication and sessions

* **Passwords** — PBKDF2-HMAC-SHA256, 210,000 iterations, 16-byte random
  salt. Iteration count and salt are stored *inside* the hash string, so
  raising the cost later does not invalidate credentials
  (`needs_rehash()` flags weaker hashes for upgrade on next login).
  PBKDF2 rather than argon2/bcrypt is a deliberate trade: it is in every
  Python 3.9+ install, so an air-gapped deployment needs no compiled
  dependency to store passwords safely.
* **Password policy** — ≥12 characters and ≥3 character classes, enforced
  on user creation and password change.
* **Raw passwords are never stored, logged or returned.** Credential-shaped
  keys are redacted from logs and from audit metadata recursively.
* **Sessions** — 12-hour bearer tokens stored as SHA-256 digests. A
  database leak does not yield usable credentials. Logout revokes
  immediately; changing a password revokes every other session.
* **API tokens** — `ics_…`, stored as digests, plaintext shown exactly once
  at creation. Scopes are permissions and can only narrow the owner's
  grants.
* **Lockout** — 5 consecutive failures locks an account for 15 minutes.
  Time-based and self-clearing, so it cannot be weaponised to permanently
  disable an account.
* **Enumeration** — login returns an identical error whether the account
  exists or not (asserted in tests).
* **Comparison** — every secret comparison uses `hmac.compare_digest`.

## Authorization

Five roles — `owner > admin > security > developer > viewer` — over 20
explicit permissions. Deny by default: an unknown role or an unknown
permission grants nothing.

Two escalation guards worth calling out:

* Only an **owner** can grant `owner`.
* An admin cannot demote themselves below `admin` (that would lock the
  organization out of administration).

Every route declares the permission it needs; nothing checks "is this user
an admin?" inline.

## Multi-tenancy

Every tenant-owned table has `org_id`. `ironclad.platform.tenancy` is the
only supported way to start a query:

* `org_query()` **refuses** a model with no `org_id` column, so a new
  table cannot be queried unscoped by accident.
* A row belonging to another organization returns `None`, which the API
  turns into a **404** — never a 403, so object ids cannot be probed across
  tenants.

Cross-tenant isolation is asserted for projects, findings, scans, policies,
integrations and audit records in `tests/test_api.py`.

## Input validation

* Every request body goes through a Pydantic model with `extra="forbid"`,
  so unknown fields are rejected rather than ignored.
* Page sizes are capped (`limit ≤ 200`); asking for more is a `422`.
* Snippets are truncated at 2,000 characters before storage.
* Error responses never contain stack traces — those go to the structured
  log, and the client gets a bare `{"detail": "internal error"}`.

## Secrets handling

* Findings never contain the secret itself. `SECRETS-HARDCODED-CREDENTIAL`
  redacts the value in its snippet (`PASSWORD = "su************"`); this is
  asserted in `tests/test_secrets.py`.
* Integration secrets are stored for signing use and are never returned by
  any endpoint — the API reports only `has_secret: true`.
* Audit metadata is scrubbed recursively: any key matching
  `password|secret|token|api_key|authorization|credential|private_key`
  becomes `[redacted]`, including inside nested dictionaries.
* The vendor private signing key is git-ignored and never bundled.

## Web UI hardening

Every response carries:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'self'; script-src 'self';
  style-src 'self' 'unsafe-inline'; img-src 'self' data:;
  object-src 'none'; frame-ancestors 'none'; base-uri 'self'
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

The dashboard is server-rendered Jinja2 with autoescaping, so there is no
client-side state and no `dangerouslySetInnerHTML`-class sink. The session
cookie is `HttpOnly` and `SameSite=Lax`; set `IRONCLAD_COOKIE_SECURE=1`
behind TLS.

CORS uses an explicit allowlist from `IRONCLAD_CORS_ORIGINS`. An unlisted
origin receives no CORS headers at all — the origin is never reflected.

## Resource exhaustion

| Vector | Control |
|---|---|
| Huge file | `max_file_size_kb` (default 2 MiB) — skipped and counted |
| Huge line | Lines > 2,000 chars skipped in the secrets pass |
| Malformed manifest | Reported as `DEP-MANIFEST-*`; parser exceptions contained to one file |
| Runaway job | `max_attempts` with exponential backoff, then `failed` |
| Dead worker | Stale jobs are reclaimable after a timeout |
| Blocking scan | Scans are queued; `POST /scan` returns `202` |
| Slow webhook | 10 s timeout, ≤3 attempts, 4xx not retried |
| Unbounded query | Hard `limit` cap on every list endpoint |

## Supply chain

* Scanning is offline by default. The only outbound code path is an
  explicitly configured integration or a `remote` advisory feed.
* The bundled advisory database documents itself as a curated subset with
  its provenance, and states that it is not a full feed.
* `Dockerfile` is multi-stage, runs as a non-root user, and installs no
  packages beyond `curl` (for the healthcheck).
* Kubernetes pods run `readOnlyRootFilesystem` with all capabilities
  dropped.

## Self-scan

`ironclad scan ironclad` is run in CI and currently reports **0 findings,
grade A+** across 81 files / 14,619 lines. Two real precision bugs were
found and fixed by doing this — see `CHANGELOG.md`.

## Known limitations

Stated plainly, because a scanner that overstates its guarantees is worse
than one that under-delivers:

1. **Intra-procedural taint analysis.** Flows that cross a function
   boundary are missed. This is a deliberate precision/recall trade.
2. **Python-only deep analysis.** Other languages are covered by the regex
   rule engine, which cannot model data flow.
3. **The bundled advisory database is small** (44 packages across 8
   ecosystems). It is not a substitute for a maintained feed — point
   `advisory_path` at your own overlay or an internal OSV mirror.
4. **License data is a lookup table** (61 packages). Unmapped packages are
   reported as `unknown` and never assumed permissive.
5. **No SCA reachability analysis.** A vulnerable dependency is reported
   whether or not the vulnerable code path is reachable.
6. **PBKDF2 is not argon2id.** Adequate and dependency-free, but if you can
   install `argon2-cffi`, that is stronger.
7. **Regex rule packs have inherent false positives.** Every rule in the
   extended packs is required to have a must-not-fire case; measured
   corpus precision is 1.00 on the shipped corpus, which is small and
   synthetic. Do not read that as a real-world false-positive rate.

## Security review checklist

Covered by tests, not by intention:

* [x] No command injection — no `subprocess`/`shell=True` in the scan path
* [x] No path traversal — scan root confinement, asserted for `..` and absolute paths
* [x] No SQL injection — SQLAlchemy bound parameters throughout; no string-built SQL
* [x] No XSS — server-side autoescaping plus CSP
* [x] CSRF — `SameSite=Lax` cookie; mutating dashboard actions post to the JSON API, which requires a bearer token
* [x] Authentication bypass — invalid/expired/revoked tokens rejected (tested)
* [x] Authorization bypass — per-route permissions, RBAC tested per role
* [x] IDOR / cross-tenant access — 404s tested for six resource types
* [x] Unsafe deserialization — `yaml.safe_load` only; `pickle` never used on input
* [x] Secret leakage — redaction asserted for findings, logs and audit
* [x] Resource exhaustion — caps and timeouts above
* [x] Zip bombs — not applicable; the product does not unpack archives
