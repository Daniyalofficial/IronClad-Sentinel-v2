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
* The bundled advisory database records its provenance in `_meta` — the
  upstream source and the exact commit it was generated from — and is
  regenerated by `scripts/build_advisory_db.sh`. It is a snapshot, not a
  live feed.
* `Dockerfile` is multi-stage, runs as a non-root user, and installs no
  packages beyond `curl` (for the healthcheck).
* Kubernetes pods run `readOnlyRootFilesystem` with all capabilities
  dropped.

## Self-scan

`ironclad scan ironclad` is run in CI and currently reports **0 findings,
grade A+** across 81 files / 14,619 lines. Two real precision bugs were
found and fixed by doing this — see `CHANGELOG.md`.

## Audit export and retention

Compliance evidence requires the *full* trail, not a 200-record page:

* `GET /audit/export` streams the whole trail as newline-delimited JSON or
  CSV, chunked (1000 records) with keyset pagination so a large trail does
  not get quadratically slower. Chronological oldest-first, tenant-scoped.
* CSV output defuses spreadsheet formula injection (`=`, `+`, `-`, `@`
  prefixed with a quote) — an auditor opening an export must not execute a
  formula that arrived via audit data.
* `GET /audit/retention?retention_days=N` previews the consequence without
  deleting anything.
* `POST /audit/retention/purge` requires the **admin** role and writes an
  `audit.purged` record **before** the delete, so the removal is permanently
  recorded.

Both are tenant-scoped: an export or purge can never reach another
organization's records.

## Password reset

Local authentication includes a self-service reset flow with no external
dependency required to install or test it.

| Property | How it is enforced |
|---|---|
| Token strength | `secrets.token_urlsafe(32)` — 256 bits of entropy |
| Storage | SHA-256 digest only; the raw token is never persisted, so a database leak yields no usable links |
| Single use | `used_at` is set in the **same transaction** as the password change; a used token is rejected. No code path clears it |
| Expiry | `IRONCLAD_PASSWORD_RESET_TTL_MINUTES`, default 30, hard-capped at 1440 |
| Rotation | Requesting a new link invalidates every outstanding token, so only the most recent is redeemable |
| Enumeration resistance | Identical status, body and message whether or not the address exists, and the miss path burns a dummy PBKDF2 hash so timing does not diverge |
| Rate limiting | 5 requests / 300s and 10 confirmations / 300s per client IP, both tunable |
| On success | Every existing session is revoked and the failed-login counter/lockout cleared |
| Audit | `password_reset_requested`, `_completed`, `_expired`, `_reuse_blocked`, `_inactive` |

**Redemption always returns HTTP 200 with `ok: false` on failure.** Returning
a 4xx would let a caller distinguish "no such token" from "expired" from
"already used" and probe which tokens exist.

A mail-transport failure does **not** change the response — otherwise a
delivery error would reveal that the address is real.

**Pluggable transport** (`IRONCLAD_MAIL_TRANSPORT`):

* `memory` (default) — records messages in-process. A fresh install never
  attempts a network connection, and the test suite asserts on recorded
  messages rather than on a mock that claims delivery happened.
* `smtp` — real delivery, configured entirely from `IRONCLAD_SMTP_*`. No
  credentials live in code or config files. Failures are returned, not
  raised.
* `null` — accepts and discards, for deployments that wire reset to an
  external identity flow. Explicit, unlike simply not configuring one.

An unrecognised value falls back to `memory` rather than raising, so a typo
cannot stop the API from starting.

## Brute-force protection

Account lockout alone is not brute-force protection: it is *per account*, so
an attacker guessing across an organization got `MAX_FAILED_LOGINS` attempts
against **every** address with nothing limiting the rate. Measured before
rate limiting existed: **25 credential guesses across 5 accounts in 1.9s
(~13/sec), no 429 ever returned**.

Three layers now apply:

| Layer | Default | Scope |
|---|---|---|
| Rate limit | 10 requests / 60s | per client IP, `/auth/login` |
| Volume limit | 5 requests / 300s | per account, `/auth/login` |
| Account lockout | 5 failures → 15 min | per account, self-clearing |

Plus 10 / 300s on API-token creation and 5 / 300s on password change.

After the change the same attack yields **10 guesses from one IP**, then
`429` with `Retry-After: 60` and `X-RateLimit-Limit` / `X-RateLimit-Remaining`
headers.

Every limit is operator-tunable (`IRONCLAD_RATELIMIT_*`, `LIMIT:WINDOW_SECONDS`,
`0` disables that check), because the right value depends on how many humans
and CI runners sit behind one IP.

**Multi-process caveat, stated plainly:** the default in-memory store is
per process, so with N uvicorn workers or N replicas the effective limit is
`limit × N`. Set `IRONCLAD_RATELIMIT_BACKEND=database` to share counters
across processes (costs a write per checked request), or terminate rate
limiting at your ingress/WAF.

`X-Forwarded-For` is trusted **only** when `IRONCLAD_TRUST_PROXY=1`; otherwise
an attacker could set the header and get a fresh budget per request.

A limiter whose store errors **fails open** and increments a counter — a rate
limiter that takes the API down when its own backend hiccups is worse than no
rate limiter. Volume rejections are observable via
`ironclad_rate_limited_total`, not the tenant-scoped audit log, because they
happen before authentication and have no tenant to attribute to.

## SSRF guard: what it covers and what it does not

Webhook and integration URLs are validated against a non-public-address
denylist. The following are blocked (each has a regression test):

* `169.254.169.254` and the cloud metadata hostnames
  (`metadata.google.internal`, `metadata`, `metadata.goog`)
* RFC 1918 private ranges, loopback (including `[::1]`,
  `[::ffff:127.0.0.1]`, `127.1`, and the hex/octal/decimal encodings of
  `127.0.0.1`)
* link-local, broadcast, `0.0.0.0/8`, RFC 6890, RFC 2544 benchmarking
* **RFC 6598 CGNAT (`100.64.0.0/10`)** — this was a genuine hole: Python's
  `ipaddress` module returns `is_private=False` for that range, so it passed
  the original check
* `localhost` and any `*.localhost` name, regardless of what DNS says
* userinfo/fragment/query tricks such as `http://evil.com@169.254.169.254/`

### Outbound egress allowlist

The SSRF guard is deny-by-*range*: it stops reach into internal addresses,
but it cannot constrain egress to a known set of endpoints. An operator who
wants that sets:

```bash
export IRONCLAD_EGRESS_ALLOWLIST=hooks.slack.com,api.github.com,*.webhooks.internal.example.com
```

Enforced inside `resolve_target()` **before DNS**, so an unlisted host is
never resolved and no socket is ever opened to it. Because `resolve_target()`
is called for the initial destination *and* every redirect hop, the allowlist
applies consistently to both. An unlisted redirect destination is refused.

**Exact matching semantics** — deliberately narrow:

| Entry | Matches | Does NOT match |
|---|---|---|
| `github.com` | `github.com`, `GITHUB.COM` (case-insensitive, trimmed) | `api.github.com`, `evilgithub.com`, `github.com.evil.net` |
| `*.github.com` | `api.github.com`, `a.b.github.com` | `github.com` (apex excluded), `evilgithub.com`, `github.com.evil.net` |
| `93.184.216.34` | that literal address only | any other address |

**There is no implicit suffix matching anywhere.** A bare suffix match is
precisely how `evilgithub.com` would slip past `github.com`; the wildcard
must be an explicit leading `*.` and is anchored to a label boundary, so the
character before the suffix must be a dot.

**Behaviour when unset:** unchanged. `IRONCLAD_EGRESS_ALLOWLIST` unset,
empty, or blank is treated as "no allowlist configured" — *not* as "deny
everything" — so a stray empty environment variable cannot silently break
every integration. The existing SSRF controls remain the primary control.

**The allowlist does not weaken or bypass anything:**

* Private/IP-literal destinations remain governed by the SSRF rules. Putting
  `169.254.169.254` on the allowlist does **not** make it reachable.
* Non-http(s) schemes are still refused even for an allowlisted host.
* DNS-rebinding protection is unaffected: an allowlisted host that rebinds to
  a private address is still refused by IP validation.
* Redirect validation, IP pinning, retry behaviour and HMAC signing are
  unchanged. A blocked destination is not retried.

### Per-organization egress policy

The process-global allowlist forces every organization in a multi-tenant
deployment onto one egress set, which contradicts the tenancy model enforced
everywhere else. Organizations can now set their own allowlist, stored in the
existing `Organization.settings` column — no parallel configuration system.

```
GET /org/egress-policy
PUT /org/egress-policy   {"entries": ["hooks.slack.com", "*.webhooks.internal.example.com"]}
```

Reading requires `organization.read`; updating requires
`organization.manage`. An empty list removes the policy. Every entry is
validated up front and **all** problems are returned at once. The change is
audited (`org.egress_policy_updated`, recording previous and new entries),
because it governs outbound network reach.

**Precedence is intersection — an organization can only narrow, never widen:**

| global | org | effective |
|---|---|---|
| unset | unset | no allowlist (SSRF rules only) |
| set | unset | global |
| unset | set | org |
| set | set | **intersection** |

Intersection is the safe model: a tenant cannot grant itself egress the
deployment operator did not permit, and an operator tightening the global
list immediately tightens every organization. Widening semantics would let a
tenant escalate its own network reach.

Matching uses the same secure semantics as the global allowlist: exact,
case-insensitive, explicit leading `*.` anchored to a label boundary, no
implicit suffix matching. Entry validation rejects empty entries, bare `*`,
`*.`, embedded wildcards, single-label names, malformed labels, malformed IP
literals, over-long names and duplicates.

Enforcement is inside `resolve_target()` **before DNS**, alongside the global
allowlist, so it covers the initial destination and every redirect hop. A
rejected host is never resolved and no socket is opened.

**Tenant isolation:** an organization's allowlist is read only through its
own `org_id` from the request principal, so org A's entries can never
authorize org B. A broken provider fails **closed** to "no organization
allowlist", which with a global allowlist set still restricts and never
widens egress.

Being allowlisted does not exempt a host from the SSRF rules:
`169.254.169.254` on an organization allowlist is still refused, and DNS
rebinding is still caught by IP validation.

### DNS rebinding is closed by IP pinning

The original guard resolved the hostname at *validation* time, and
`urllib.request.urlopen` then resolved it **again** when opening the socket.
An attacker controlling authoritative DNS could answer with a public address
for the validation lookup and a private one for the connection lookup. This
was reproduced, not theorised: with a rebinding resolver serving
`93.184.216.34` for the validation lookups and `127.0.0.1` afterwards, the
internal service **received the request**.

The fix resolves DNS **exactly once** in `resolve_target()`:

1. Resolve the hostname once via `getaddrinfo`.
2. Validate **every** returned address — not just the first, so a resolver
   cannot put a public address first and a private one second.
3. Pin that address. The socket connects to that exact IP via connection
   classes that override `connect()`.
4. The original hostname is preserved for the `Host` header and TLS SNI, so
   pinning does not weaken certificate validation.
5. Automatic redirects are disabled. Each redirect destination is resolved
   and validated again before any connection is made to it, bounded at 5
   hops.

Because validation and connection use the same resolution, they cannot
disagree. Re-running the original attack now yields
`blocked: refusing rebind.attacker.example: resolved to non-public address
127.0.0.1` and the internal service receives nothing.

Note that `IRONCLAD_ALLOW_PRIVATE_WEBHOOKS=1` is an operator override for
local and test delivery, and it applies to every hop including redirects.
That is intentional and pinned by a test so it cannot change silently.

## Known limitations

Stated plainly, because a scanner that overstates its guarantees is worse
than one that under-delivers:

1. **Intra-procedural taint analysis.** Flows that cross a function
   boundary are missed. This is a deliberate precision/recall trade.
2. **Python-only deep analysis.** Other languages are covered by the regex
   rule engine, which cannot model data flow.
3. **The bundled advisory database is a snapshot** (13,095 packages across
   8 ecosystems, generated from `github/advisory-database`). It goes stale
   between releases — regenerate it, or point `advisory_path` at your own
   overlay or an internal OSV mirror.
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
