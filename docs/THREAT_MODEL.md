# Threat model

Scope: IronClad Sentinel as deployed by an enterprise — CLI, API, worker,
dashboard, database. Out of scope: the host OS, the container runtime, and
the networks you put in front of it.

## Assets

| Asset | Why it matters |
|---|---|
| Scanned source code | The reason this product is self-hosted in the first place |
| Findings database | A map of an organization's weaknesses |
| Credentials (password hashes, session/API token digests) | Lateral movement into the platform |
| Integration secrets | Webhook signing keys, GitHub/GitLab/Jira tokens |
| Audit log | The record of who accepted which risk, and when |
| License signing key (vendor side) | Ability to mint licenses |

## Actors

1. **Malicious repository author** — controls file contents, names,
   directory structure and manifest contents of a scanned tree. May be an
   external contributor to a repository the platform scans.
2. **Authenticated low-privilege user** — a `viewer` or `developer` trying
   to exceed their role, or to read another organization's data.
3. **Attacker on the network path** — between a client and the API, or
   between the worker and an integration endpoint.
4. **Malicious or compromised advisory feed / integration endpoint** — a
   server the platform is told to trust.
5. **Platform operator** — trusted with infrastructure, but not with
   reading other tenants' findings.

## Entry points and controls

### E1. The scanned repository

| Threat | Control | Tested by |
|---|---|---|
| Code execution during a scan | The scanning path contains no `eval`, `exec` or `subprocess`; files are parsed, never imported | `tests/test_mvp_acceptance.py` (no placeholder/eval markers), self-scan |
| Resource exhaustion via a huge file | `max_file_size_kb` (default 2 MiB) — file skipped and counted | `tests/test_v2_hardening.py` |
| Parser crash aborting a scan | Per-file exception handling; a `SyntaxError` file is skipped | `tests/test_python_flows.py::test_syntax_error_file_is_skipped_not_crashed` |
| Regex denial of service in a rule | Rule patterns are reviewed and bounded; lines > 2,000 chars are skipped in the secrets pass | `tests/test_secrets.py` |
| Manifest poisoning | Malformed manifests produce `DEP-MANIFEST-*` findings rather than being silently ignored; parser exceptions are contained to one manifest | `tests/test_dependency_ecosystems.py` |
| Secret exfiltration via a finding | Secret values are redacted in snippets; findings carry a length, not the value | `tests/test_secrets.py::test_credential_finding_never_echoes_the_secret` |
| Symlink escape | Scan targets are resolved with `realpath` and confined to the scan root | `tests/test_api.py::test_scan_rejects_a_target_outside_the_scan_root` |

**Residual risk:** a rule with a catastrophic-backtracking regex could still
stall a scan. Mitigation: `--fail-on` runs are time-boxed in CI; the
`rules/` packs are reviewed on change.

### E2. `POST /scan` target path

| Threat | Control |
|---|---|
| Arbitrary file read | Target resolved inside `IRONCLAD_SCAN_ROOT`; traversal and absolute escapes rejected with `400`; re-validated at execution time because a queued job can outlive the directory |
| NUL-byte injection | Rejected by the request schema |
| Unbounded work | Scans are queued, not run inline; `wait: true` is opt-in for small trees |

### E3. HTTP request bodies

| Threat | Control |
|---|---|
| Mass assignment | Pydantic models with `extra="forbid"` |
| Oversized payloads | Bounded string lengths; `limit ≤ 200` on every list endpoint |
| Type confusion | Constrained ints, enumerated choices, `EmailStr` |
| Injection into SQL | SQLAlchemy bound parameters throughout; no string-built SQL anywhere |

### E4. Authentication

| Threat | Control | Tested by |
|---|---|---|
| Credential stuffing | 5 failures → 15-minute time-based lockout (self-clearing, so it cannot be abused to disable an account) | `tests/test_api.py` |
| Account enumeration | Identical `401` for unknown account and wrong password | `test_login_does_not_leak_whether_an_account_exists` |
| Offline cracking after a DB leak | PBKDF2-HMAC-SHA256, 210k iterations, per-user salt, cost stored in the hash | `tests/test_security.py` |
| Session theft via DB leak | Sessions and API tokens stored as SHA-256 digests only | `test_api_token_round_trip` |
| Replay after logout | Logout revokes immediately; password change revokes all other sessions | `test_logout_revokes_the_session`, `test_password_change_invalidates_other_sessions` |
| Timing attack | `hmac.compare_digest` for every secret comparison | — |

### E5. Authorization

| Threat | Control |
|---|---|
| Vertical escalation | 20 explicit permissions, deny by default; per-route declaration |
| Granting `owner` | Only an owner can grant owner |
| Self-lockout | An admin cannot demote themselves below admin |
| Token privilege escalation | API-token scopes are intersected with the owner's permissions — they can narrow, never widen |

### E6. Multi-tenancy

| Threat | Control | Tested by |
|---|---|---|
| IDOR across tenants | Every query starts from `org_query()`; a foreign row returns `None` → `404`, never `403` (no existence oracle) | 6 cross-tenant tests in `tests/test_api.py` |
| Forgetting the filter on a new table | `org_query()` raises if the model has no `org_id` | `test_org_query_refuses_an_unscoped_model` |
| Bulk operation on a mixed id list | `assert_same_org()` / `scoped_ids()` | `test_assert_same_org_detects_a_mix` |

### E7. Outbound integrations

| Threat | Control |
|---|---|
| SSRF into the internal network | Webhook URLs must be https; private/link-local/reserved hosts rejected unless `IRONCLAD_ALLOW_PRIVATE_WEBHOOKS=1` |
| Forged payloads at the receiver | HMAC-SHA256 signature in `X-IronClad-Signature` |
| Slow/dead endpoint stalling a worker | 10 s timeout, ≤3 attempts, 4xx not retried |
| Secret disclosure | Integration secrets are never returned; audit metadata redacted recursively |

### E8. Advisory feed

| Threat | Control |
|---|---|
| Silent egress of repository metadata | `remote` is opt-in; the default `bundled` source never opens a socket |
| Cleartext interception | https enforced; plain http rejected at construction |
| Feed outage blocking CI | Failure degrades to the bundled database and records a warning |
| Poisoned advisory | Records only affect severity/remediation text of a finding; they cannot execute anything |

### E9. Web dashboard

| Threat | Control |
|---|---|
| XSS | Server-side Jinja2 autoescaping; CSP with `script-src 'self'` |
| Clickjacking | `X-Frame-Options: DENY` + `frame-ancestors 'none'` |
| MIME sniffing | `X-Content-Type-Options: nosniff` |
| CSRF | `SameSite=Lax` cookie; mutating actions require a bearer token against the JSON API |
| Session theft via XSS | `HttpOnly` cookie; `Secure` available via `IRONCLAD_COOKIE_SECURE=1` |

### E10. Audit log

| Threat | Control |
|---|---|
| Tampering | Append-only: no update or delete code path exists anywhere in the product |
| Sensitive data at rest | Credential-shaped keys redacted recursively before insert |
| Denial (deleting evidence) | No endpoint or CLI command deletes audit rows |

## Deployment hardening

* Container runs as a non-root user; Kubernetes pods add
  `readOnlyRootFilesystem`, drop all capabilities, and use
  `seccompProfile: RuntimeDefault`.
* Repositories are mounted **read-only**.
* PostgreSQL is not published to the host in compose.
* `/docs` is off unless explicitly enabled.
* Error responses never include stack traces.

## Explicitly out of scope / not defended

1. **A compromised host or container runtime.** If the attacker has the
   process, they have the database credentials.
2. **A malicious platform operator with database access.** They can read
   findings. The audit log is append-only at the application layer, not at
   the database layer; use database-level immutability (WORM storage,
   logical replication to a separate account) if that is a requirement.
3. **Availability attacks on the API itself.** Rate limiting belongs in
   your ingress/WAF; the app implements login lockout but no general
   rate limiting.
4. **Client-side compromise.** A stolen session token is valid until
   expiry or revocation; there is no device binding.
5. **Currency of the bundled advisory data.** It is a snapshot of
   `github/advisory-database` taken at release time (the exact upstream
   commit is recorded in `_meta.source`). Advisories published after that
   snapshot are unknown to an unrefreshed install, so absence of a finding
   is not evidence of absence of a vulnerability.

## Detection-quality honesty

The scanner is intra-procedural for taint analysis, deep only for Python,
and regex-based for other languages. `docs/BENCHMARKS.md` publishes measured
precision/recall **and states that the corpus is small and synthetic** —
a 1.00 score there is not a real-world false-positive rate.
