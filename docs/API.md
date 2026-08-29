# IronClad Sentinel — API reference

Base URL: `/` (the JSON API owns the spec paths; the dashboard lives under `/ui`).

Authentication: `Authorization: Bearer <token>`, where the token is either a
**session token** from `POST /auth/login` or an **API token** (`ics_…`) from
`POST /auth/tokens`. Every response carries `X-Request-Id`; send your own to
have it echoed and threaded through the logs.

The interactive docs (`/docs`) and the OpenAPI schema (`/openapi.json`) are
**disabled by default**, because together they enumerate the whole API
surface. Opt in with `IRONCLAD_ENABLE_DOCS=1` for local development and leave
it unset in production.

## Conventions

* **Errors** are `{"detail": ...}`. `detail` is a list of strings for
  policy/schema validation failures so a caller can fix everything at once.
* **Pagination** is `?limit=&offset=`. `limit` is capped at 200; asking for
  more is a `422`, not a silent truncation.
* **Tenancy** is enforced server-side from the authenticated principal. A
  resource belonging to another organization returns **404**, never 403, so
  object ids cannot be probed across tenants.
* **Authorization** failures return `403` with the missing permission named
  in `detail`.

| Code | Meaning |
|---|---|
| 200 | OK |
| 201 | Created |
| 202 | Scan accepted and queued |
| 204 | No content |
| 400 | Bad request (e.g. scan target outside the scan root) |
| 401 | Missing/invalid/expired credentials |
| 403 | Authenticated but not permitted |
| 404 | Not found **or** owned by another organization |
| 409 | Conflict (duplicate slug, cancelling a finished scan) |
| 422 | Validation failure |
| 429 | Rate limit or account lockout. Rate-limit responses carry `Retry-After`, `X-RateLimit-Limit` and `X-RateLimit-Remaining` |
| 500 | Internal error (detail is never leaked; it goes to the log) |

## Health and operations

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/health` | none | Liveness + dependency checks |
| GET | `/ready` | none | Readiness; 503 when the database is unreachable |
| GET | `/version` | none | Product/version/python |
| GET | `/metrics` | none | Prometheus text exposition |

`/metrics` includes `ironclad_scans_total`, `ironclad_scan_failures_total`,
`ironclad_scan_duration_seconds` (histogram), `ironclad_files_scanned_total`,
`ironclad_findings_total`, `ironclad_worker_job_duration_seconds`,
`ironclad_api_request_duration_seconds`, `ironclad_api_requests_total` and
`ironclad_queue_depth{status="queued|running|succeeded|failed|cancelled"}`.

## Authentication

| Method | Path | Notes |
|---|---|---|
| POST | `/auth/login` | `{email, password}` → `{access_token, expires_in, user}` |
| POST | `/auth/logout` | Revokes the presented session (204) |
| GET | `/auth/me` | Current user |
| GET | `/auth/permissions` | Role → permission matrix |
| POST | `/auth/password` | Change password; revokes all other sessions |
| POST | `/auth/password-reset/request` | **Unauthenticated.** Request a reset link. Rate limited 5/300s per IP. Response is identical whether or not the account exists. |
| POST | `/auth/password-reset/confirm` | **Unauthenticated.** Redeem a token. Rate limited 10/300s per IP. Always returns 200; `ok` carries the result so failure modes stay indistinguishable. |
| POST | `/auth/tokens` | Create an API token — plaintext returned **once** |
| GET | `/auth/tokens` | List tokens (prefix only, never plaintext) |
| DELETE | `/auth/tokens/{id}` | Revoke |

Login returns the same `401 invalid email or password` whether the account
exists or not. Five consecutive failures lock the account for 15 minutes
(`429`); the lockout is time-based and self-clearing so it cannot be abused
to permanently disable an account.

Token scopes **are** permissions. `scan:read` and `scan.read` are both
accepted and normalised; an unknown scope is a `422`. A token can narrow its
owner's permissions but never widen them.

```bash
TOKEN=$(curl -s -X POST localhost:8000/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"owner@acme-corp.com","password":"…"}' | jq -r .access_token)
curl -s localhost:8000/projects -H "authorization: Bearer $TOKEN"
```

## Organization and users

| Method | Path | Permission |
|---|---|---|
| GET | `/org` | `organization.read` |
| GET | `/org/egress-policy` | `organization.read` — the org's outbound egress allowlist, plus the effective list after intersecting with the global allowlist |
| PUT | `/org/egress-policy` | `organization.manage` — replace the allowlist; an empty list removes it. All validation problems returned at once (422). Audited. |
| GET | `/users` | `user.read` |
| POST | `/users` | `user.manage` |
| PATCH | `/users/{id}/role` | `user.manage` |

Only an **owner** can grant `owner`. An admin cannot demote themselves below
`admin` (that would lock the organization out of administration).

## Projects

| Method | Path | Permission |
|---|---|---|
| GET | `/projects` | `project.read` |
| POST | `/projects` | `project.manage` |
| GET | `/projects/{id}` | `project.read` |
| DELETE | `/projects/{id}` | `project.manage` — archives, never deletes history |

## Scans

| Method | Path | Permission |
|---|---|---|
| POST | `/scan` | `scan.create` → **202** |
| GET | `/scan/{id}` | `scan.read` |
| GET | `/scans` | `scan.read` |
| GET | `/scan/{id}/findings` | `finding.read` |
| GET | `/scan/{id}/result` | `scan.read` — scan + recomputed policy decision |
| POST | `/scan/{id}/cancel` | `scan.cancel` |
| GET | `/jobs` | `scan.read` |
| GET | `/dashboard` | `project.read` |

`POST /scan` body:

```json
{
  "project_id": 1,
  "target": "payments-api",
  "revision": "a1b2c3d",
  "policy_id": 3,
  "policy": {"version": 1, "fail_on": "high"},
  "idempotency_key": "ci-run-4242",
  "wait": false
}
```

* `target` is resolved **inside `IRONCLAD_SCAN_ROOT`**. An absolute path
  outside it, or `..` traversal that escapes it, is `400`. This is the
  guard that stops the endpoint from becoming an arbitrary file reader.
* `policy` (inline) or `policy_id` (stored); an invalid policy is `422`
  with the full problem list.
* `idempotency_key` replays: the same key returns the same scan and queues
  no new work.
* `wait: true` runs the scan inline before responding — intended for small
  repositories and CI, not for large trees.

## Findings

| Method | Path | Permission |
|---|---|---|
| GET | `/findings` | `finding.read` — filters: `severity`, `status`, `rule_id`, `project_id` |
| GET | `/findings/{id}` | `finding.read` |
| GET | `/findings/{id}/events` | `finding.read` |
| PATCH | `/findings/{id}` | `finding.manage` |

`PATCH` body: `{"status": "open|resolved|suppressed", "reason": "..."}`.
Suppressing **requires** a non-blank reason (`422` otherwise); every
transition is written to `finding_events` and to the audit log.

## SBOM and licenses

| Method | Path | Permission |
|---|---|---|
| GET | `/sbom?project_id=` | `sbom.read` |
| GET | `/sbom/document?project_id=` | `sbom.read` — raw CycloneDX 1.5 |
| GET | `/sbom/components?project_id=` | `sbom.read` — filter `license_class` |
| GET | `/licenses?project_id=` | `license.read` — counts + blocked/unknown lists |

## Policies and baselines

| Method | Path | Permission |
|---|---|---|
| GET | `/policies` | `policy.read` |
| POST | `/policies` | `policy.manage` — create or bump version |
| POST | `/policies/validate` | `policy.read` |
| DELETE | `/policies/{id}` | `policy.manage` |
| GET | `/baselines?project_id=` | `project.read` |

## Integrations

| Method | Path | Permission |
|---|---|---|
| GET | `/integrations` | `integration.read` |
| POST | `/integrations` | `integration.manage` |
| DELETE | `/integrations/{id}` | `integration.manage` |
| POST | `/integrations/{id}/test` | `integration.manage` — real delivery |

Kinds: `webhook`, `github`, `gitlab`, `slack`, `teams`, `jira`. Config is
validated at creation. Secrets are stored but **never returned**; the list
only reports `has_secret: true`. Webhook payloads are HMAC-SHA256 signed
(`X-IronClad-Signature: sha256=<hex>`) and a webhook URL pointing at a
private/link-local address is rejected unless
`IRONCLAD_ALLOW_PRIVATE_WEBHOOKS=1`.

## Audit

| Method | Path | Permission |
|---|---|---|
| GET | `/audit` | `audit.read` — filter `action`, paginated (max 200) |
| GET | `/audit/export` | `audit.read` — **full trail** as newline-delimited JSON (`?format=jsonl`, default) or CSV (`?format=csv`); filters `action`, `actor`, `since`, `until` (`YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS`). Streams in chunks, chronological oldest-first, returns `X-Audit-Records`. |
| GET | `/audit/retention` | `audit.read` — preview what a retention window would remove. Deletes nothing. |
| POST | `/audit/retention/purge` | `audit.read` **+ admin role** — delete records older than `retention_days`. Irreversible; the purge is itself audited *before* the delete runs. |

Records are append-only: no endpoint updates or deletes them, and
credential-shaped metadata keys are redacted before they are stored.

The one exception is `POST /audit/retention/purge`, which exists because
compliance frameworks require a *defined* retention period. It requires the
admin role, and it writes an `audit.purged` record **before** deleting, so
the fact that audit history was removed — how much, and against what cutoff —
is itself permanent. Deleting the record of a deletion would defeat the
purpose of an audit log.

The paged `GET /audit` caps at 200 records, which is not usable as compliance
evidence; use `/audit/export` for that. CSV exports prefix values beginning
with `=`, `+`, `-` or `@` with a single quote to prevent spreadsheet formula
injection, so an auditor opening an export cannot execute a formula that
arrived via audit data.

## Dashboard

Server-rendered HTML under `/ui`: `/ui/` (overview), `/ui/projects`,
`/ui/projects/{id}`, `/ui/findings`, `/ui/findings/{id}`, `/ui/policies`,
`/ui/integrations`, `/ui/audit`, `/ui/settings`, `/ui/login`. Session is an
`HttpOnly`, `SameSite=Lax` cookie. Every number on a page is read from the
database at render time.
