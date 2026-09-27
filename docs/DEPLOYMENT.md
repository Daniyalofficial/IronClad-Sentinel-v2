# Deployment

Three supported topologies. Pick the smallest one that meets your needs —
every one of them runs the same image and the same migrations.

| Topology | When to use | Storage |
|---|---|---|
| **CLI only** | Laptops, pre-commit hooks, CI jobs | none |
| **Single host** | One team, a few dozen repositories | SQLite or Postgres |
| **Kubernetes** | Multiple teams, parallel scans, HA | Postgres |

---

## 1. CLI only (no server)

```bash
pip install ironclad-sentinel
ironclad doctor
ironclad scan . --policy policy.yaml --format sarif --output-dir reports
```

No database, no network, nothing listening. This is the air-gapped path and
it needs only the core dependencies.

---

## 2. Single host with Docker Compose

```bash
export POSTGRES_PASSWORD="$(openssl rand -hex 24)"
export IRONCLAD_SIGNING_KEY="$(openssl rand -hex 32)"   # >= 32 characters
export IRONCLAD_SCAN_HOST_DIR=/srv/repos                 # repositories to scan
docker compose up -d --build
docker compose run --rm api migrate
# /ready returns 503 until the first organization is created below.
```

`docker-compose.yml` runs three services:

* `db` — PostgreSQL 16, **not** published to the host
* `api` — API + dashboard on **127.0.0.1:8000 by default** (plaintext HTTP;
  terminate TLS in your reverse proxy before making it externally available)
* `worker` — scan worker (separate so a CPU-bound scan cannot starve the API)

Override `IRONCLAD_HOST_BIND` only when you intend to publish the HTTP port;
never expose plaintext login or OIDC callback traffic to the internet.
Forwarded headers are trusted only from loopback by default. If your TLS
proxy connects from a different IP, explicitly set `IRONCLAD_FORWARDED_ALLOW_IPS`
to *that proxy's* IP and prevent direct untrusted access to the API. Set
`IRONCLAD_COOKIE_SECURE=1` behind HTTPS and, only when the proxy is trusted,
`IRONCLAD_TRUST_PROXY=1` for client IP-based rate limits. Compose uses database
rate-limit counters so multiple API processes do not each get a fresh budget.

Repositories are mounted at `/work` **read-only**. The scanner only parses
files; it has no reason to write to a target tree, and read-only is what
makes that enforceable rather than aspirational.

Required variables fail fast rather than defaulting to something insecure:
`POSTGRES_PASSWORD` and `IRONCLAD_SIGNING_KEY` have no defaults.

### First-time setup

```bash
docker compose exec -it api ironclad server init \
  --org-name "Acme Corp" --org-slug acme \
  --admin-email secops@acme-corp.com
# Enter and confirm the owner password at the hidden prompt; do not put it
# in the process command line or your shell history.
```

The password policy is enforced here too (≥12 characters, ≥3 character
classes). After setup, `curl -fsS http://localhost:8000/ready` returns
`{"ready":true,...}`. If it stays at 503, check that init, API and worker
all use the **same** `IRONCLAD_DATABASE_URL` and `IRONCLAD_SCAN_ROOT`.

### Optional enterprise OIDC / SSO

Configure **one trusted HTTPS OpenID Connect provider for one existing
organization**. Register `https://sentinel.example.com/auth/oidc/callback`
as an exact redirect URI with that provider, then provide these values as
out-of-band secrets/environment (never commit a populated `.env` file):

```bash
export IRONCLAD_OIDC_ISSUER='https://idp.example.com/tenant'
export IRONCLAD_OIDC_CLIENT_ID='your-registered-client-id'
export IRONCLAD_OIDC_CLIENT_SECRET='your-secret-from-the-idp'
export IRONCLAD_OIDC_REDIRECT_URI='https://sentinel.example.com/auth/oidc/callback'
export IRONCLAD_OIDC_ORG_SLUG='acme'
export IRONCLAD_COOKIE_SECURE=1
# After the owner/org and SSO users are provisioned and a real IdP login works:
export IRONCLAD_DISABLE_PASSWORD_LOGIN=1
# docker compose up -d --build
```

The redirect URI **must** be HTTPS and end exactly in `/auth/oidc/callback`.
The browser-state cookie is always `Secure`; test with a real TLS URL, not
plain `http://localhost`. Provision users in the configured organization
first (the `/users` API); only a verified IdP email matching an active local
account can bind to a stable issuer/subject. IdP claims cannot choose a role
or tenant. OIDC uses authorization code + PKCE, browser-bound single-use
state, signed ID tokens, issuer/audience/nonce checks and TLS verification.
The provider must support either `client_secret_basic` (default) or
`client_secret_post` (`IRONCLAD_OIDC_TOKEN_AUTH_METHOD`). The default OIDC
session TTL is one hour (`IRONCLAD_OIDC_SESSION_TTL_SECONDS`, 60–43,200).
For a private CA, mount the certificate in the API container and set
`IRONCLAD_OIDC_CA_BUNDLE` to its absolute path; never disable TLS checking.
The authentication service requires access to the configured IdP; scanners
do not make OIDC requests.

SSO-only users can create/revoke a one-time-display, limited-permission
API token at `/ui/settings` without a local password. The form currently
issues `finding.read`, `scan.create` and `scan.read`; use the authenticated
API when you need a different permitted scope set. API-token revocation is
immediate. **IdP logout and external deprovisioning are not pushed to
IronClad**: locally revoke sessions/tokens and deactivate a user when needed;
existing OIDC sessions otherwise expire at their local TTL. There is no JIT
provisioning, multi-provider org routing, SCIM or enterprise IdP live-tenant
certification here. See [enterprise release gate](ENTERPRISE_RELEASE_GATE_2026-09-27.md)
for what was actually verified.

---

## 3. Kubernetes

```bash
kubectl apply -f deploy/k8s/00-namespace.yaml

kubectl -n ironclad create secret generic ironclad-secrets \
  --from-literal=IRONCLAD_SIGNING_KEY="$(openssl rand -hex 32)" \
  --from-literal=IRONCLAD_DATABASE_URL="postgresql+psycopg2://user:pass@host:5432/ironclad"

kubectl apply -f deploy/k8s/
kubectl -n ironclad create job --from=cronjob/ironclad-migrate "migrate-$(date +%s)"
```

| Manifest | Purpose |
|---|---|
| `00-namespace.yaml` | Namespace with `restricted` pod-security enforcement |
| `10-configmap.yaml` | Non-secret configuration |
| `20-secret.yaml` | **Template with placeholders** — create the real secret out of band |
| `30-api.yaml` | API Deployment (2 replicas) + Service, probes, limits |
| `35-migrate-job.yaml` | Suspended CronJob usable as a one-shot migration runner |
| `40-worker.yaml` | Worker Deployment, scaled separately from the API |
| `50-hpa.yaml` | HPA for both; 5-minute scale-down stabilisation |
| `60-ingress.yaml` | TLS-terminating ingress example |
| `70-pvc.yaml` | Read-only volume holding the repositories to scan |

Hardening applied to every pod: `runAsNonRoot`, `readOnlyRootFilesystem`,
`allowPrivilegeEscalation: false`, all capabilities dropped,
`seccompProfile: RuntimeDefault`, resource requests **and** limits.

The worker HPA scales down slowly (300 s stabilisation) on purpose: a
claimed job is recoverable after the stale timeout, but waiting is cheaper
than reclaiming.

### Why the API and worker are separate

A 100k-file scan is CPU-bound and takes ~47 s of wall clock (see
`BENCHMARKS.md`). If it ran inside an API request it would consume a worker
slot, hold a transaction, and time out behind most ingress proxies. The
queue makes `POST /scan` return `202` immediately.

---

## Database

### Migrations

Migrations are numbered SQL files under
`ironclad/platform/migrations/<dialect>/` and are applied by
`ironclad.platform.database.run_migrations`. Schema is **never** created by
application code (`create_all()` is not used anywhere).

* Idempotent — re-running applies nothing.
* Checksummed — editing an already-applied file raises instead of letting
  environments drift. Add a new file instead.
* One transaction per file.

```bash
ironclad server init ...          # creates schema + first organization
# or, against an existing database:
python -c "from ironclad.platform.database import build_engine, run_migrations; \
print(run_migrations(build_engine(), verbose=True))"
```

### PostgreSQL

```bash
pip install 'ironclad-sentinel[server,postgres]'
export IRONCLAD_DATABASE_URL="postgresql+psycopg2://user:pass@host:5432/ironclad"
```

Indexes lead with `org_id` because that is always the first predicate in a
tenant-scoped query. There are no speculative indexes.

### SQLite

Default for development: `sqlite:///./.ironclad/ironclad.db`. WAL journal
mode and `PRAGMA foreign_keys=ON` are set on connect, so the API can read
while the worker writes.

---

## Configuration reference

For a **local CLI scan**, precedence is **CLI flags → `IRONCLAD_*`
environment variables → project `.ironclad.yml` →
`~/.ironclad/config.yml` → built-in defaults**. API and worker scans ignore
the scanned repository's `.ironclad.yml`: it is attacker-controlled input,
not permission to change server engines, ignores or egress. Use trusted
operator environment/global configuration or an authorized API policy there.

| Variable | Default | Purpose |
|---|---|---|
| `IRONCLAD_DATABASE_URL` | `sqlite:///./.ironclad/ironclad.db` | SQLAlchemy URL |
| `IRONCLAD_SIGNING_KEY` | per-process random | HMAC key for stateless tokens; **must** be ≥32 chars and stable in production |
| `IRONCLAD_SCAN_ROOT` | current working directory | Only targets inside this root may be scanned |
| `IRONCLAD_LOG_LEVEL` | `INFO` | Structured log level |
| `IRONCLAD_CORS_ORIGINS` | empty | Comma-separated allowlist; unlisted origins get no CORS headers |
| `IRONCLAD_ENABLE_DOCS` | `0` | Set to `1` to enable `/docs` + `/openapi.json` (development only) |
| `IRONCLAD_COOKIE_SECURE` | `0` | Set to `1` behind TLS to mark local dashboard login cookies `Secure` (OIDC cookies are always secure) |
| `IRONCLAD_DISABLE_PASSWORD_LOGIN` | `0` | Set to `1` **only after** verified OIDC and first-owner bootstrap; disables local API/dashboard sign-in and reset |
| `IRONCLAD_OIDC_ISSUER` / `_CLIENT_ID` / `_CLIENT_SECRET` / `_REDIRECT_URI` / `_ORG_SLUG` | unset | All five required to enable one OIDC provider, client and local organization |
| `IRONCLAD_OIDC_TOKEN_AUTH_METHOD` | `client_secret_basic` | Or `client_secret_post` if the provider requires it |
| `IRONCLAD_OIDC_SESSION_TTL_SECONDS` | `3600` | Local OIDC session lifetime (60–43,200 seconds) |
| `IRONCLAD_OIDC_CA_BUNDLE` | unset | Absolute path in the API container to a trusted custom CA certificate |
| `IRONCLAD_ADVISORY_SOURCE` | `bundled` | `bundled` \| `directory` \| `remote` |
| `IRONCLAD_ADVISORY_PATH` | — | Overlay directory for `directory` |
| `IRONCLAD_ADVISORY_ENDPOINT` | — | OSV-compatible HTTPS endpoint for `remote` |
| `IRONCLAD_ALLOW_PRIVATE_WEBHOOKS` | `0` | Allow webhook URLs pointing at private/link-local hosts |
| `IRONCLAD_RATELIMIT_ENABLED` | `1` | Set to `0` to disable rate limiting entirely |
| `IRONCLAD_RATELIMIT_BACKEND` | `memory` outside Compose; `database` in Compose | `database` shares counters across processes |
| `IRONCLAD_RATELIMIT_LOGIN` | `10:60` | Per-IP login limit, `LIMIT:WINDOW_SECONDS` (`0` disables) |
| `IRONCLAD_RATELIMIT_LOGIN_ACCOUNT` | `5:300` | Per-account login volume limit |
| `IRONCLAD_RATELIMIT_TOKEN_CREATE` | `10:300` | Per-user API-token creation limit |
| `IRONCLAD_RATELIMIT_PASSWORD_CHANGE` | `5:300` | Per-user password-change limit |
| `IRONCLAD_RATELIMIT_GENERAL` | `600:60` | Per-IP limit for other API traffic |
| `IRONCLAD_TRUST_PROXY` | `0` in Compose | Trust `X-Forwarded-For` **only** when the API cannot be accessed except through your reverse proxy |
| `IRONCLAD_FORWARDED_ALLOW_IPS` | `127.0.0.1` | Uvicorn-trusted proxy IPs; do not set to wildcard on a public listener |
| `IRONCLAD_HOST_BIND` | `127.0.0.1` in Compose | Bind the host-side plaintext HTTP port (different from the container's `IRONCLAD_BIND_HOST`) |
| `IRONCLAD_MAIL_TRANSPORT` | `memory` | `memory` \| `smtp` \| `null` |
| `IRONCLAD_MAIL_FROM` | `IronClad Sentinel <no-reply@ironclad.local>` | From address for transactional mail |
| `IRONCLAD_SMTP_HOST` | unset | SMTP host (required for `smtp`) |
| `IRONCLAD_SMTP_PORT` | `587` | SMTP port |
| `IRONCLAD_SMTP_USERNAME` / `_PASSWORD` | unset | SMTP credentials |
| `IRONCLAD_SMTP_STARTTLS` | `1` | Use STARTTLS |
| `IRONCLAD_SMTP_SSL` | `0` | Use implicit TLS (SMTPS) |
| `IRONCLAD_SMTP_TIMEOUT` | `15` | SMTP timeout, seconds |
| `IRONCLAD_PASSWORD_RESET_TTL_MINUTES` | `30` | Reset link lifetime, max 1440 |
| `IRONCLAD_PASSWORD_RESET_URL_BASE` | unset | Dashboard base URL used to build reset links |
| `IRONCLAD_EGRESS_ALLOWLIST` | unset | Comma-separated hostnames permitted for outbound integration delivery. Exact match, case-insensitive; `*.` prefix allows subdomains. Unset means no allowlist and existing SSRF controls apply |
| `IRONCLAD_RATELIMIT_PASSWORD_RESET_REQUEST` | `5:300` | Per-IP reset-request limit |
| `IRONCLAD_RATELIMIT_PASSWORD_RESET_REDEEM` | `10:300` | Per-IP reset-confirm limit |
| `IRONCLAD_BIND_HOST` / `IRONCLAD_PORT` | `0.0.0.0` / `8000` | Container bind address |
| `IRONCLAD_API_WORKERS` | `1` | uvicorn worker count |

Scanner variables: `IRONCLAD_MIN_SEVERITY`, `IRONCLAD_OUTPUT_DIR`,
`IRONCLAD_BASELINE`, `IRONCLAD_ENTROPY_THRESHOLD`,
`IRONCLAD_MAX_FILE_SIZE_KB`, `IRONCLAD_IGNORE_RULES`, `IRONCLAD_ENGINES`.

> **`IRONCLAD_SIGNING_KEY` in production.** Without it, a random per-process
> key is generated, so stateless tokens do not survive a restart and are not
> shared between replicas. That is the safe development behaviour, not the
> production one — set the variable explicitly when you run more than one
> process.

---

## Operations

### Health

* `/health` — liveness (200); reports `degraded` if the database cannot be
  queried or no organization has been initialized
* `/ready` — readiness; returns `503` until the database is reachable **and**
  an organization exists. Startup logs the resolved database location if no
  organization is found; this catches mismatched working directories early.

### Logs

One JSON object per line with `timestamp`, `level`, `logger`, `event`,
`request_id`, `correlation_id`, `org_id`, `scan_id`. Credential-shaped keys
are redacted before they reach a log line.

A scan started by an HTTP request carries the request's id as its
`correlation_id`, so one investigation can join API log → scan log → worker
log.

### Metrics

`/metrics` in Prometheus text format. Scrape it directly; there is no
background thread and no client library.

### Local account recovery (without SMTP)

Run on a trusted host/container with access to the **same database URL** as
the API. These operations are audited and require database access, not an
unauthenticated HTTP endpoint. Passwords are prompted, never required in
command-line arguments:

```bash
ironclad server unlock --org acme --email secops@acme-corp.com
ironclad server reset-password --org acme --email secops@acme-corp.com
```

`unlock` preserves the password and active sessions; `reset-password` sets a
new password and revokes all active sessions, API tokens and unused reset
links for that account. A missing SQLite file is refused, not silently
created. In a multi-replica install, in-memory login rate limits may need to
expire before the new login works even after clearing the database lockout.

### Release-time advisory freshness

The shipped database is an **offline snapshot**, not an auto-updating feed.
Before promoting a build, while online and with `.venv/bin` on `PATH`, run:

```bash
bash scripts/build_advisory_db.sh
python scripts/check_advisory_freshness.py  # <=24h and both current upstream heads
```

A snapshot can become stale again whenever either source advances. The
checker fails closed on an unverified Git head; `--offline` checks only age
and **does not qualify** a release. Freshness is not correctness: the two
feeds can disagree about an affected version. See the dated enterprise
release-gate report for the last age/head measurement and an unresolved
PyPA-versus-GitHub range disagreement. This is a build/release operation,
not a product network call on every scan.

### Backup and restore

See [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md). Back up **both** the
PostgreSQL database and the signing key, integration/IdP secrets, scanned
repository contents and necessary configuration. A source ZIP cannot restore
those operational assets; reports and SBOMs are normally derived data.

```bash
pg_dump -Fc ironclad > ironclad-$(date +%F).dump     # backup
pg_restore -d ironclad_restored ironclad-2026-08-27.dump
```

### Restricting outbound egress

**Per-organization policies.** The environment variable is process-global.
In a multi-tenant deployment, each organization can set its own allowlist
through `PUT /org/egress-policy` (requires `organization.manage`), stored in
the organization's settings. The two combine by **intersection**, so an
organization can only narrow what the operator permitted, never widen it.
See `docs/SECURITY.md` for the full precedence table.


By default integrations may reach any public host; the SSRF guard blocks
internal and non-public addresses. To constrain egress to known endpoints:

```bash
export IRONCLAD_EGRESS_ALLOWLIST=hooks.slack.com,api.github.com,gitlab.example.com
```

Matching is exact and case-insensitive. A leading `*.` allows subdomains
(`*.webhooks.internal.example.com` matches `a.webhooks.internal.example.com`
but not `webhooks.internal.example.com` itself). There is no implicit suffix
matching, so `evilgithub.com` can never match `github.com`.

The check runs before DNS, so an unlisted host is never resolved or connected
to, and it applies to every redirect hop. Leaving it unset preserves the
existing behaviour exactly.

### Password reset mail

The default transport is `memory`, which records messages in-process and
sends nothing — so a fresh install works with no SMTP credentials. For real
delivery:

```bash
export IRONCLAD_MAIL_TRANSPORT=smtp
export IRONCLAD_SMTP_HOST=smtp.internal.example.com
export IRONCLAD_SMTP_PORT=587
export IRONCLAD_SMTP_USERNAME=ironclad
export IRONCLAD_SMTP_PASSWORD="$SMTP_PASSWORD"
export IRONCLAD_MAIL_FROM="IronClad Sentinel <no-reply@example.com>"
export IRONCLAD_PASSWORD_RESET_URL_BASE="https://sec.example.com"
```

`IRONCLAD_PASSWORD_RESET_URL_BASE` must point at your own deployment; without
it the mail contains the bare token rather than a clickable link. SMTP
credentials belong in your secret manager, never in a config file.

### Running the PostgreSQL test suite

```bash
export IRONCLAD_TEST_POSTGRES_URL="postgresql+psycopg2://user:pass@host/ironclad_test"
pytest tests/test_postgres.py -v
```

**This suite drops every table in the target database.** It refuses to run
unless the database name contains `test`, `verify`, `ci`, `scratch`, `tmp` or
`temp`; override with `IRONCLAD_TEST_POSTGRES_ALLOW_UNSAFE=1` only against a
database you are happy to lose.

No PostgreSQL instance? The `pgserver` wheel bundles a real server, no Docker
required:

```bash
pip install pgserver
python -c "import pgserver; print(pgserver.get_server('/tmp/pgdata').get_uri())"
```

Restore is tested by `tests/test_database.py`, which recreates the schema
from migrations against a fresh database and verifies row counts and
constraints survive the round trip.

### Upgrading

```bash
docker compose pull && docker compose run --rm api migrate && docker compose up -d
```

Migrations are forward-only and additive where possible. A checksum
mismatch is a hard failure, not a warning — that is the point.
