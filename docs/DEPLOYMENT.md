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
curl -fsS http://localhost:8000/ready
```

`docker-compose.yml` runs three services:

* `db` — PostgreSQL 16, **not** published to the host
* `api` — API + dashboard on port 8000
* `worker` — scan worker (separate so a CPU-bound scan cannot starve the API)

Repositories are mounted at `/work` **read-only**. The scanner only parses
files; it has no reason to write to a target tree, and read-only is what
makes that enforceable rather than aspirational.

Required variables fail fast rather than defaulting to something insecure:
`POSTGRES_PASSWORD` and `IRONCLAD_SIGNING_KEY` have no defaults.

### First-time setup

```bash
docker compose exec api ironclad server init \
  --org-name "Acme Corp" --org-slug acme \
  --admin-email secops@acme-corp.com \
  --admin-password "$ADMIN_PASSWORD"
```

The password policy is enforced here too (≥12 characters, ≥3 character
classes).

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

Precedence, highest first: **CLI flags → `IRONCLAD_*` environment
variables → project `.ironclad.yml` → `~/.ironclad/config.yml` → built-in
defaults**.

| Variable | Default | Purpose |
|---|---|---|
| `IRONCLAD_DATABASE_URL` | `sqlite:///./.ironclad/ironclad.db` | SQLAlchemy URL |
| `IRONCLAD_SIGNING_KEY` | per-process random | HMAC key for stateless tokens; **must** be ≥32 chars and stable in production |
| `IRONCLAD_SCAN_ROOT` | current working directory | Only targets inside this root may be scanned |
| `IRONCLAD_LOG_LEVEL` | `INFO` | Structured log level |
| `IRONCLAD_CORS_ORIGINS` | empty | Comma-separated allowlist; unlisted origins get no CORS headers |
| `IRONCLAD_ENABLE_DOCS` | `0` | Set to `1` to enable `/docs` + `/openapi.json` (development only) |
| `IRONCLAD_COOKIE_SECURE` | `0` | Set to `1` behind TLS to mark the dashboard cookie `Secure` |
| `IRONCLAD_ADVISORY_SOURCE` | `bundled` | `bundled` \| `directory` \| `remote` |
| `IRONCLAD_ADVISORY_PATH` | — | Overlay directory for `directory` |
| `IRONCLAD_ADVISORY_ENDPOINT` | — | OSV-compatible HTTPS endpoint for `remote` |
| `IRONCLAD_ALLOW_PRIVATE_WEBHOOKS` | `0` | Allow webhook URLs pointing at private/link-local hosts |
| `IRONCLAD_RATELIMIT_ENABLED` | `1` | Set to `0` to disable rate limiting entirely |
| `IRONCLAD_RATELIMIT_BACKEND` | `memory` | `database` shares counters across processes |
| `IRONCLAD_RATELIMIT_LOGIN` | `10:60` | Per-IP login limit, `LIMIT:WINDOW_SECONDS` (`0` disables) |
| `IRONCLAD_RATELIMIT_LOGIN_ACCOUNT` | `5:300` | Per-account login volume limit |
| `IRONCLAD_RATELIMIT_TOKEN_CREATE` | `10:300` | Per-user API-token creation limit |
| `IRONCLAD_RATELIMIT_PASSWORD_CHANGE` | `5:300` | Per-user password-change limit |
| `IRONCLAD_RATELIMIT_GENERAL` | `600:60` | Per-IP limit for other API traffic |
| `IRONCLAD_TRUST_PROXY` | unset | Trust `X-Forwarded-For` (only behind a proxy you control) |
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

* `/health` — liveness plus a `SELECT 1` database probe
* `/ready` — readiness; returns `503` when the database is unreachable

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

### Backup and restore

See [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md). Short version: the
database is the only state that matters. Everything else — reports, SBOMs,
baselines — is either derived from it or committed to the scanned
repository.

```bash
pg_dump -Fc ironclad > ironclad-$(date +%F).dump     # backup
pg_restore -d ironclad_restored ironclad-2026-08-27.dump
```

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
