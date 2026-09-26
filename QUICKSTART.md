# IronClad Sentinel v2 — verified local quick start

These steps are for a local checkout and an isolated SQLite database. A scan
is **offline by default**; the bundled advisory feed is a snapshot, not a
live vulnerability service. For PostgreSQL/containers, see
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## 1. Install and scan a repository

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[server,postgres,dev]'
ironclad doctor
ironclad scan /absolute/path/to/repository --quiet --output-dir /tmp/ironclad-reports
```

The CLI can load a project-owned `.ironclad.yml`; review it before scanning
an untrusted project. File symlinks, named pipes and other non-regular files
are skipped. Reports are written to the selected output directory, not the
source tree.

## 2. Set up a local server

Use **absolute paths** so `server init`, the API and the worker all see the
same database and scan root even when launched in different working
directories. Keep the signing key in your secret manager; it must be stable
across API restarts/replicas and at least 32 characters long.

```bash
export IRONCLAD_DATABASE_URL='sqlite:////absolute/path/to/ironclad.db'
export IRONCLAD_SCAN_ROOT='/absolute/path/to/checked-out-repositories'
export IRONCLAD_SIGNING_KEY='<32-or-more-random-characters-from-your-secret-manager>'

ironclad server init --org-name 'My Team' --org-slug my-team \
  --admin-email owner@example.com --admin-password "$ADMIN_PASSWORD"
ironclad serve --host 127.0.0.1 --port 8000
```

Set `ADMIN_PASSWORD` securely before the init command; the current init
command passes it as a CLI option, so avoid putting a literal secret into
shell history. Do not use the placeholder signing key in a real deployment.

Start the worker in another shell with the **same** three environment
variables:

```bash
. .venv/bin/activate
ironclad server worker
```

Visit `http://127.0.0.1:8000/ui/`, sign in, create a project and queue a
scan. `GET /health` is liveness (200 even when uninitialized, with
`status=degraded`); `GET /ready` returns 503 until an organization exists.
If login says the account does not exist, compare the API/worker database URL
and the actual initialized SQLite file before resetting the password.

The server **ignores `.ironclad.yml` inside scanned repositories**: an
untrusted repository must not disable engines or initiate outbound advisory
queries. Configure server scans through trusted environment/global settings
or an authorized API policy. `wait: true` runs a small scan inline under a
claimed job: a live worker will not duplicate it, and a worker can reclaim
it after the stale timeout if the API dies. For large repositories use the
default queued mode.

## 3. Recover an owner without SMTP

The default mail transport stores reset messages in the API process; it does
not send email. On a trusted host with access to the **existing** database:

```bash
ironclad server unlock --org my-team --email owner@example.com
ironclad server reset-password --org my-team --email owner@example.com
```

`unlock` keeps the password and sessions; `reset-password` prompts (and
confirms) the new password and revokes active sessions, API tokens and old
reset links. Both actions are audited. A mistyped SQLite path is refused
rather than silently creating a second database.

## 4. Verify and back up

```bash
python -m pytest -q
python benchmarks/corpus_metrics.py --fail-below 0.95
python benchmarks/scale_benchmark.py --tiers 10000
```

The supplied downloadable source ZIP is **not a database backup**. Back up
and restore the database separately using [docs/DISASTER_RECOVERY.md](docs/DISASTER_RECOVERY.md).
For what was actually measured on this upgrade (and the remaining limits),
see [docs/UPGRADE_VALIDATION_2026-09-26.md](docs/UPGRADE_VALIDATION_2026-09-26.md).
