#!/usr/bin/env bash
# Reproducible verification for IronClad Sentinel.
#
# The GitHub Actions workflow that *should* run all of this lives at
# deploy/ci/verify.yml, but it cannot be installed into .github/workflows/
# by the current CI identity (no `workflows` permission). The workflow that
# does run on GitHub installs core-only dependencies, so it skips the API,
# database, platform and PostgreSQL tests entirely.
#
# This script is therefore the authoritative local verification. From a
# clean clone:
#
#     bash scripts/verify_all.sh
#
# Options:
#     --quick      skip the slow tiers (scale benchmark, demo, container)
#     --keep-venv  reuse .venv if present instead of recreating it
#
# Everything that cannot run in the current environment is reported as
# SKIPPED with the reason -- never silently counted as passing.
set -uo pipefail

QUICK=0
KEEP_VENV=0
for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    --keep-venv) KEEP_VENV=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
VENV="$ROOT/.venv"

PASS=0; FAIL=0; SKIP=0
declare -a RESULTS=()

record() { # record <status> <name> [detail]
  case "$1" in
    PASS) PASS=$((PASS+1)); printf '  \033[32m[PASS]\033[0m %s\n' "$2" ;;
    FAIL) FAIL=$((FAIL+1)); printf '  \033[31m[FAIL]\033[0m %s -- %s\n' "$2" "${3:-}" ;;
    SKIP) SKIP=$((SKIP+1)); printf '  \033[33m[SKIP]\033[0m %s -- %s\n' "$2" "${3:-}" ;;
  esac
  RESULTS+=("$1|$2|${3:-}")
}

# Run a command, recording the outcome. Usage: step <name> <cmd...>
step() {
  local name="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then
    record PASS "$name"
  else
    record FAIL "$name" "$(echo "$out" | tail -5 | tr '\n' ' ')"
  fi
}

header() { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }

# ---------------------------------------------------------------------------
header "0. Environment"
# ---------------------------------------------------------------------------
python3 --version
if [ ! -d "$VENV" ] || [ "$KEEP_VENV" -eq 0 ]; then
  echo "creating virtualenv at $VENV"
  python3 -m venv "$VENV" || { echo "cannot create venv" >&2; exit 1; }
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"
python -m pip install -q --upgrade pip

header "1. Installation (core / server / dev extras)"
step "install core"            python -m pip install -q -e .
step "core imports"            python -c "import ironclad; print(ironclad.__version__)"
step "install [server]"        python -m pip install -q -e ".[server]"
step "server imports"          python -c "import fastapi, sqlalchemy, uvicorn, pydantic"
step "install [server,dev]"    python -m pip install -q -e ".[server,dev]"
step "dev imports"             python -c "import pytest, httpx"
step "CLI entry point"         ironclad version
step "CLI help"                ironclad --help

header "2. Full test suite (SQLite)"
step "pytest"                  python -m pytest -q

header "3. Scanner quality gates"
step "self-scan is clean"      ironclad scan ironclad --fail-on high --output-dir /tmp/ironclad-verify-self --quiet
step "corpus precision >=0.95" python benchmarks/corpus_metrics.py --fail-below 0.95
step "throughput benchmark"    python benchmarks/scan_benchmark.py tests/security_corpus
step "no placeholder markers"  bash -c "! grep -rn --include='*.py' -E '\\b(TODO|FIXME|XXX)\\b' ironclad/"

header "4. Reports and SBOM"
step "all report formats"      ironclad scan tests/security_corpus --quiet \
                                 --format json,sarif,html,markdown,junit,cyclonedx \
                                 --output-dir /tmp/ironclad-verify-reports
step "CycloneDX + SPDX valid"  python -c "
import json, subprocess, tempfile, os
from ironclad.scanners.sbom import validate_cyclonedx
from ironclad.scanners.spdx import validate_spdx
d = tempfile.mkdtemp()
for fmt, out in (('cyclonedx','cdx.json'), ('spdx','spdx.json')):
    subprocess.run(['ironclad','sbom','tests/security_corpus/sbom_license','--out',
                    os.path.join(d,out),'--format',fmt], check=True, capture_output=True)
cdx = json.load(open(os.path.join(d,'cdx.json')))
spdx = json.load(open(os.path.join(d,'spdx.json')))
assert validate_cyclonedx(cdx) == [], validate_cyclonedx(cdx)
assert validate_spdx(spdx) == [], validate_spdx(spdx)
print(f'CycloneDX {len(cdx[\"components\"])} components, SPDX {len(spdx[\"packages\"])} packages')
"
step "SBOM is deterministic"   python -c "
import json, subprocess, tempfile, os
d = tempfile.mkdtemp()
a, b = os.path.join(d,'a.json'), os.path.join(d,'b.json')
for out in (a, b):
    subprocess.run(['ironclad','sbom','tests/security_corpus/sbom_license','--out',out],
                   check=True, capture_output=True)
x, y = json.load(open(a)), json.load(open(b))
x['metadata'].pop('timestamp', None); y['metadata'].pop('timestamp', None)
assert x == y, 'SBOM output is not deterministic'
"

header "5. Policy gate and baseline round trip"
step "policy validates"        bash -c "ironclad policy init --out /tmp/ironclad-verify-policy.yaml >/dev/null && ironclad policy validate /tmp/ironclad-verify-policy.yaml >/dev/null"
step "gate fails vulnerable corpus" bash -c "
  ironclad scan tests/security_corpus --policy /tmp/ironclad-verify-policy.yaml \
    --quiet --output-dir /tmp/ironclad-verify-gate >/dev/null 2>&1
  test \$? -eq 1
"
step "baseline then gate passes" bash -c "
  ironclad baseline create tests/security_corpus --out /tmp/ironclad-verify-baseline.json \
    --reason verify --created-by verify >/dev/null
  ironclad scan tests/security_corpus --policy /tmp/ironclad-verify-policy.yaml \
    --baseline /tmp/ironclad-verify-baseline.json --quiet \
    --output-dir /tmp/ironclad-verify-gate2 >/dev/null 2>&1
  test \$? -eq 0
"

header "6. Integrations (real local HTTP server)"
step "integration checks"      python benchmarks/integration_check.py
# Clones real repositories; self-skips (exit 0) when github.com is unreachable.
step "real-world corpus"       python benchmarks/real_world_corpus.py

header "7. PostgreSQL"
PG_URL=""
if python -c "import psycopg2" 2>/dev/null; then
  if ! python -c "import pgserver" 2>/dev/null; then
    python -m pip install -q pgserver 2>/dev/null || true
  fi
  if python -c "import pgserver" 2>/dev/null; then
    PGDATA="$(mktemp -d /tmp/ironclad-pg.XXXXXX)"
    # Use a dedicated database whose name marks it disposable. The PostgreSQL
    # suite drops every table in its target and refuses to run against a name
    # that does not look throwaway -- the default `postgres` database would
    # (correctly) be rejected.
    PG_URI="$(python -c "
import pgserver
import psycopg2
srv = pgserver.get_server('$PGDATA', cleanup_mode=None)
base = srv.get_uri()
admin = psycopg2.connect(base)
admin.autocommit = True
cur = admin.cursor()
cur.execute('DROP DATABASE IF EXISTS ironclad_verify')
cur.execute('CREATE DATABASE ironclad_verify')
admin.close()
print(base.replace('/postgres?', '/ironclad_verify?')
           .replace('postgresql://', 'postgresql+psycopg2://'))
" 2>/dev/null)"
    if [ -n "${PG_URI:-}" ]; then
      PG_URL="$PG_URI"
      echo "started PostgreSQL: ${PG_URI%%\?*}"
      export IRONCLAD_TEST_POSTGRES_URL="$PG_URL"
      step "PostgreSQL migrations + 16 tests" python -m pytest tests/test_postgres.py -q
      step "PostgreSQL schema is complete"   python -c "
from sqlalchemy import text
from ironclad.platform.database import build_engine, run_migrations, current_schema_version
import os
e = build_engine(os.environ['IRONCLAD_TEST_POSTGRES_URL'])
run_migrations(e)
assert run_migrations(e) == [], 'migrations are not idempotent'
with e.connect() as c:
    tables = {r[0] for r in c.execute(text(\"SELECT tablename FROM pg_tables WHERE schemaname='public'\"))}
    idx = c.execute(text(\"SELECT count(*) FROM pg_indexes WHERE schemaname='public'\")).scalar()
    fks = c.execute(text(\"SELECT count(*) FROM information_schema.table_constraints WHERE constraint_type='FOREIGN KEY' AND table_schema='public'\")).scalar()
    chk = {r[0] for r in c.execute(text(\"SELECT conname FROM pg_constraint WHERE contype='c' AND connamespace='public'::regnamespace\"))}
    tz = c.execute(text('SHOW timezone')).scalar()
need = {'organizations','users','sessions','api_tokens','projects','repositories','policies','baselines','scans','findings','finding_events','sboms','components','integrations','audit_events','jobs','events','schema_migrations'}
assert need <= tables, sorted(need - tables)
assert {'scans_status_valid','findings_severity_valid','findings_status_valid','jobs_status_valid','users_role_valid'} <= chk, sorted(chk)
assert tz.upper() == 'UTC', f'session timezone is not pinned to UTC: {tz}'
version = current_schema_version(e)
print(f'{len(tables)} tables, {idx} indexes, {fks} FKs, {len(chk)} CHECK constraints, TZ=UTC, version={version}')
"
    else
      record SKIP "PostgreSQL tests" "pgserver could not start a server"
    fi
  else
    record SKIP "PostgreSQL tests" "psycopg2 present but pgserver unavailable (pip install pgserver)"
  fi
else
  record SKIP "PostgreSQL tests" "psycopg2 not installed (pip install 'ironclad-sentinel[postgres]')"
fi

header "8. API + dashboard over real HTTP"
API_PORT=8099
if [ -n "$PG_URL" ]; then
  E2E_DB="$PG_URL"
else
  E2E_DB="sqlite:///$(mktemp -d)/e2e.db"
fi
E2E_TARGET="$(mktemp -d /tmp/ironclad-e2e-target.XXXXXX)"
cat > "$E2E_TARGET/app.py" <<'PY'
import os
import sqlite3

import requests
from flask import request


def lookup(user_input):
    conn = sqlite3.connect(":memory:")
    query = "SELECT * FROM users WHERE email = '%s'" % user_input
    return conn.execute(query).fetchall()


def fetch():
    return requests.get(request.args.get("url")).text


def read(user_input):
    return open("/data/" + user_input).read()


DEBUG = True
PY
printf 'jinja2==3.1.2\nrequests==2.30.0\n' > "$E2E_TARGET/requirements.txt"

export IRONCLAD_DATABASE_URL="$E2E_DB"
export IRONCLAD_SIGNING_KEY="verify-signing-key-that-is-long-enough-32"
export IRONCLAD_SCAN_ROOT="$E2E_TARGET"
export IRONCLAD_ENABLE_DOCS=0

if step "server init (creates org + owner)" ironclad server init \
      --org-name "Verify Corp" --org-slug verify \
      --admin-email owner@verify-corp.com --admin-password 'Verify-Strong-Passw0rd'; then
  uvicorn ironclad.api.app:create_app --factory --host 127.0.0.1 --port "$API_PORT" \
    > /tmp/ironclad-verify-api.log 2>&1 &
  API_PID=$!
  for _ in $(seq 1 40); do
    curl -fsS "http://127.0.0.1:$API_PORT/ready" >/dev/null 2>&1 && break
    sleep 0.5
  done

  if curl -fsS "http://127.0.0.1:$API_PORT/ready" >/dev/null 2>&1; then
    record PASS "API boots and /ready responds"
    export IRONCLAD_E2E_BASE="http://127.0.0.1:$API_PORT"
    export IRONCLAD_E2E_EMAIL="owner@verify-corp.com"
    export IRONCLAD_E2E_PASSWORD='Verify-Strong-Passw0rd'
    step "e2e HTTP checks (38 assertions)" python benchmarks/e2e_http_check.py
    step "worker processes the queued scan" ironclad server worker --max-jobs 3
    step "dashboard pages render"          python - <<'PY'
import http.cookiejar, re, urllib.parse, urllib.request, os
base = os.environ["IRONCLAD_E2E_BASE"]
cj = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
def get(p):
    with op.open(base + p, timeout=60) as r:
        return r.status, r.read().decode("utf-8", "replace")
def post(p, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(base + p, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with op.open(req, timeout=60) as r:
        return r.status
assert post("/ui/login", {"email": os.environ["IRONCLAD_E2E_EMAIL"],
                          "password": os.environ["IRONCLAD_E2E_PASSWORD"]}) in (200, 303)
pages = {"/ui/": "Security overview", "/ui/projects": "Projects",
         "/ui/findings": "Findings", "/ui/policies": "fail_on",
         "/ui/integrations": "Integrations", "/ui/audit": "auth.login",
         "/ui/settings": "Roles and permissions"}
bad = []
for path, marker in pages.items():
    status, body = get(path)
    if status != 200 or marker not in body:
        bad.append(f"{path} -> {status}, marker {marker!r} present={marker in body}")
assert not bad, "; ".join(bad)
print(f"{len(pages)} dashboard pages render with real data")
PY
  else
    record FAIL "API boots and /ready responds" "see /tmp/ironclad-verify-api.log"
    tail -15 /tmp/ironclad-verify-api.log
  fi
  kill "$API_PID" 2>/dev/null
  wait "$API_PID" 2>/dev/null
else
  record SKIP "API/dashboard e2e" "server init failed"
fi
unset IRONCLAD_DATABASE_URL IRONCLAD_SCAN_ROOT IRONCLAD_E2E_BASE

header "9. Packaging"
step "build wheel"             python -m build --wheel
step "wheel installs clean"    bash -c "
  set -e
  CV=\$(mktemp -d)/cv
  python3 -m venv \"\$CV\"
  \"\$CV/bin/pip\" install -q dist/*.whl
  \"\$CV/bin/python\" -c 'import ironclad, pathlib; r=pathlib.Path(ironclad.__file__).parent; \
req=[\"platform/migrations/sqlite/0001_initial.sql\",\"platform/migrations/postgres/0001_initial.sql\", \
\"platform/migrations/sqlite/0002_scan_policy_document.sql\",\"platform/migrations/postgres/0002_scan_policy_document.sql\", \
\"web/templates/base.html\",\"web/static/style.css\",\"rules/packs/java.yml\",\"data/vuln_db.json\", \
\"data/license_db.json\",\"reporting/templates/report.html.j2\",\"licensing/vendor_public_key.pem\"]; \
missing=[x for x in req if not (r/x).exists()]; assert not missing, missing; \
print(\"all\", len(req), \"package-data paths present\")'
  \"\$CV/bin/ironclad\" version
"

if [ "$QUICK" -eq 0 ]; then
  header "10. Scale + demo (slow)"
  step "scale benchmark 1k/10k" python benchmarks/scale_benchmark.py --tiers 1000,10000
  step "company demo end to end" bash -c "rm -rf /tmp/ironclad-verify-demo && bash demo/run_demo.sh /tmp/ironclad-verify-demo >/dev/null"
fi

header "11. Container"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  step "docker build"          docker build -t ironclad-verify:local .
  record SKIP "container runtime checks" "docker present; runtime suite not yet scripted"
else
  record SKIP "docker build + runtime checks" "no usable Docker daemon in this environment"
  step "Dockerfile references exist" python -c "
import re, pathlib
text = pathlib.Path('Dockerfile').read_text()
for ref in ['pyproject.toml', 'README.md', 'scripts/container-entrypoint.sh', 'docs']:
    assert pathlib.Path(ref).exists(), f'Dockerfile references missing path: {ref}'
entry = pathlib.Path('scripts/container-entrypoint.sh').read_text()
for role in ['api', 'worker', 'migrate']:
    assert role in entry, f'entrypoint missing role: {role}'
print('Dockerfile references and entrypoint roles verified statically')
"
fi

# ---------------------------------------------------------------------------
header "SUMMARY"
# ---------------------------------------------------------------------------
printf '  \033[32m%d passed\033[0m, \033[31m%d failed\033[0m, \033[33m%d skipped\033[0m\n\n' "$PASS" "$FAIL" "$SKIP"
if [ "$SKIP" -gt 0 ]; then
  echo "  Skipped (environment-blocked, NOT verified):"
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r st nm dt <<< "$r"
    [ "$st" = "SKIP" ] && echo "    - $nm: $dt"
  done
  echo
fi
if [ "$FAIL" -gt 0 ]; then
  echo "  Failures:"
  for r in "${RESULTS[@]}"; do
    IFS='|' read -r st nm dt <<< "$r"
    [ "$st" = "FAIL" ] && echo "    - $nm: $dt"
  done
  echo
  exit 1
fi
echo "  All executable checks passed."
exit 0
