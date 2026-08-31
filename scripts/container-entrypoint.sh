#!/usr/bin/env bash
# Container entrypoint: apply migrations, then run the requested role.
#
# Roles:
#   api     - HTTP API + dashboard (default)
#   worker  - background scan worker
#   migrate - apply migrations and exit
#   shell   - drop into a shell (debugging)
set -euo pipefail

: "${IRONCLAD_DATABASE_URL:?IRONCLAD_DATABASE_URL must be set}"

role="${1:-api}"
shift || true

case "$role" in
  migrate)
    python - <<'PY'
from ironclad.platform.database import build_engine, run_migrations
applied = run_migrations(build_engine(), verbose=True)
print(f"migrations applied: {applied or 'none (already up to date)'}")
PY
    ;;
  api)
    python - <<'PY'
from ironclad.platform.database import build_engine, run_migrations
run_migrations(build_engine(), verbose=True)
PY
    exec uvicorn ironclad.api.app:create_app --factory \
        --host "${IRONCLAD_BIND_HOST:-0.0.0.0}" \
        --port "${IRONCLAD_PORT:-8000}" \
        --proxy-headers \
        --forwarded-allow-ips "${IRONCLAD_FORWARDED_ALLOW_IPS:-*}" \
        --workers "${IRONCLAD_API_WORKERS:-1}"
    ;;
  worker)
    exec ironclad server worker "${@}"
    ;;
  shell)
    exec /bin/bash "${@}"
    ;;
  *)
    echo "unknown role: $role (expected api|worker|migrate|shell)" >&2
    exit 2
    ;;
esac
