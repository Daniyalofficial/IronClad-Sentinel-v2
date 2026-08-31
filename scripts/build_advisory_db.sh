#!/usr/bin/env bash
# Regenerate ironclad/data/vuln_db.json from the public GitHub Advisory
# Database.
#
# The bundled advisory database is generated data, not hand-written: every
# advisory id, affected range, severity and CVE alias in it comes from
# github/advisory-database, which is the same data osv.dev serves. This
# script is how that file is produced, so its provenance is reproducible
# rather than asserted.
#
#   bash scripts/build_advisory_db.sh            # full regeneration
#   bash scripts/build_advisory_db.sh --dry-run  # build to a temp file only
#
# Requires network access to github.com. IronClad itself never fetches
# advisories at scan time; this is a release-time build step.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SOURCE_REPO="https://github.com/github/advisory-database"
WORKDIR="${TMPDIR:-/tmp}/ironclad-advisory-src"
OUTPUT="ironclad/data/vuln_db.json"
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1 && OUTPUT="$(mktemp -t ironclad-vulndb.XXXXXX.json)"

echo "==> advisory source: $SOURCE_REPO"
if [[ -d "$WORKDIR/.git" ]]; then
  git -C "$WORKDIR" fetch --depth 1 -q origin main
  git -C "$WORKDIR" reset --hard -q FETCH_HEAD
else
  rm -rf "$WORKDIR"
  # --filter=blob:none --sparse keeps the checkout to the reviewed advisories
  # rather than the full repository history.
  git clone --depth 1 --filter=blob:none --sparse -q "$SOURCE_REPO" "$WORKDIR"
  git -C "$WORKDIR" sparse-checkout set advisories/github-reviewed
fi

ADVISORY_DIR="$WORKDIR/advisories/github-reviewed"
[[ -d "$ADVISORY_DIR" ]] || { echo "error: $ADVISORY_DIR not found" >&2; exit 1; }
echo "==> $(find "$ADVISORY_DIR" -name '*.json' | wc -l) advisory records available"

UPSTREAM_COMMIT="$(git -C "$WORKDIR" rev-parse HEAD)"
LABEL="github/advisory-database (advisories/github-reviewed) at ${UPSTREAM_COMMIT}"
echo "==> generating $OUTPUT from $LABEL"
ironclad advisories import-osv --source "$ADVISORY_DIR" --output "$OUTPUT" \
  --source-label "$LABEL"

if [[ "$DRY_RUN" == "1" ]]; then
  echo "==> dry run: wrote $OUTPUT ($(wc -c < "$OUTPUT") bytes); bundled database unchanged"
else
  echo "==> bundled database updated"
  ironclad advisories stats
fi
