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

# Two independently maintained feeds are merged. They disagree with each
# other often enough to be worth having: the GitHub-reviewed set carries no
# advisory at all for some packages (click, for one), and PyPA's NVD-derived
# feed has records the reviewed set lacks. Merging is deduplicated by CVE,
# because the two feeds assign different identifiers to the same
# vulnerability.
SOURCE_REPO="https://github.com/github/advisory-database"
SOURCE_SUBDIR="advisories/github-reviewed"
SECOND_REPO="https://github.com/pypa/advisory-database"
SECOND_SUBDIR="vulns"
WORKDIR="${TMPDIR:-/tmp}/ironclad-advisory-src"
SECOND_WORKDIR="${TMPDIR:-/tmp}/ironclad-advisory-pypa"
OUTPUT="ironclad/data/vuln_db.json"
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1 && OUTPUT="$(mktemp -t ironclad-vulndb.XXXXXX.json)"

sync_feed() {  # <repo> <subdir> <workdir>
  local repo="$1" subdir="$2" workdir="$3"
  echo "==> advisory source: $repo"
  if [[ -d "$workdir/.git" ]]; then
    git -C "$workdir" fetch --depth 1 -q origin main
    git -C "$workdir" reset --hard -q FETCH_HEAD
  else
    rm -rf "$workdir"
    # --filter=blob:none --sparse keeps the checkout to the advisory records
    # rather than the full repository history.
    git clone --depth 1 --filter=blob:none --sparse -q "$repo" "$workdir"
    git -C "$workdir" sparse-checkout set "$subdir"
  fi
  [[ -d "$workdir/$subdir" ]] || { echo "error: $workdir/$subdir not found" >&2; exit 1; }
}

sync_feed "$SOURCE_REPO" "$SOURCE_SUBDIR" "$WORKDIR"
sync_feed "$SECOND_REPO" "$SECOND_SUBDIR" "$SECOND_WORKDIR"

ADVISORY_DIR="$WORKDIR/$SOURCE_SUBDIR"
SECOND_DIR="$SECOND_WORKDIR/$SECOND_SUBDIR"
echo "==> $(find "$ADVISORY_DIR" -name '*.json' | wc -l) GHSA records, $(find "$SECOND_DIR" -name '*.yaml' | wc -l) PyPA records"

GHSA_COMMIT="$(git -C "$WORKDIR" rev-parse HEAD)"
PYPA_COMMIT="$(git -C "$SECOND_WORKDIR" rev-parse HEAD)"
LABEL="github/advisory-database@${GHSA_COMMIT:0:12} + pypa/advisory-database@${PYPA_COMMIT:0:12}"
echo "==> generating $OUTPUT from $LABEL"
ironclad advisories import-osv --source "$ADVISORY_DIR" --source "$SECOND_DIR" \
  --output "$OUTPUT" --source-label "$LABEL"

if [[ "$DRY_RUN" == "1" ]]; then
  echo "==> dry run: wrote $OUTPUT ($(wc -c < "$OUTPUT") bytes); bundled database unchanged"
else
  echo "==> bundled database updated"
  ironclad advisories stats
fi
