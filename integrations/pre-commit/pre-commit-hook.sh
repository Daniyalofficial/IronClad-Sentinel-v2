#!/usr/bin/env bash
#
# IronClad Sentinel pre-commit hook.
#
# Install:
#   cp integrations/pre-commit/pre-commit-hook.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Behavior: runs a fast scan restricted to staged files only, and blocks
# the commit if any CRITICAL/HIGH finding is introduced. Everything runs
# locally on the developer's machine -- no network access required.

set -euo pipefail

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM || true)

if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

if ! command -v ironclad >/dev/null 2>&1; then
  echo "[ironclad] CLI not found on PATH -- skipping pre-commit scan (install with: pip install ironclad-sentinel)"
  exit 0
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# Copy staged files into a scratch tree preserving relative paths so the
# scanner only looks at what's about to be committed, not the whole repo.
while IFS= read -r file; do
  [ -f "$file" ] || continue
  mkdir -p "$TMP_DIR/$(dirname "$file")"
  git show ":$file" > "$TMP_DIR/$file" 2>/dev/null || cp "$file" "$TMP_DIR/$file"
done <<< "$STAGED_FILES"

echo "[ironclad] Scanning staged changes..."
if ! ironclad scan "$TMP_DIR" --format json --output-dir "$TMP_DIR/.ironclad-out" --fail-on high --quiet; then
  echo ""
  echo "[ironclad] COMMIT BLOCKED: high/critical severity findings detected in staged changes."
  echo "[ironclad] Review the report above, fix the issues, or use 'git commit --no-verify' to override (not recommended)."
  exit 1
fi

echo "[ironclad] No blocking findings. Proceeding with commit."
exit 0
