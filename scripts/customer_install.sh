#!/usr/bin/env bash
#
# Customer-facing installer for IronClad Sentinel.
# Run this ON THE CUSTOMER'S MACHINE (their laptop, CI runner, or an
# air-gapped server) after you have delivered:
#   - the wheel file (ironclad_sentinel-X.Y.Z-py3-none-any.whl), or
#   - the standalone binary (ironclad-sentinel), and
#   - their signed license.json
#
# This script performs NO network calls other than the local pip install
# of the wheel you provided (which itself has zero runtime network
# dependencies once installed).

set -euo pipefail

INSTALL_DIR="${IRONCLAD_INSTALL_DIR:-$HOME/.local/share/ironclad-sentinel}"
LICENSE_DIR="$HOME/.ironclad"
WHEEL_FILE="${1:-}"
LICENSE_FILE="${2:-}"

if [ -z "$WHEEL_FILE" ] || [ ! -f "$WHEEL_FILE" ]; then
  echo "Usage: $0 <path-to-ironclad_sentinel-*.whl> <path-to-license.json>"
  exit 1
fi

echo "=== Installing IronClad Sentinel ==="
mkdir -p "$INSTALL_DIR" "$LICENSE_DIR"

python3 -m venv "$INSTALL_DIR/venv"
# shellcheck disable=SC1091
source "$INSTALL_DIR/venv/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet "$WHEEL_FILE"

if [ -n "$LICENSE_FILE" ] && [ -f "$LICENSE_FILE" ]; then
  cp "$LICENSE_FILE" "$LICENSE_DIR/license.json"
  echo "License installed at $LICENSE_DIR/license.json"
fi

BIN_LINK="/usr/local/bin/ironclad"
if [ -w "$(dirname "$BIN_LINK")" ]; then
  ln -sf "$INSTALL_DIR/venv/bin/ironclad" "$BIN_LINK"
  echo "Symlinked CLI to $BIN_LINK"
else
  echo "Add this to your shell profile to use the 'ironclad' command:"
  echo "  export PATH=\"$INSTALL_DIR/venv/bin:\$PATH\""
fi

echo ""
echo "=== Installation complete ==="
"$INSTALL_DIR/venv/bin/ironclad" license status || true
echo ""
echo "Run a scan with:  ironclad scan /path/to/your/project"
