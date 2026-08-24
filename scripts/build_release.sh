#!/usr/bin/env bash
#
# Builds distributable IronClad Sentinel artifacts:
#   1. A standard Python wheel + sdist (for customers who install via pip
#      into their own air-gapped package index / artifact repository).
#   2. A single-file standalone executable via PyInstaller (for customers
#      who want a zero-dependency binary with no Python install required
#      at all -- the strongest "on-prem CLI" packaging option and the
#      easiest to hand a security team that will run it in a locked-down
#      environment).
#
# Run this on YOUR build machine, never on a customer machine.

set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== IronClad Sentinel release build ==="

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate

pip install --quiet --upgrade pip build pyinstaller
pip install --quiet -e .

echo "--- Running test suite before packaging ---"
pip install --quiet pytest
python -m pytest tests/ -q

echo "--- Building wheel + sdist ---"
rm -rf dist build *.egg-info
python -m build

echo "--- Building standalone single-file binary (PyInstaller) ---"
pyinstaller \
  --onefile \
  --name ironclad-sentinel \
  --add-data "ironclad/rules/packs:ironclad/rules/packs" \
  --add-data "ironclad/data:ironclad/data" \
  --add-data "ironclad/reporting/templates:ironclad/reporting/templates" \
  --add-data "ironclad/licensing/vendor_public_key.pem:ironclad/licensing" \
  --hidden-import ironclad.scanners.ast_python \
  --hidden-import ironclad.scanners.rule_engine \
  --hidden-import ironclad.scanners.secrets \
  --hidden-import ironclad.scanners.dependency \
  --hidden-import ironclad.scanners.iac \
  --hidden-import ironclad.scanners.sbom \
  ironclad/cli.py

echo ""
echo "=== Build complete ==="
echo "Wheel/sdist: ./dist/*.whl, ./dist/*.tar.gz"
echo "Standalone binary: ./dist/ironclad-sentinel"
echo ""
echo "Distribute the wheel to customers with a Python environment, or the"
echo "standalone binary to customers who want zero Python dependency."
