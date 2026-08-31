#!/usr/bin/env bash
# End-to-end company demonstration.
#
# Reproducible story, no hand-waving:
#
#   1. A realistic "company repository" is generated with several planted
#      vulnerabilities plus dependencies with known CVEs and a copyleft license.
#   2. IronClad scans it, produces findings + SBOM + license analysis + SARIF.
#   3. The CI gate fails on the findings.
#   4. A developer fixes the issues (the fix is a real code edit, not a
#      suppression and not a baseline entry).
#   5. The same gate now passes.
#
# Every number printed below comes from the tool's own output. Nothing is
# hardcoded or faked.
#
# Usage: bash demo/run_demo.sh [workdir]
set -euo pipefail

WORKDIR="${1:-$(mktemp -d /tmp/ironclad-demo.XXXXXX)}"
REPO="$WORKDIR/payments-api"
REPORTS="$WORKDIR/reports"
POLICY="$WORKDIR/policy.yaml"
BASELINE="$WORKDIR/baseline.json"

bold() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
note() { printf '    %s\n' "$1"; }

bold "Step 0 -- environment"
ironclad version
note "workdir: $WORKDIR"

# --------------------------------------------------------------------------- #
bold "Step 1 -- generate the company repository"
mkdir -p "$REPO"
cat > "$REPO/db.py" <<'PY'
import sqlite3


def find_user(user_input):
    conn = sqlite3.connect(":memory:")
    query = "SELECT * FROM users WHERE email = '%s'" % user_input
    return conn.execute(query).fetchall()
PY
cat > "$REPO/files.py" <<'PY'
import os

from flask import request


def download():
    name = request.args.get("name")
    with open(os.path.join("/var/data", name)) as handle:
        return handle.read()
PY
cat > "$REPO/integrations.py" <<'PY'
import requests
from flask import request


def proxy_fetch():
    return requests.get(request.args.get("url")).text
PY
cat > "$REPO/config.py" <<'PY'
DEBUG = True
SECRET_KEY = "hardcoded-development-secret-key-1234567890"
ALLOWED_HOSTS = ["*"]
PY
cat > "$REPO/requirements.txt" <<'TXT'
jinja2==3.1.2
requests==2.30.0
paramiko==3.3.0
TXT
note "generated 4 Python files + requirements.txt in $REPO"

# --------------------------------------------------------------------------- #
bold "Step 2 -- scan and produce every report format"
ironclad policy init --out "$POLICY"
ironclad policy validate "$POLICY"

set +e
ironclad scan "$REPO" \
  --policy "$POLICY" \
  --format json,sarif,html,markdown,junit,cyclonedx \
  --output-dir "$REPORTS" \
  --quiet
SCAN_EXIT=$?
set -e
note "scan exit code: $SCAN_EXIT (1 = security gate failed, as expected)"
note "reports written:"
for f in "$REPORTS"/*; do note "  $(basename "$f") ($(wc -c < "$f") bytes)"; done

bold "Step 3 -- what the gate objected to"
python - "$REPORTS/ironclad-report.json" <<'PY'
import json, sys
from collections import Counter

report = json.load(open(sys.argv[1]))
print(f"    grade={report['grade']} risk_score={report['risk_score']} "
      f"files={report['stats']['files_scanned']} findings={report['total_findings']}")
print(f"    severities: {report['severity_counts']}")
print("    rules triggered:")
for rule, count in Counter(f["rule_id"] for f in report["findings"]).most_common():
    print(f"      {count:>2}  {rule}")
PY

bold "Step 4 -- SBOM and license analysis"
ironclad sbom "$REPO" --out "$WORKDIR/sbom.cyclonedx.json" --project-name payments-api
ironclad sbom "$REPO" --out "$WORKDIR/sbom.spdx.json" --format spdx --project-name payments-api
python - "$WORKDIR/sbom.cyclonedx.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
print(f"    CycloneDX {doc['specVersion']}: {len(doc['components'])} components, "
      f"{len(doc.get('dependencies', []))} dependency nodes")
for c in doc["components"]:
    licenses = ",".join(l["license"]["id"] for l in c.get("licenses", [])) or "UNKNOWN"
    print(f"      {c['purl']:<45} {licenses}")
PY
note "license findings:"
ironclad scan "$REPO" --quiet --output-dir "$REPORTS" --format json >/dev/null 2>&1 || true
python - "$REPORTS/ironclad-report.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
lic = [f for f in report["findings"] if f["category"] == "license-compliance"]
dep = [f for f in report["findings"] if f["category"] == "vulnerable-dependency"]
for f in lic:
    print(f"      [{f['severity']:<8}] {f['rule_id']}: {f['title']}")
print(f"    vulnerable dependencies: {len(dep)}")
for f in dep:
    print(f"      [{f['severity']:<8}] {f['extra'].get('package')}@"
          f"{f['extra'].get('installed_version')} -> {f['extra'].get('cve')} "
          f"(fixed in {f['extra'].get('fixed_version')})")
PY

bold "Step 5 -- SARIF is valid and uploadable"
python - "$REPORTS/ironclad-report.sarif.json" <<'PY'
import json, sys
sarif = json.load(open(sys.argv[1]))
run = sarif["runs"][0]
print(f"    sarifVersion={sarif['version']} tool={run['tool']['driver']['name']} "
      f"results={len(run['results'])} rules={len(run['tool']['driver'].get('rules', []))}")
PY

bold "Step 6 -- baseline the backlog, then gate on new findings only"
ironclad baseline create "$REPO" --out "$BASELINE" --reason "DEMO-1 pre-existing backlog" \
  --expires-in-days 30 --created-by "secops@example.com"
ironclad baseline list "$BASELINE"
set +e
ironclad scan "$REPO" --policy "$POLICY" --baseline "$BASELINE" --quiet \
  --output-dir "$REPORTS"
BASELINED_EXIT=$?
set -e
note "gated with baseline: exit $BASELINED_EXIT (0 = accepted backlog does not block CI)"

bold "Step 7 -- developer fixes the code (real edits, no suppression)"
cat > "$REPO/db.py" <<'PY'
import sqlite3


def find_user(email):
    conn = sqlite3.connect(":memory:")
    return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchall()
PY
cat > "$REPO/files.py" <<'PY'
import os

from flask import request
from werkzeug.utils import secure_filename

DATA_ROOT = "/var/data"


def download():
    name = secure_filename(request.args.get("name", ""))
    candidate = os.path.realpath(os.path.join(DATA_ROOT, name))
    if not candidate.startswith(DATA_ROOT + os.sep):
        raise ValueError("path escapes the data root")
    with open(candidate) as handle:
        return handle.read()
PY
cat > "$REPO/integrations.py" <<'PY'
import requests

ALLOWED_UPSTREAMS = {
    "https://api.internal.example.com/v1/status",
}


def fetch_status():
    return requests.get("https://api.internal.example.com/v1/status", timeout=5).text
PY
cat > "$REPO/config.py" <<'PY'
import os

DEBUG = os.environ.get("APP_DEBUG") == "1"
SECRET_KEY = os.environ["APP_SECRET_KEY"]
ALLOWED_HOSTS = ["payments.example.com"]
PY
cat > "$REPO/requirements.txt" <<'TXT'
jinja2==3.1.4
requests==2.32.3
paramiko==3.4.1
TXT
note "rewrote 4 files with parameterised SQL, canonicalised paths, an"
note "allowlisted upstream, env-sourced secrets and patched dependencies"

bold "Step 8 -- re-scan: the same gate must now pass"
set +e
ironclad scan "$REPO" --policy "$POLICY" --quiet --output-dir "$REPORTS" \
  --format json,sarif
FIXED_EXIT=$?
set -e
python - "$REPORTS/ironclad-report.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
print(f"    grade={report['grade']} risk_score={report['risk_score']} "
      f"findings={report['total_findings']} severities={report['severity_counts']}")
for f in report["findings"]:
    print(f"      [{f['severity']:<8}] {f['rule_id']} {f['location']['file_path']}:"
          f"{f['location']['start_line']}")
PY
note "post-fix scan exit code: $FIXED_EXIT"

bold "Step 9 -- fixed findings are visible as resolved"
ironclad baseline diff "$REPO" --baseline "$BASELINE" || true

bold "Result"
if [ "$SCAN_EXIT" -eq 1 ] && [ "$BASELINED_EXIT" -eq 0 ] && [ "$FIXED_EXIT" -eq 0 ]; then
  echo "    PASS -- vulnerable tree failed the gate, baselined backlog did not"
  echo "           block CI, and the fixed tree passes the same gate."
else
  echo "    UNEXPECTED -- exits were scan=$SCAN_EXIT baselined=$BASELINED_EXIT fixed=$FIXED_EXIT"
  exit 1
fi
echo "    artifacts: $WORKDIR"
