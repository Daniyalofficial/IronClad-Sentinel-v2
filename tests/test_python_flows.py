"""Flow-detector tests (Phase 1 SAST): vulnerable, safe and edge cases.

Fixtures live in ``tests/security_corpus/flows/`` so the same files are
exercised by the corpus scan in CI -- a rule that regresses shows up both
here and in the corpus results.
"""
import os

import pytest

from ironclad.core.config import IronCladConfig
from ironclad.core.engine import run_scan
from ironclad.scanners.python_flows import (
    collect_import_aliases,
    resolve_name,
    scan_python_flows,
)

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "security_corpus", "flows")

#: rule id -> vulnerable fixture that must trigger it
VULNERABLE = {
    "PY-AST-PATH-TRAVERSAL": "vuln_path_traversal.py",
    "PY-AST-SSRF": "vuln_ssrf.py",
    "PY-AST-XSS": "vuln_xss.py",
    "PY-AST-OPEN-REDIRECT": "vuln_open_redirect.py",
    "PY-AST-UNSAFE-XML-PARSER": "vuln_xxe.py",
    "PY-AST-INSECURE-RANDOM": "vuln_insecure_random.py",
    "PY-AST-WEAK-TLS-PROTOCOL": "vuln_weak_tls.py",
    "PY-AST-TEMPLATE-INJECTION": "vuln_template_injection.py",
    "PY-AST-UNSAFE-YAML-LOADER": "vuln_yaml_loader.py",
}

#: every safe fixture must produce zero flow findings
SAFE_FIXTURES = [name for name in sorted(os.listdir(FIXTURE_DIR)) if name.startswith("safe_")]


def _scan(fixture):
    path = os.path.join(FIXTURE_DIR, fixture)
    return scan_python_flows(path, fixture)


@pytest.mark.parametrize("rule_id,fixture", sorted(VULNERABLE.items()))
def test_vulnerable_fixture_triggers_the_rule(rule_id, fixture):
    findings = _scan(fixture)
    assert rule_id in {f.rule_id for f in findings}, (
        f"{fixture} did not trigger {rule_id}; got {sorted({f.rule_id for f in findings})}")


@pytest.mark.parametrize("rule_id,fixture", sorted(VULNERABLE.items()))
def test_vulnerable_finding_is_complete(rule_id, fixture):
    finding = next(f for f in _scan(fixture) if f.rule_id == rule_id)
    assert finding.title
    assert finding.description
    assert finding.remediation, "every rule must ship remediation guidance"
    assert finding.cwe and finding.cwe.startswith("CWE-")
    assert finding.owasp
    assert finding.confidence in {"low", "medium", "high"}
    assert finding.severity.value in {"critical", "high", "medium", "low", "info"}
    assert finding.location.file_path == fixture
    assert finding.location.start_line >= 1
    assert finding.location.snippet
    assert finding.references, "every rule must cite at least one reference"


@pytest.mark.parametrize("fixture", SAFE_FIXTURES)
def test_safe_fixture_produces_no_flow_findings(fixture):
    findings = _scan(fixture)
    assert findings == [], [(f.rule_id, f.location.start_line) for f in findings]


def test_every_vulnerable_fixture_has_a_matching_safe_fixture():
    for rule_id, fixture in VULNERABLE.items():
        safe = "safe_" + fixture[len("vuln_"):]
        assert os.path.isfile(os.path.join(FIXTURE_DIR, safe)), (
            f"{rule_id}: vulnerable fixture {fixture} has no matching {safe}")


# --------------------------------------------------------------------------- #
# Edge cases
# --------------------------------------------------------------------------- #
def _scan_source(tmp_path, source):
    path = tmp_path / "case.py"
    path.write_text(source, encoding="utf-8")
    return scan_python_flows(str(path), "case.py")


def test_constant_path_is_not_flagged(tmp_path):
    assert _scan_source(tmp_path, 'with open("/etc/hosts") as fh:\n    data = fh.read()\n') == []


def test_sanitized_path_is_not_flagged(tmp_path):
    source = (
        "import os\n"
        "from werkzeug.utils import secure_filename\n"
        "def go(user_input):\n"
        "    return open(os.path.join('/data', secure_filename(user_input))).read()\n"
    )
    assert _scan_source(tmp_path, source) == []


def test_basename_sanitizer_is_not_flagged(tmp_path):
    source = (
        "import os\n"
        "def go(user_input):\n"
        "    return open(os.path.join('/data', os.path.basename(user_input))).read()\n"
    )
    assert _scan_source(tmp_path, source) == []


def test_taint_through_fstring_is_detected(tmp_path):
    source = (
        "def go(user_input):\n"
        "    return open(f'/data/{user_input}').read()\n"
    )
    assert [f.rule_id for f in _scan_source(tmp_path, source)] == ["PY-AST-PATH-TRAVERSAL"]


def test_taint_through_intermediate_variable_is_detected(tmp_path):
    source = (
        "def go(user_input):\n"
        "    target = user_input\n"
        "    other = target\n"
        "    return open('/data/' + other).read()\n"
    )
    assert [f.rule_id for f in _scan_source(tmp_path, source)] == ["PY-AST-PATH-TRAVERSAL"]


def test_taint_does_not_leak_across_functions(tmp_path):
    source = (
        "def source(user_input):\n"
        "    return user_input\n"
        "\n"
        "def sink():\n"
        "    return open('/data/static.txt').read()\n"
    )
    assert _scan_source(tmp_path, source) == []


def test_environment_variable_is_treated_as_untrusted(tmp_path):
    source = (
        "import os\n"
        "import requests\n"
        "requests.get(os.environ['UPSTREAM_URL'])\n"
    )
    assert [f.rule_id for f in _scan_source(tmp_path, source)] == ["PY-AST-SSRF"]


def test_url_for_redirect_is_not_flagged(tmp_path):
    source = (
        "from flask import redirect, url_for\n"
        "def go():\n"
        "    return redirect(url_for('index'))\n"
    )
    assert _scan_source(tmp_path, source) == []


def test_random_used_for_non_security_values_is_not_flagged(tmp_path):
    source = (
        "import random\n"
        "def pick():\n"
        "    return random.choice(['red', 'green', 'blue'])\n"
    )
    assert _scan_source(tmp_path, source) == []


def test_syntax_error_file_is_skipped_not_crashed(tmp_path):
    assert _scan_source(tmp_path, "def broken(:\n    pass\n") == []


def test_missing_file_is_skipped_not_crashed(tmp_path):
    assert scan_python_flows(str(tmp_path / "absent.py"), "absent.py") == []


def test_reassignment_to_a_constant_clears_taint(tmp_path):
    source = (
        "def go(user_input):\n"
        "    name = user_input\n"
        "    name = 'index.html'\n"
        "    return open('/data/' + name).read()\n"
    )
    assert _scan_source(tmp_path, source) == []


# --------------------------------------------------------------------------- #
# Import alias resolution
# --------------------------------------------------------------------------- #
def test_alias_resolution_expands_module_aliases(tmp_path):
    source = (
        "import xml.etree.ElementTree as ET\n"
        "import requests as r\n"
        "def go(body):\n"
        "    return ET.fromstring(body)\n"
    )
    path = tmp_path / "aliased.py"
    path.write_text(source, encoding="utf-8")
    import ast

    aliases = collect_import_aliases(ast.parse(source))
    assert resolve_name("ET.fromstring", aliases) == "xml.etree.ElementTree.fromstring"
    assert resolve_name("r.get", aliases) == "requests.get"
    assert resolve_name("unknown.thing", aliases) == "unknown.thing"


def test_aliased_import_still_triggers_xxe(tmp_path):
    source = (
        "import xml.dom.minidom as minidom_alias\n"
        "def go(body):\n"
        "    return minidom_alias.parseString(body)\n"
    )
    assert [f.rule_id for f in _scan_source(tmp_path, source)] == ["PY-AST-UNSAFE-XML-PARSER"]


def test_defusedxml_alias_is_not_flagged(tmp_path):
    source = (
        "import defusedxml.minidom as safe_minidom\n"
        "def go(body):\n"
        "    return safe_minidom.parseString(body)\n"
    )
    assert _scan_source(tmp_path, source) == []


# --------------------------------------------------------------------------- #
# Integration: the engine runs these detectors under the ast-python engine
# --------------------------------------------------------------------------- #
def test_engine_runs_flow_detectors_end_to_end():
    config = IronCladConfig(target=FIXTURE_DIR, enabled_engines=["ast-python"],
                            min_severity="info")
    result = run_scan(config)
    rule_ids = {f.rule_id for f in result.findings}
    assert set(VULNERABLE) <= rule_ids
    assert all(f.engine.value == "ast-python" for f in result.findings
               if f.rule_id.startswith("PY-AST-"))


def test_flow_findings_survive_reporting_round_trip():
    config = IronCladConfig(target=FIXTURE_DIR, enabled_engines=["ast-python"])
    result = run_scan(config)
    payload = result.to_dict()
    flow_findings = [f for f in payload["findings"] if f["rule_id"] in VULNERABLE]
    assert flow_findings
    for finding in flow_findings:
        assert finding["cwe"]
        assert finding["location"]["file_path"].endswith(".py")
