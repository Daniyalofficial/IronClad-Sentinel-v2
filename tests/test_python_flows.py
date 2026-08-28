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


# --------------------------------------------------------------------------- #
# Precision regressions found by scanning five real OSS projects
# (flask, click, requests, httpx, jinja2 — see docs/REAL_WORLD_CORPUS.md)
# --------------------------------------------------------------------------- #
def test_usedforsecurity_false_is_not_a_weak_hash(tmp_path):
    """`hashlib.md5(x, usedforsecurity=False)` is the stdlib's own escape hatch.

    Found on requests/src/requests/auth.py, which sets the flag on every
    digest because HTTP digest auth is not a security-sensitive use.
    """
    source = (
        "import hashlib\n"
        "\n"
        "\n"
        "def digest(x):\n"
        "    return hashlib.md5(x, usedforsecurity=False).hexdigest()\n"
    )
    findings = _scan_source(tmp_path, source)
    assert "PY-AST-WEAK-HASH" not in {f.rule_id for f in findings}


def test_weak_hash_without_the_flag_is_still_reported(tmp_path):
    # WEAK-HASH lives in the structural visitor, so this goes through
    # scan_python_file rather than the flow scanner.
    from ironclad.scanners.ast_python import scan_python_file

    source = "import hashlib\n\n\ndef digest(x):\n    return hashlib.md5(x).hexdigest()\n"
    path = tmp_path / "weak.py"
    path.write_text(source, encoding="utf-8")
    assert "PY-AST-WEAK-HASH" in {f.rule_id for f in scan_python_file(str(path), "weak.py")}


def test_assert_on_an_authority_identifier_is_not_a_security_check(tmp_path):
    """A substring test for "auth" matched `authority_match` in httpx.

    httpx/httpx/_urlparse.py:306 is a URL-parser invariant, not an
    authorization check.
    """
    source = (
        "def parse(url):\n"
        "    authority_match = match(url)\n"
        "    assert authority_match is not None\n"
        "    return authority_match\n"
    )
    findings = _scan_source(tmp_path, source)
    assert "PY-AST-ASSERT-SECURITY-CHECK" not in {f.rule_id for f in findings}


def test_genuine_auth_assert_is_still_reported(tmp_path):
    from ironclad.scanners.ast_python import scan_python_file

    source = (
        "def handle(user):\n"
        "    assert user.is_authenticated\n"
        "    return user\n"
    )
    path = tmp_path / "authz.py"
    path.write_text(source, encoding="utf-8")
    fired = {f.rule_id for f in scan_python_file(str(path), "authz.py")}
    assert "PY-AST-ASSERT-SECURITY-CHECK" in fired


def test_assert_rule_is_skipped_entirely_in_test_files(tmp_path):
    """`assert` is the correct idiom in tests; 86 of 87 hits were test files."""
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    path = test_dir / "test_auth.py"
    path.write_text("def test_it():\n    assert user_authenticated is True\n", encoding="utf-8")
    from ironclad.scanners.ast_python import scan_python_file

    assert scan_python_file(str(path), "tests/test_auth.py") == []


def test_credential_named_namespace_prefix_is_not_a_secret(tmp_path):
    """`TOKEN_COMMENT_BEGIN` is a lexer constant, not a credential.

    Found on jinja2/src/jinja2/lexer.py, which produced 12 findings from one
    dictionary of token-type names.
    """
    from ironclad.core.walker import DiscoveredFile
    from ironclad.scanners.secrets import scan_file_for_secrets

    path = tmp_path / "lexer.py"
    path.write_text(
        'TOKEN_COMMENT_BEGIN = "begin of comment"\n'
        'TOKEN_VARIABLE_END = "end of print statement"\n',
        encoding="utf-8")
    discovered = DiscoveredFile(path=str(path), rel_path="lexer.py", language="python",
                                size_bytes=path.stat().st_size)
    assert scan_file_for_secrets(discovered) == []


def test_real_credential_shaped_name_is_still_reported(tmp_path):
    from ironclad.core.walker import DiscoveredFile
    from ironclad.scanners.secrets import scan_file_for_secrets

    path = tmp_path / "cfg.py"
    path.write_text('API_TOKEN = "Zk9pQ2xR7vN4mT8sW1yB6dF3hJ0aL5e"\n', encoding="utf-8")
    discovered = DiscoveredFile(path=str(path), rel_path="cfg.py", language="python",
                                size_bytes=path.stat().st_size)
    assert scan_file_for_secrets(discovered), "a two-segment credential name must still fire"


def test_docstring_examples_do_not_trigger_rules(tmp_path):
    """Documentation examples are prose, not live configuration.

    Found on flask/src/flask/config.py (DEBUG = True / SECRET_KEY = '...'
    inside the from_object docstring) and httpx/httpx/_urls.py (a basic-auth
    URL inside a docstring).
    """
    source = (
        'def from_object(obj):\n'
        '    """Load configuration from an object.\n'
        '\n'
        '    For example::\n'
        '\n'
        '        DEBUG = True\n'
        "        SECRET_KEY = 'development key'\n"
        '    """\n'
        '    return obj\n'
    )
    path = tmp_path / "config.py"
    path.write_text(source, encoding="utf-8")

    from ironclad.core.walker import DiscoveredFile
    from ironclad.rules.schema import load_rule_packs
    from ironclad.scanners.rule_engine import scan_file_with_rules

    discovered = DiscoveredFile(path=str(path), rel_path="config.py", language="python",
                                size_bytes=path.stat().st_size)
    rules = load_rule_packs([str(tmp_path.parent.parent / "IronClad-Sentinel-v2"
                                 / "ironclad" / "rules" / "packs")])
    if not rules:  # fall back to the installed package location
        import ironclad, os
        rules = load_rule_packs([os.path.join(os.path.dirname(ironclad.__file__), "rules", "packs")])
    fired = {f.rule_id for f in scan_file_with_rules(discovered, rules)}
    assert "PY-DJANGO-DEBUG-TRUE" not in fired
    assert "PY-DJANGO-SECRET-HARDCODED" not in fired


def test_live_configuration_outside_a_docstring_is_still_reported(tmp_path):
    source = "DEBUG = True\nSECRET_KEY = 'a-real-development-key-1234'\n"
    path = tmp_path / "live.py"
    path.write_text(source, encoding="utf-8")

    from ironclad.core.walker import DiscoveredFile
    from ironclad.rules.schema import load_rule_packs
    from ironclad.scanners.rule_engine import scan_file_with_rules
    import ironclad, os

    discovered = DiscoveredFile(path=str(path), rel_path="live.py", language="python",
                                size_bytes=path.stat().st_size)
    rules = load_rule_packs([os.path.join(os.path.dirname(ironclad.__file__), "rules", "packs")])
    fired = {f.rule_id for f in scan_file_with_rules(discovered, rules)}
    assert "PY-DJANGO-DEBUG-TRUE" in fired
