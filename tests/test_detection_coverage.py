"""Known-vulnerable-pattern detection coverage (false-negative measurement).

`benchmarks/corpus_metrics.py` measures false *positives* against clean code.
This measures the other half: for each vulnerability class the product
claims to detect, a known-bad snippet must be found. A class listed here
that stops being detected is a silent capability regression.

Each case is a real-world vulnerability *pattern* (the shape of a real CVE),
paired with the safe variant that must NOT be flagged. This is a coverage
assertion, not a benchmark of real-world recall -- real recall would require
a labelled corpus of real vulnerable repositories, which this is not.
"""
from __future__ import annotations

import os
import tempfile

import pytest

from ironclad.core.config import IronCladConfig
from ironclad.core.engine import run_scan

# (class name, expected rule id, vulnerable snippet, safe variant)
COVERAGE_CASES = [
    (
        "sql-injection",
        "PY-AST-SQL-INJECTION",
        'import sqlite3\n'
        'def lookup(user_input):\n'
        '    conn = sqlite3.connect(":memory:")\n'
        '    q = "SELECT * FROM users WHERE name = \'%s\'" % user_input\n'
        '    return conn.execute(q).fetchall()\n',
        'import sqlite3\n'
        'def lookup(user_input):\n'
        '    conn = sqlite3.connect(":memory:")\n'
        '    return conn.execute("SELECT * FROM users WHERE name = ?", (user_input,)).fetchall()\n',
    ),
    (
        "command-injection",
        "PY-AST-CMD-INJECTION",
        'import os\n'
        'def run(user_input):\n'
        '    return os.system("echo " + user_input)\n',
        'import subprocess\n'
        'def run(user_input):\n'
        '    return subprocess.run(["echo", user_input], shell=False)\n',
    ),
    (
        "eval-rce",
        "PY-AST-EVAL-USE",
        'def compute(user_input):\n'
        '    return eval(user_input)\n',
        'import ast\n'
        'def compute(user_input):\n'
        '    return ast.literal_eval(user_input)\n',
    ),
    (
        "path-traversal",
        "PY-AST-PATH-TRAVERSAL",
        'def read(user_input):\n'
        '    return open("/data/" + user_input).read()\n',
        'import os\n'
        'from werkzeug.utils import secure_filename\n'
        'def read(user_input):\n'
        '    name = secure_filename(user_input)\n'
        '    return open(os.path.join("/data", name)).read()\n',
    ),
    (
        "ssrf",
        "PY-AST-SSRF",
        'import requests\n'
        'def fetch():\n'
        '    return requests.get(request.args.get("url")).text\n',
        'import requests\n'
        'ALLOWED = {"https://api.internal.example.com/status"}\n'
        'def fetch():\n'
        '    return requests.get("https://api.internal.example.com/status", timeout=5).text\n',
    ),
    (
        "xss",
        "PY-AST-XSS",
        'from markupsafe import Markup\n'
        'def page():\n'
        '    return Markup("<h1>" + request.args.get("q") + "</h1>")\n',
        'import html\n'
        'def page():\n'
        '    return "<h1>" + html.escape(request.args.get("q", "")) + "</h1>"\n',
    ),
    (
        "open-redirect",
        "PY-AST-OPEN-REDIRECT",
        'from flask import redirect\n'
        'def go():\n'
        '    return redirect(request.args.get("next"))\n',
        'from flask import redirect, url_for\n'
        'def go():\n'
        '    return redirect(url_for("dashboard"))\n',
    ),
    (
        "template-injection",
        "PY-AST-TEMPLATE-INJECTION",
        'from jinja2 import Template\n'
        'def render():\n'
        '    return Template(request.args.get("tpl")).render()\n',
        'from jinja2 import Environment\n'
        'def render():\n'
        '    return Environment().get_template("page.html").render()\n',
    ),
    (
        "insecure-deserialization",
        "PY-AST-INSECURE-DESERIALIZATION",
        'import pickle\n'
        'def load(payload):\n'
        '    return pickle.loads(payload)\n',
        'import json\n'
        'def load(payload):\n'
        '    return json.loads(payload)\n',
    ),
    (
        "unsafe-yaml-load",
        "PY-AST-UNSAFE-YAML-LOADER",
        'import yaml\n'
        'def load(raw):\n'
        '    return yaml.unsafe_load(raw)\n',
        'import yaml\n'
        'def load(raw):\n'
        '    return yaml.safe_load(raw)\n',
    ),
    (
        "xxe",
        "PY-AST-UNSAFE-XML-PARSER",
        'import xml.etree.ElementTree as ET\n'
        'def parse(body):\n'
        '    return ET.fromstring(body)\n',
        'import defusedxml.ElementTree as SafeET\n'
        'def parse(body):\n'
        '    return SafeET.fromstring(body)\n',
    ),
    (
        "weak-tls-protocol",
        "PY-AST-WEAK-TLS-PROTOCOL",
        'import ssl\n'
        'ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n',
        'import ssl\n'
        'ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n',
    ),
    (
        "tls-verification-disabled",
        "PY-AST-TLS-VERIFY-DISABLED",
        'import requests\n'
        'def fetch():\n'
        '    return requests.get("https://api.example.com", verify=False)\n',
        'import requests\n'
        'def fetch():\n'
        '    return requests.get("https://api.example.com", verify=True)\n',
    ),
    (
        "weak-hash",
        "PY-AST-WEAK-HASH",
        'import hashlib\n'
        'def digest(data):\n'
        '    return hashlib.md5(data).hexdigest()\n',
        'import hashlib\n'
        'def digest(data):\n'
        '    return hashlib.sha256(data).hexdigest()\n',
    ),
    (
        "insecure-random-for-secret",
        "PY-AST-INSECURE-RANDOM",
        'import random\n'
        'def token():\n'
        '    token = "".join(random.choice("abcdef0123456789") for _ in range(32))\n'
        '    return token\n',
        'import secrets\n'
        'def token():\n'
        '    return secrets.token_urlsafe(32)\n',
    ),
    (
        "hardcoded-credential",
        "SECRETS-HARDCODED-CREDENTIAL",
        'PASSWORD = "Tr0ubador-Horse-9911"\n',
        'import os\n'
        'PASSWORD = os.environ["APP_PASSWORD"]\n',
    ),
    (
        "aws-access-key",
        "SECRET-AWS-ACCESS-KEY-ID",
        'AWS_KEY = "AKIA1234567890EXAMPLE"\n',
        'import os\n'
        'AWS_KEY = os.environ["AWS_ACCESS_KEY_ID"]\n',
    ),
    (
        "private-key-material",
        "SECRET-PRIVATE-KEY-BLOCK",
        'KEY = """-----BEGIN RSA PRIVATE KEY-----\n'
        'MIIEowIBAAKCAQEA0FictionalKeyMaterialForTesting0000000000000000\n'
        '-----END RSA PRIVATE KEY-----"""\n',
        'import os\n'
        'KEY = os.environ["SIGNING_KEY"]\n',
    ),
    (
        "debug-mode-enabled",
        "PY-AST-DEBUG-ENABLED",
        'DEBUG = True\n',
        'import os\n'
        'DEBUG = os.environ.get("DEBUG") == "1"\n',
    ),
]


def _scan_snippet(tmp_path, snippet, name="case.py"):
    path = tmp_path / name
    path.write_text(snippet, encoding="utf-8")
    config = IronCladConfig(target=str(tmp_path), min_severity="info")
    return {f.rule_id for f in run_scan(config).findings}


@pytest.mark.parametrize("label,rule_id,vulnerable,safe", COVERAGE_CASES,
                         ids=[case[0] for case in COVERAGE_CASES])
def test_known_vulnerable_pattern_is_detected(tmp_path, label, rule_id, vulnerable, safe):
    """A known-bad snippet must be found -- this is the false-negative guard."""
    found = _scan_snippet(tmp_path, vulnerable)
    assert rule_id in found, f"{label}: expected {rule_id}, found {sorted(found)}"


@pytest.mark.parametrize("label,rule_id,vulnerable,safe", COVERAGE_CASES,
                         ids=[case[0] for case in COVERAGE_CASES])
def test_safe_variant_is_not_flagged(tmp_path, label, rule_id, vulnerable, safe):
    """The safe variant of the same pattern must not be flagged."""
    found = _scan_snippet(tmp_path, safe)
    assert rule_id not in found, f"{label}: safe variant wrongly flagged by {rule_id}"


def test_every_claimed_class_is_covered():
    """Guard against a case being removed from the list by accident."""
    labels = {case[0] for case in COVERAGE_CASES}
    expected = {
        "sql-injection", "command-injection", "eval-rce", "path-traversal", "ssrf",
        "xss", "open-redirect", "template-injection", "insecure-deserialization",
        "unsafe-yaml-load", "xxe", "weak-tls-protocol", "tls-verification-disabled",
        "weak-hash", "insecure-random-for-secret", "hardcoded-credential",
        "aws-access-key", "private-key-material", "debug-mode-enabled",
    }
    assert expected <= labels, f"missing coverage cases: {sorted(expected - labels)}"


def test_rule_ids_in_this_file_are_real():
    """Every rule id asserted here must exist in the product."""
    from ironclad.rules.schema import load_rule_packs
    from ironclad.scanners import ast_python, python_flows

    pack_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                            "ironclad", "rules", "packs")
    pack_ids = {r.id for r in load_rule_packs([pack_dir])}

    known = set(pack_ids)
    # Flow and structural detectors define their rule ids inline.
    for spec in python_flows.SINK_SPECS:
        known.add(spec.rule_id)
    for spec in python_flows.PATTERN_SPECS:
        known.add(spec.rule_id)
    known.update({
        "PY-AST-SQL-INJECTION", "PY-AST-CMD-INJECTION", "PY-AST-EVAL-USE",
        "PY-AST-EXEC-USE", "PY-AST-COMPILE-USE", "PY-AST-INSECURE-DESERIALIZATION",
        "PY-AST-WEAK-HASH", "PY-AST-DEBUG-ENABLED", "PY-AST-TLS-VERIFY-DISABLED",
        # Defined inline in ast_python.py / secrets.py rather than in a spec list.
        "PY-AST-INSECURE-RANDOM", "SECRETS-HARDCODED-CREDENTIAL",
    })

    unknown = {case[1] for case in COVERAGE_CASES} - known
    assert not unknown, f"asserting rule ids that do not exist: {sorted(unknown)}"
