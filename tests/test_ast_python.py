import os
import tempfile

from ironclad.scanners.ast_python import scan_python_file


def _scan_source(source: str):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as fh:
        fh.write(source)
        path = fh.name
    try:
        return scan_python_file(path, os.path.basename(path))
    finally:
        os.unlink(path)


def test_detects_command_injection():
    findings = _scan_source(
        "import subprocess\n"
        "def run(user_input):\n"
        "    cmd = 'echo ' + user_input\n"
        "    subprocess.run(cmd, shell=True)\n"
    )
    rule_ids = {f.rule_id for f in findings}
    assert "PY-AST-CMD-INJECTION" in rule_ids


def test_detects_sql_injection():
    findings = _scan_source(
        "def search(request):\n"
        "    q = request.args.get('q')\n"
        "    cursor.execute('SELECT * FROM t WHERE x = %s' % q)\n"
    )
    rule_ids = {f.rule_id for f in findings}
    assert "PY-AST-SQL-INJECTION" in rule_ids


def test_detects_eval_use():
    findings = _scan_source("x = eval(input())\n")
    rule_ids = {f.rule_id for f in findings}
    assert "PY-AST-EVAL-USE" in rule_ids


def test_detects_pickle_deserialization():
    findings = _scan_source(
        "import pickle\n"
        "def load(data):\n"
        "    return pickle.loads(data)\n"
    )
    rule_ids = {f.rule_id for f in findings}
    assert "PY-AST-INSECURE-DESERIALIZATION" in rule_ids


def test_yaml_safe_load_not_flagged():
    findings = _scan_source(
        "import yaml\n"
        "def load(data):\n"
        "    return yaml.load(data, Loader=yaml.SafeLoader)\n"
    )
    rule_ids = {f.rule_id for f in findings}
    assert "PY-AST-INSECURE-DESERIALIZATION" not in rule_ids


def test_detects_weak_hash():
    findings = _scan_source("import hashlib\nhashlib.md5(b'x')\n")
    rule_ids = {f.rule_id for f in findings}
    assert "PY-AST-WEAK-HASH" in rule_ids


def test_detects_tls_verify_disabled():
    findings = _scan_source("import requests\nrequests.get('https://x', verify=False)\n")
    rule_ids = {f.rule_id for f in findings}
    assert "PY-AST-TLS-VERIFY-DISABLED" in rule_ids


def test_detects_assert_security_check():
    findings = _scan_source(
        "def check(user):\n"
        "    assert user.is_admin\n"
    )
    rule_ids = {f.rule_id for f in findings}
    assert "PY-AST-ASSERT-SECURITY-CHECK" in rule_ids


def test_detects_mutable_default_arg():
    findings = _scan_source("def f(x, items=[]):\n    items.append(x)\n")
    rule_ids = {f.rule_id for f in findings}
    assert "PY-AST-MUTABLE-DEFAULT-ARG" in rule_ids


def test_clean_code_produces_no_findings():
    findings = _scan_source(
        "def add(a, b):\n"
        "    return a + b\n"
    )
    assert findings == []


def test_syntax_error_does_not_crash():
    findings = _scan_source("def broken(:\n")
    assert findings == []
