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


def test_sql_injection_from_flask_json_flows_through_get_and_assignment():
    findings = _scan_source(
        "from flask import request\n"
        "def login():\n"
        "    payload = request.get_json()\n"
        "    username = payload.get('username')\n"
        "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
        "    db.session.execute(query)\n"
    )
    assert [(f.rule_id, f.location.start_line) for f in findings
            if f.rule_id == "PY-AST-SQL-INJECTION"] == [("PY-AST-SQL-INJECTION", 5)]


def test_sqlalchemy_text_interpolation_of_graphql_resolver_argument():
    findings = _scan_source(
        "from sqlalchemy import text as sql_text\n"
        "class Queries:\n"
        "    def resolve_pastes(self, info, filter=None):\n"
        "        return Paste.query.filter(sql_text(\"title = '%s' OR content = '%s'\" % (filter, filter)))\n"
    )
    assert [(f.rule_id, f.location.start_line) for f in findings
            if f.rule_id == "PY-AST-SQL-INJECTION"] == [("PY-AST-SQL-INJECTION", 4)]


def test_sqlalchemy_text_with_bound_parameter_or_non_sql_text_is_not_injection():
    findings = _scan_source(
        "from sqlalchemy import text as sql_text\n"
        "def text(data):\n"
        "    return data\n"
        "class Queries:\n"
        "    def resolve_pastes(self, info, filter=None):\n"
        "        safe = sql_text('title = :title').bindparams(title=filter)\n"
        "        prose = text('welcome ' + filter)\n"
        "        return safe, prose\n"
    )
    assert "PY-AST-SQL-INJECTION" not in {f.rule_id for f in findings}


def test_sql_bind_parameter_may_be_untrusted_without_injecting_the_query():
    findings = _scan_source(
        "def search(request):\n"
        "    cursor.execute('SELECT * FROM t WHERE id = :id', request.args)\n"
    )
    assert "PY-AST-SQL-INJECTION" not in {f.rule_id for f in findings}


def test_sqlalchemy_text_import_shadowed_by_local_name_is_not_a_sql_sink():
    findings = _scan_source(
        "from sqlalchemy import text\n"
        "def page(request):\n"
        "    text = str\n"
        "    return text('Hello ' + request.args['name'])\n"
    )
    assert "PY-AST-SQL-INJECTION" not in {f.rule_id for f in findings}


def test_function_local_sqlalchemy_import_does_not_bleed_to_another_function():
    findings = _scan_source(
        "def sql(request):\n"
        "    from sqlalchemy import text as sql_text\n"
        "    return sql_text('SELECT * FROM t WHERE name = ' + request.args['name'])\n"
        "def prose(request):\n"
        "    def sql_text(value):\n"
        "        return value\n"
        "    return sql_text('Hello ' + request.args['name'])\n"
    )
    assert [(f.rule_id, f.location.start_line) for f in findings
            if f.rule_id == "PY-AST-SQL-INJECTION"] == [("PY-AST-SQL-INJECTION", 3)]


def test_dynamic_sql_query_is_still_detected_with_safe_bind_values():
    findings = _scan_source(
        "def search(request):\n"
        "    cursor.execute(f'SELECT * FROM {request.args[\"table\"]} WHERE id = :id', "
        "request.args)\n"
    )
    assert "PY-AST-SQL-INJECTION" in {f.rule_id for f in findings}


def test_distinct_sql_queries_sharing_the_same_sink_are_not_deduplicated(tmp_path):
    from ironclad.core.baseline import create_baseline
    from ironclad.core.config import IronCladConfig
    from ironclad.core.engine import run_scan

    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(
        "def by_name(request):\n"
        "    query = f\"SELECT * FROM users WHERE name = '{request.args['name']}'\"\n"
        "    db.execute(query)\n"
        "\n"
        "def by_email(request):\n"
        "    query = f\"SELECT * FROM users WHERE email = '{request.args['email']}'\"\n"
        "    db.execute(query)\n",
        encoding="utf-8",
    )
    config = IronCladConfig(target=str(project), enabled_engines=["ast-python"],
                            report_formats=["json"])
    scan = run_scan(config)
    sql = [f for f in scan.findings if f.rule_id == "PY-AST-SQL-INJECTION"]
    assert [f.location.start_line for f in sql] == [2, 6]
    assert len({f.fingerprint for f in sql}) == 2

    # Accepting the first injection must never silently accept the second.
    baseline = tmp_path / "baseline.json"
    create_baseline(sql[:1], reason="SEC-1").save(str(baseline))
    config.baseline_file = str(baseline)
    with_baseline = run_scan(config)
    assert [f.location.start_line for f in with_baseline.new_findings
            if f.rule_id == "PY-AST-SQL-INJECTION"] == [6]
    assert with_baseline.baseline_suppressed == 1
