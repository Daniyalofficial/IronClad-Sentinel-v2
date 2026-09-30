"""Jinja Environment.from_string controls template syntax, not context data."""
from ironclad.scanners.python_flows import scan_python_flows


def _ssti_lines(tmp_path, source):
    path = tmp_path / "view.py"
    path.write_text(source, encoding="utf-8")
    return [finding.location.start_line for finding in scan_python_flows(str(path), path.name)
            if finding.rule_id == "PY-AST-TEMPLATE-INJECTION"]


def test_bound_jinja_environment_from_string_uses_tainted_template(tmp_path):
    lines = _ssti_lines(tmp_path,
        "from jinja2 import Environment as JEnv\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/')\n"
        "def page(username=None):\n"
        "    renderer = JEnv()\n"
        "    return renderer.from_string('Hello ' + username).render()\n")
    assert lines == [7]


def test_inline_jinja_environment_from_string_is_a_sink(tmp_path):
    lines = _ssti_lines(tmp_path,
        "from jinja2 import Environment\n"
        "from flask import request\n"
        "def page():\n"
        "    return Environment().from_string(request.args.get('template')).render()\n")
    assert lines == [4]


def test_fixed_template_with_autoescaped_context_is_not_template_injection(tmp_path):
    lines = _ssti_lines(tmp_path,
        "from jinja2 import Environment\n"
        "from flask import request\n"
        "def page():\n"
        "    renderer = Environment(autoescape=True)\n"
        "    return renderer.from_string('Hello {{ name }}').render("
        "name=request.args.get('name'))\n")
    assert lines == []


def test_unrelated_from_string_and_reassigned_environment_are_not_jinja_sinks(tmp_path):
    lines = _ssti_lines(tmp_path,
        "from jinja2 import Environment\n"
        "from flask import request\n"
        "def parse(parser):\n"
        "    parser.from_string(request.args.get('format'))\n"
        "    renderer = Environment()\n"
        "    renderer = parser\n"
        "    return renderer.from_string(request.args.get('template'))\n")
    assert lines == []
