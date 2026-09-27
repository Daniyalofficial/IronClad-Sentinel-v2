"""HTML output contexts must distinguish data binding from HTML construction."""

from ironclad.scanners.python_flows import scan_python_flows


def _scan(tmp_path, source):
    path = tmp_path / "view.py"
    path.write_text(source, encoding="utf-8")
    return scan_python_flows(str(path), path.name)


def _xss_lines(findings):
    return [f.location.start_line for f in findings if f.rule_id == "PY-AST-XSS"]


def test_flask_route_returns_unescaped_html_from_request(tmp_path):
    findings = _scan(tmp_path,
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/hello')\n"
        "def hello():\n"
        "    name = request.args.get('name', '')\n"
        "    return f'<h1>Hello, {name}!</h1>'\n")
    assert _xss_lines(findings) == [6]


def test_flask_route_html_escape_is_not_reported(tmp_path):
    findings = _scan(tmp_path,
        "from flask import Flask, request\n"
        "import html\n"
        "app = Flask(__name__)\n"
        "@app.route('/hello')\n"
        "def hello():\n"
        "    return f'<h1>Hello, {html.escape(request.args.get(\"name\", \"\"))}!</h1>'\n")
    assert _xss_lines(findings) == []


def test_unrelated_helper_returning_a_string_is_not_a_web_response(tmp_path):
    findings = _scan(tmp_path,
        "def make_label(request):\n"
        "    return f'<h1>Hello, {request.args.get(\"name\")}!</h1>'\n")
    assert _xss_lines(findings) == []


def test_django_http_response_and_starlette_html_response_are_html_sinks(tmp_path):
    findings = _scan(tmp_path,
        "from django.http import HttpResponse\n"
        "from starlette.responses import HTMLResponse as Html\n"
        "def django_page(request):\n"
        "    return HttpResponse('User ' + str(request.POST.get('id')))\n"
        "def starlette_page():\n"
        "    return Html(f'<h1>{request.args.get(\"name\")}</h1>')\n")
    assert _xss_lines(findings) == [4, 6]


def test_template_context_is_autoescaped_and_does_not_taint_template(tmp_path):
    findings = _scan(tmp_path,
        "def safe_page():\n"
        "    return render_template_string('<h1>{{ name }}</h1>', "
        "name=request.args.get('name'))\n")
    assert not {'PY-AST-XSS', 'PY-AST-TEMPLATE-INJECTION'} & {f.rule_id for f in findings}


def test_imported_flask_template_renderer_detects_tainted_template_source(tmp_path):
    findings = _scan(tmp_path,
        "from flask import render_template_string as render\n"
        "def page():\n"
        "    return render(request.args.get('template'))\n")
    # The same user-controlled template is SSTI (CWE-1336), not a second
    # independent XSS alert at the identical source/sink pair.
    assert [f.rule_id for f in findings] == ['PY-AST-TEMPLATE-INJECTION']


def test_flask_json_html_echo_uses_modelled_request_source(tmp_path):
    findings = _scan(tmp_path,
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/hello')\n"
        "def hello():\n"
        "    data = request.get_json()\n"
        "    name = data.get('name')\n"
        "    return f'<h1>Hello, {name}!</h1>'\n")
    assert _xss_lines(findings) == [7]
