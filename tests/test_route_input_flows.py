"""HTTP route placeholders are attacker-controlled parameters, not helpers."""

from ironclad.scanners.python_flows import scan_python_flows


def _scan(tmp_path, source):
    target = tmp_path / "routes.py"
    target.write_text(source, encoding="utf-8")
    return scan_python_flows(str(target), target.name)


def _hits(findings, rule_id):
    return [f.location.start_line for f in findings if f.rule_id == rule_id]


def test_flask_path_converter_flows_to_filesystem(tmp_path):
    findings = _scan(tmp_path,
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/download/<path:filename>')\n"
        "def download(filename):\n"
        "    return open('/srv/uploads/' + filename).read()\n")
    assert _hits(findings, "PY-AST-PATH-TRAVERSAL") == [5]


def test_starlette_url_placeholder_flows_to_ssrf_sink(tmp_path):
    findings = _scan(tmp_path,
        "from fastapi import APIRouter\n"
        "import requests\n"
        "router = APIRouter()\n"
        "@router.get('/proxy/{destination:path}')\n"
        "def proxy(destination):\n"
        "    return requests.get(destination, timeout=2).text\n")
    assert _hits(findings, "PY-AST-SSRF") == [6]


def test_non_route_helper_and_unbound_dependency_are_not_assumed_remote(tmp_path):
    findings = _scan(tmp_path,
        "from fastapi import APIRouter, Depends\n"
        "import requests\n"
        "router = APIRouter()\n"
        "def internal_helper(url):\n"
        "    return requests.get(url).text\n"
        "@router.get('/items/{item_id}')\n"
        "def item(item_id, dependency=Depends(internal_helper)):\n"
        "    return requests.get(dependency).text\n")
    assert _hits(findings, "PY-AST-SSRF") == []


def test_fastapi_scalar_query_parameter_is_remote_input(tmp_path):
    findings = _scan(tmp_path,
        "from fastapi import FastAPI\n"
        "import requests\n"
        "app = FastAPI()\n"
        "@app.get('/proxy')\n"
        "def proxy(url: str = 'https://example.org'):\n"
        "    return requests.get(url, timeout=2).text\n")
    assert _hits(findings, "PY-AST-SSRF") == [6]


def test_fastapi_query_parameter_flows_into_html_response(tmp_path):
    findings = _scan(tmp_path,
        "from fastapi import FastAPI\n"
        "from fastapi.responses import HTMLResponse\n"
        "app = FastAPI()\n"
        "@app.get('/hello')\n"
        "def hello(name: str = 'Guest'):\n"
        "    return HTMLResponse(f'<h1>Hello {name}</h1>')\n")
    assert _hits(findings, "PY-AST-XSS") == [6]


def test_fastapi_dependency_and_request_injections_are_not_tainted_params(tmp_path):
    findings = _scan(tmp_path,
        "from fastapi import APIRouter, Depends, Request\n"
        "import requests\n"
        "router = APIRouter()\n"
        "@router.get('/proxy')\n"
        "def proxy(db=Depends(lambda: None), request: Request = None):\n"
        "    requests.get(db)\n"
        "    return requests.get(request).text\n")
    assert _hits(findings, "PY-AST-SSRF") == []


def test_flask_get_decorator_does_not_bind_non_placeholder_parameters(tmp_path):
    findings = _scan(tmp_path,
        "from flask import Flask\n"
        "import requests\n"
        "app = Flask(__name__)\n"
        "@app.get('/proxy')\n"
        "def proxy(url='https://example.org'):\n"
        "    return requests.get(url).text\n")
    assert _hits(findings, "PY-AST-SSRF") == []


def test_escaped_route_placeholder_is_not_html_injection(tmp_path):
    findings = _scan(tmp_path,
        "from flask import Flask\n"
        "import html\n"
        "app = Flask(__name__)\n"
        "@app.route('/user/<name>')\n"
        "def view(name):\n"
        "    return '<h1>' + html.escape(name) + '</h1>'\n")
    assert _hits(findings, "PY-AST-XSS") == []
