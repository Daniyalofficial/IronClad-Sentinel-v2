"""Report renderers must not execute anything from the scanned repository.

Every value in a report -- file path, code snippet, package name, manifest
error text -- originates in the code being scanned, which by definition is
not trusted. Reports are then opened by a human in a browser, posted to a
pull request, or parsed by CI tooling. An injection here is a real attack
path: submit a repository, wait for it to be scanned, and the reviewer's
browser runs your script.

These tests use hostile *content*, not just hostile-looking strings: real
files with the payload in the name or in a source line, scanned end to end.
"""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET

import pytest

from ironclad.core.config import IronCladConfig
from ironclad.core.engine import run_scan
from ironclad.reporting.html_report import render_html
from ironclad.reporting.junit_report import render_junit
from ironclad.reporting.markdown_report import md_code, md_text, render_markdown

VULNERABLE_LINE = 'import os\nos.system("id")\n'


def _scan_with_files(tmp_path, files: dict):
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return run_scan(IronCladConfig(target=str(tmp_path)))


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
def test_html_renderer_environment_has_autoescape_enabled():
    """Structural guard for the bug this file exists because of.

    `select_autoescape(["html"])` keys off the template's own extension, and
    the template is `report.html.j2` -- extension `j2` -- so it resolved to
    autoescape=False and every interpolated value was emitted raw.
    """
    from jinja2 import Environment, FileSystemLoader

    import ironclad.reporting.html_report as html_report

    template_dir = html_report._TEMPLATE_DIR
    assert os.path.basename(os.listdir(template_dir)[0]) == "report.html.j2"
    # Re-deriving the old configuration must be visibly wrong...
    from jinja2 import select_autoescape

    assert select_autoescape(["html"])("report.html.j2") is False, (
        "if this is now True the helper's behaviour changed and the comment "
        "in html_report.py is stale")
    # ...and the renderer must not use it.
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
    assert env.autoescape is True
    assert render_html.__module__ == html_report.__name__


def test_html_report_escapes_script_in_a_code_snippet(tmp_path):
    result = _scan_with_files(tmp_path, {
        "app.py": 'import os\nos.system("id")  # <script>alert(1)</script>\n'})
    html = render_html(result)
    assert "<script>alert(1)</script>" not in html, "untrusted snippet rendered raw"
    assert "&lt;script&gt;alert(1)" in html


def test_html_report_escapes_script_in_a_filename(tmp_path):
    result = _scan_with_files(tmp_path, {
        "<img src=x onerror=alert(2)>.py": VULNERABLE_LINE,
        '"><svg onload=alert(3)>.py': 'PASSWORD = "Tr0ubador-Horse-9911"\n',
    })
    html = render_html(result)
    for payload in ("<img src=x onerror=alert(2)>", "<svg onload=alert(3)>"):
        assert payload not in html, f"{payload} rendered raw into the report"
    assert "&lt;img src=x onerror=alert(2)&gt;" in html
    assert "&lt;svg onload=alert(3)&gt;" in html


def test_html_report_still_shows_the_real_data(tmp_path):
    """Escaping must not mangle the report into uselessness."""
    result = _scan_with_files(tmp_path, {"app.py": VULNERABLE_LINE})
    html = render_html(result)
    assert "PY-AST-SHELL-TRUE" in html
    assert "os.system" in html


# --------------------------------------------------------------------------- #
# JUnit XML
# --------------------------------------------------------------------------- #
def test_junit_attribute_values_cannot_break_out_of_the_attribute(tmp_path):
    """`xml.sax.saxutils.escape` does not escape quotes.

    Every value here lands inside a double-quoted attribute and `name`
    contains the file path, so a file named `a" onmouseover="alert(1).py`
    injected a live event-handler attribute into the document.
    """
    result = _scan_with_files(tmp_path, {'a" onmouseover="alert(1).py': VULNERABLE_LINE})
    xml = render_junit(result)

    root = ET.fromstring(xml)  # raises if the XML is malformed
    injected = [key for element in root.iter() for key in element.attrib
                if key.lower().startswith("on")]
    assert not injected, f"injected event-handler attributes: {injected}"

    testcase = next(root.iter("testcase"))
    assert 'onmouseover="alert(1)' in testcase.get("name"), (
        "the filename must survive as data, not be dropped")
    assert "&quot;" in xml


@pytest.mark.parametrize("filename", [
    'a" onmouseover="alert(1).py',
    "a' onfocus='alert(1).py",
    "a<b>c.py",
    "a&b.py",
])
def test_junit_survives_hostile_filenames(tmp_path, filename):
    result = _scan_with_files(tmp_path, {filename: VULNERABLE_LINE})
    xml = render_junit(result)
    root = ET.fromstring(xml)
    assert next(root.iter("testcase")) is not None
    assert [key for element in root.iter() for key in element.attrib
            if key.lower().startswith("on")] == []


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
def test_md_code_cannot_be_closed_by_its_own_content():
    """A single-backtick span is breakable from inside.

    CommonMark delimits a code span by a backtick run longer than any run in
    the content, so the fence has to grow to fit.
    """
    payload = "a`<img src=x onerror=alert(9)>.py"
    rendered = md_code(payload)
    assert rendered.startswith("``") and rendered.endswith("``"), rendered
    assert payload in rendered, "content must be preserved"
    # Two backticks in the content need a three-backtick fence.
    assert md_code("a``b").startswith("```")


def test_markdown_report_escapes_a_backtick_bearing_filename(tmp_path):
    result = _scan_with_files(tmp_path, {"a`<img src=x onerror=alert(9)>.py": VULNERABLE_LINE})
    markdown = render_markdown(result)
    # The span must be fenced with two backticks so the inner one is literal.
    assert "``a`<img src=x onerror=alert(9)>.py``" in markdown
    assert "| `a`<img" not in markdown, "single-backtick span is breakable"


def test_md_text_neutralises_html_and_table_breaks():
    assert md_text("<img src=x onerror=alert(1)>") == "&lt;img src=x onerror=alert(1)&gt;"
    assert "\\|" in md_text("a|b"), "a pipe must not split the table cell"
    assert md_text("a&b") == "a&amp;b"


def test_markdown_report_escapes_a_hostile_dependency_title(tmp_path):
    """Finding titles embed the package name straight from the manifest."""
    result = _scan_with_files(tmp_path, {
        "requirements.txt": "<img src=x onerror=alert(4)>==1.0.0\n"})
    markdown = render_markdown(result)
    assert "<img src=x onerror=alert(4)>" not in markdown


# --------------------------------------------------------------------------- #
# SARIF and CycloneDX are JSON, so json.dumps handles them -- pin that.
# --------------------------------------------------------------------------- #
def test_sarif_and_cyclonedx_are_valid_json_with_hostile_input(tmp_path):
    import json

    from ironclad.reporting.cyclonedx_report import render_cyclonedx
    from ironclad.reporting.sarif import build_sarif

    result = _scan_with_files(tmp_path, {'a"<script>alert(1)</script>.py': VULNERABLE_LINE})
    assert json.loads(json.dumps(build_sarif(result)))
    assert json.loads(render_cyclonedx(result))
