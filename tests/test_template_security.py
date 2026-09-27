"""Django/Jinja templates: explicit autoescape bypass is an HTML sink."""

from jinja2 import Environment

from ironclad.core.config import IronCladConfig
from ironclad.core.engine import run_scan
from ironclad.core.walker import classify


def _findings(tmp_path, files):
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    result = run_scan(IronCladConfig(target=str(tmp_path), enabled_engines=["rule-engine"],
                                     report_formats=["json"]))
    return [f for f in result.findings if f.rule_id == "JINJA-UNESCAPED-SAFE-FILTER"]


def test_explicit_safe_filter_in_html_template_is_reported(tmp_path):
    findings = _findings(tmp_path, {"templates/profile.html": "<h1>{{ user.bio | safe }}</h1>\n"})
    assert [(f.location.file_path, f.location.start_line, f.cwe) for f in findings] == [
        ("templates/profile.html", 1, "CWE-79")]


def test_jinja2_extension_is_scanned_for_the_same_rule(tmp_path):
    assert classify("profile.jinja2") == "html"
    findings = _findings(tmp_path, {"templates/profile.jinja2": "<p>{{ request.args['q']|safe }}</p>\n"})
    assert [(f.location.file_path, f.location.start_line) for f in findings] == [
        ("templates/profile.jinja2", 1)]


def test_escaped_or_literal_values_and_template_comments_are_not_reported(tmp_path):
    findings = _findings(tmp_path, {
        "templates/safe.html": (
            "<h1>{{ user.bio }}</h1>\n"
            "<p>{{ user.bio|escape }}</p>\n"
            "<p>{{ 'constant'|safe }}</p>\n"
            "{# {{ request.args['name'] | safe }} #}\n"
            "<p>{# ignored {{ request.args['q']|safe }} #}{{ user.bio }}</p>\n"
        ),
    })
    assert findings == []


def test_template_comment_on_same_line_does_not_hide_real_safe_filter(tmp_path):
    findings = _findings(tmp_path, {
        "profile.html": "{# {{ ignored|safe }} #} <p>{{ name|safe }}</p>\n",
    })
    assert [(f.location.file_path, f.location.start_line) for f in findings] == [
        ("profile.html", 1)]


def test_multiline_html_comment_expressions_are_scanned_at_correct_lines(tmp_path):
    findings = _findings(tmp_path, {
        "profile.html": "<!--\r\n{{ payload|safe }}\r\n--> <p>{{ name|safe }}</p>\r\n",
    })
    assert [(f.location.file_path, f.location.start_line) for f in findings] == [
        ("profile.html", 2), ("profile.html", 3)]


def test_html_comment_is_not_a_jinja_comment_and_can_be_escaped_by_payload(tmp_path):
    source = "<!-- {{ payload|safe }} -->\n"
    rendered = Environment(autoescape=True).from_string(source).render(
        payload="--><script>alert(1)</script><!--")
    assert "<!-- --><script>alert(1)</script><!-- -->" in rendered
    findings = _findings(tmp_path, {"profile.html": source})
    assert [(f.location.file_path, f.location.start_line) for f in findings] == [
        ("profile.html", 1)]


def test_comment_delimiters_inside_jinja_comment_cannot_hide_live_template(tmp_path):
    findings = _findings(tmp_path, {
        "template-comment.html": "{# <!-- #} <p>{{ name|safe }}</p>\n",
    })
    assert [(f.location.file_path, f.location.start_line) for f in findings] == [
        ("template-comment.html", 1)]


def test_jinja_comment_inside_html_comment_must_not_report_unrendered_expression(tmp_path):
    findings = _findings(tmp_path, {
        "html-comment.html": "<!-- {# --> <p>{{ name|safe }}</p> #}\n",
    })
    assert findings == []
