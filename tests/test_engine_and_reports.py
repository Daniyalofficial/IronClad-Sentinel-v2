import json
import os
import shutil
import tempfile

from ironclad.core.config import IronCladConfig
from ironclad.core.engine import run_scan
from ironclad.reporting import write_reports
from ironclad.reporting.sarif import build_sarif
from ironclad.reporting.markdown_report import render_markdown
from ironclad.reporting.junit_report import render_junit

DEMO_APP = os.path.join(os.path.dirname(__file__), "..", "demo", "vulnerable_app")


def test_full_scan_of_demo_app_finds_known_bugs():
    config = IronCladConfig.load(DEMO_APP, {})
    result = run_scan(config)
    rule_ids = {f.rule_id for f in result.findings}

    expected_subset = {
        "SECRET-AWS-ACCESS-KEY-ID",
        "SECRET-STRIPE-KEY",
        "PY-AST-SQL-INJECTION",
        "PY-AST-EVAL-USE",
        "PY-AST-INSECURE-DESERIALIZATION",
        "DOCKER-CURL-PIPE-SH",
        "DOCKER-MISSING-USER",
    }
    missing = expected_subset - rule_ids
    assert not missing, f"expected findings missing: {missing}"
    assert result.risk_score() > 0
    assert result.grade() in {"C", "D", "F"}


def test_scan_produces_deterministic_fingerprints_across_runs():
    config = IronCladConfig.load(DEMO_APP, {})
    result1 = run_scan(config)
    result2 = run_scan(config)
    fps1 = {f.fingerprint for f in result1.findings}
    fps2 = {f.fingerprint for f in result2.findings}
    assert fps1 == fps2


def test_all_report_formats_render_without_error():
    config = IronCladConfig.load(DEMO_APP, {})
    result = run_scan(config)

    sarif_doc = build_sarif(result)
    assert sarif_doc["version"] == "2.1.0"
    assert len(sarif_doc["runs"][0]["results"]) == len(result.findings)

    md = render_markdown(result)
    assert "IronClad Sentinel" in md

    junit_xml = render_junit(result)
    assert "<testsuite" in junit_xml

    tmpdir = tempfile.mkdtemp()
    try:
        written = write_reports(result, ["json", "html", "sarif", "markdown", "junit"], tmpdir)
        for fmt, path in written.items():
            assert os.path.isfile(path)
            assert os.path.getsize(path) > 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_min_severity_filter_reduces_findings():
    config_all = IronCladConfig.load(DEMO_APP, {"min_severity": "info"})
    config_critical = IronCladConfig.load(DEMO_APP, {"min_severity": "critical"})
    result_all = run_scan(config_all)
    result_critical = run_scan(config_critical)
    assert len(result_critical.findings) < len(result_all.findings)
    assert all(f.severity.value == "critical" for f in result_critical.findings)


def test_ignore_rule_ids_suppresses_specific_rule():
    config = IronCladConfig.load(DEMO_APP, {"ignore_rule_ids": ["SECRET-AWS-ACCESS-KEY-ID"]})
    result = run_scan(config)
    assert not any(f.rule_id == "SECRET-AWS-ACCESS-KEY-ID" for f in result.findings)
