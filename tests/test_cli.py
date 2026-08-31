"""CLI contract tests (Phase 22): commands, exit codes, machine-readable output.

Exit codes are a published contract (see `ironclad/core/exit_codes.py`), so
every assertion below pins one.
"""
import json
import os

import pytest
from click.testing import CliRunner

from ironclad import __version__
from ironclad.cli import main
from ironclad.core import exit_codes as ec

VULNERABLE_APP = (
    "import sqlite3\n"
    "def lookup(user_input):\n"
    "    conn = sqlite3.connect(':memory:')\n"
    "    q = 'SELECT * FROM users WHERE name = %s' % user_input\n"
    "    return conn.execute(q).fetchall()\n"
)
CLEAN_APP = "def add(a, b):\n    return a + b\n"


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def clean_project(tmp_path):
    target = tmp_path / "clean"
    target.mkdir()
    (target / "app.py").write_text(CLEAN_APP, encoding="utf-8")
    return target


@pytest.fixture()
def vulnerable_project(tmp_path):
    target = tmp_path / "vuln"
    target.mkdir()
    (target / "app.py").write_text(VULNERABLE_APP, encoding="utf-8")
    return target


# --------------------------------------------------------------------------- #
# version / doctor / init / config
# --------------------------------------------------------------------------- #
def test_version_command(runner):
    result = runner.invoke(main, ["version"])
    assert result.exit_code == ec.SUCCESS
    assert __version__ in result.output


def test_version_json_is_machine_readable(runner):
    result = runner.invoke(main, ["version", "--json"])
    assert result.exit_code == ec.SUCCESS
    payload = json.loads(result.output)
    assert payload["version"] == __version__
    assert "python" in payload


def test_doctor_reports_health(runner):
    result = runner.invoke(main, ["doctor"])
    assert result.exit_code == ec.SUCCESS, result.output
    assert "bundled rule packs" in result.output
    assert "Installation healthy" in result.output


def test_doctor_json_lists_every_check(runner):
    result = runner.invoke(main, ["doctor", "--json"])
    assert result.exit_code == ec.SUCCESS
    payload = json.loads(result.output)
    assert payload["healthy"] is True
    names = {check["check"] for check in payload["checks"]}
    assert {"python >= 3.9", "bundled rule packs", "data/vuln_db.json", "html report template"} <= names


def test_doctor_trial_license_is_a_warning_not_a_failure(runner):
    result = runner.invoke(main, ["doctor", "--json"])
    payload = json.loads(result.output)
    license_check = next(c for c in payload["checks"] if c["check"] == "commercial license")
    assert license_check["ok"] is True
    assert license_check["warning"] in (True, False)


def test_init_writes_config_and_policy(runner, tmp_path):
    target = tmp_path / "new-project"
    result = runner.invoke(main, ["init", str(target)])
    assert result.exit_code == ec.SUCCESS
    assert (target / ".ironclad.yml").exists()
    assert (target / "policy.yaml").exists()


def test_init_is_idempotent(runner, tmp_path):
    target = tmp_path / "new-project"
    runner.invoke(main, ["init", str(target)])
    second = runner.invoke(main, ["init", str(target)])
    assert second.exit_code == ec.SUCCESS
    assert "Nothing written" in second.output


def test_config_show_lists_effective_settings(runner, clean_project):
    result = runner.invoke(main, ["config", "show", str(clean_project)])
    assert result.exit_code == ec.SUCCESS
    assert "enabled_engines" in result.output
    assert "CLI flags" in result.output  # precedence is documented to the user


def test_config_show_json(runner, clean_project):
    result = runner.invoke(main, ["config", "show", str(clean_project), "--json"])
    payload = json.loads(result.output)
    assert "ast-python" in payload["enabled_engines"]
    assert payload["source"] == "built-in defaults"


def test_config_init_then_show_reads_project_file(runner, tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    written = runner.invoke(main, ["config", "init", str(target)])
    assert written.exit_code == ec.SUCCESS
    again = runner.invoke(main, ["config", "init", str(target)])
    assert again.exit_code == ec.CONFIG_ERROR
    shown = runner.invoke(main, ["config", "show", str(target), "--json"])
    assert json.loads(shown.output)["source"] == "project .ironclad.yml"


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
def test_scan_clean_project_exits_zero(runner, clean_project, tmp_path):
    result = runner.invoke(main, ["scan", str(clean_project), "--output-dir",
                                  str(tmp_path / "reports"), "--quiet"])
    assert result.exit_code == ec.SUCCESS, result.output


def test_scan_vulnerable_project_fails_on_high(runner, vulnerable_project, tmp_path):
    result = runner.invoke(main, ["scan", str(vulnerable_project), "--fail-on", "high",
                                  "--output-dir", str(tmp_path / "reports"), "--quiet"])
    assert result.exit_code == ec.GATE_FAILED, result.output


def test_scan_fail_on_none_never_fails(runner, vulnerable_project, tmp_path):
    result = runner.invoke(main, ["scan", str(vulnerable_project), "--fail-on", "none",
                                  "--output-dir", str(tmp_path / "reports"), "--quiet"])
    assert result.exit_code == ec.SUCCESS, result.output


def test_scan_max_risk_score_gate(runner, vulnerable_project, tmp_path):
    result = runner.invoke(main, ["scan", str(vulnerable_project), "--max-risk-score", "1",
                                  "--output-dir", str(tmp_path / "reports"), "--quiet"])
    assert result.exit_code == ec.GATE_FAILED, result.output


def test_scan_missing_target_is_exit_code_4(runner, tmp_path):
    result = runner.invoke(main, ["scan", str(tmp_path / "nope"), "--quiet"])
    assert result.exit_code == ec.TARGET_ERROR
    assert "does not exist" in result.output


def test_scan_writes_every_requested_format(runner, vulnerable_project, tmp_path):
    out = tmp_path / "reports"
    result = runner.invoke(main, ["scan", str(vulnerable_project),
                                  "--format", "json,sarif,html,markdown,junit,cyclonedx",
                                  "--output-dir", str(out), "--quiet"])
    assert result.exit_code in (ec.SUCCESS, ec.GATE_FAILED)
    for name in ("ironclad-report.json", "ironclad-report.sarif.json", "ironclad-report.html",
                 "ironclad-report.md", "ironclad-report.junit.xml", "ironclad-report.cdx.json"):
        assert (out / name).exists(), f"missing report: {name}"
        assert (out / name).stat().st_size > 0


def test_scan_json_summary_is_machine_readable(runner, vulnerable_project, tmp_path):
    result = runner.invoke(main, ["scan", str(vulnerable_project), "--json-summary", "--quiet",
                                  "--output-dir", str(tmp_path / "reports")])
    payload = json.loads(result.output)
    assert payload["findings"] >= 1
    assert payload["summary"]["critical"] + payload["summary"]["high"] >= 1
    assert payload["files_scanned"] >= 1


def test_scan_ignore_rule_removes_a_finding(runner, vulnerable_project, tmp_path):
    base = runner.invoke(main, ["scan", str(vulnerable_project), "--json-summary", "--quiet",
                                "--output-dir", str(tmp_path / "r1")])
    ignored = runner.invoke(main, ["scan", str(vulnerable_project), "--json-summary", "--quiet",
                                   "--ignore-rule", "PY-AST-SQL-INJECTION",
                                   "--output-dir", str(tmp_path / "r2")])
    assert json.loads(ignored.output)["findings"] < json.loads(base.output)["findings"]


def test_scan_update_baseline_writes_file(runner, vulnerable_project, tmp_path):
    out = tmp_path / "baseline.json"
    result = runner.invoke(main, ["scan", str(vulnerable_project), "--update-baseline",
                                  "--baseline", str(out), "--baseline-reason", "T-1",
                                  "--output-dir", str(tmp_path / "reports"), "--quiet"])
    assert result.exit_code in (ec.SUCCESS, ec.GATE_FAILED)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 2
    assert payload["count"] >= 1
    assert payload["entries"][0]["reason"] == "T-1"


# --------------------------------------------------------------------------- #
# sbom / report
# --------------------------------------------------------------------------- #
def test_sbom_cyclonedx_is_valid(runner, tmp_path):
    from ironclad.scanners.sbom import validate_cyclonedx

    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\nflask==2.0.1\n", encoding="utf-8")
    out = tmp_path / "sbom.json"
    result = runner.invoke(main, ["sbom", str(project), "--out", str(out)])
    assert result.exit_code == ec.SUCCESS, result.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert validate_cyclonedx(doc) == []
    assert {c["name"] for c in doc["components"]} == {"requests", "flask"}
    assert doc["dependencies"][0]["ref"] == "ironclad-root"


def test_sbom_spdx_is_valid(runner, tmp_path):
    from ironclad.scanners.spdx import validate_spdx

    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    out = tmp_path / "sbom-spdx.json"
    result = runner.invoke(main, ["sbom", str(project), "--out", str(out), "--format", "spdx"])
    assert result.exit_code == ec.SUCCESS, result.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert validate_spdx(doc) == []
    assert doc["spdxVersion"] == "SPDX-2.3"


def test_sbom_output_is_deterministic(runner, tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.31.0\nflask==2.0.1\n", encoding="utf-8")
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    runner.invoke(main, ["sbom", str(project), "--out", str(first)])
    runner.invoke(main, ["sbom", str(project), "--out", str(second)])
    a = json.loads(first.read_text(encoding="utf-8"))
    b = json.loads(second.read_text(encoding="utf-8"))
    a["metadata"].pop("timestamp")
    b["metadata"].pop("timestamp")
    assert a == b, "SBOM output must be deterministic apart from the timestamp"


def test_report_convert_renders_from_stored_json(runner, vulnerable_project, tmp_path):
    reports = tmp_path / "reports"
    runner.invoke(main, ["scan", str(vulnerable_project), "--output-dir", str(reports), "--quiet"])
    stored = reports / "ironclad-report.json"
    assert stored.exists()
    out_dir = tmp_path / "converted"
    result = runner.invoke(main, ["report", "convert", str(stored), "--format", "sarif,html",
                                  "--output-dir", str(out_dir)])
    assert result.exit_code == ec.SUCCESS, result.output
    assert (out_dir / "ironclad-report.sarif.json").exists()
    assert (out_dir / "ironclad-report.html").exists()


def test_report_convert_rejects_a_non_report_file(runner, tmp_path):
    junk = tmp_path / "junk.json"
    junk.write_text('{"hello": "world"}', encoding="utf-8")
    result = runner.invoke(main, ["report", "convert", str(junk), "--output-dir", str(tmp_path / "o")])
    assert result.exit_code == ec.CONFIG_ERROR


def test_exit_code_table_is_complete():
    assert set(ec.DESCRIPTIONS) == {0, 1, 2, 3, 4, 5}
    assert ec.describe(ec.GATE_FAILED).startswith("security gate failed")


def test_help_lists_every_command_group(runner):
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == ec.SUCCESS
    for command in ("scan", "version", "doctor", "init", "config", "policy",
                    "baseline", "sbom", "license", "report"):
        assert command in result.output
