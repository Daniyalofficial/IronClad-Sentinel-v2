"""Tests for the organization policy engine (Phase 2)."""
import copy
import json
from datetime import datetime, timezone

import pytest
from click.testing import CliRunner

from ironclad.cli import main
from ironclad.core.config import IronCladConfig
from ironclad.core.models import CodeLocation, Engine, Finding, ScanResult, ScanStats, Severity
from ironclad.core.policy import (
    Policy,
    PolicyError,
    evaluate_policy,
    filter_findings_for_policy,
    write_example_policy,
)

BASE_POLICY = {
    "version": 1,
    "name": "test-policy",
    "fail_on": "high",
    "severity_gates": {"critical": 0, "high": 0},
}


def _finding(rule_id="PY-AST-SQL-INJECTION", severity=Severity.HIGH, confidence="high",
             category="injection", file="app/db.py", line=10, extra=None):
    return Finding(
        rule_id=rule_id,
        title=f"{rule_id} title",
        description="description",
        severity=severity,
        engine=Engine.AST_PYTHON,
        category=category,
        confidence=confidence,
        location=CodeLocation(file_path=file, start_line=line, snippet="x = 1"),
        extra=extra or {},
    )


def _result(findings):
    return ScanResult(target="t", findings=findings, stats=ScanStats())


def test_example_policy_round_trips(tmp_path):
    path = str(tmp_path / "policy.yaml")
    write_example_policy(path)
    policy = Policy.load(path)
    assert policy.name == "example-standard"
    assert policy.fail_on == "high"
    assert "GPL-3.0" in policy.license_policy.blocked
    # Normalised dict must survive a YAML round trip unchanged.
    import yaml

    again = Policy.from_dict(policy.to_dict())
    assert again.to_dict() == policy.to_dict()


def test_unknown_top_level_key_is_rejected():
    with pytest.raises(PolicyError) as excinfo:
        Policy.from_dict({**BASE_POLICY, "bogus": 1})
    assert any("bogus" in problem for problem in excinfo.value.problems)


def test_all_problems_are_reported_at_once():
    with pytest.raises(PolicyError) as excinfo:
        Policy.from_dict({"version": 99, "fail_on": "whenever", "max_risk_score": -3})
    problems = excinfo.value.problems
    assert len(problems) >= 3


def test_bad_severity_gate_value_is_rejected():
    with pytest.raises(PolicyError):
        Policy.from_dict({**BASE_POLICY, "severity_gates": {"high": "none"}})


def test_unknown_engine_is_rejected():
    with pytest.raises(PolicyError):
        Policy.from_dict({**BASE_POLICY, "engines": {"enabled": ["magic-scanner"]}})


def test_license_allowed_and_blocked_conflict_is_rejected():
    with pytest.raises(PolicyError) as excinfo:
        Policy.from_dict({**BASE_POLICY, "licenses": {"allowed": ["MIT"], "blocked": ["MIT"]}})
    assert any("both allowed and blocked" in p for p in excinfo.value.problems)


def test_missing_file_is_a_policy_error(tmp_path):
    with pytest.raises(PolicyError):
        Policy.load(str(tmp_path / "nope.yaml"))


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #
def test_clean_scan_passes():
    decision = evaluate_policy(_result([]), Policy.from_dict(BASE_POLICY))
    assert decision.passed
    assert decision.exit_code == 0
    assert decision.violations == []


def test_high_finding_fails_fail_on_high():
    decision = evaluate_policy(_result([_finding()]), Policy.from_dict(BASE_POLICY))
    assert not decision.passed
    assert decision.exit_code == 1
    kinds = {v.kind for v in decision.violations}
    assert "severity" in kinds and "severity_gate" in kinds


def test_medium_finding_passes_fail_on_high_but_breaks_fail_on_medium():
    result = _result([_finding(severity=Severity.MEDIUM)])
    assert evaluate_policy(result, Policy.from_dict(BASE_POLICY)).passed
    assert not evaluate_policy(result, Policy.from_dict({**BASE_POLICY, "fail_on": "medium"})).passed


def test_fail_on_none_never_gates():
    policy = Policy.from_dict({**BASE_POLICY, "fail_on": "none", "severity_gates": {}})
    assert evaluate_policy(_result([_finding(severity=Severity.CRITICAL)]), policy).passed


def test_fail_on_any_ignores_info():
    policy = Policy.from_dict({**BASE_POLICY, "fail_on": "any", "severity_gates": {}})
    assert evaluate_policy(_result([_finding(severity=Severity.INFO)]), policy).passed
    assert not evaluate_policy(_result([_finding(severity=Severity.LOW)]), policy).passed


def test_risk_score_cap_is_enforced():
    policy = Policy.from_dict({**BASE_POLICY, "fail_on": "none", "severity_gates": {},
                               "max_risk_score": 10})
    assert not evaluate_policy(_result([_finding(severity=Severity.HIGH)]), policy).passed


def test_evaluation_is_deterministic():
    findings = [_finding(line=1), _finding(line=2, rule_id="OTHER")]
    policy = Policy.from_dict(BASE_POLICY)
    first = evaluate_policy(_result(copy.deepcopy(findings)), policy).to_dict()
    second = evaluate_policy(_result(copy.deepcopy(findings)), policy).to_dict()
    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_confidence_floor_drops_low_confidence_findings():
    policy = Policy.from_dict({**BASE_POLICY, "rules": {"min_confidence": "high"}})
    assert evaluate_policy(_result([_finding(confidence="low")]), policy).passed
    assert not evaluate_policy(_result([_finding(confidence="high")]), policy).passed


def test_ignored_rules_are_not_gated():
    policy = Policy.from_dict({**BASE_POLICY, "rules": {"ignore": ["PY-AST-SQL-INJECTION"]}})
    assert evaluate_policy(_result([_finding()]), policy).passed


def test_severity_override_can_downgrade_a_rule():
    policy = Policy.from_dict({**BASE_POLICY,
                               "rules": {"severity_overrides": {"PY-AST-SQL-INJECTION": "low"}}})
    result = _result([_finding(severity=Severity.CRITICAL)])
    filtered = filter_findings_for_policy(result.findings, policy)
    assert filtered[0].severity is Severity.LOW
    assert filtered[0].extra["policy_severity_override"] == "critical"
    assert evaluate_policy(result, policy).passed


def test_blocked_license_is_a_violation():
    policy = Policy.from_dict({**BASE_POLICY, "fail_on": "none", "severity_gates": {},
                               "licenses": {"allowed": ["MIT"], "blocked": ["GPL-3.0"]}})
    finding = _finding(rule_id="LICENSE-COPYLEFT-DEPENDENCY", category="license-compliance",
                       severity=Severity.HIGH, extra={"license": "GPL-3.0", "package": "copyleft-pkg"})
    decision = evaluate_policy(_result([finding]), policy)
    assert not decision.passed
    assert any(v.kind == "license_blocked" for v in decision.violations)


def test_allowed_license_is_not_a_violation():
    policy = Policy.from_dict({**BASE_POLICY, "fail_on": "none", "severity_gates": {},
                               "licenses": {"allowed": ["MIT"]}})
    finding = _finding(rule_id="LICENSE-UNKNOWN", category="license-compliance",
                       severity=Severity.LOW, extra={"license": "MIT", "package": "ok-pkg"})
    assert evaluate_policy(_result([finding]), policy).passed


def test_unknown_license_defaults_to_warning_not_violation():
    policy = Policy.from_dict({**BASE_POLICY, "fail_on": "none", "severity_gates": {}})
    finding = _finding(rule_id="LICENSE-UNKNOWN", category="license-compliance",
                       severity=Severity.LOW, extra={"license": "UNKNOWN", "package": "mystery"})
    assert evaluate_policy(_result([finding]), policy).passed


def test_unknown_license_can_be_blocked():
    policy = Policy.from_dict({**BASE_POLICY, "fail_on": "none", "severity_gates": {},
                               "licenses": {"allowed": ["MIT"], "unknown": "block"}})
    finding = _finding(rule_id="LICENSE-UNKNOWN", category="license-compliance",
                       severity=Severity.LOW, extra={"license": "UNKNOWN", "package": "mystery"})
    decision = evaluate_policy(_result([finding]), policy)
    assert any(v.kind == "license_unknown" for v in decision.violations)


def test_blocked_dependency_is_a_violation():
    policy = Policy.from_dict({**BASE_POLICY, "fail_on": "none", "severity_gates": {},
                               "dependencies": {"block": [{"name": "left-pad", "ecosystem": "javascript"}]}})
    finding = _finding(rule_id="DEP-XYZ", category="vulnerable-dependency", severity=Severity.LOW,
                       extra={"package": "left-pad", "ecosystem": "javascript"})
    decision = evaluate_policy(_result([finding]), policy)
    assert any(v.kind == "blocked_dependency" for v in decision.violations)


def test_baselined_findings_do_not_gate():
    finding = _finding()
    result = _result([finding])
    result.new_findings = []
    result.baseline_applied = True
    result.baseline_suppressed = 1
    decision = evaluate_policy(result, Policy.from_dict(BASE_POLICY))
    assert decision.passed, "an accepted (baselined) finding must not fail the build"
    assert decision.summary["evaluated_findings"] == 0


def test_new_findings_still_gate_when_baseline_active():
    old, new = _finding(line=1), _finding(line=99, rule_id="PY-AST-CMD-INJECTION")
    result = _result([old, new])
    result.new_findings = [new]
    result.baseline_applied = True
    decision = evaluate_policy(result, Policy.from_dict(BASE_POLICY))
    assert not decision.passed
    assert {v.rule_id for v in decision.violations if v.kind == "severity"} == {"PY-AST-CMD-INJECTION"}


# --------------------------------------------------------------------------- #
# Policy -> config folding
# --------------------------------------------------------------------------- #
def test_apply_to_config_is_additive_and_does_not_mutate():
    policy = Policy.from_dict({**BASE_POLICY, "rules": {"ignore": ["R1"]},
                               "paths": {"exclude": ["vendor/**"], "exclude_dirs": ["third_party"]}})
    config = IronCladConfig(target=".", ignore_rule_ids=["R0"])
    merged = policy.apply_to_config(config)
    assert merged.ignore_rule_ids == ["R0", "R1"]
    assert "vendor/**" in merged.ignore_paths
    assert "third_party" in merged.exclude_dirs
    assert config.ignore_rule_ids == ["R0"], "original config must not be mutated"


def test_apply_to_config_restricts_engines():
    policy = Policy.from_dict({**BASE_POLICY, "engines": {"enabled": ["secrets"]}})
    merged = policy.apply_to_config(IronCladConfig(target="."))
    assert merged.enabled_engines == ["secrets"]


def test_apply_to_config_takes_stricter_entropy_threshold():
    policy = Policy.from_dict({**BASE_POLICY, "secrets": {"entropy_threshold": 3.9}})
    assert policy.apply_to_config(IronCladConfig(target=".")).entropy_threshold == 3.9
    policy2 = Policy.from_dict({**BASE_POLICY, "secrets": {"entropy_threshold": 5.0}})
    assert policy2.apply_to_config(IronCladConfig(target=".")).entropy_threshold == 4.3


# --------------------------------------------------------------------------- #
# CLI surface
# --------------------------------------------------------------------------- #
def test_cli_policy_validate_reports_valid(tmp_path):
    path = tmp_path / "policy.yaml"
    write_example_policy(str(path))
    result = CliRunner().invoke(main, ["policy", "validate", str(path)])
    assert result.exit_code == 0, result.output
    assert "VALID" in result.output


def test_cli_policy_validate_exit_code_3_on_invalid(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("version: 1\nfail_on: nonsense\n", encoding="utf-8")
    result = CliRunner().invoke(main, ["policy", "validate", str(path)])
    assert result.exit_code == 3
    assert "fail_on" in result.output


def test_cli_policy_show_emits_json(tmp_path):
    path = tmp_path / "policy.yaml"
    write_example_policy(str(path))
    result = CliRunner().invoke(main, ["policy", "show", str(path)])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["fail_on"] == "high"


def test_cli_scan_with_policy_fails_the_build(tmp_path):
    target = tmp_path / "proj"
    target.mkdir()
    (target / "app.py").write_text(
        "import sqlite3\n"
        "def lookup(user_input):\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    q = 'SELECT * FROM users WHERE name = %s' % user_input\n"
        "    return conn.execute(q).fetchall()\n",
        encoding="utf-8",
    )
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("version: 1\nname: ci\nfail_on: high\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(target), "--policy", str(policy_path),
                                  "--output-dir", str(tmp_path / "reports"), "--quiet"])
    assert result.exit_code == 1, result.output
    assert "POLICY FAIL" in result.output


def test_cli_scan_without_findings_passes_policy(tmp_path):
    target = tmp_path / "clean"
    target.mkdir()
    (target / "ok.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("version: 1\nname: ci\nfail_on: high\n", encoding="utf-8")
    result = CliRunner().invoke(main, ["scan", str(target), "--policy", str(policy_path),
                                       "--output-dir", str(tmp_path / "reports"), "--quiet"])
    assert result.exit_code == 0, result.output
    assert "POLICY PASS" in result.output
