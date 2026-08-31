"""Tests for the v2 baseline (Phase 3): expiry, pruning, abuse prevention."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from ironclad.cli import main
from ironclad.core.baseline import (
    Baseline,
    BaselineEntry,
    BaselineError,
    create_baseline,
    diff_baseline,
    load_baseline_fingerprints,
    prune_baseline,
    write_baseline,
)
from ironclad.core.models import CodeLocation, Engine, Finding, Severity

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _finding(rule_id="PY-AST-SQL-INJECTION", line=1, severity=Severity.HIGH, snippet=None):
    return Finding(
        rule_id=rule_id,
        title="title",
        description="description",
        severity=severity,
        engine=Engine.AST_PYTHON,
        category="injection",
        location=CodeLocation(file_path="app/db.py", start_line=line, snippet=snippet or f"x = {line}"),
    )


def test_create_records_reason_owner_and_expiry():
    findings = [_finding()]
    baseline = create_baseline(findings, reason="TICKET-1", created_by="sec@corp",
                               expires_in_days=30, now=NOW)
    entry = baseline.entries[0]
    assert entry.reason == "TICKET-1"
    assert entry.created_by == "sec@corp"
    assert entry.expires_at == NOW + timedelta(days=30)
    assert entry.rule_id == "PY-AST-SQL-INJECTION"
    assert entry.file == "app/db.py"
    assert entry.line == 1


def test_critical_findings_require_a_reason():
    with pytest.raises(BaselineError) as excinfo:
        create_baseline([_finding(severity=Severity.CRITICAL)], now=NOW)
    assert "--reason" in str(excinfo.value)
    assert "--force" in str(excinfo.value)


def test_force_overrides_the_reason_guard():
    baseline = create_baseline([_finding(severity=Severity.CRITICAL)], force=True, now=NOW)
    assert len(baseline.entries) == 1


def test_entries_expire_and_stop_suppressing():
    findings = [_finding()]
    baseline = create_baseline(findings, expires_in_days=1, now=NOW)
    assert baseline.active_fingerprints(NOW + timedelta(hours=1)) == {findings[0].fingerprint}
    later = NOW + timedelta(days=2)
    assert baseline.active_fingerprints(later) == set()
    assert len(baseline.expired_entries(later)) == 1

    diff = diff_baseline(findings, baseline, now=later)
    assert len(diff.expired) == 1
    assert diff.new == findings, "an expired acceptance must gate CI again"


def test_suppressed_findings_are_not_reported_as_new():
    findings = [_finding()]
    baseline = create_baseline(findings, now=NOW)
    diff = diff_baseline(findings, baseline, now=NOW)
    assert diff.new == []
    assert diff.suppressed_count == 1
    assert diff.fixed == []


def test_fixed_findings_are_reported_for_pruning():
    old = _finding(line=1)
    baseline = create_baseline([old], now=NOW)
    diff = diff_baseline([], baseline, now=NOW)
    assert [e.fingerprint for e in diff.fixed] == [old.fingerprint]


def test_prune_removes_stale_entries_only():
    keep, gone = _finding(line=1), _finding(line=2, rule_id="OTHER")
    baseline = create_baseline([keep, gone], now=NOW)
    pruned, removed = prune_baseline(baseline, [keep])
    assert removed == 1
    assert [e.fingerprint for e in pruned.entries] == [keep.fingerprint]


def test_save_and_load_round_trip_is_stable(tmp_path):
    findings = [_finding(line=1), _finding(line=2, rule_id="OTHER")]
    path = str(tmp_path / "baseline.json")
    create_baseline(findings, reason="R", now=NOW).save(path)
    payload = json.loads(open(path, encoding="utf-8").read())
    assert payload["schema_version"] == 2
    assert payload["count"] == 2
    assert payload["entries"][0]["reason"] == "R"

    reloaded = Baseline.load(path)
    assert reloaded.active_fingerprints(NOW) == {f.fingerprint for f in findings}
    assert reloaded.legacy is False
    # Saving again produces the same bytes (deterministic ordering).
    first = open(path, encoding="utf-8").read()
    reloaded.save(path)
    second = open(path, encoding="utf-8").read()
    assert json.loads(first)["entries"] == json.loads(second)["entries"]


def test_legacy_v1_baseline_is_still_readable(tmp_path):
    path = tmp_path / "old.json"
    finding = _finding()
    path.write_text(json.dumps({
        "generated_at": 1700000000.0,
        "tool": "IronClad Sentinel",
        "count": 1,
        "fingerprints": [finding.fingerprint],
    }), encoding="utf-8")
    baseline = Baseline.load(str(path))
    assert baseline.legacy is True
    assert baseline.schema_version == 1
    assert baseline.active_fingerprints(NOW) == {finding.fingerprint}


def test_legacy_write_baseline_helper_still_works(tmp_path):
    path = str(tmp_path / "bl.json")
    findings = [_finding()]
    write_baseline(path, findings)
    assert load_baseline_fingerprints(path) == {findings[0].fingerprint}


def test_malformed_baseline_raises_instead_of_silently_passing(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        load_baseline_fingerprints(str(path))


def test_missing_baseline_is_empty(tmp_path):
    assert load_baseline_fingerprints(str(tmp_path / "absent.json")) == set()
    assert Baseline.load(None).entries == []


def test_entry_serialization_round_trip():
    entry = BaselineEntry(fingerprint="abc", rule_id="R", file="f.py", line=3,
                          severity="high", reason="why", created_at=NOW,
                          expires_at=NOW + timedelta(days=5), created_by="me")
    restored = BaselineEntry.from_dict(entry.to_dict())
    assert restored == entry


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@pytest.fixture()
def vulnerable_project(tmp_path):
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
    return target


def test_cli_baseline_create_refuses_critical_without_reason(vulnerable_project, tmp_path):
    out = tmp_path / "baseline.json"
    result = CliRunner().invoke(main, ["baseline", "create", str(vulnerable_project),
                                       "--out", str(out)])
    assert result.exit_code == 3, result.output
    assert "--reason" in result.output
    assert not out.exists()


def test_cli_baseline_create_then_scan_passes(vulnerable_project, tmp_path):
    out = tmp_path / "baseline.json"
    runner = CliRunner()
    created = runner.invoke(main, ["baseline", "create", str(vulnerable_project),
                                   "--out", str(out), "--reason", "TICKET-9",
                                   "--expires-in-days", "30", "--created-by", "ci"])
    assert created.exit_code == 0, created.output
    assert out.exists()

    gated = runner.invoke(main, ["scan", str(vulnerable_project), "--fail-on", "high",
                                 "--baseline", str(out), "--output-dir", str(tmp_path / "r"),
                                 "--quiet"])
    assert gated.exit_code == 0, gated.output

    listing = runner.invoke(main, ["baseline", "list", str(out)])
    assert listing.exit_code == 0
    assert "TICKET-9" in listing.output


def test_cli_baseline_prune_reports_stale_entries(vulnerable_project, tmp_path):
    out = tmp_path / "baseline.json"
    runner = CliRunner()
    runner.invoke(main, ["baseline", "create", str(vulnerable_project), "--out", str(out),
                         "--reason", "T", "--force"])
    (vulnerable_project / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    pruned = runner.invoke(main, ["baseline", "prune", str(vulnerable_project),
                                  "--baseline", str(out), "--write"])
    assert pruned.exit_code == 0, pruned.output
    assert "Removed" in pruned.output
    assert Baseline.load(str(out)).entries == []


def test_cli_baseline_diff_exit_code_reflects_new_findings(vulnerable_project, tmp_path):
    out = tmp_path / "baseline.json"
    runner = CliRunner()
    runner.invoke(main, ["baseline", "create", str(vulnerable_project), "--out", str(out),
                         "--reason", "T", "--force"])
    same = runner.invoke(main, ["baseline", "diff", str(vulnerable_project), "--baseline", str(out)])
    assert same.exit_code == 0, same.output
    assert "new: 0" in same.output

    (vulnerable_project / "more.py").write_text(
        "import os\ndef run(user_input):\n    return os.system('echo ' + user_input)\n",
        encoding="utf-8",
    )
    changed = runner.invoke(main, ["baseline", "diff", str(vulnerable_project), "--baseline", str(out)])
    assert changed.exit_code == 1, changed.output
    assert "new: 1" in changed.output
