import os
import tempfile

from ironclad.core.baseline import apply_baseline, load_baseline_fingerprints, write_baseline
from ironclad.core.models import CodeLocation, Engine, Finding, Severity


def _finding(rule_id="R1", path="a.py", line=1):
    return Finding(
        rule_id=rule_id, title="t", description="d", severity=Severity.HIGH,
        engine=Engine.RULE_ENGINE, location=CodeLocation(file_path=path, start_line=line, snippet="x=1"),
    )


def test_write_and_load_baseline_roundtrip():
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "baseline.json")
    findings = [_finding("R1"), _finding("R2")]
    write_baseline(path, findings)
    fps = load_baseline_fingerprints(path)
    assert len(fps) == 2
    assert all(isinstance(fp, str) for fp in fps)


def test_apply_baseline_suppresses_known_findings():
    f1 = _finding("R1")
    f2 = _finding("R2")
    baseline_fps = {f1.fingerprint}
    kept, suppressed = apply_baseline([f1, f2], baseline_fps)
    assert suppressed == 1
    assert kept == [f2]


def test_apply_baseline_with_empty_baseline_keeps_all():
    f1 = _finding("R1")
    kept, suppressed = apply_baseline([f1], set())
    assert suppressed == 0
    assert kept == [f1]


def test_missing_baseline_file_returns_empty_set():
    assert load_baseline_fingerprints("/nonexistent/path.json") == set()
