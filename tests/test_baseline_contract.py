import json

from ironclad.core.baseline import apply_baseline, load_baseline_fingerprints, write_baseline
from ironclad.core.models import CodeLocation, Engine, Finding, Severity


def _finding(rule="TEST-BASELINE"):
    return Finding(
        rule_id=rule,
        title="Baseline fixture",
        description="Deterministic baseline fixture.",
        severity=Severity.MEDIUM,
        engine=Engine.RULE_ENGINE,
        location=CodeLocation("src/app.py", 3, 3, snippet="fixture()"),
    )


def test_baseline_round_trip_and_suppression(tmp_path):
    finding = _finding()
    path = tmp_path / ".ironclad" / "baseline.json"
    write_baseline(str(path), [finding])
    loaded = load_baseline_fingerprints(str(path))
    assert finding.fingerprint in loaded

    kept, suppressed = apply_baseline([finding, _finding("NEW-RULE")], loaded)
    assert suppressed == 1
    assert [f.rule_id for f in kept] == ["NEW-RULE"]


def test_baseline_is_deterministic_and_deduplicated(tmp_path):
    first = _finding()
    path = tmp_path / "baseline.json"
    write_baseline(str(path), [first, first])
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["count"] == 2
    assert doc["fingerprints"] == [first.fingerprint]
