import json

from ironclad.core.models import CodeLocation, Engine, Finding, ScanResult, ScanStats, Severity
from ironclad.reporting.sarif import TOOL_URI, build_sarif


def _result():
    finding = Finding(
        rule_id="TEST-001",
        title="Test security finding",
        description="A deterministic SARIF fixture.",
        severity=Severity.HIGH,
        engine=Engine.RULE_ENGINE,
        category="test",
        location=CodeLocation("src/app.py", 7, 7, snippet="dangerous()"),
        confidence="high",
    )
    return ScanResult(
        target=".", findings=[finding], stats=ScanStats(files_scanned=1, lines_scanned=10),
    )


def test_sarif_contract_and_metadata():
    doc = build_sarif(_result())
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["informationUri"] == TOOL_URI
    assert driver["organization"] == "Daniyalofficial"
    assert driver["rules"][0]["id"] == "TEST-001"
    result = run["results"][0]
    assert result["ruleId"] == "TEST-001"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"
    assert result["partialFingerprints"]["ironcladFingerprint/v1"]


def test_sarif_is_json_serializable():
    encoded = json.dumps(build_sarif(_result()))
    assert "TEST-001" in encoded
