from pathlib import Path

from ironclad.core.walker import DiscoveredFile
from ironclad.scanners.dependency import ParsedDependency
from ironclad.scanners.sbom import (
    COPYLEFT_LICENSES,
    PERMISSIVE_LICENSES,
    _license_for,
    _purl,
    build_sbom,
    scan_license_compliance,
)


def _manifest(tmp_path: Path, text: str) -> DiscoveredFile:
    path = tmp_path / "requirements.txt"
    path.write_text(text, encoding="utf-8")
    return DiscoveredFile(
        path=str(path), rel_path="requirements.txt", language="other",
        size_bytes=path.stat().st_size, is_dependency_manifest=True,
    )


def test_unknown_license_is_explicit():
    dep = ParsedDependency("not-in-db", "1.0.0", "python", "requirements.txt")
    assert _license_for(dep, {"python": {}}) == "UNKNOWN"


def test_known_license_is_normalized():
    dep = ParsedDependency("Requests", "2.31.0", "python", "requirements.txt")
    assert _license_for(dep, {"python": {"requests": "Apache-2.0"}}) == "Apache-2.0"


def test_policy_sets_are_conservative():
    assert "GPL-3.0" in COPYLEFT_LICENSES
    assert "AGPL-3.0" in COPYLEFT_LICENSES
    assert "MIT" in PERMISSIVE_LICENSES
    assert "Apache-2.0" in PERMISSIVE_LICENSES
    assert "UNKNOWN" not in PERMISSIVE_LICENSES


def test_license_scanner_flags_copyleft_and_unknown(tmp_path):
    manifest = _manifest(tmp_path, "paramiko==3.4.0\nnot-in-db==1.0.0\n")
    findings = scan_license_compliance([manifest])
    rule_ids = {finding.rule_id for finding in findings}
    assert "LICENSE-COPYLEFT-DEPENDENCY" in rule_ids
    assert "LICENSE-UNKNOWN" in rule_ids


def test_sbom_uses_known_license_and_marks_unknown(tmp_path):
    manifest = _manifest(tmp_path, "requests==2.31.0\nnot-in-db==1.0.0\n")
    doc = build_sbom([manifest], project_name="test-project")
    components = {component["name"]: component for component in doc["components"]}
    assert components["requests"]["licenses"][0]["license"]["id"] == "Apache-2.0"
    assert components["not-in-db"]["properties"][0]["value"] == "UNKNOWN"


def test_sbom_deduplicates_identical_components(tmp_path):
    manifest = _manifest(tmp_path, "requests==2.31.0\nrequests==2.31.0\n")
    doc = build_sbom([manifest], project_name="test-project")
    requests = [c for c in doc["components"] if c["name"] == "requests"]
    assert len(requests) == 1


def test_purl_ecosystems_are_deterministic():
    assert _purl("python", "requests", "2.31.0") == "pkg:pypi/requests@2.31.0"
    assert _purl("javascript", "lodash", "4.17.21") == "pkg:npm/lodash@4.17.21"
    assert _purl("unknown", "demo", "1.0") == "pkg:generic/demo@1.0"
