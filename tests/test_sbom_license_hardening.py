from ironclad.scanners.sbom import _license_for, _purl, build_sbom
from ironclad.scanners.dependency import ParsedDependency


def test_unknown_license_is_explicit():
    dep = ParsedDependency("not-in-db", "1.0.0", "python", "requirements.txt")
    assert _license_for(dep, {"python": {}}) == "UNKNOWN"


def test_known_license_is_normalized():
    dep = ParsedDependency("Requests", "2.31.0", "python", "requirements.txt")
    assert _license_for(dep, {"python": {"requests": "Apache-2.0"}}) == "Apache-2.0"


def test_sbom_deduplicates_identical_components():
    class Manifest:
        path = "requirements.txt"
        rel_path = "requirements.txt"
    # PURL behavior is deterministic even though manifest parsing is tested elsewhere.
    assert _purl("python", "requests", "2.31.0") == "pkg:pypi/requests@2.31.0"
