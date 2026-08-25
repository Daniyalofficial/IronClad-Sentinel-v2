from ironclad.scanners.sbom import _purl


def test_purl_uses_ecosystem_mapping():
    assert _purl("python", "requests", "2.31.0") == "pkg:pypi/requests@2.31.0"
    assert _purl("javascript", "lodash", "4.17.21") == "pkg:npm/lodash@4.17.21"


def test_unknown_ecosystem_is_generic():
    assert _purl("unknown", "demo", "1.0") == "pkg:generic/demo@1.0"
