from ironclad.scanners.sbom import COPYLEFT_LICENSES, PERMISSIVE_LICENSES


def test_policy_sets_are_explicit():
    assert "GPL-3.0" in COPYLEFT_LICENSES
    assert "AGPL-3.0" in COPYLEFT_LICENSES
    assert "MIT" in PERMISSIVE_LICENSES
    assert "Apache-2.0" in PERMISSIVE_LICENSES


def test_unknown_license_is_not_silently_treated_as_permissive():
    assert "UNKNOWN" not in PERMISSIVE_LICENSES
