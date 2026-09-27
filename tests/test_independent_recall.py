"""Feed comparison failures must not be mislabeled as absent advisories."""
from __future__ import annotations


def test_pypa_disagreement_is_reported_without_changing_the_recall_gate():
    from benchmarks.independent_recall import explain_unmatched

    class Bundled:
        def lookup(self, ecosystem, name):
            assert (ecosystem, name) == ("python", "cryptography")
            return [{"cve": "CVE-2026-69249", "affected": ">=42.0.0, <49.0.0",
                     "id": "GHSA-jwv3-5hgf-82ww"}]

    disputed = explain_unmatched(Bundled(), "cryptography", "37.0.4",
                                 "CVE-2026-69249", ">=0, <49.0.0")
    assert "range disagreement" in disputed
    assert ">=42.0.0, <49.0.0" in disputed
    assert ">=0, <49.0.0" in disputed
    assert "absent" not in disputed

    not_in_bundle = explain_unmatched(Bundled(), "cryptography", "37.0.4",
                                      "CVE-2026-99999", ">=0, <49.0.0")
    assert "absent" in not_in_bundle

    matching = explain_unmatched(Bundled(), "cryptography", "44.0.0",
                                 "CVE-2026-69249", ">=0, <49.0.0")
    assert "scanner pipeline" in matching
