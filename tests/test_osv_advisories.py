"""OSV advisory conversion, overlay loading, and the remote OSV endpoint.

The overlay tests use **real, unmodified** records from
``github/advisory-database`` (see ``tests/fixtures/osv/PROVENANCE.md``) so
the conversion is proven against genuine OSV data rather than an
approximation of the schema that this codebase also wrote.

None of these tests touch the network.
"""
from __future__ import annotations

import io
import json
import os

import pytest

from ironclad.core.config import IronCladConfig
from ironclad.core.engine import run_scan
from ironclad.core.walker import DiscoveredFile
from ironclad.scanners import osv
from ironclad.scanners.advisories import (
    BundledAdvisorySource,
    DirectoryAdvisorySource,
    RemoteAdvisorySource,
)
from ironclad.scanners.dependency import _satisfies_affected_range, scan_dependencies

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "osv")


def _load(name: str) -> dict:
    with open(os.path.join(FIXTURES, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _manifest(tmp_path, filename: str, content: str) -> DiscoveredFile:
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    return DiscoveredFile(path=str(path), rel_path=filename, language="other",
                          size_bytes=len(content), is_dependency_manifest=True)


def _matches(version: str, spec: str) -> bool:
    return _satisfies_affected_range(version, spec)


# --------------------------------------------------------------------------- #
# Conversion of real OSV records
# --------------------------------------------------------------------------- #
def test_real_ghsa_record_converts_to_a_range_that_matches():
    """requests CVE-2018-18074: introduced 0, fixed 2.20.0."""
    entries = osv.record_to_entries(_load("GHSA-x84v-xcm2-53pg.json"))
    assert len(entries) == 1
    eco, name, advisory = entries[0]
    assert (eco, name) == ("python", "requests")
    assert advisory["id"] == "GHSA-x84v-xcm2-53pg"
    assert advisory["cve"] == "CVE-2018-18074"
    assert advisory["severity"] == "high"
    assert advisory["fixed_in"] == "2.20.0"
    # `introduced: 0` means "from the beginning", so no lower bound appears.
    assert advisory["affected"] == "<2.20.0"
    assert _matches("2.19.1", advisory["affected"])
    assert not _matches("2.20.0", advisory["affected"])
    assert not _matches("2.31.0", advisory["affected"])


def test_real_record_with_lower_bound_and_last_affected():
    """binwalk CVE-2022-4510: introduced 2.1.2b, last_affected 2.3.3.

    Exercises both a real lower bound (so versions *below* the range are not
    flagged) and `<=` from `last_affected`, which has no `fixed` event at all.
    """
    eco, name, advisory = osv.record_to_entries(_load("GHSA-3cm8-v4mc-gppg.json"))[0]
    assert (eco, name) == ("python", "binwalk")
    assert advisory["cve"] == "CVE-2022-4510"
    assert advisory["affected"] == ">=2.1.2b, <=2.3.3"
    assert advisory["fixed_in"] == "", "this advisory has no fixed version"
    assert _matches("2.3.0", advisory["affected"])
    assert _matches("2.3.3", advisory["affected"])
    assert not _matches("2.3.4", advisory["affected"]), "above last_affected is safe"
    assert not _matches("2.1.0", advisory["affected"]), "below introduced is safe"


def test_pyyaml_and_jinja2_real_records_convert():
    pyyaml = osv.record_to_entries(_load("GHSA-rprw-h62v-c2w7.json"))[0]
    jinja = osv.record_to_entries(_load("GHSA-462w-v97r-4m45.json"))[0]
    assert (pyyaml[0], pyyaml[1]) == ("python", "PyYAML")
    assert pyyaml[2]["severity"] == "critical"
    assert pyyaml[2]["cve"] == "CVE-2017-18342"
    assert (jinja[0], jinja[1]) == ("python", "Jinja2")
    assert jinja[2]["cve"] == "CVE-2019-10906"


# --------------------------------------------------------------------------- #
# Range semantics
# --------------------------------------------------------------------------- #
def test_open_ended_range_still_matches_later_versions():
    spec = osv.affected_range_from_osv(
        [{"type": "ECOSYSTEM", "events": [{"introduced": "1.4.0"}]}])
    assert spec == ">=1.4.0"
    assert _matches("9.9.9", spec), "an unfixed vulnerability affects later versions"
    assert not _matches("1.3.9", spec)


def test_record_with_no_range_information_matches_every_version():
    """An empty spec would mean "matches nothing" to the matcher."""
    assert osv.affected_range_from_osv([]) == ">=0"
    assert _matches("0.0.1", ">=0")
    assert _matches("99.0.0", ">=0")


def test_disjoint_ranges_become_alternatives():
    spec = osv.affected_range_from_osv([
        {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]},
        {"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.1.0"}]},
    ])
    assert spec == ">=1.0.0, <1.2.0 || >=2.0.0, <2.1.0"
    assert _matches("1.1.0", spec)
    assert _matches("2.0.5", spec)
    assert not _matches("1.5.0", spec), "the gap between ranges is not vulnerable"
    assert not _matches("3.0.0", spec)


def test_explicit_version_list_becomes_alternatives():
    spec = osv.affected_range_from_osv([], versions=["1.0.0", "1.0.1"])
    assert spec == "=1.0.0 || =1.0.1"
    assert _matches("1.0.1", spec)
    assert not _matches("1.0.2", spec)


def test_git_ranges_are_dropped_rather_than_guessed():
    """Commit hashes are not comparable to the versions parsed from manifests."""
    spec = osv.affected_range_from_osv([
        {"type": "GIT", "events": [{"introduced": "abc123"}, {"fixed": "def456"}]},
    ])
    assert spec == ">=0", "a GIT-only record must not emit a bogus version range"


def test_git_only_advisory_says_it_is_not_version_scoped():
    """Refusing to guess must not look like a version-scoped match.

    A GIT-only record has no published version range, so every declared
    version is reported. The finding text has to say that, or an operator
    reads ">=0" as a real range and cannot tell why every release of the
    package is flagged.
    """
    entries = osv.record_to_entries({
        "id": "GHSA-gitonly",
        "summary": "Command injection in the plugin loader",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "demo-lib"},
                      "ranges": [{"type": "GIT",
                                  "events": [{"introduced": "abc123"}, {"fixed": "def456"}]}]}],
    })
    advisory = entries[0][2]
    assert advisory["affected"] == ">=0"
    assert "commits rather than released versions" in advisory["summary"]
    assert "Command injection in the plugin loader" in advisory["summary"], (
        "the original summary must survive the annotation")


def test_limit_event_is_treated_as_exclusive_upper_bound():
    spec = osv.affected_range_from_osv(
        [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"limit": "2.0.0"}]}])
    assert spec == ">=1.0.0, <2.0.0"


# --------------------------------------------------------------------------- #
# Ecosystem and field mapping
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("osv_eco,expected", [
    ("PyPI", "python"), ("npm", "javascript"), ("Go", "go"),
    ("RubyGems", "ruby"), ("Packagist", "php"), ("Maven", "java"),
    ("crates.io", "rust"), ("NuGet", "nuget"),
])
def test_ecosystem_mapping(osv_eco, expected):
    assert osv.ironclad_ecosystem(osv_eco) == expected


@pytest.mark.parametrize("osv_eco", ["Debian:11", "Alpine:v3.18", "Linux", "", "PyPI"])
def test_unmappable_ecosystems(osv_eco):
    """IronClad has no manifest parser for distro feeds, so they must be dropped.

    ``PyPI`` is in the list as the control: it must map, the others must not.
    """
    if osv_eco == "PyPI":
        assert osv.ironclad_ecosystem(osv_eco) == "python"
    else:
        assert osv.ironclad_ecosystem(osv_eco) is None


def test_record_for_an_unscannable_ecosystem_produces_no_entries():
    record = {
        "id": "GHSA-0000-0000-0000",
        "aliases": ["CVE-2024-0001"],
        "affected": [{"package": {"ecosystem": "Debian:11", "name": "openssl"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"}, {"fixed": "1.1"}]}]}],
    }
    assert osv.record_to_entries(record) == []


def test_severity_falls_back_to_medium_when_only_a_cvss_vector_exists():
    record = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/UI:N/S:U/C:H/I:H/A:H"}]}
    assert osv.severity_from_osv(record) == "medium", (
        "a CVSS vector carries no base score, so this must not invent one")


def test_moderate_normalises_to_high():
    assert osv.severity_from_osv({"database_specific": {"severity": "MODERATE"}}) == "high"


def test_iter_records_handles_all_three_payload_shapes():
    record = {"id": "GHSA-x", "affected": []}
    assert osv.iter_records(record) == [record]
    assert osv.iter_records({"vulns": [record]}) == [record]
    assert osv.iter_records([record]) == [record]
    assert osv.iter_records({"python": {"requests": []}}) == [], (
        "IronClad's own schema must not be mistaken for an OSV payload")


def test_build_database_is_idempotent():
    records = [_load("GHSA-x84v-xcm2-53pg.json")] * 3
    db = osv.build_database(osv.iter_records(records) * 2)
    assert len(db["python"]["requests"]) == 1


# --------------------------------------------------------------------------- #
# Directory overlay: the documented "internal OSV mirror" path
# --------------------------------------------------------------------------- #
def test_directory_overlay_loads_a_real_osv_dump(tmp_path):
    """The whole point: drop real OSV files into advisory_path and they work."""
    overlay = tmp_path / "advisories"
    overlay.mkdir()
    for name in os.listdir(FIXTURES):
        if name.endswith(".json"):
            (overlay / name).write_text(
                open(os.path.join(FIXTURES, name), encoding="utf-8").read(), encoding="utf-8")

    source = DirectoryAdvisorySource(directory=str(overlay))
    advisories = source.lookup("python", "requests")
    assert any(a["id"] == "GHSA-x84v-xcm2-53pg" for a in advisories)
    assert source.warnings == [], f"real OSV data must load without warnings: {source.warnings}"

    # And it reaches the scanner as a real finding.
    manifest = _manifest(tmp_path, "requirements.txt", "requests==2.19.1\n")
    findings = scan_dependencies([manifest], source=source)
    ids = {f.extra.get("advisory_id") for f in findings}
    assert "GHSA-x84v-xcm2-53pg" in ids, [f.title for f in findings]


def test_overlay_merges_over_bundled_without_losing_bundled_entries(tmp_path):
    overlay = tmp_path / "advisories"
    overlay.mkdir()
    (overlay / "osv.json").write_text(
        json.dumps(_load("GHSA-x84v-xcm2-53pg.json")), encoding="utf-8")

    source = DirectoryAdvisorySource(directory=str(overlay))
    bundled_only = BundledAdvisorySource().lookup("python", "django")
    assert bundled_only, "the bundled database must still be consulted"
    assert source.lookup("python", "django") == bundled_only
    assert any(a["id"] == "GHSA-x84v-xcm2-53pg" for a in source.lookup("python", "requests"))


def test_overlay_still_accepts_the_native_ironclad_schema(tmp_path):
    """Backwards compatibility: existing overlays must keep working."""
    overlay = tmp_path / "advisories"
    overlay.mkdir()
    (overlay / "org.json").write_text(json.dumps({
        "python": {"internal-sdk": [{
            "id": "ORG-1", "cve": None, "affected": "<2.0.0",
            "severity": "critical", "summary": "internal advisory", "fixed_in": "2.0.0"}]}
    }), encoding="utf-8")

    source = DirectoryAdvisorySource(directory=str(overlay))
    assert [a["id"] for a in source.lookup("python", "internal-sdk")] == ["ORG-1"]


def test_overlay_accepts_an_osv_batch_response(tmp_path):
    overlay = tmp_path / "advisories"
    overlay.mkdir()
    (overlay / "batch.json").write_text(json.dumps({
        "vulns": [_load("GHSA-rprw-h62v-c2w7.json"), _load("GHSA-462w-v97r-4m45.json")]
    }), encoding="utf-8")

    source = DirectoryAdvisorySource(directory=str(overlay))
    assert any(a["cve"] == "CVE-2017-18342" for a in source.lookup("python", "pyyaml"))
    assert any(a["cve"] == "CVE-2019-10906" for a in source.lookup("python", "jinja2"))


def test_overlay_warns_when_osv_records_cover_no_scannable_ecosystem(tmp_path):
    overlay = tmp_path / "advisories"
    overlay.mkdir()
    (overlay / "distro.json").write_text(json.dumps({
        "id": "GHSA-distro-only", "affected": [
            {"package": {"ecosystem": "Debian:11", "name": "openssl"},
             "ranges": [{"type": "ECOSYSTEM",
                         "events": [{"introduced": "0"}, {"fixed": "1.1"}]}]}]}),
        encoding="utf-8")

    source = DirectoryAdvisorySource(directory=str(overlay))
    assert source.lookup("python", "openssl") == []
    assert any("none for an ecosystem" in w for w in source.warnings), source.warnings


def test_overlay_skips_a_corrupt_file_without_aborting(tmp_path):
    overlay = tmp_path / "advisories"
    overlay.mkdir()
    (overlay / "a-broken.json").write_text("{not json", encoding="utf-8")
    (overlay / "b-good.json").write_text(
        json.dumps(_load("GHSA-x84v-xcm2-53pg.json")), encoding="utf-8")

    source = DirectoryAdvisorySource(directory=str(overlay))
    assert any(a["id"] == "GHSA-x84v-xcm2-53pg" for a in source.lookup("python", "requests"))
    assert any("a-broken.json" in w for w in source.warnings)


def test_setting_only_advisory_path_actually_takes_effect(tmp_path):
    """The bundled DB's own guidance says "point advisory_path at your overlay".

    With ``advisory_source`` left at its default this used to be silently
    ignored: the scan quietly used the 44-package bundled database while the
    operator believed their internal feed was in effect. For a security tool
    that is the worst possible failure mode -- no error, wrong answer.
    """
    overlay = tmp_path / "advisories"
    overlay.mkdir()
    (overlay / "org.json").write_text(json.dumps({
        "python": {"internal-sdk": [{
            "id": "ORG-ONLY-1", "cve": None, "affected": "<2.0.0",
            "severity": "critical", "summary": "only in the overlay", "fixed_in": "2.0.0"}]}
    }), encoding="utf-8")

    target = tmp_path / "app"
    target.mkdir()
    (target / "requirements.txt").write_text("internal-sdk==1.0.0\n")

    result = run_scan(IronCladConfig(target=str(target), advisory_path=str(overlay)))
    ids = {f.extra.get("advisory_id") for f in result.findings}
    assert "ORG-ONLY-1" in ids, (
        f"advisory_path was set but ignored; findings={[f.rule_id for f in result.findings]}")


# --------------------------------------------------------------------------- #
# Remote OSV endpoint (regressions for the hand-rolled converter it replaced)
# --------------------------------------------------------------------------- #
class _FakeResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _patch_remote(monkeypatch, payload: dict) -> None:
    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda request, timeout=None: _FakeResponse(payload))


def test_remote_source_respects_the_introduced_bound(monkeypatch):
    """Regression: the old converter ignored `introduced`, flagging safe versions."""
    _patch_remote(monkeypatch, {"vulns": [{
        "id": "GHSA-rangy",
        "aliases": ["CVE-2024-9999"],
        "database_specific": {"severity": "HIGH"},
        "summary": "vulnerable only from 2.0.0",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "demo-lib"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "2.0.0"}, {"fixed": "2.5.0"}]}]}],
    }]})
    source = RemoteAdvisorySource(endpoint="https://osv.example/v1", fallback=BundledAdvisorySource())

    spec = next(a["affected"] for a in source.lookup("python", "demo-lib")
                if a["id"] == "GHSA-rangy")
    assert spec == ">=2.0.0, <2.5.0"
    assert not _matches("1.0.0", spec), "a version below `introduced` is not vulnerable"
    assert _matches("2.4.0", spec)


def test_remote_source_reports_advisories_that_have_no_fix(monkeypatch):
    """Regression: those used to be converted to "<0", which matches nothing."""
    _patch_remote(monkeypatch, {"vulns": [{
        "id": "GHSA-unfixed",
        "aliases": ["CVE-2024-9998"],
        "database_specific": {"severity": "CRITICAL"},
        "summary": "no fix available yet",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "demo-lib"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"}]}]}],
    }]})
    source = RemoteAdvisorySource(endpoint="https://osv.example/v1", fallback=BundledAdvisorySource())

    advisory = next(a for a in source.lookup("python", "demo-lib") if a["id"] == "GHSA-unfixed")
    assert advisory["affected"] != "<0"
    assert _matches("99.0.0", advisory["affected"]), "an unfixed advisory must still match"


def test_remote_source_ignores_other_packages_in_the_same_response(monkeypatch):
    """A record naming several packages must not be attributed to the wrong one."""
    _patch_remote(monkeypatch, {"vulns": [{
        "id": "GHSA-shared",
        "affected": [
            {"package": {"ecosystem": "PyPI", "name": "demo-lib"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]},
            {"package": {"ecosystem": "PyPI", "name": "something-else"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.0"}]}]},
        ],
    }]})
    source = RemoteAdvisorySource(endpoint="https://osv.example/v1", fallback=BundledAdvisorySource())
    ids = [a["id"] for a in source.lookup("python", "demo-lib") if a["id"] == "GHSA-shared"]
    assert ids == ["GHSA-shared"]
    # the other package's range must not leak into demo-lib's lookup
    spec = next(a["affected"] for a in source.lookup("python", "demo-lib") if a["id"] == "GHSA-shared")
    assert spec == "<1.0"


def test_overlay_directory_does_not_silently_disable_bundled_detection(tmp_path):
    """The failure mode this fixes, asserted directly.

    Handing a directory to the bundled file loader raised ``OSError`` inside
    ``_load``, which is caught and turned into an empty database. The scan
    then reported *zero* vulnerable dependencies and exited 0 -- a clean bill
    of health produced by a configuration mistake.
    """
    overlay = tmp_path / "advisories"
    overlay.mkdir()
    (overlay / "org.json").write_text(json.dumps({
        "python": {"internal-sdk": [{
            "id": "ORG-ONLY-1", "cve": None, "affected": "<2.0.0",
            "severity": "critical", "summary": "only in the overlay", "fixed_in": "2.0.0"}]}
    }), encoding="utf-8")

    target = tmp_path / "app"
    target.mkdir()
    # internal-sdk comes from the overlay; jinja2 comes from the bundled DB.
    (target / "requirements.txt").write_text("internal-sdk==1.0.0\njinja2==3.1.2\n")

    result = run_scan(IronCladConfig(target=str(target), advisory_path=str(overlay)))
    ids = {f.extra.get("advisory_id") for f in result.findings}
    assert "ORG-ONLY-1" in ids, "overlay advisory missing"
    assert any(str(i).startswith("GHSA-") for i in ids if i), (
        f"bundled advisories were silently dropped; got {ids}")
    sources = {f.extra.get("advisory_source") for f in result.findings
               if f.extra.get("advisory_id")}
    assert sources and all(s.startswith("directory:") for s in sources), sources


def test_advisory_path_pointing_at_a_file_still_replaces_the_database(tmp_path):
    """Backwards compatibility: a file path is a replacement DB, not an overlay."""
    db_file = tmp_path / "custom_db.json"
    db_file.write_text(json.dumps({
        "python": {"replacement-only": [{
            "id": "REPL-1", "cve": None, "affected": "<3.0.0",
            "severity": "high", "summary": "replacement db", "fixed_in": "3.0.0"}]}
    }), encoding="utf-8")

    target = tmp_path / "app"
    target.mkdir()
    (target / "requirements.txt").write_text("replacement-only==1.0.0\njinja2==3.1.2\n")

    result = run_scan(IronCladConfig(target=str(target), advisory_path=str(db_file)))
    ids = {f.extra.get("advisory_id") for f in result.findings}
    assert "REPL-1" in ids
    assert not any(str(i).startswith("GHSA-") for i in ids if i), (
        "a replacement database must not be merged with the bundled one")


# --------------------------------------------------------------------------- #
# `ironclad advisories import-osv`
# --------------------------------------------------------------------------- #
def test_import_osv_lowercases_package_keys(tmp_path):
    """The scanner normalises names before lookup, so keys must be lowercase.

    A mixed-case key such as "PyYAML" or "github.com/Traefik/traefik" is never
    found by a lookup for the normalised name, which silently drops every
    advisory for that package.
    """
    from click.testing import CliRunner

    from ironclad.cli import main
    from ironclad.scanners.advisories import BundledAdvisorySource

    source = tmp_path / "osv"
    source.mkdir()
    (source / "pyyaml.json").write_text(
        open(os.path.join(FIXTURES, "GHSA-rprw-h62v-c2w7.json"), encoding="utf-8").read(),
        encoding="utf-8")
    out = tmp_path / "db.json"

    result = CliRunner().invoke(main, ["advisories", "import-osv",
                                       "--source", str(source), "--output", str(out),
                                       "--json"])
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary["osv_records_read"] == 1
    assert summary["package_count"] == 1

    written = json.loads(out.read_text(encoding="utf-8"))
    keys = list(written["python"])
    assert keys == ["pyyaml"], f"keys must be lowercased, got {keys}"
    assert BundledAdvisorySource(path=str(out)).lookup("python", "pyyaml")


def test_import_osv_filters_ecosystems_and_reports_provenance(tmp_path):
    from click.testing import CliRunner

    from ironclad.cli import main

    source = tmp_path / "osv"
    source.mkdir()
    for name in ("GHSA-x84v-xcm2-53pg.json", "GHSA-462w-v97r-4m45.json"):
        (source / name).write_text(
            open(os.path.join(FIXTURES, name), encoding="utf-8").read(), encoding="utf-8")
    out = tmp_path / "db.json"

    result = CliRunner().invoke(main, ["advisories", "import-osv", "--source", str(source),
                                       "--output", str(out), "--ecosystems", "javascript",
                                       "--json"])
    assert result.exit_code == 0, result.output
    written = json.loads(out.read_text(encoding="utf-8"))
    assert [k for k in written if not k.startswith("_")] == [], (
        "both fixtures are PyPI records, so filtering to javascript keeps nothing")
    meta = written["_meta"]
    assert meta["osv_records_read"] == 2, "records are still counted even when filtered out"
    assert meta["package_count"] == 0
    assert meta["generator_version"]


def test_import_osv_keeps_only_the_requested_ecosystem(tmp_path):
    """Positive control for the filter above."""
    from click.testing import CliRunner

    from ironclad.cli import main

    source = tmp_path / "osv"
    source.mkdir()
    (source / "requests.json").write_text(
        open(os.path.join(FIXTURES, "GHSA-x84v-xcm2-53pg.json"), encoding="utf-8").read(),
        encoding="utf-8")
    out = tmp_path / "db.json"

    result = CliRunner().invoke(main, ["advisories", "import-osv", "--source", str(source),
                                       "--output", str(out), "--ecosystems", "python",
                                       "--json"])
    assert result.exit_code == 0, result.output
    written = json.loads(out.read_text(encoding="utf-8"))
    assert [k for k in written if not k.startswith("_")] == ["python"]
    assert written["_meta"]["package_count"] == 1


def test_import_osv_rejects_an_unknown_ecosystem(tmp_path):
    from click.testing import CliRunner

    from ironclad.cli import main
    from ironclad.core import exit_codes as ec

    result = CliRunner().invoke(main, ["advisories", "import-osv", "--source", str(tmp_path),
                                       "--output", str(tmp_path / "db.json"),
                                       "--ecosystems", "cobol"])
    assert result.exit_code == ec.CONFIG_ERROR
    assert "unknown ecosystem" in result.output


def test_import_osv_requires_a_directory(tmp_path):
    from click.testing import CliRunner

    from ironclad.cli import main
    from ironclad.core import exit_codes as ec

    result = CliRunner().invoke(main, ["advisories", "import-osv",
                                       "--source", str(tmp_path / "missing"),
                                       "--output", str(tmp_path / "db.json")])
    assert result.exit_code == ec.TARGET_ERROR


def test_import_osv_skips_corrupt_files_and_keeps_going(tmp_path):
    from click.testing import CliRunner

    from ironclad.cli import main

    source = tmp_path / "osv"
    source.mkdir()
    (source / "broken.json").write_text("{not json", encoding="utf-8")
    (source / "good.json").write_text(
        open(os.path.join(FIXTURES, "GHSA-x84v-xcm2-53pg.json"), encoding="utf-8").read(),
        encoding="utf-8")
    out = tmp_path / "db.json"

    result = CliRunner().invoke(main, ["advisories", "import-osv", "--source", str(source),
                                       "--output", str(out), "--json"])
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary["unreadable_files"] == 1
    assert summary["osv_records_read"] == 1


def test_machine_readable_output_stays_parseable_with_long_values(tmp_path):
    """Regression: `--json` must emit valid JSON however long the values are.

    The importer originally printed through `console.print(json.dumps(...))`.
    Rich word-wraps at 80 columns when stdout is not a terminal, so a long
    string value was split across lines *inside* the quoted string and the
    output stopped being valid JSON -- silently, and only for values long
    enough to wrap. Every other `--json` command in the CLI uses
    `console.print_json`, which does not wrap; this pins that.
    """
    import json as _json

    from click.testing import CliRunner

    from ironclad.cli import main

    source = tmp_path / "osv"
    source.mkdir()
    (source / "requests.json").write_text(
        open(os.path.join(FIXTURES, "GHSA-x84v-xcm2-53pg.json"), encoding="utf-8").read(),
        encoding="utf-8")
    long_label = "github/advisory-database (advisories/github-reviewed) at " + "e" * 120

    result = CliRunner().invoke(main, ["advisories", "import-osv", "--source", str(source),
                                       "--output", str(tmp_path / "db.json"),
                                       "--source-label", long_label, "--json"])
    assert result.exit_code == 0, result.output
    parsed = _json.loads(result.output)
    assert parsed["sources"] == [long_label], "the value must survive intact"


# --------------------------------------------------------------------------- #
# Second feed: pypa/advisory-database (YAML, PYSEC identifiers)
# --------------------------------------------------------------------------- #
def _yaml_fixture(name: str) -> str:
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return fh.read()


def test_yaml_osv_records_are_imported(tmp_path):
    """PyPA publishes the same OSV schema as YAML, so the importer must read it."""
    from click.testing import CliRunner

    from ironclad.cli import main

    source = tmp_path / "pypa"
    source.mkdir()
    (source / "PYSEC-2025-3.yaml").write_text(_yaml_fixture("PYSEC-2025-3.yaml"),
                                              encoding="utf-8")
    out = tmp_path / "db.json"
    result = CliRunner().invoke(main, ["advisories", "import-osv", "--source", str(source),
                                       "--output", str(out), "--json"])
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary["osv_records_read"] == 1
    assert summary["package_count"] == 1

    written = json.loads(out.read_text(encoding="utf-8"))
    advisory = written["python"]["autodzee"][0]
    assert advisory["id"] == "PYSEC-2025-3"
    assert advisory["affected"] == ">=0"


def test_record_with_no_version_information_is_dropped():
    """Missing data must not become "every version is vulnerable".

    PYSEC-2025-74 describes a vulnerability in **Nautobot**, names `jinja2` as
    the affected package, and carries no ranges and no versions. Converted
    naively it asserted that every jinja2 release ever published is
    vulnerable to someone else's bug -- and because jinja2 is declared as a
    range in most projects, it fired on real repositories.
    """
    import yaml

    record = yaml.safe_load(_yaml_fixture("PYSEC-2025-74.yaml"))
    assert record["affected"][0]["package"]["name"] == "jinja2", (
        "fixture must still be the Nautobot/jinja2 mismatch this guards against")
    assert osv.record_to_entries(record) == []


def test_malicious_package_advisory_with_no_fix_is_still_kept():
    """The control for the test above: no fix really does mean every version.

    PYSEC-2025-3 is a malicious PyPI package with `introduced: 0` and no
    patched release. Dropping it would hide a real vulnerability, so the rule
    is specifically about *absent* version data, not about unbounded ranges.
    """
    import yaml

    record = yaml.safe_load(_yaml_fixture("PYSEC-2025-3.yaml"))
    entries = osv.record_to_entries(record)
    assert len(entries) == 1
    eco, name, advisory = entries[0]
    assert (eco, name) == ("python", "autodzee")
    assert advisory["affected"] == ">=0"
    assert advisory["fixed_in"] == ""


def test_merging_two_feeds_dedupes_by_cve(tmp_path):
    """Two feeds name the same vulnerability differently.

    GHSA and PyPA assign different identifiers to one CVE, so merging them
    without deduplicating would report most Python vulnerabilities twice.
    """
    from click.testing import CliRunner

    from ironclad.cli import main

    ghsa = tmp_path / "ghsa"
    ghsa.mkdir()
    (ghsa / "a.json").write_text(json.dumps({
        "id": "GHSA-aaaa-bbbb-cccc",
        "aliases": ["CVE-2024-0001"],
        "database_specific": {"severity": "HIGH"},
        "summary": "first feed",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "demo-lib"},
                      "ranges": [{"type": "ECOSYSTEM",
                                  "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}],
    }), encoding="utf-8")

    pypa = tmp_path / "pypa"
    pypa.mkdir()
    (pypa / "b.yaml").write_text(
        "id: PYSEC-2024-1\n"
        "aliases:\n  - CVE-2024-0001\n"
        "summary: second feed\n"
        "affected:\n"
        "  - package:\n      ecosystem: PyPI\n      name: demo-lib\n"
        "    ranges:\n"
        "      - type: ECOSYSTEM\n"
        "        events:\n"
        "          - introduced: '0'\n"
        "          - fixed: 1.2.3\n",
        encoding="utf-8")

    out = tmp_path / "db.json"
    result = CliRunner().invoke(main, ["advisories", "import-osv",
                                       "--source", str(ghsa), "--source", str(pypa),
                                       "--output", str(out), "--json"])
    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary["osv_records_read"] == 2
    assert summary["advisory_count"] == 1, "the same CVE must not be stored twice"
    assert summary["duplicate_cves_merged"] == 1

    written = json.loads(out.read_text(encoding="utf-8"))
    kept = written["python"]["demo-lib"]
    assert [a["id"] for a in kept] == ["GHSA-aaaa-bbbb-cccc"], (
        "the first source listed wins, so precedence is predictable")


def test_importer_reports_every_source_in_provenance(tmp_path):
    from click.testing import CliRunner

    from ironclad.cli import main

    source = tmp_path / "ghsa"
    source.mkdir()
    (source / "a.json").write_text(
        open(os.path.join(FIXTURES, "GHSA-x84v-xcm2-53pg.json"), encoding="utf-8").read(),
        encoding="utf-8")
    out = tmp_path / "db.json"
    result = CliRunner().invoke(main, ["advisories", "import-osv", "--source", str(source),
                                       "--output", str(out),
                                       "--source-label", "feed-a@abc123 + feed-b@def456",
                                       "--json"])
    assert result.exit_code == 0, result.output
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["_meta"]["sources"] == ["feed-a@abc123 + feed-b@def456"]


def test_bundled_database_contains_no_version_less_advisories():
    """Guard the shipped database itself, not just the converter."""
    import json as _json

    path = os.path.join(os.path.dirname(__file__), "..", "ironclad", "data", "vuln_db.json")
    with open(path, encoding="utf-8") as fh:
        db = _json.load(fh)
    offenders = []
    for eco, packages in db.items():
        if eco.startswith("_"):
            continue
        for package, advisories in packages.items():
            for advisory in advisories:
                spec = str(advisory.get("affected", ""))
                if spec in {"", ">=0"} and not advisory.get("fixed_in") and not spec:
                    offenders.append(f"{eco}/{package}: {advisory.get('id')}")
                assert spec, f"{eco}/{package} has an empty affected range"
    assert not offenders
