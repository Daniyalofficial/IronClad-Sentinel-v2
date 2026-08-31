import os
import tempfile

from ironclad.core.walker import DiscoveredFile
import pytest

from ironclad.scanners.dependency import (
    _satisfies_affected_range,
    normalize_spec,
    parse_package_lock,
    parse_package_json,
    parse_requirements_txt,
    range_permits_version,
    scan_dependencies,
    spec_is_pinned,
)


def _manifest(filename: str, content: str):
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return DiscoveredFile(path=path, rel_path=filename, language="other",
                          size_bytes=len(content), is_dependency_manifest=True)


def test_compound_advisory_range():
    assert _satisfies_affected_range("2.5.0", ">=2.0.0, <3.0.0")
    assert not _satisfies_affected_range("3.0.0", ">=2.0.0, <3.0.0")


def test_requirements_range_keeps_declared_spec():
    deps = parse_requirements_txt(_manifest("requirements.txt", "requests>=2.20,<2.31\n"))
    assert deps[0].version == "2.20"
    assert deps[0].declared_spec == ">=2.20,<2.31"


def test_npm_caret_range_that_admits_the_fix_is_not_reported():
    """``^4.17.11`` permits 4.17.19 and later, so the manifest is not evidence
    of a vulnerable install.

    Previously the range floor (4.17.11) was treated as the installed version
    and reported as a known vulnerability. That is a false positive: running
    the installer against this manifest yields the newest 4.x, which is
    patched. The lockfile -- where the installed version is actually recorded
    -- is scanned separately and still reports a vulnerable 4.17.11.
    """
    deps = parse_package_json(_manifest("package.json", '{"dependencies":{"lodash":"^4.17.11"}}'))
    assert deps[0].version == "4.17.11", "the range floor is still parsed"
    assert deps[0].declared_spec == "^4.17.11"
    assert deps[0].is_pinned is False

    findings = scan_dependencies([_manifest("package.json", '{"dependencies":{"lodash":"^4.17.11"}}')])
    assert [f.extra.get("package") for f in findings] == []


def test_npm_range_that_excludes_the_fix_is_reported():
    """A range that cannot be satisfied by the patched release is a real finding.

    Asserted as a property of every reported advisory rather than a hardcoded
    ID list, so regenerating the advisory database cannot silently invalidate
    the test: each finding must be one whose fixed release the range excludes,
    and no advisory whose fix the range admits may be reported.
    """
    spec = ">=4.17.11,<4.17.19"
    findings = scan_dependencies(
        [_manifest("package.json", '{"dependencies":{"lodash":"%s"}}' % spec)])
    assert findings, "this range excludes several patched releases"
    for f in findings:
        assert f.extra["is_pinned"] is False
        assert f.confidence == "medium"
        assert "cannot be satisfied" in f.title
        fixed = f.extra["fixed_version"]
        assert range_permits_version(spec, fixed) is False, (
            f"{f.extra['advisory_id']} is fixed in {fixed}, which {spec} permits -- "
            f"it must not be reported")


def test_npm_exact_version_is_pinned_and_reported_at_high_confidence():
    findings = scan_dependencies([_manifest("package.json", '{"dependencies":{"lodash":"4.17.11"}}')])
    assert findings, "lodash 4.17.11 has known advisories"
    assert all(f.extra["package"] == "lodash" for f in findings)
    assert all(f.extra["is_pinned"] for f in findings)
    assert all(f.confidence == "high" for f in findings)
    assert all(str(f.extra["advisory_id"]).startswith("GHSA-") for f in findings)


def test_package_lock_v3_is_scanned():
    lock = _manifest("package-lock.json", '{"lockfileVersion":3,"packages":{"":{"name":"demo"},"node_modules/lodash":{"version":"4.17.11"}}}')
    deps = parse_package_lock(lock)
    assert any(d.name == "lodash" and d.version == "4.17.11" for d in deps)
    findings = scan_dependencies([lock])
    assert any(f.extra.get("package") == "lodash" for f in findings)


def test_patched_lockfile_is_clean():
    # 4.18.0 is above every patched release the advisory database knows for
    # lodash, so a lockfile pinned there must produce nothing.
    lock = _manifest("package-lock.json", '{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.18.0"}}}')
    assert scan_dependencies([lock]) == []


# --------------------------------------------------------------------------- #
# Pinned vs range: the semantics that decide whether a manifest declaration is
# evidence of a vulnerable install at all.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("spec,pinned", [
    ("4.17.11", True),            # bare version (npm, Maven, go.mod)
    ("==2.3.2", True),            # PEP 440 exact pin
    ("=1.2.3", True),             # Cargo exact pin
    ("v1.2.3", True),
    ("^4.17.11", False),          # npm/Cargo caret
    ("~4.17.11", False),          # tilde
    ("~> 7.0", False),            # Ruby pessimistic
    (">=1.26,<3", False),
    (">=2023.5.7", False),
    ("1.x", False),
    ("*", False),
    ("[1.0,2.0)", False),         # Maven/NuGet bracket range
    ("latest", False),
    ("", False),
    (None, False),
])
def test_spec_is_pinned(spec, pinned):
    assert spec_is_pinned(spec) is pinned


@pytest.mark.parametrize("spec,normalized", [
    ("^1.5.0", ">=1.5.0, <2.0.0"),
    ("^0.5.0", ">=0.5.0, <0.6.0"),     # npm: 0.x carets do not cross minor
    ("~1.5.0", ">=1.5.0, <1.6.0"),
    ("~> 7.0", ">=7.0, <8"),
    ("1.x", ">=1.0.0, <2.0.0"),
    ("1.2.x", ">=1.2.0, <1.3.0"),
    ("[1.0,2.0)", ">=1.0, <2.0"),
    ("(1.0,2.0]", ">1.0, <=2.0"),
    (">=1.26,<3", ">=1.26, <3"),
    (">=1.0 || <0.5", ">=1.0 || <0.5"),   # npm OR range
    ("*", ">=0"),
])
def test_normalize_spec(spec, normalized):
    assert normalize_spec(spec) == normalized


def test_normalize_spec_refuses_to_guess_unknown_syntax():
    """Untranslatable syntax must return None, never a fabricated range."""
    for spec in ["git+https://x/y.git", "file:../local", "workspace:^1.0",
                 ">=1.0 || unparseable", "some-branch-name"]:
        assert normalize_spec(spec) is None, spec


@pytest.mark.parametrize("spec,version,expected", [
    ("^4.17.11", "4.17.21", True),
    (">=4.17.11,<4.17.19", "4.17.19", False),
    (">=4.17.11,<4.17.19", "4.17.18", True),
    ("~> 7.0", "7.9.9", True),
    ("~> 7.0", "8.0.0", False),
    ("unparseable-branch", "1.0.0", None),
    (None, "1.0.0", None),
])
def test_range_permits_version(spec, version, expected):
    assert range_permits_version(spec, version) is expected


def test_lockfile_entry_is_pinned_even_though_the_manifest_was_a_range():
    """A lockfile records what was actually installed, so it stays high-confidence."""
    lock = _manifest("package-lock.json",
                     '{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.11"}}}')
    deps = parse_package_lock(lock)
    assert deps[0].is_pinned is True
    findings = scan_dependencies([lock])
    assert findings and all(f.confidence == "high" for f in findings)
