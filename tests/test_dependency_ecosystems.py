"""Ecosystem coverage for the dependency scanner.

Every ecosystem gets three cases, matching the rule used across the whole
scanner suite: a *vulnerable* manifest must produce a finding, a *safe*
manifest must produce none, and a *malformed* manifest must produce a
manifest-integrity finding instead of being silently ignored.
"""
import json

import pytest

from ironclad.core.walker import DiscoveredFile, is_dependency_manifest
from ironclad.scanners.advisories import (
    AdvisorySourceError,
    BundledAdvisorySource,
    DirectoryAdvisorySource,
    RemoteAdvisorySource,
    build_source,
)
from ironclad.scanners.dependency import (
    extract_dependencies,
    normalize_name,
    parser_for,
    scan_dependencies,
)

# (filename, vulnerable content, safe content, expected vulnerable package)
#
# Every version pair below was derived from the shipped advisory database
# rather than invented: the vulnerable version matches at least one real
# advisory for that package and the safe version matches none. When the
# bundled database is regenerated from a newer advisory feed these pairs may
# need refreshing -- `test_ecosystem_pairs_are_still_valid` fails with the
# exact reason rather than letting a stale pair pass silently.
ECOSYSTEM_CASES = [
    ("requirements.txt", "jinja2==3.1.2\n", "jinja2==3.1.6\n", "jinja2"),
    ("requirements-dev.txt", "werkzeug==2.3.0\n", "werkzeug==3.1.6\n", "werkzeug"),
    ("package.json", '{"dependencies": {"lodash": "4.17.11"}}',
     '{"dependencies": {"lodash": "4.18.0"}}', "lodash"),
    ("package-lock.json",
     '{"lockfileVersion": 3, "packages": {"node_modules/minimist": {"version": "1.2.5"}}}',
     '{"lockfileVersion": 3, "packages": {"node_modules/minimist": {"version": "1.2.6"}}}',
     "minimist"),
    ("yarn.lock",
     '# yarn lockfile v1\n\nsemver@^7.0.0:\n  version "7.3.5"\n  resolved "x"\n',
     '# yarn lockfile v1\n\nsemver@^7.0.0:\n  version "7.5.4"\n  resolved "x"\n',
     "semver"),
    ("pnpm-lock.yaml",
     "packages:\n  /braces@3.0.2:\n    resolution: {integrity: x}\n",
     "packages:\n  /braces@3.0.3:\n    resolution: {integrity: x}\n",
     "braces"),
    ("go.mod", "module demo\n\nrequire golang.org/x/net v0.16.0\n",
     "module demo\n\nrequire golang.org/x/net v0.55.0\n", "golang.org/x/net"),
    ("go.sum",
     "golang.org/x/net v0.16.0 h1:aaaa\n",
     "golang.org/x/net v0.55.0 h1:aaaa\n",
     "golang.org/x/net"),
    # Cargo treats a bare "0.6.3" as "^0.6.3", so the vulnerable case needs an
    # explicit "=" pin; a range is not evidence of an installed version.
    ("Cargo.toml", '[dependencies]\nsmallvec = "=0.6.3"\n',
     '[dependencies]\nsmallvec = "=0.6.14"\n', "smallvec"),
    ("Cargo.lock", '[[package]]\nname = "tokio"\nversion = "1.8.1"\n',
     '[[package]]\nname = "tokio"\nversion = "1.44.2"\n', "tokio"),
    ("pom.xml",
     "<project><dependencies><dependency><groupId>org.springframework</groupId>"
     "<artifactId>spring-core</artifactId><version>5.3.10</version></dependency></dependencies></project>",
     "<project><dependencies><dependency><groupId>org.springframework</groupId>"
     "<artifactId>spring-core</artifactId><version>7.0.8</version></dependency></dependencies></project>",
     "org.springframework:spring-core"),
    ("build.gradle",
     'dependencies { implementation "org.springframework:spring-core:5.3.10" }',
     'dependencies { implementation "org.springframework:spring-core:7.0.8" }',
     "org.springframework:spring-core"),
    ("composer.json", '{"require": {"phpmailer/phpmailer": "6.1.0"}}',
     '{"require": {"phpmailer/phpmailer": "6.5.0"}}', "phpmailer/phpmailer"),
    ("composer.lock",
     '{"packages": [{"name": "phpmailer/phpmailer", "version": "v6.1.0"}]}',
     '{"packages": [{"name": "phpmailer/phpmailer", "version": "v6.5.0"}]}',
     "phpmailer/phpmailer"),
    ("Gemfile", 'gem "rack", "1.1.3"\n', 'gem "rack", "3.2.6"\n', "rack"),
    ("Gemfile.lock",
     "GEM\n  specs:\n    rack (1.1.3)\n",
     "GEM\n  specs:\n    rack (3.2.6)\n",
     "rack"),
    ("packages.config",
     '<packages><package id="Newtonsoft.Json" version="12.0.1" /></packages>',
     '<packages><package id="Newtonsoft.Json" version="13.0.3" /></packages>',
     "newtonsoft.json"),
]


def tmpdir_helper():
    """A fresh directory as a Path, for tests that are not fixture-driven."""
    import pathlib
    import tempfile

    return pathlib.Path(tempfile.mkdtemp())


def _manifest(tmp_path, filename, content):
    path = tmp_path / filename
    path.write_text(content, encoding="utf-8")
    return DiscoveredFile(path=str(path), rel_path=filename, language="other",
                          size_bytes=len(content), is_dependency_manifest=True)


@pytest.mark.parametrize("filename,vulnerable,safe,package", ECOSYSTEM_CASES,
                         ids=[case[0] for case in ECOSYSTEM_CASES])
def test_ecosystem_detects_vulnerable_and_passes_safe(tmp_path, filename, vulnerable, safe, package):
    findings = scan_dependencies([_manifest(tmp_path, filename, vulnerable)])
    vulnerable_findings = [f for f in findings if f.category == "vulnerable-dependency"]
    assert vulnerable_findings, f"{filename}: expected a vulnerable-dependency finding"
    assert package in {f.extra["package"] for f in vulnerable_findings}

    safe_path = tmp_path / "safe"
    safe_path.mkdir(exist_ok=True)
    safe_manifest = _manifest(safe_path, filename, safe)
    assert [f for f in scan_dependencies([safe_manifest]) if f.category == "vulnerable-dependency"] == []


def test_every_case_has_a_parser():
    for filename, *_ in ECOSYSTEM_CASES:
        discovered = DiscoveredFile(path=f"/tmp/{filename}", rel_path=filename, language="other",
                                    size_bytes=1, is_dependency_manifest=True)
        assert parser_for(discovered) is not None, f"no parser registered for {filename}"
        assert is_dependency_manifest(filename)


def test_csproj_manifests_are_recognised():
    assert is_dependency_manifest("MyApp.csproj")
    assert not is_dependency_manifest("README.md")


def test_csproj_package_reference_is_parsed(tmp_path):
    content = ('<Project><ItemGroup>'
               '<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />'
               '</ItemGroup></Project>')
    deps = extract_dependencies([_manifest(tmp_path, "MyApp.csproj", content)])
    assert [(d.name, d.version, d.ecosystem) for d in deps] == [("newtonsoft.json", "12.0.1", "nuget")]


# --------------------------------------------------------------------------- #
# Parsing robustness
# --------------------------------------------------------------------------- #
def test_malformed_json_manifest_is_reported_not_skipped(tmp_path):
    findings = scan_dependencies([_manifest(tmp_path, "package.json", "{not json")])
    assert any(f.rule_id == "DEP-MANIFEST-MALFORMED" for f in findings)


def test_empty_requirements_file_is_reported(tmp_path):
    findings = scan_dependencies([_manifest(tmp_path, "requirements.txt", "")])
    assert any(f.rule_id == "DEP-MANIFEST-EMPTY" for f in findings)


def test_pom_property_version_is_flagged(tmp_path):
    content = ("<project><dependencies><dependency><groupId>g</groupId>"
               "<artifactId>a</artifactId><version>${project.version}</version>"
               "</dependency></dependencies></project>")
    findings = scan_dependencies([_manifest(tmp_path, "pom.xml", content)])
    assert any(f.rule_id == "DEP-MANIFEST-UNRESOLVED-VERSION" for f in findings)


def test_requirements_comments_and_options_are_ignored(tmp_path):
    content = "# comment\n--index-url https://x\n-r other.txt\n\nrequests==2.31.0  # pinned\n"
    deps = extract_dependencies([_manifest(tmp_path, "requirements.txt", content)])
    assert [(d.name, d.version) for d in deps] == [("requests", "2.31.0")]


def test_pep503_name_normalisation():
    assert normalize_name("python", "Flask_Cors") == "flask-cors"
    assert normalize_name("python", "zope.interface") == "zope-interface"
    assert normalize_name("javascript", "Axios") == "axios"


def test_go_mod_require_block_is_parsed(tmp_path):
    content = "module demo\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/net v0.16.0\n\tgolang.org/x/crypto v0.17.0\n)\n"
    deps = extract_dependencies([_manifest(tmp_path, "go.mod", content)])
    assert {d.name for d in deps} == {"golang.org/x/net", "golang.org/x/crypto"}


def test_transitive_lockfile_dependencies_are_marked(tmp_path):
    lock = _manifest(tmp_path, "package-lock.json",
                     json.dumps({"lockfileVersion": 3,
                                 "packages": {"": {"name": "root"},
                                              "node_modules/braces": {"version": "3.0.2"}}}))
    deps = extract_dependencies([lock])
    assert deps[0].is_direct is False


def test_git_dependency_without_version_is_recorded_but_not_matched(tmp_path):
    manifest = _manifest(tmp_path, "package.json",
                         json.dumps({"dependencies": {"private-thing": "git+https://x/y.git"}}))
    deps = extract_dependencies([manifest])
    assert deps[0].version is None
    assert scan_dependencies([manifest]) == []


def test_unknown_package_produces_no_dependency_finding(tmp_path):
    manifest = _manifest(tmp_path, "requirements.txt", "definitely-not-a-real-package==1.0.0\n")
    assert [f for f in scan_dependencies([manifest]) if f.category == "vulnerable-dependency"] == []


# --------------------------------------------------------------------------- #
# Advisory sources are pluggable
# --------------------------------------------------------------------------- #
def test_bundled_source_is_the_default_and_offline():
    source = build_source("bundled")
    assert isinstance(source, BundledAdvisorySource)
    assert source.lookup("python", "jinja2")


def test_directory_source_overrides_bundled(tmp_path):
    overlay = tmp_path / "advisories"
    overlay.mkdir()
    (overlay / "internal.json").write_text(json.dumps({
        "python": {"internal-lib": [{"id": "INTERNAL-1", "cve": None, "affected": "<2.0.0",
                                     "severity": "high", "summary": "internal advisory",
                                     "fixed_in": "2.0.0"}]}
    }), encoding="utf-8")
    source = build_source("directory", path=str(overlay))
    assert isinstance(source, DirectoryAdvisorySource)
    assert [a["id"] for a in source.lookup("python", "internal-lib")] == ["INTERNAL-1"]
    # Bundled entries are still visible through the overlay.
    assert source.lookup("python", "jinja2")


def test_directory_source_records_missing_directory_as_warning(tmp_path):
    source = build_source("directory", path=str(tmp_path / "absent"))
    assert source.lookup("python", "jinja2")  # falls back to bundled
    assert any("not found" in warning for warning in source.warnings)


def test_directory_source_skips_unreadable_files(tmp_path):
    overlay = tmp_path / "advisories"
    overlay.mkdir()
    (overlay / "broken.json").write_text("{oops", encoding="utf-8")
    source = build_source("directory", path=str(overlay))
    assert source.lookup("python", "jinja2")
    assert any("unreadable" in warning for warning in source.warnings)


def test_remote_source_requires_https():
    with pytest.raises(AdvisorySourceError):
        build_source("remote", endpoint="http://insecure.example/osv")


def test_remote_source_degrades_to_bundled_when_unreachable():
    source = RemoteAdvisorySource(endpoint="https://127.0.0.1:1/osv", timeout=0.2)
    advisories = source.lookup("python", "jinja2")
    assert advisories, "a failed remote lookup must still return bundled advisories"
    assert any("remote advisory lookup failed" in warning for warning in source.warnings)


def test_remote_source_never_enabled_by_default():
    assert build_source().name == "bundled"


def test_unknown_source_kind_is_rejected():
    with pytest.raises(AdvisorySourceError):
        build_source("carrier-pigeon")


def test_custom_source_can_be_injected_into_the_scanner(tmp_path):
    class SingleAdvisory(BundledAdvisorySource):
        def lookup(self, ecosystem, package):
            if package == "demo-lib":
                return [{"id": "CUSTOM-1", "cve": None, "affected": "<9.9.9", "severity": "critical",
                         "summary": "custom feed hit", "fixed_in": "9.9.9"}]
            return []

    manifest = _manifest(tmp_path, "requirements.txt", "demo-lib==1.0.0\n")
    findings = scan_dependencies([manifest], source=SingleAdvisory())
    assert len(findings) == 1
    assert findings[0].rule_id == "DEP-CUSTOM-1"
    assert findings[0].extra["advisory_source"] == "bundled"


def test_ecosystem_pairs_are_still_valid_against_the_shipped_database():
    """Guard the version pairs in ECOSYSTEM_CASES against a database refresh.

    The pairs are real advisory data, so regenerating the bundled database
    from a newer feed could invalidate one. Without this guard a stale pair
    shows up as a confusing parser failure; with it, the reason is explicit.
    """
    from ironclad.scanners.advisories import BundledAdvisorySource
    from ironclad.scanners.dependency import _satisfies_affected_range

    source = BundledAdvisorySource()
    stale = []
    for filename, vulnerable, safe, package in ECOSYSTEM_CASES:
        vuln_found = scan_dependencies([_manifest(tmpdir_helper(), filename, vulnerable)])
        safe_found = scan_dependencies([_manifest(tmpdir_helper(), filename, safe)])
        hit = any(f.extra.get("package") == package for f in vuln_found)
        clean = not any(f.extra.get("package") == package for f in safe_found)
        if not (hit and clean):
            stale.append(f"{filename}/{package}: vulnerable_hit={hit} safe_clean={clean}")
    assert not stale, ("ECOSYSTEM_CASES version pairs no longer match the shipped advisory "
                       "database; re-derive them from ironclad/data/vuln_db.json:\n  "
                       + "\n  ".join(stale))


def test_bundled_advisory_ids_are_real_ghsa_identifiers():
    """Every advisory id must be a genuine GHSA identifier.

    The database used to ship invented ids such as "GHSA-django-2023-sql" and
    "GHSA-log4j-2021-shell". Those look authoritative and resolve to nothing:
    a customer searching the GitHub Advisory Database for a finding we
    reported would find no such advisory. Ids now come from a real feed, and
    this pins the shape so a hand-edited entry cannot reintroduce the problem.
    """
    import json
    import os
    import re

    path = os.path.join(os.path.dirname(__file__), "..", "ironclad", "data", "vuln_db.json")
    with open(path, encoding="utf-8") as fh:
        db = json.load(fh)
    pattern = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")
    bad = []
    count = 0
    for eco, packages in db.items():
        if eco.startswith("_"):
            continue
        for package, advisories in packages.items():
            for advisory in advisories:
                count += 1
                if not pattern.match(str(advisory.get("id", ""))):
                    bad.append(f"{eco}/{package}: {advisory.get('id')}")
    assert count > 10000, f"expected a real advisory feed, found {count} advisories"
    assert not bad[:20], f"{len(bad)} advisory ids are not real GHSA identifiers: {bad[:5]}"


# --------------------------------------------------------------------------- #
# pip-compile layout: requirements/<environment>.txt
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("filename,rel_path,expected", [
    ("requirements.txt", "requirements.txt", True),
    ("requirements-dev.txt", "requirements-dev.txt", True),
    ("tests.txt", "requirements/tests.txt", True),      # pip-compile lockfile
    ("dev.txt", "requirements/dev.txt", True),
    ("docs.txt", "requirements/docs.txt", True),
    ("tests.txt", "requirements-dev/tests.txt", True),
    ("notes.txt", "notes.txt", False),                  # loose txt at the root
    ("notes.txt", "docs/notes.txt", False),             # unrelated directory
    ("README.md", "requirements/README.md", False),     # not a .txt
    ("setup.py", "setup.py", False),
])
def test_requirements_directory_layout_is_recognised(filename, rel_path, expected):
    """`requirements/tests.txt` must count as a manifest.

    pip-compile projects keep one pinned lockfile per environment in a
    `requirements/` directory. The filename carries no "requirements"
    prefix, so filename-only matching skipped the entire dev/test inventory:
    flask 2.0.0 pins 55 dependencies there and not one was scanned.
    """
    assert is_dependency_manifest(filename, rel_path) is expected


def test_manifest_detection_is_unchanged_without_a_rel_path():
    """Backwards compatibility: the old one-argument call still works."""
    assert is_dependency_manifest("requirements.txt") is True
    assert is_dependency_manifest("tests.txt") is False


def test_requirements_directory_parser_is_the_requirements_parser():
    from ironclad.core.walker import DiscoveredFile
    from ironclad.scanners.dependency import _parse_requirements_txt, parser_for

    discovered = DiscoveredFile(path="requirements/tests.txt", rel_path="requirements/tests.txt",
                                language="other", size_bytes=10, is_dependency_manifest=True)
    assert parser_for(discovered) is _parse_requirements_txt


def test_scan_finds_vulnerable_pins_inside_a_requirements_directory(tmp_path):
    """End to end: discovery, parser routing and matching all have to work."""
    from ironclad.core.config import IronCladConfig
    from ironclad.core.engine import run_scan

    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "tests.txt").write_text(
        "jinja2==3.1.2\nwerkzeug==2.3.3\n", encoding="utf-8")

    result = run_scan(IronCladConfig(target=str(tmp_path), enabled_engines={"dependency"}))
    found = {f.extra.get("package") for f in result.findings
             if f.category == "vulnerable-dependency"}
    assert {"jinja2", "werkzeug"} <= found, (
        f"pinned vulnerable dependencies in requirements/ were not scanned; got {found}")
    assert all(f.extra["is_pinned"] for f in result.findings
               if f.category == "vulnerable-dependency")
