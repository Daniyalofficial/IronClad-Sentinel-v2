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
ECOSYSTEM_CASES = [
    ("requirements.txt", "jinja2==3.1.2\n", "jinja2==3.1.4\n", "jinja2"),
    ("requirements-dev.txt", "werkzeug==2.3.0\n", "werkzeug==3.0.1\n", "werkzeug"),
    ("package.json", '{"dependencies": {"axios": "1.5.0"}}',
     '{"dependencies": {"axios": "1.6.2"}}', "axios"),
    ("package-lock.json",
     '{"lockfileVersion": 3, "packages": {"node_modules/minimist": {"version": "1.2.5"}}}',
     '{"lockfileVersion": 3, "packages": {"node_modules/minimist": {"version": "1.2.8"}}}',
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
     "module demo\n\nrequire golang.org/x/net v0.17.0\n", "golang.org/x/net"),
    ("go.sum",
     "golang.org/x/net v0.16.0 h1:aaaa\n",
     "golang.org/x/net v0.17.0 h1:aaaa\n",
     "golang.org/x/net"),
    ("Cargo.toml", '[dependencies]\ntime = "0.1.40"\n', '[dependencies]\ntime = "0.3.30"\n', "time"),
    ("Cargo.lock", '[[package]]\nname = "smallvec"\nversion = "1.6.0"\n',
     '[[package]]\nname = "smallvec"\nversion = "1.11.0"\n', "smallvec"),
    ("pom.xml",
     "<project><dependencies><dependency><groupId>org.springframework</groupId>"
     "<artifactId>spring-core</artifactId><version>5.3.10</version></dependency></dependencies></project>",
     "<project><dependencies><dependency><groupId>org.springframework</groupId>"
     "<artifactId>spring-core</artifactId><version>5.3.20</version></dependency></dependencies></project>",
     "org.springframework:spring-core"),
    ("build.gradle",
     'dependencies { implementation "org.springframework:spring-core:5.3.10" }',
     'dependencies { implementation "org.springframework:spring-core:5.3.20" }',
     "org.springframework:spring-core"),
    ("composer.json", '{"require": {"phpmailer/phpmailer": "6.1.0"}}',
     '{"require": {"phpmailer/phpmailer": "6.5.0"}}', "phpmailer/phpmailer"),
    ("composer.lock",
     '{"packages": [{"name": "phpmailer/phpmailer", "version": "v6.1.0"}]}',
     '{"packages": [{"name": "phpmailer/phpmailer", "version": "v6.5.0"}]}',
     "phpmailer/phpmailer"),
    ("Gemfile", 'gem "json", "2.6.0"\n', 'gem "json", "2.7.5"\n', "json"),
    ("Gemfile.lock",
     "GEM\n  specs:\n    json (2.6.0)\n",
     "GEM\n  specs:\n    json (2.7.5)\n",
     "json"),
    ("packages.config",
     '<packages><package id="Newtonsoft.Json" version="12.0.1" /></packages>',
     '<packages><package id="Newtonsoft.Json" version="13.0.3" /></packages>',
     "newtonsoft.json"),
]


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
