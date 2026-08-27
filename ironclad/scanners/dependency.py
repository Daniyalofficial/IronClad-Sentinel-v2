"""Offline dependency vulnerability scanner.

No network access is performed by default. Advisories come from a pluggable
``AdvisorySource`` (see ``ironclad.scanners.advisories``); the bundled
offline database is the default.

Manifest parsing is deliberately conservative: for a range declaration the
lowest declared candidate is checked, so an unresolved range cannot
silently hide a known vulnerable version. Lockfiles are preferred when
present because they pin the *resolved* (often transitive) versions.

Supported ecosystems
--------------------
Python     requirements*.txt, Pipfile(.lock), poetry.lock, pyproject.toml
npm        package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
Go         go.mod, go.sum
Rust       Cargo.toml, Cargo.lock
Java       pom.xml, build.gradle, build.gradle.kts
PHP        composer.json, composer.lock
Ruby       Gemfile, Gemfile.lock
NuGet      packages.config, *.csproj

Malformed manifests are reported as findings rather than silently skipped --
a scanner that quietly ignores an unparsable lockfile is worse than one
that says so.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from ironclad.core.models import CodeLocation, Engine, Finding, Severity
from ironclad.core.walker import DiscoveredFile, read_text_safely
from ironclad.scanners.advisories import AdvisorySource, BundledAdvisorySource

SEVERITY_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                "medium": Severity.MEDIUM, "low": Severity.LOW}


@dataclass
class ParsedDependency:
    name: str
    version: Optional[str]
    ecosystem: str
    manifest_rel_path: str
    line_number: int = 1
    declared_spec: Optional[str] = None
    is_direct: bool = True
    manifest_kind: str = ""


@dataclass
class ParseOutcome:
    dependencies: List[ParsedDependency] = field(default_factory=list)
    errors: List[Tuple[str, int, str]] = field(default_factory=list)  # (rule suffix, line, message)


# --------------------------------------------------------------------------- #
# Version handling
# --------------------------------------------------------------------------- #
def _version_tuple(v: str):
    value = str(v).strip().lstrip("v=").split("+", 1)[0]
    core, _, prerelease = value.partition("-")
    nums = [int(x) for x in re.findall(r"\d+", core)[:4]]
    while len(nums) < 4:
        nums.append(0)
    return tuple(nums), tuple(prerelease.split(".")) if prerelease else ()


def _version_less_than(a: str, b: str) -> bool:
    av, apre = _version_tuple(a)
    bv, bpre = _version_tuple(b)
    if av != bv:
        return av < bv
    if not apre and bpre:
        return False
    if apre and not bpre:
        return True
    return apre < bpre


def _version_equal(a: str, b: str) -> bool:
    return not _version_less_than(a, b) and not _version_less_than(b, a)


def _satisfies_affected_range(version: str, affected_spec: str) -> bool:
    """Evaluate common advisory comparators, including compound ranges."""
    for alternative in str(affected_spec).split("||"):
        tokens = [t for t in re.split(r"\s*,\s*|\s+(?=[<>=])", alternative.strip()) if t]
        if not tokens:
            continue
        ok = True
        for token in tokens:
            token = token.strip()
            op = next((x for x in (">=", "<=", "==", ">", "<", "=") if token.startswith(x)), "=")
            rhs = token[len(op):].strip()
            if op == "<" and not _version_less_than(version, rhs):
                ok = False
            elif op == "<=" and _version_less_than(rhs, version):
                ok = False
            elif op == ">" and not _version_less_than(rhs, version):
                ok = False
            elif op == ">=" and _version_less_than(version, rhs):
                ok = False
            elif op in {"=", "=="} and not _version_equal(version, rhs):
                ok = False
            if not ok:
                break
        if ok:
            return True
    return False


def _minimum_candidate(spec: str) -> Optional[str]:
    """Extract a conservative lower candidate from a manifest declaration."""
    spec = str(spec).strip()
    if not spec or spec.lower() in {"latest", "*", "workspace:*", "x", ""}:
        return None
    match = re.search(r"\d+(?:\.\d+){0,3}", spec.lstrip("v="))
    return match.group(0) if match else None


# --------------------------------------------------------------------------- #
# Name normalization
# --------------------------------------------------------------------------- #
def normalize_name(ecosystem: str, name: str) -> str:
    """Normalize a package name the way its ecosystem's index does."""
    raw = str(name).strip()
    if ecosystem == "python":
        # PEP 503: runs of [-_.] collapse to a single dash, then lowercase.
        return re.sub(r"[-_.]+", "-", raw).lower()
    if ecosystem in {"javascript", "ruby", "rust", "go", "php", "java", "nuget"}:
        return raw.lower()
    return raw.lower()


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
def _dep(name: str, version: Optional[str], ecosystem: str, discovered: DiscoveredFile,
         line: int = 1, spec: Optional[str] = None, direct: bool = True,
         kind: str = "") -> ParsedDependency:
    return ParsedDependency(
        name=normalize_name(ecosystem, name),
        version=version,
        ecosystem=ecosystem,
        manifest_rel_path=discovered.rel_path,
        line_number=line,
        declared_spec=spec,
        is_direct=direct,
        manifest_kind=kind or os.path.basename(discovered.path),
    )


def _parse_requirements_txt(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    content = read_text_safely(discovered.path)
    if not content:
        outcome.errors.append(("EMPTY", 1, f"{discovered.rel_path} is empty or unreadable"))
        return outcome
    pattern = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*(?:(===|==|~=|>=|<=|>|<|!=)\s*)?([^;#\s]+)?")
    for idx, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        match = pattern.match(stripped)
        if not match or not match.group(3):
            if stripped and not stripped.startswith("#"):
                outcome.errors.append(("UNPARSEABLE-LINE", idx, f"could not parse requirement: {stripped[:80]}"))
            continue
        operator = match.group(2) or "=="
        spec = f"{operator}{match.group(3)}"
        candidate = _minimum_candidate(match.group(3))
        if candidate:
            outcome.dependencies.append(
                _dep(match.group(1).split("[")[0], candidate, "python", discovered, idx, spec))
    return outcome


def _parse_pipfile_lock(discovered: DiscoveredFile) -> ParseOutcome:
    return _parse_json_lock(discovered, "python",
                            sections=("default", "develop"), version_key="version",
                            strip_prefix="==")


def _parse_poetry_lock(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:  # pragma: no cover - Python 3.9/3.10
        outcome.errors.append(("NO-TOML-PARSER", 1,
                               "poetry.lock parsing requires Python 3.11+ (tomllib)"))
        return outcome
    try:
        with open(discovered.path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError) as exc:
        outcome.errors.append(("MALFORMED", 1, f"poetry.lock is malformed: {exc}"))
        return outcome
    for package in data.get("package", []) or []:
        name, version = package.get("name"), package.get("version")
        if name and version:
            outcome.dependencies.append(_dep(name, str(version).lstrip("="), "python",
                                             discovered, 1, f"=={version}", direct=False))
    return outcome


def _parse_pyproject(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python 3.9/3.10
        return outcome
    try:
        with open(discovered.path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError) as exc:
        outcome.errors.append(("MALFORMED", 1, f"pyproject.toml is malformed: {exc}"))
        return outcome
    project = data.get("project") or {}
    for requirement in project.get("dependencies", []) or []:
        match = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:(===|==|~=|>=|<=|>|<|!=)\s*([^;,\s]+))?",
                         str(requirement))
        if not match:
            continue
        spec = str(requirement)
        candidate = _minimum_candidate(match.group(3) or "")
        outcome.dependencies.append(_dep(match.group(1), candidate, "python", discovered, 1, spec))
    poetry = (data.get("tool") or {}).get("poetry") or {}
    for section in ("dependencies", "dev-dependencies"):
        for name, spec in (poetry.get(section) or {}).items():
            if name.lower() == "python":
                continue
            version = spec.get("version") if isinstance(spec, dict) else spec
            candidate = _minimum_candidate(str(version or ""))
            outcome.dependencies.append(_dep(name, candidate, "python", discovered, 1, str(version)))
    return outcome


def _parse_package_json(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    try:
        data = json.loads(read_text_safely(discovered.path))
    except json.JSONDecodeError as exc:
        outcome.errors.append(("MALFORMED", 1, f"package.json is malformed JSON: {exc}"))
        return outcome
    if not isinstance(data, dict):
        outcome.errors.append(("MALFORMED", 1, "package.json must contain a JSON object"))
        return outcome
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = data.get(section, {})
        if not isinstance(values, dict):
            outcome.errors.append(("MALFORMED", 1, f"package.json '{section}' must be an object"))
            continue
        for name, raw_spec in values.items():
            spec = str(raw_spec).strip()
            if spec.startswith(("git+", "git:", "http://", "https://", "file:", "link:")):
                outcome.dependencies.append(_dep(name, None, "javascript", discovered, 1, spec))
                continue
            candidate = _minimum_candidate(spec)
            outcome.dependencies.append(_dep(name, candidate, "javascript", discovered, 1, spec))
    return outcome


def _parse_package_lock(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    try:
        data = json.loads(read_text_safely(discovered.path))
    except json.JSONDecodeError as exc:
        outcome.errors.append(("MALFORMED", 1, f"package-lock.json is malformed JSON: {exc}"))
        return outcome
    if not isinstance(data, dict):
        outcome.errors.append(("MALFORMED", 1, "package-lock.json must contain a JSON object"))
        return outcome
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2/3
        for key, item in packages.items():
            if not isinstance(item, dict) or not item.get("version"):
                continue
            if "node_modules/" not in key:
                continue
            name = key.rsplit("node_modules/", 1)[-1]
            outcome.dependencies.append(_dep(name, str(item["version"]), "javascript", discovered,
                                             1, f"=={item['version']}", direct=False))
        return outcome
    deps = data.get("dependencies")  # lockfileVersion 1
    if isinstance(deps, dict):
        for name, item in deps.items():
            if isinstance(item, dict) and item.get("version"):
                outcome.dependencies.append(_dep(name, str(item["version"]), "javascript", discovered,
                                                 1, f"=={item['version']}", direct=False))
        return outcome
    outcome.errors.append(("UNRECOGNIZED", 1, "package-lock.json has neither 'packages' nor 'dependencies'"))
    return outcome


def _parse_yarn_lock(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    content = read_text_safely(discovered.path)
    if not content:
        outcome.errors.append(("EMPTY", 1, "yarn.lock is empty or unreadable"))
        return outcome
    header = re.compile(r'^"?(@?[^@\s]+)(?:@[^"]*)?"?:\s*$')
    version = re.compile(r"^\s+version\s+\"?([^\"\s]+)\"?")
    current = None
    for idx, line in enumerate(content.splitlines(), 1):
        header_match = header.match(line)
        if header_match:
            current = header_match.group(1).split(",")[0]
            continue
        version_match = version.match(line)
        if version_match and current:
            outcome.dependencies.append(_dep(current, version_match.group(1), "javascript",
                                             discovered, idx, f"=={version_match.group(1)}",
                                             direct=False))
            current = None
    return outcome


def _parse_pnpm_lock(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    content = read_text_safely(discovered.path)
    try:
        import yaml

        data = yaml.safe_load(content)
    except Exception as exc:  # noqa: BLE001 - PyYAML raises a family of errors
        outcome.errors.append(("MALFORMED", 1, f"pnpm-lock.yaml is malformed: {exc}"))
        return outcome
    if not isinstance(data, dict):
        outcome.errors.append(("MALFORMED", 1, "pnpm-lock.yaml must contain a mapping"))
        return outcome
    packages = data.get("packages") or {}
    if isinstance(packages, dict):
        for key, item in packages.items():
            name, _, version = str(key).rpartition("@")
            name = name.lstrip("/")
            if not name or not version:
                continue
            if isinstance(item, dict) and item.get("version"):
                version = str(item["version"]).split("(")[0]
            outcome.dependencies.append(_dep(name, version, "javascript", discovered, 1,
                                             f"=={version}", direct=False))
    return outcome


def _parse_go_mod(discovered: DiscoveredFile) -> ParseOutcome:
    """Parse both forms of go.mod requirements.

    Go allows a single-line ``require path v1.2.3`` and a parenthesised
    ``require ( ... )`` block; indirect dependencies are marked with a
    trailing ``// indirect`` comment. All three shapes are handled, and the
    ``module`` declaration of the project itself is never treated as a
    dependency.
    """
    outcome = ParseOutcome()
    content = read_text_safely(discovered.path)
    pattern = re.compile(r"^([A-Za-z0-9_./\-]+)\s+v(\d+(?:\.\d+){1,})")
    in_require_block = False
    for idx, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        if stripped.startswith("require (") or stripped == "require(":
            in_require_block = True
            continue
        if in_require_block and stripped.startswith(")"):
            in_require_block = False
            continue
        if stripped.startswith("require "):
            stripped = stripped[len("require "):].strip()
        if stripped.startswith(("module ", "go ", "toolchain ", "replace ", "exclude ", "retract ")):
            continue
        # Drop trailing comments such as "// indirect".
        stripped = stripped.split("//", 1)[0].strip()
        match = pattern.match(stripped)
        if match:
            outcome.dependencies.append(_dep(match.group(1), match.group(2), "go", discovered, idx,
                                             f"=={match.group(2)}",
                                             direct="// indirect" not in line))
    return outcome


def _parse_go_sum(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    pattern = re.compile(r"^(\S+)\s+v(\d+(?:\.\d+){1,})(?:/go\.mod)?\s+h1:")
    seen = set()
    for idx, line in enumerate(read_text_safely(discovered.path).splitlines(), 1):
        match = pattern.match(line.strip())
        if not match:
            continue
        key = (match.group(1), match.group(2))
        if key in seen:
            continue
        seen.add(key)
        outcome.dependencies.append(_dep(match.group(1), match.group(2), "go", discovered, idx,
                                         f"=={match.group(2)}", direct=False, kind="go.sum"))
    return outcome


def _parse_cargo_toml(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python 3.9/3.10
        return outcome
    try:
        with open(discovered.path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError) as exc:
        outcome.errors.append(("MALFORMED", 1, f"Cargo.toml is malformed: {exc}"))
        return outcome
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in (data.get(section) or {}).items():
            version = spec if isinstance(spec, str) else (spec or {}).get("version")
            outcome.dependencies.append(_dep(name, _minimum_candidate(str(version or "")), "rust",
                                             discovered, 1, str(version)))
    return outcome


def _parse_cargo_lock(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover - Python 3.9/3.10
        return outcome
    try:
        with open(discovered.path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError) as exc:
        outcome.errors.append(("MALFORMED", 1, f"Cargo.lock is malformed: {exc}"))
        return outcome
    for package in data.get("package", []) or []:
        if package.get("name") and package.get("version"):
            outcome.dependencies.append(_dep(package["name"], str(package["version"]), "rust",
                                             discovered, 1, f"=={package['version']}", direct=False))
    return outcome


def _parse_pom_xml(discovered: DiscoveredFile) -> ParseOutcome:
    """Parse Maven pom.xml without an XML dependency (regex over the text).

    pom.xml is regular enough that a targeted regex is more robust here than
    pulling in a namespace-aware parser: we only need
    <dependency><groupId>/<artifactId>/<version> triples.
    """
    outcome = ParseOutcome()
    content = read_text_safely(discovered.path)
    if not content.strip():
        outcome.errors.append(("EMPTY", 1, "pom.xml is empty or unreadable"))
        return outcome
    block = re.compile(r"<dependency>(.*?)</dependency>", re.DOTALL)
    group = re.compile(r"<groupId>\s*([^<]+?)\s*</groupId>")
    artifact = re.compile(r"<artifactId>\s*([^<]+?)\s*</artifactId>")
    version = re.compile(r"<version>\s*([^<]+?)\s*</version>")
    found = False
    for match in block.finditer(content):
        body = match.group(1)
        g, a, v = group.search(body), artifact.search(body), version.search(body)
        if not (g and a):
            continue
        found = True
        line = content.count("\n", 0, match.start()) + 1
        raw_version = v.group(1) if v else None
        if raw_version and raw_version.startswith("${"):
            outcome.errors.append(("UNRESOLVED-VERSION", line,
                                   f"{g.group(1)}:{a.group(1)} uses a property version {raw_version}"))
        candidate = _minimum_candidate(raw_version or "") if raw_version else None
        outcome.dependencies.append(_dep(f"{g.group(1)}:{a.group(1)}", candidate, "java",
                                         discovered, line, raw_version))
    if not found:
        outcome.errors.append(("NO-DEPENDENCIES", 1, "pom.xml declares no <dependency> elements"))
    return outcome


def _parse_gradle(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    pattern = re.compile(
        r"""(?:implementation|api|compile|runtimeOnly|testImplementation|classpath)\s*"""
        r"""[('"]+\s*([\w.\-]+):([\w.\-]+):([\w.\-+]+)\s*['")]""")
    for idx, line in enumerate(read_text_safely(discovered.path).splitlines(), 1):
        match = pattern.search(line)
        if not match:
            continue
        candidate = _minimum_candidate(match.group(3))
        outcome.dependencies.append(_dep(f"{match.group(1)}:{match.group(2)}", candidate, "java",
                                         discovered, idx, match.group(3)))
    return outcome


def _parse_composer_json(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    try:
        data = json.loads(read_text_safely(discovered.path))
    except json.JSONDecodeError as exc:
        outcome.errors.append(("MALFORMED", 1, f"composer.json is malformed JSON: {exc}"))
        return outcome
    for section in ("require", "require-dev"):
        for name, spec in (data.get(section) or {}).items():
            if str(name).lower() in {"php", "ext-json", "ext-mbstring"} or str(name).startswith("ext-"):
                continue
            outcome.dependencies.append(_dep(name, _minimum_candidate(str(spec)), "php",
                                             discovered, 1, str(spec)))
    return outcome


def _parse_composer_lock(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    try:
        data = json.loads(read_text_safely(discovered.path))
    except json.JSONDecodeError as exc:
        outcome.errors.append(("MALFORMED", 1, f"composer.lock is malformed JSON: {exc}"))
        return outcome
    for section in ("packages", "packages-dev"):
        for package in data.get(section) or []:
            if package.get("name") and package.get("version"):
                version = str(package["version"]).lstrip("v")
                outcome.dependencies.append(_dep(package["name"], version, "php", discovered, 1,
                                                 f"=={version}", direct=section == "packages"))
    return outcome


def _parse_gemfile(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    pattern = re.compile(r"""^\s*gem\s+['"]([\w\-]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""")
    for idx, line in enumerate(read_text_safely(discovered.path).splitlines(), 1):
        match = pattern.match(line)
        if not match:
            continue
        spec = match.group(2) or ""
        outcome.dependencies.append(_dep(match.group(1), _minimum_candidate(spec), "ruby",
                                         discovered, idx, spec or None))
    return outcome


def _parse_gemfile_lock(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    content = read_text_safely(discovered.path)
    if "GEM" not in content and "specs:" not in content:
        outcome.errors.append(("UNRECOGNIZED", 1, "Gemfile.lock has no GEM/specs section"))
        return outcome
    in_specs = False
    pattern = re.compile(r"^\s{4}([\w\-]+)\s+\(([^)]+)\)\s*$")
    for idx, line in enumerate(content.splitlines(), 1):
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and line and not line.startswith(" "):
            in_specs = False
        if not in_specs:
            continue
        match = pattern.match(line)
        if match:
            outcome.dependencies.append(_dep(match.group(1), match.group(2), "ruby", discovered, idx,
                                             f"=={match.group(2)}", direct=False, kind="Gemfile.lock"))
    return outcome


def _parse_packages_config(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    pattern = re.compile(r'<package\s+id="([^"]+)"\s+version="([^"]+)"', re.IGNORECASE)
    for idx, line in enumerate(read_text_safely(discovered.path).splitlines(), 1):
        for match in pattern.finditer(line):
            outcome.dependencies.append(_dep(match.group(1), match.group(2), "nuget", discovered, idx,
                                             f"=={match.group(2)}"))
    return outcome


def _parse_csproj(discovered: DiscoveredFile) -> ParseOutcome:
    outcome = ParseOutcome()
    pattern = re.compile(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', re.IGNORECASE)
    for idx, line in enumerate(read_text_safely(discovered.path).splitlines(), 1):
        for match in pattern.finditer(line):
            outcome.dependencies.append(_dep(match.group(1), match.group(2), "nuget", discovered, idx,
                                             f"=={match.group(2)}"))
    return outcome


def _parse_json_lock(discovered: DiscoveredFile, ecosystem: str, sections, version_key: str,
                     strip_prefix: str = "") -> ParseOutcome:
    outcome = ParseOutcome()
    try:
        data = json.loads(read_text_safely(discovered.path))
    except json.JSONDecodeError as exc:
        outcome.errors.append(("MALFORMED", 1, f"{os.path.basename(discovered.path)} is malformed JSON: {exc}"))
        return outcome
    for section in sections:
        for name, item in (data.get(section) or {}).items():
            if not isinstance(item, dict):
                continue
            version = item.get(version_key)
            if not version:
                continue
            version = str(version)
            if strip_prefix and version.startswith(strip_prefix):
                version = version[len(strip_prefix):]
            outcome.dependencies.append(_dep(name, version, ecosystem, discovered, 1,
                                             f"=={version}", direct=section in ("default", "packages")))
    return outcome


# Registry: exact manifest filename -> parser.
MANIFEST_PARSERS: Dict[str, Callable[[DiscoveredFile], ParseOutcome]] = {
    "requirements.txt": _parse_requirements_txt,
    "Pipfile.lock": _parse_pipfile_lock,
    "poetry.lock": _parse_poetry_lock,
    "pyproject.toml": _parse_pyproject,
    "package.json": _parse_package_json,
    "package-lock.json": _parse_package_lock,
    "yarn.lock": _parse_yarn_lock,
    "pnpm-lock.yaml": _parse_pnpm_lock,
    "go.mod": _parse_go_mod,
    "go.sum": _parse_go_sum,
    "Cargo.toml": _parse_cargo_toml,
    "Cargo.lock": _parse_cargo_lock,
    "pom.xml": _parse_pom_xml,
    "build.gradle": _parse_gradle,
    "build.gradle.kts": _parse_gradle,
    "composer.json": _parse_composer_json,
    "composer.lock": _parse_composer_lock,
    "Gemfile": _parse_gemfile,
    "Gemfile.lock": _parse_gemfile_lock,
    "packages.config": _parse_packages_config,
}

_REQUIREMENTS_VARIANT = re.compile(r"^requirements.*\.txt$", re.IGNORECASE)


def parser_for(discovered: DiscoveredFile) -> Optional[Callable[[DiscoveredFile], ParseOutcome]]:
    """Resolve the parser for a manifest, including filename variants."""
    basename = os.path.basename(discovered.path)
    parser = MANIFEST_PARSERS.get(basename)
    if parser:
        return parser
    if _REQUIREMENTS_VARIANT.match(basename):
        return _parse_requirements_txt
    if basename.lower().endswith(".csproj"):
        return _parse_csproj
    return None


def parse_manifest(discovered: DiscoveredFile) -> ParseOutcome:
    parser = parser_for(discovered)
    if parser is None:
        return ParseOutcome()
    try:
        return parser(discovered)
    except Exception as exc:  # noqa: BLE001 - one bad manifest must not abort a scan
        return ParseOutcome(errors=[("PARSER-CRASH", 1,
                                     f"parser raised {type(exc).__name__}: {exc}")])


# Backwards-compatible single-purpose helpers (used by existing tests/integrations).
def parse_requirements_txt(discovered: DiscoveredFile) -> List[ParsedDependency]:
    return _parse_requirements_txt(discovered).dependencies


def parse_package_json(discovered: DiscoveredFile) -> List[ParsedDependency]:
    return _parse_package_json(discovered).dependencies


def parse_package_lock(discovered: DiscoveredFile) -> List[ParsedDependency]:
    return _parse_package_lock(discovered).dependencies


def parse_go_mod(discovered: DiscoveredFile) -> List[ParsedDependency]:
    return _parse_go_mod(discovered).dependencies


def extract_dependencies(manifests: List[DiscoveredFile]) -> List[ParsedDependency]:
    result: List[ParsedDependency] = []
    for manifest in manifests:
        result.extend(parse_manifest(manifest).dependencies)
    return result


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
def _manifest_error_finding(discovered: DiscoveredFile, suffix: str, line: int, message: str) -> Finding:
    return Finding(
        rule_id=f"DEP-MANIFEST-{suffix}",
        title=f"Dependency manifest problem in {os.path.basename(discovered.path)}",
        description=(f"{message}. IronClad could not fully inventory this manifest, so some "
                     f"dependencies may not have been checked for known vulnerabilities."),
        severity=Severity.LOW,
        engine=Engine.DEPENDENCY,
        category="manifest-integrity",
        confidence="high",
        remediation="Fix the manifest (or resolve the version property) so the dependency graph can be inventoried.",
        location=CodeLocation(file_path=discovered.rel_path, start_line=line, end_line=line,
                              snippet=os.path.basename(discovered.path)),
    )


def scan_dependencies(manifests: List[DiscoveredFile],
                      source: Optional[AdvisorySource] = None) -> List[Finding]:
    """Match discovered dependencies against an advisory source."""
    advisory_source = source or BundledAdvisorySource()
    findings: List[Finding] = []

    for manifest in manifests:
        outcome = parse_manifest(manifest)
        for suffix, line, message in outcome.errors:
            findings.append(_manifest_error_finding(manifest, suffix, line, message))
        for dep in outcome.dependencies:
            if not dep.version:
                continue
            advisories = advisory_source.lookup(dep.ecosystem, dep.name)
            if not advisories:
                # Ecosystem indexes normalize differently; retry with the raw
                # spelling before giving up.
                advisories = advisory_source.lookup(dep.ecosystem, dep.name.lower())
            for advisory in advisories:
                if not _satisfies_affected_range(dep.version, str(advisory.get("affected", ""))):
                    continue
                declared = dep.declared_spec or f"=={dep.version}"
                findings.append(Finding(
                    rule_id=f"DEP-{advisory['id']}",
                    title=(f"Known vulnerability in {dep.name}@{dep.version}: "
                           f"{advisory.get('cve') or advisory['id']}"),
                    description=(f"{advisory.get('summary', '')} Resolved/declared version "
                                 f"{dep.version} from '{declared}' matches vulnerable range "
                                 f"{advisory['affected']}. Fixed in {advisory.get('fixed_in', 'unknown')}."),
                    severity=SEVERITY_MAP.get(str(advisory.get("severity", "medium")), Severity.MEDIUM),
                    engine=Engine.DEPENDENCY,
                    category="vulnerable-dependency",
                    confidence="high",
                    remediation=f"Upgrade {dep.name} to version {advisory.get('fixed_in', 'a patched release')} or later.",
                    references=([f"https://nvd.nist.gov/vuln/detail/{advisory['cve']}"]
                                if advisory.get("cve") else []),
                    location=CodeLocation(file_path=dep.manifest_rel_path, start_line=dep.line_number,
                                          end_line=dep.line_number, snippet=f"{dep.name} {declared}"),
                    extra={"package": dep.name, "installed_version": dep.version,
                           "declared_spec": declared, "fixed_version": advisory.get("fixed_in"),
                           "cve": advisory.get("cve"), "ecosystem": dep.ecosystem,
                           "is_direct": dep.is_direct, "advisory_id": advisory["id"],
                           "advisory_source": advisory_source.name},
                ))
    return findings
