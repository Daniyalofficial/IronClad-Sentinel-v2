"""
Offline dependency vulnerability scanner.

Parses common dependency manifest formats (requirements.txt, package.json,
package-lock.json, go.mod) to extract package name + pinned/declared
version, then matches against the bundled offline advisory database in
`ironclad/data/vuln_db.json` using simple, dependency-free version range
comparison (no `packaging`/`semver` network calls -- comparisons are done
with a small local version-tuple comparator good enough for advisory
matching).

This deliberately never queries a live vulnerability API (OSV, Snyk,
NVD, GitHub Advisory API) -- the whole point of IronClad Sentinel is to
work fully air-gapped. Operators are expected to refresh
`ironclad/data/vuln_db.json` themselves during controlled update windows
(e.g. pulling a new signed copy alongside a new tool release), which is
documented in the README.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from ironclad.core.models import CodeLocation, Engine, Finding, Severity
from ironclad.core.walker import DiscoveredFile, read_text_safely

_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "vuln_db.json")

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


@dataclass
class ParsedDependency:
    name: str
    version: Optional[str]
    ecosystem: str
    manifest_rel_path: str
    line_number: int = 1


def _load_db() -> Dict:
    try:
        with open(_DB_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


_VERSION_TOKEN = re.compile(r"(\d+)")


def _version_tuple(v: str):
    v = v.strip()
    v = re.split(r"[-+]", v)[0]  # strip prerelease/build metadata
    parts = v.split(".")
    result = []
    for p in parts:
        m = _VERSION_TOKEN.match(p)
        result.append(int(m.group(1)) if m else 0)
    while len(result) < 4:
        result.append(0)
    return tuple(result[:4])


def _version_less_than(a: str, b: str) -> bool:
    try:
        return _version_tuple(a) < _version_tuple(b)
    except Exception:
        return False


def _satisfies_affected_range(version: str, affected_spec: str) -> bool:
    """
    Extremely small range parser supporting the subset of syntax used in
    our bundled DB: "<X.Y.Z" (only form used). Extend here if the DB
    grows richer range expressions.
    """
    affected_spec = affected_spec.strip()
    if affected_spec.startswith("<="):
        return not _version_less_than(affected_spec[2:], version)
    if affected_spec.startswith("<"):
        return _version_less_than(version, affected_spec[1:])
    if affected_spec.startswith(">="):
        return not _version_less_than(version, affected_spec[2:])
    if affected_spec.startswith(">"):
        return _version_less_than(affected_spec[1:], version)
    if affected_spec.startswith("=="):
        return _version_tuple(version) == _version_tuple(affected_spec[2:])
    return version == affected_spec


def parse_requirements_txt(discovered: DiscoveredFile) -> List[ParsedDependency]:
    content = read_text_safely(discovered.path)
    deps = []
    pattern = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)")
    for idx, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        match = pattern.match(stripped)
        if match:
            deps.append(ParsedDependency(
                name=match.group(1).lower(),
                version=match.group(2),
                ecosystem="python",
                manifest_rel_path=discovered.rel_path,
                line_number=idx,
            ))
    return deps


def parse_package_json(discovered: DiscoveredFile) -> List[ParsedDependency]:
    content = read_text_safely(discovered.path)
    deps = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    for section in ("dependencies", "devDependencies"):
        section_data = data.get(section, {})
        if not isinstance(section_data, dict):
            continue
        for name, version_spec in section_data.items():
            cleaned = re.sub(r"^[~^>=<\s]+", "", str(version_spec))
            if not re.match(r"^\d", cleaned):
                continue  # skip "latest", git urls, workspace:* etc.
            deps.append(ParsedDependency(
                name=name,
                version=cleaned,
                ecosystem="javascript",
                manifest_rel_path=discovered.rel_path,
            ))
    return deps


def parse_go_mod(discovered: DiscoveredFile) -> List[ParsedDependency]:
    content = read_text_safely(discovered.path)
    deps = []
    pattern = re.compile(r"^\s*([A-Za-z0-9_./\-]+)\s+v(\d+\.\d+\.\d+)")
    for idx, line in enumerate(content.splitlines(), start=1):
        match = pattern.match(line)
        if match and "require" not in line and "module" not in line:
            deps.append(ParsedDependency(
                name=match.group(1),
                version=match.group(2),
                ecosystem="go",
                manifest_rel_path=discovered.rel_path,
                line_number=idx,
            ))
    return deps


MANIFEST_PARSERS = {
    "requirements.txt": parse_requirements_txt,
    "package.json": parse_package_json,
    "go.mod": parse_go_mod,
}


def extract_dependencies(manifests: List[DiscoveredFile]) -> List[ParsedDependency]:
    all_deps: List[ParsedDependency] = []
    for manifest in manifests:
        filename = os.path.basename(manifest.path)
        parser = MANIFEST_PARSERS.get(filename)
        if parser:
            all_deps.extend(parser(manifest))
    return all_deps


def scan_dependencies(manifests: List[DiscoveredFile]) -> List[Finding]:
    db = _load_db()
    deps = extract_dependencies(manifests)
    findings: List[Finding] = []

    for dep in deps:
        ecosystem_db = db.get(dep.ecosystem, {})
        advisories = ecosystem_db.get(dep.name.lower()) or ecosystem_db.get(dep.name)
        if not advisories or not dep.version:
            continue

        for advisory in advisories:
            if _satisfies_affected_range(dep.version, advisory["affected"]):
                findings.append(Finding(
                    rule_id=f"DEP-{advisory['id']}",
                    title=f"Known vulnerability in {dep.name}@{dep.version}: {advisory.get('cve', advisory['id'])}",
                    description=(
                        f"{advisory['summary']} Installed version {dep.version} matches the "
                        f"vulnerable range {advisory['affected']}. Fixed in {advisory['fixed_in']}."
                    ),
                    severity=SEVERITY_MAP.get(advisory["severity"], Severity.MEDIUM),
                    engine=Engine.DEPENDENCY,
                    category="vulnerable-dependency",
                    cwe=None,
                    remediation=f"Upgrade {dep.name} to version {advisory['fixed_in']} or later.",
                    confidence="high",
                    references=[f"https://nvd.nist.gov/vuln/detail/{advisory['cve']}"] if advisory.get("cve") else [],
                    location=CodeLocation(
                        file_path=dep.manifest_rel_path,
                        start_line=dep.line_number,
                        end_line=dep.line_number,
                        snippet=f"{dep.name} == {dep.version}",
                    ),
                    extra={"package": dep.name, "installed_version": dep.version,
                           "fixed_version": advisory["fixed_in"], "cve": advisory.get("cve")},
                ))

    return findings
