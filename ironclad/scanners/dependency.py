"""Offline dependency vulnerability scanner.

No network access is performed. Advisories come exclusively from the local
bundled database. Manifest parsing is deliberately conservative: for a
range declaration, the lowest declared candidate is checked so an unresolved
range cannot silently hide a known vulnerable version.
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


def _load_db() -> Dict:
    try:
        with open(_DB_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


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
            if op == "<" and not _version_less_than(version, rhs): ok = False
            elif op == "<=" and _version_less_than(rhs, version): ok = False
            elif op == ">" and not _version_less_than(rhs, version): ok = False
            elif op == ">=" and _version_less_than(version, rhs): ok = False
            elif op in {"=", "=="} and not _version_equal(version, rhs): ok = False
            if not ok:
                break
        if ok:
            return True
    return False


def _minimum_candidate(spec: str) -> Optional[str]:
    """Extract a conservative lower candidate from a manifest declaration."""
    spec = str(spec).strip()
    if not spec or spec.lower() in {"latest", "*", "workspace:*"}:
        return None
    match = re.search(r"\d+(?:\.\d+){0,3}", spec.lstrip("v="))
    return match.group(0) if match else None


def parse_requirements_txt(discovered: DiscoveredFile) -> List[ParsedDependency]:
    content = read_text_safely(discovered.path)
    deps = []
    pattern = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:(==|~=|>=|<=|>|<|!=)\s*)?([^;#\s]+)?")
    for idx, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        m = pattern.match(stripped)
        if not m or not m.group(3):
            continue
        operator = m.group(2) or "=="
        spec = f"{operator}{m.group(3)}"
        candidate = _minimum_candidate(m.group(3))
        if candidate:
            deps.append(ParsedDependency(m.group(1).lower(), candidate, "python",
                discovered.rel_path, idx, spec))
    return deps


def parse_package_json(discovered: DiscoveredFile) -> List[ParsedDependency]:
    try:
        data = json.loads(read_text_safely(discovered.path))
    except json.JSONDecodeError:
        return []
    deps = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = data.get(section, {})
        if not isinstance(values, dict):
            continue
        for name, raw_spec in values.items():
            spec = str(raw_spec).strip()
            candidate = _minimum_candidate(spec)
            if candidate:
                deps.append(ParsedDependency(name, candidate, "javascript", discovered.rel_path, 1, spec))
    return deps


def parse_package_lock(discovered: DiscoveredFile) -> List[ParsedDependency]:
    try:
        data = json.loads(read_text_safely(discovered.path))
    except json.JSONDecodeError:
        return []
    deps = []
    packages = data.get("packages", {})
    if not isinstance(packages, dict):
        return deps
    for key, item in packages.items():
        if not isinstance(item, dict) or "node_modules/" not in key or not item.get("version"):
            continue
        name = key.rsplit("node_modules/", 1)[-1]
        deps.append(ParsedDependency(name, str(item["version"]), "javascript",
            discovered.rel_path, 1, f"=={item['version']}"))
    return deps


def parse_go_mod(discovered: DiscoveredFile) -> List[ParsedDependency]:
    content = read_text_safely(discovered.path)
    pattern = re.compile(r"^\s*([A-Za-z0-9_./\-]+)\s+v(\d+(?:\.\d+){2,})")
    deps = []
    for idx, line in enumerate(content.splitlines(), 1):
        m = pattern.match(line)
        if m and not line.strip().startswith("module "):
            deps.append(ParsedDependency(m.group(1), m.group(2), "go", discovered.rel_path, idx, f"=={m.group(2)}"))
    return deps


MANIFEST_PARSERS = {"requirements.txt": parse_requirements_txt,
                    "package.json": parse_package_json,
                    "package-lock.json": parse_package_lock,
                    "go.mod": parse_go_mod}


def extract_dependencies(manifests: List[DiscoveredFile]) -> List[ParsedDependency]:
    result = []
    for manifest in manifests:
        parser = MANIFEST_PARSERS.get(os.path.basename(manifest.path))
        if parser:
            result.extend(parser(manifest))
    return result


def scan_dependencies(manifests: List[DiscoveredFile]) -> List[Finding]:
    db = _load_db()
    findings = []
    for dep in extract_dependencies(manifests):
        advisories = db.get(dep.ecosystem, {}).get(dep.name.lower()) or db.get(dep.ecosystem, {}).get(dep.name)
        if not advisories or not dep.version:
            continue
        for advisory in advisories:
            if not _satisfies_affected_range(dep.version, advisory["affected"]):
                continue
            declared = dep.declared_spec or f"=={dep.version}"
            findings.append(Finding(
                rule_id=f"DEP-{advisory['id']}",
                title=f"Known vulnerability in {dep.name}@{dep.version}: {advisory.get('cve', advisory['id'])}",
                description=(f"{advisory['summary']} Declared/resolved version {dep.version} from '{declared}' "
                             f"matches vulnerable range {advisory['affected']}. Fixed in {advisory['fixed_in']}."),
                severity=SEVERITY_MAP.get(advisory["severity"], Severity.MEDIUM),
                engine=Engine.DEPENDENCY, category="vulnerable-dependency", cwe=None,
                remediation=f"Upgrade {dep.name} to version {advisory['fixed_in']} or later.",
                confidence="high",
                references=[f"https://nvd.nist.gov/vuln/detail/{advisory['cve']}"] if advisory.get("cve") else [],
                location=CodeLocation(file_path=dep.manifest_rel_path, start_line=dep.line_number,
                                      end_line=dep.line_number, snippet=f"{dep.name} {declared}"),
                extra={"package": dep.name, "installed_version": dep.version,
                       "declared_spec": declared, "fixed_version": advisory["fixed_in"],
                       "cve": advisory.get("cve")},
            ))
    return findings
