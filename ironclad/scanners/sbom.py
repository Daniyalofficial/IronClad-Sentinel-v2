"""SBOM generation and conservative license compliance checking."""
from __future__ import annotations

import json
import os
import uuid
from typing import Dict, List

from ironclad.core.models import CodeLocation, Engine, Finding, Severity
from ironclad.core.walker import DiscoveredFile
from ironclad.scanners.dependency import ParsedDependency, extract_dependencies

_LICENSE_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "license_db.json")
COPYLEFT_LICENSES = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"}
PERMISSIVE_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "ISC "}


def _load_license_db() -> Dict[str, Dict[str, str]]:
    try:
        with open(_LICENSE_DB_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _license_for(dep: ParsedDependency, db: Dict[str, Dict[str, str]]) -> str:
    return db.get(dep.ecosystem, {}).get(dep.name.lower(), "UNKNOWN")


def _purl(ecosystem: str, name: str, version: str) -> str:
    type_map = {"python": "pypi", "javascript": "npm", "go": "golang", "ruby": "gem", "php": "composer", "java": "maven"}
    return f"pkg:{type_map.get(ecosystem, 'generic')}/{name}@{version}"


def build_sbom(manifests: List[DiscoveredFile], project_name: str = "scanned-project") -> Dict:
    db = _load_license_db()
    components = []
    seen = set()
    for dep in extract_dependencies(manifests):
        version = dep.version or "unknown"
        key = (dep.ecosystem, dep.name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        license_id = _license_for(dep, db)
        component = {
            "type": "library", "name": dep.name, "version": version,
            "purl": _purl(dep.ecosystem, dep.name, version),
        }
        if license_id != "UNKNOWN":
            component["licenses"] = [{"license": {"id": license_id}}]
        else:
            component["properties"] = [{"name": "ironclad:license-status", "value": "UNKNOWN"}]
        components.append(component)

    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "component": {"type": "application", "name": project_name},
            "tools": [{"vendor": "IronClad Sentinel", "name": "ironclad-sbom-generator", "version": "1.1.0"}],
        },
        "components": components,
    }


def scan_license_compliance(manifests: List[DiscoveredFile], disallowed: List[str] = None) -> List[Finding]:
    disallowed_set = set(disallowed) if disallowed is not None else set(COPYLEFT_LICENSES)
    db = _load_license_db()
    findings: List[Finding] = []
    for dep in extract_dependencies(manifests):
        license_id = _license_for(dep, db)
        if license_id == "UNKNOWN":
            findings.append(Finding(
                rule_id="LICENSE-UNKNOWN",
                title=f"License could not be identified: {dep.name}",
                description=f"IronClad has no bundled license mapping for {dep.name}. It is not assumed permissive.",
                severity=Severity.LOW, engine=Engine.LICENSE, category="license-compliance",
                remediation="Verify the dependency's license from authoritative package metadata and update the organization policy/database.",
                confidence="high",
                location=CodeLocation(file_path=dep.manifest_rel_path, start_line=dep.line_number, end_line=dep.line_number,
                                      snippet=f"{dep.name} {dep.declared_spec or dep.version or ''}"),
                extra={"license": "UNKNOWN", "package": dep.name},
            ))
        elif license_id in disallowed_set:
            findings.append(Finding(
                rule_id="LICENSE-COPYLEFT-DEPENDENCY",
                title=f"Dependency under restrictive license: {dep.name} ({license_id})",
                description=f"{dep.name}@{dep.version or 'unknown'} is mapped to {license_id}; enterprise legal review may be required.",
                severity=Severity.MEDIUM, engine=Engine.LICENSE, category="license-compliance",
                remediation=f"Review the use of {dep.name}, obtain approval, or replace it with an approved alternative.",
                confidence="medium",
                location=CodeLocation(file_path=dep.manifest_rel_path, start_line=dep.line_number, end_line=dep.line_number,
                                      snippet=f"{dep.name} {dep.declared_spec or dep.version or ''}"),
                extra={"license": license_id, "package": dep.name},
            ))
    return findings
