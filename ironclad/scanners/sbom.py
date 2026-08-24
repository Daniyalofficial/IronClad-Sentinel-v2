"""
SBOM (Software Bill of Materials) generation + open-source license
compliance checking.

Produces a CycloneDX-shaped JSON document (the industry-standard SBOM
format many enterprise procurement/security review processes now
require) purely from locally discovered dependency manifests -- no
package registry lookups are performed. License identification uses a
small bundled table of common package -> SPDX license mappings; packages
not found in the table are reported as "UNKNOWN" so the report is honest
about its own coverage rather than guessing.
"""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Dict, List

from ironclad.core.models import CodeLocation, Engine, Finding, Severity
from ironclad.core.walker import DiscoveredFile
from ironclad.scanners.dependency import ParsedDependency, extract_dependencies

_LICENSE_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "license_db.json")

# License categories relevant to enterprise compliance review.
COPYLEFT_LICENSES = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"}
PERMISSIVE_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC ", "ISC"}


def _load_license_db() -> Dict[str, str]:
    try:
        with open(_LICENSE_DB_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


@dataclass
class SBOMComponent:
    name: str
    version: str
    ecosystem: str
    license: str
    purl: str


def _purl(ecosystem: str, name: str, version: str) -> str:
    type_map = {"python": "pypi", "javascript": "npm", "go": "golang", "ruby": "gem", "php": "composer", "java": "maven"}
    purl_type = type_map.get(ecosystem, "generic")
    return f"pkg:{purl_type}/{name}@{version}"


def build_sbom(manifests: List[DiscoveredFile], project_name: str = "scanned-project") -> Dict:
    license_db = _load_license_db()
    deps = extract_dependencies(manifests)

    components = []
    for dep in deps:
        license_id = license_db.get(dep.ecosystem, {}).get(dep.name.lower(), "UNKNOWN")
        components.append({
            "type": "library",
            "name": dep.name,
            "version": dep.version or "unknown",
            "purl": _purl(dep.ecosystem, dep.name, dep.version or "unknown"),
            "licenses": [{"license": {"id": license_id}}] if license_id != "UNKNOWN" else [],
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": project_name},
            "tools": [{"vendor": "IronClad Sentinel", "name": "ironclad-sbom-generator", "version": "1.0.0"}],
        },
        "components": components,
    }


def scan_license_compliance(manifests: List[DiscoveredFile], disallowed: List[str] = None) -> List[Finding]:
    """
    Flags dependencies under licenses that commonly trigger enterprise
    legal review (strong copyleft) unless the operator has explicitly
    allowlisted them. `disallowed` defaults to strong copyleft licenses,
    which is the single most common corporate open-source policy trigger
    (obligation to release derivative source code).
    """
    disallowed = set(disallowed) if disallowed else set(COPYLEFT_LICENSES)
    license_db = _load_license_db()
    deps = extract_dependencies(manifests)
    findings: List[Finding] = []

    for dep in deps:
        license_id = license_db.get(dep.ecosystem, {}).get(dep.name.lower())
        if not license_id:
            continue
        if license_id in disallowed:
            findings.append(Finding(
                rule_id="LICENSE-COPYLEFT-DEPENDENCY",
                title=f"Dependency under restrictive license: {dep.name} ({license_id})",
                description=(
                    f"{dep.name}@{dep.version or 'unknown'} is licensed under {license_id}, a "
                    f"strong copyleft license. Depending on how it's linked/distributed, this "
                    f"may create an obligation to release derivative source code under the "
                    f"same license -- a common blocker in enterprise legal review."
                ),
                severity=Severity.MEDIUM,
                engine=Engine.LICENSE,
                category="license-compliance",
                remediation=(
                    f"Have legal/compliance review the usage of {dep.name}, or replace it with "
                    f"a permissively-licensed alternative (MIT/Apache-2.0/BSD)."
                ),
                confidence="medium",
                location=CodeLocation(
                    file_path=dep.manifest_rel_path,
                    start_line=dep.line_number,
                    end_line=dep.line_number,
                    snippet=f"{dep.name} == {dep.version}",
                ),
                extra={"license": license_id, "package": dep.name},
            ))

    return findings
