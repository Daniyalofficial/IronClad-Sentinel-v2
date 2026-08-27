"""CycloneDX 1.5 report renderer.

This is the *findings* flavour of CycloneDX: the same 1.5 document the SBOM
command produces, extended with a ``vulnerabilities`` array so that a
single CycloneDX file carries both the component inventory and the
findings that apply to it. Consumers that only understand SBOMs ignore the
extra array; consumers that understand VEX/vulnerability reports get
machine-readable remediation data.

Findings that are not tied to a package (SAST, secrets, IaC) are still
represented -- they become vulnerability entries whose ``affects`` list is
empty and whose location is carried in ``properties`` -- so no finding is
silently dropped by choosing this format.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Dict, List

from ironclad.core.models import ScanResult, Severity
from ironclad.scanners.sbom import CDX_NAMESPACE, ROOT_BOM_REF, SBOM_TOOL_VERSION, _iso

CDX_SEVERITY = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}

# OWASP-style CVSS-ish qualitative mapping is enough for CycloneDX's
# `ratings[].severity`; IronClad does not compute numeric CVSS scores and
# does not pretend to.


def _vuln_id(result: ScanResult, index: int, fingerprint: str) -> str:
    digest = hashlib.sha256(f"{result.target}|{index}|{fingerprint}".encode("utf-8")).hexdigest()[:12]
    return f"IRONCLAD-{digest.upper()}"


def build_vulnerabilities(result: ScanResult) -> List[Dict]:
    vulnerabilities: List[Dict] = []
    component_refs = {c.get("purl") for c in (result.sbom or {}).get("components", [])}
    for index, finding in enumerate(result.sorted_findings()):
        purl = str(finding.extra.get("purl", "")) if finding.extra else ""
        affects = []
        if purl and (not component_refs or purl in component_refs):
            affects.append({"ref": purl})
        entry: Dict[str, object] = {
            "id": _vuln_id(result, index, finding.fingerprint),
            "source": {"name": f"IronClad Sentinel {finding.engine.value} engine"},
            "ratings": [{
                "severity": CDX_SEVERITY[finding.severity],
                "method": "other",
                "justification": "IronClad severity model (see docs/ARCHITECTURE.md)",
            }],
            "cwes": [int(finding.cwe.split("-")[1])] if finding.cwe and finding.cwe.startswith("CWE-") else [],
            "description": finding.description,
            "recommendation": finding.remediation,
            "advisories": [{"url": url} for url in finding.references],
            "affects": affects,
            "properties": [
                {"name": "ironclad:rule-id", "value": finding.rule_id},
                {"name": "ironclad:category", "value": finding.category},
                {"name": "ironclad:confidence", "value": finding.confidence},
                {"name": "ironclad:fingerprint", "value": finding.fingerprint},
                {"name": "ironclad:file", "value": finding.location.file_path},
                {"name": "ironclad:line", "value": str(finding.location.start_line)},
            ],
        }
        vulnerabilities.append(entry)
    return vulnerabilities


def render_cyclonedx(result: ScanResult) -> str:
    base: Dict[str, object] = dict(result.sbom) if result.sbom else {}
    components = base.get("components", [])
    document: Dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": base.get("serialNumber") or f"urn:uuid:{uuid.uuid5(CDX_NAMESPACE, result.target)}",
        "version": 1,
        "metadata": base.get("metadata") or {
            "timestamp": _iso(None),
            "component": {"type": "application", "bom-ref": ROOT_BOM_REF, "name": result.target},
            "tools": [{"vendor": "IronClad Sentinel", "name": "ironclad-sentinel",
                       "version": SBOM_TOOL_VERSION}],
        },
        "components": components,
        "vulnerabilities": build_vulnerabilities(result),
    }
    if "dependencies" in base:
        document["dependencies"] = base["dependencies"]
    return json.dumps(document, indent=2, sort_keys=True) + "\n"
