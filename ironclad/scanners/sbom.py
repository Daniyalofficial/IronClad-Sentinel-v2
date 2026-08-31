"""SBOM generation and license compliance checking.

Two outputs are produced from the same in-memory component model so the
two formats can never disagree:

* CycloneDX 1.5 JSON (``build_sbom``) -- what enterprise procurement and
  most CI uploaders expect.
* SPDX 2.3 JSON (``ironclad.scanners.spdx.build_spdx``).

Guarantees the CycloneDX builder makes:

* **Stable component identity** -- every component carries a ``bom-ref``
  equal to its PURL, and PURLs follow the ecosystem mapping in ``_purl``.
* **Duplicate elimination** -- keyed on (ecosystem, lowercase name, version).
* **Deterministic output** -- the ``serialNumber`` is a UUIDv5 over the
  sorted component identities, so scanning the same tree twice produces
  byte-identical documents apart from ``metadata.timestamp`` (which can be
  pinned for golden-file tests).
* **Dependency relationships** -- the root component ``dependsOn`` every
  discovered component, so consumers can build a graph.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from ironclad.core.models import CodeLocation, Engine, Finding, Severity
from ironclad.core.spdx_expr import (
    DEFAULT_PERMISSIVE,
    LicensePolicySets,
    default_policy,
    parse_expression,
)
from ironclad.core.walker import DiscoveredFile
from ironclad.scanners.dependency import ParsedDependency, extract_dependencies

_LICENSE_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "license_db.json")

# Kept as module constants for backwards compatibility and for tests that
# assert the conservative defaults; the runtime policy comes from
# `ironclad.core.spdx_expr` and is fully externalized via policy.yaml.
COPYLEFT_LICENSES = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0"}
PERMISSIVE_LICENSES = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "ISC "}

CDX_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # uuid5 DNS namespace
ROOT_BOM_REF = "ironclad-root"
SBOM_TOOL_VERSION = "1.1.0"

_PURL_TYPES = {
    "python": "pypi",
    "javascript": "npm",
    "go": "golang",
    "ruby": "gem",
    "php": "composer",
    "java": "maven",
    "rust": "cargo",
    "nuget": "nuget",
}


def _load_license_db() -> Dict[str, Dict[str, str]]:
    try:
        with open(_LICENSE_DB_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _license_for(dep: ParsedDependency, db: Dict[str, Dict[str, str]]) -> str:
    """Look up a dependency's license, normalizing name case.

    Returns the literal string ``UNKNOWN`` when the bundled database has no
    mapping -- callers must treat that as "requires human review", never as
    "permissive".
    """
    ecosystem = db.get(dep.ecosystem, {})
    return ecosystem.get(dep.name.lower(), ecosystem.get(dep.name, "UNKNOWN"))


def _purl(ecosystem: str, name: str, version: str) -> str:
    """Build a Package URL. Ecosystem names outside the map stay ``generic``."""
    purl_type = _PURL_TYPES.get(ecosystem, "generic")
    namespace, _, bare = name.rpartition("/")
    if purl_type == "maven" and namespace:
        return f"pkg:{purl_type}/{namespace}/{bare}@{version}"
    if namespace and purl_type in {"npm", "composer", "golang"}:
        return f"pkg:{purl_type}/{namespace}/{bare}@{version}"
    return f"pkg:{purl_type}/{name}@{version}"


def _iso(timestamp: Optional[datetime]) -> str:
    value = timestamp or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect_components(manifests: List[DiscoveredFile]) -> List[Dict[str, str]]:
    """De-duplicated, sorted component list shared by CycloneDX and SPDX."""
    db = _load_license_db()
    seen = set()
    components: List[Dict[str, str]] = []
    for dep in extract_dependencies(manifests):
        version = dep.version or "unknown"
        key = (dep.ecosystem, dep.name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        license_id = _license_for(dep, db)
        components.append({
            "ecosystem": dep.ecosystem,
            "name": dep.name,
            "version": version,
            "license": license_id,
            "purl": _purl(dep.ecosystem, dep.name, version),
            "manifest": dep.manifest_rel_path,
            "declared_spec": dep.declared_spec or f"=={version}",
        })
    components.sort(key=lambda c: (c["ecosystem"], c["name"].lower(), c["version"]))
    return components


def _serial_number(project_name: str, components: List[Dict[str, str]]) -> str:
    basis = "|".join([project_name] + [c["purl"] for c in components])
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return f"urn:uuid:{uuid.uuid5(CDX_NAMESPACE, digest)}"


def build_sbom(
    manifests: List[DiscoveredFile],
    project_name: str = "scanned-project",
    timestamp: Optional[datetime] = None,
    include_dependencies: bool = True,
) -> Dict:
    """Build a CycloneDX 1.5 JSON document from discovered manifests."""
    components = collect_components(manifests)
    cdx_components = []
    for component in components:
        entry: Dict[str, object] = {
            "type": "library",
            "bom-ref": component["purl"],
            "name": component["name"],
            "version": component["version"],
            "purl": component["purl"],
            "properties": [
                {"name": "ironclad:ecosystem", "value": component["ecosystem"]},
                {"name": "ironclad:manifest", "value": component["manifest"]},
            ],
        }
        license_id = component["license"]
        if license_id != "UNKNOWN":
            expression = parse_expression(license_id)
            if expression.operator == "OR" and len(expression.ids) > 1:
                entry["licenses"] = [{"license": {"id": lid}} for lid in expression.ids]
            else:
                entry["licenses"] = [{"license": {"id": license_id}}]
        else:
            entry["properties"].append({"name": "ironclad:license-status", "value": "UNKNOWN"})
        cdx_components.append(entry)

    document: Dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": _serial_number(project_name, components),
        "version": 1,
        "metadata": {
            "timestamp": _iso(timestamp),
            "component": {
                "type": "application",
                "bom-ref": ROOT_BOM_REF,
                "name": project_name,
            },
            "tools": [{
                "vendor": "IronClad Sentinel",
                "name": "ironclad-sbom-generator",
                "version": SBOM_TOOL_VERSION,
            }],
        },
        "components": cdx_components,
    }
    if include_dependencies:
        document["dependencies"] = [{
            "ref": ROOT_BOM_REF,
            "dependsOn": [c["purl"] for c in components],
        }] + [{"ref": c["purl"], "dependsOn": []} for c in components]
    return document


def validate_cyclonedx(doc: Dict) -> List[str]:
    """Structural validation of a CycloneDX document.

    Returns a list of human-readable problems (empty == valid). This is a
    deliberate subset of the CycloneDX 1.5 JSON schema: the fields IronClad
    emits and the invariants consumers rely on. It is not a full schema
    validator and does not claim to be one.
    """
    problems: List[str] = []
    if doc.get("bomFormat") != "CycloneDX":
        problems.append("bomFormat must be 'CycloneDX'")
    if doc.get("specVersion") != "1.5":
        problems.append(f"unsupported specVersion: {doc.get('specVersion')!r}")
    if not str(doc.get("serialNumber", "")).startswith("urn:uuid:"):
        problems.append("serialNumber must be a urn:uuid:... value")
    components = doc.get("components")
    if not isinstance(components, list):
        problems.append("components must be a list")
        return problems

    refs = set()
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            problems.append(f"components[{index}] is not an object")
            continue
        for required in ("type", "name", "version", "purl", "bom-ref"):
            if required not in component:
                problems.append(f"components[{index}] missing required field '{required}'")
        ref = component.get("bom-ref")
        if ref in refs:
            problems.append(f"duplicate bom-ref: {ref}")
        refs.add(ref)
        purl = str(component.get("purl", ""))
        if not purl.startswith("pkg:"):
            problems.append(f"components[{index}] has a malformed purl: {purl!r}")
        licenses = component.get("licenses")
        if licenses is not None:
            if not isinstance(licenses, list) or not licenses:
                problems.append(f"components[{index}] licenses must be a non-empty list")
            else:
                for entry in licenses:
                    if not isinstance(entry, dict) or "license" not in entry:
                        problems.append(f"components[{index}] licenses entry must be {{'license': ...}}")

    for index, dependency in enumerate(doc.get("dependencies") or []):
        if "ref" not in dependency:
            problems.append(f"dependencies[{index}] missing 'ref'")
            continue
        for dep_ref in dependency.get("dependsOn", []):
            if dep_ref not in refs and dep_ref != ROOT_BOM_REF:
                problems.append(f"dependencies[{index}] references unknown component '{dep_ref}'")
    return problems


def scan_license_compliance(
    manifests: List[DiscoveredFile],
    disallowed: Optional[List[str]] = None,
    policy: Optional[LicensePolicySets] = None,
) -> List[Finding]:
    """Flag dependencies whose license the organization's policy rejects.

    ``policy`` wins when supplied; ``disallowed`` is the legacy positional
    form (a flat block list) and is kept so existing integrations and tests
    continue to work.
    """
    if policy is None:
        policy = default_policy()
        if disallowed is not None:
            policy = LicensePolicySets(
                allowed=set(DEFAULT_PERMISSIVE) - set(disallowed),
                warning=set(),
                blocked=set(disallowed),
                unknown_action="warn",
            )
    findings: List[Finding] = []
    for dep in extract_dependencies(manifests):
        license_id = _license_for(dep, _load_license_db())
        classification = policy.classify(license_id)
        snippet = f"{dep.name} {dep.declared_spec or dep.version or ''}".strip()
        location = CodeLocation(file_path=dep.manifest_rel_path, start_line=dep.line_number,
                                end_line=dep.line_number, snippet=snippet)
        common = dict(engine=Engine.LICENSE, category="license-compliance",
                      location=location, extra={"license": license_id, "package": dep.name,
                                                "ecosystem": dep.ecosystem,
                                                "classification": classification})
        if classification == "unknown":
            findings.append(Finding(
                rule_id="LICENSE-UNKNOWN",
                title=f"License could not be identified: {dep.name}",
                description=(f"IronClad has no bundled license mapping for {dep.name}. "
                             f"It is not assumed permissive."),
                severity=Severity.MEDIUM if policy.unknown_action == "block" else Severity.LOW,
                remediation=("Verify the dependency's license from authoritative package metadata "
                             "and update the organization policy/database."),
                confidence="high", **common,
            ))
        elif classification == "blocked":
            # Rule ID `LICENSE-COPYLEFT-DEPENDENCY` is the stable public ID
            # for "policy-blocked license" since v1.0. It is deliberately
            # kept (rather than renamed) because baseline files and CI
            # ignore-lists reference it by name.
            findings.append(Finding(
                rule_id="LICENSE-COPYLEFT-DEPENDENCY",
                title=f"Dependency under blocked license: {dep.name} ({license_id})",
                description=(f"{dep.name}@{dep.version or 'unknown'} is mapped to {license_id}, "
                             f"which organization license policy blocks."),
                severity=Severity.HIGH,
                remediation=(f"Remove {dep.name}, obtain a recorded legal exception, or replace "
                             f"it with an approved alternative."),
                confidence="high", **common,
            ))
        elif classification == "warning":
            findings.append(Finding(
                rule_id="LICENSE-REVIEW-REQUIRED",
                title=f"Dependency under weak-copyleft license: {dep.name} ({license_id})",
                description=(f"{dep.name}@{dep.version or 'unknown'} is mapped to {license_id}. "
                             f"Weak-copyleft licenses are usually acceptable when the library is "
                             f"used unmodified, but require a recorded review."),
                severity=Severity.LOW,
                remediation="Record a license review decision, or replace the dependency if the obligation is unacceptable.",
                confidence="medium", **common,
            ))
    return findings
