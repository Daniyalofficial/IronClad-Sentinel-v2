"""SPDX 2.3 JSON SBOM generation.

Built from the exact same component model as the CycloneDX output
(``ironclad.scanners.sbom.collect_components``), so the two formats can
never disagree about what is in a build.

SPDX quirks handled here:

* Every element needs an ``SPDXID`` of the form ``SPDXRef-<chars>``; we
  derive a deterministic, collision-free id from the PURL.
* A package with no known license must be ``NOASSERTION``, not omitted.
* ``filesAnalyzed`` is ``false`` because IronClad inventories manifests,
  not individual source files.
* ``documentNamespace`` must be a unique URI; we hash the component set so
  the same tree always yields the same namespace (golden-file friendly).
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

from ironclad.core.spdx_expr import parse_expression
from ironclad.core.walker import DiscoveredFile
from ironclad.scanners.sbom import collect_components

SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"
LICENSE_LIST_VERSION = "3.22"
DOCUMENT_ID = "SPDXRef-DOCUMENT"
ROOT_PACKAGE_PREFIX = "SPDXRef-Package-Root"

# Map IronClad ecosystems to the SPDX reference-type prefix used with the
# purl external reference category.
_REFERENCE_TYPES = {
    "python": "purl", "javascript": "purl", "go": "purl", "ruby": "purl",
    "php": "purl", "java": "purl", "rust": "purl",
}


def _spdx_id(purl: str) -> str:
    digest = hashlib.sha256(purl.encode("utf-8")).hexdigest()[:16]
    return f"SPDXRef-Package-{digest}"


def _declared_license(license_id: str) -> str:
    if not license_id or license_id == "UNKNOWN":
        return "NOASSERTION"
    expression = parse_expression(license_id)
    if expression.is_unknown:
        return "NOASSERTION"
    if expression.operator == "OR" and len(expression.ids) > 1:
        return " OR ".join(expression.ids)
    if expression.operator == "AND" and len(expression.ids) > 1:
        return " AND ".join(expression.ids)
    if expression.exceptions:
        return f"{expression.ids[0]} WITH {expression.exceptions[0]}"
    return expression.ids[0]


def _iso(timestamp: Optional[datetime]) -> str:
    value = timestamp or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_spdx(
    manifests: List[DiscoveredFile],
    project_name: str = "scanned-project",
    timestamp: Optional[datetime] = None,
) -> Dict:
    """Build an SPDX 2.3 JSON document from discovered manifests."""
    from ironclad import __version__

    components = collect_components(manifests)
    packages: List[Dict[str, object]] = []
    relationships: List[Dict[str, str]] = []
    root_id = f"{ROOT_PACKAGE_PREFIX}-{hashlib.sha256(project_name.encode()).hexdigest()[:12]}"

    packages.append({
        "SPDXID": root_id,
        "name": project_name,
        "versionInfo": "0.0.0",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
    })

    for component in components:
        spdx_id = _spdx_id(component["purl"])
        declared = _declared_license(component["license"])
        packages.append({
            "SPDXID": spdx_id,
            "name": component["name"],
            "versionInfo": component["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": declared,
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": _REFERENCE_TYPES.get(component["ecosystem"], "purl"),
                "referenceLocator": component["purl"],
            }],
            "annotations": [{
                "annotator": "Tool: ironclad-sentinel",
                "annotationDate": _iso(timestamp),
                "annotationType": "OTHER",
                "comment": f"declared in {component['manifest']} as {component['declared_spec']}",
            }],
        })
        relationships.append({
            "spdxElementId": root_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElementId": spdx_id,
        })

    relationships.append({
        "spdxElementId": DOCUMENT_ID,
        "relationshipType": "DESCRIBES",
        "relatedSpdxElementId": root_id,
    })

    namespace_digest = hashlib.sha256(
        ("|".join([project_name] + [c["purl"] for c in components])).encode("utf-8")
    ).hexdigest()

    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": DOCUMENT_ID,
        "name": f"{project_name} SBOM",
        "documentNamespace": f"https://ironclad.local/spdx/{namespace_digest}",
        "creationInfo": {
            "created": _iso(timestamp),
            "creators": [f"Tool: ironclad-sentinel-{__version__}"],
            "licenseListVersion": LICENSE_LIST_VERSION,
        },
        "documentDescribes": [root_id],
        "packages": packages,
        "relationships": relationships,
    }


def validate_spdx(doc: Dict) -> List[str]:
    """Structural validation of an SPDX 2.3 JSON document.

    Returns a list of problems; empty means valid. Covers the fields
    IronClad emits and the invariants SPDX consumers rely on (unique
    SPDXIDs, DESCRIBES relationship, declared licenses present).
    """
    problems: List[str] = []
    if doc.get("spdxVersion") != SPDX_VERSION:
        problems.append(f"unexpected spdxVersion: {doc.get('spdxVersion')!r}")
    if doc.get("dataLicense") != DATA_LICENSE:
        problems.append("dataLicense must be CC0-1.0")
    if doc.get("SPDXID") != DOCUMENT_ID:
        problems.append("document SPDXID must be SPDXRef-DOCUMENT")
    if not str(doc.get("documentNamespace", "")).startswith("https://"):
        problems.append("documentNamespace must be an https URI")

    packages = doc.get("packages")
    if not isinstance(packages, list) or not packages:
        problems.append("packages must be a non-empty list")
        return problems

    ids = set()
    for index, package in enumerate(packages):
        spdx_id = package.get("SPDXID")
        if not spdx_id or not str(spdx_id).startswith("SPDXRef-"):
            problems.append(f"packages[{index}] has an invalid SPDXID: {spdx_id!r}")
        if spdx_id in ids:
            problems.append(f"duplicate SPDXID: {spdx_id}")
        ids.add(spdx_id)
        for required in ("name", "versionInfo", "downloadLocation", "licenseDeclared", "copyrightText"):
            if required not in package:
                problems.append(f"packages[{index}] missing '{required}'")
        if "filesAnalyzed" not in package:
            problems.append(f"packages[{index}] missing 'filesAnalyzed'")

    for index, relationship in enumerate(doc.get("relationships") or []):
        for endpoint in ("spdxElementId", "relatedSpdxElementId"):
            target = relationship.get(endpoint)
            if target not in ids and target != DOCUMENT_ID:
                problems.append(f"relationships[{index}] references unknown element {target!r}")

    described = set(doc.get("documentDescribes") or [])
    if not described:
        problems.append("documentDescribes must list at least one package")
    elif not described <= ids:
        problems.append("documentDescribes references an element that is not a package")
    return problems


def render_spdx_json(doc: Dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


if __name__ == "__main__":  # pragma: no cover - manual helper
    raise SystemExit("use `ironclad sbom . --format spdx` to generate an SPDX document")
