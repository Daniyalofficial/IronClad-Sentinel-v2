"""
SARIF 2.1.0 report generator.

SARIF (Static Analysis Results Interchange Format) is the format GitHub
Code Scanning, Azure DevOps, and most enterprise security dashboards
natively ingest. Producing valid SARIF means IronClad Sentinel plugs
straight into a customer's existing security tooling.
"""
from __future__ import annotations

import json
from typing import Dict

from ironclad.core.models import ScanResult

TOOL_URI = "https://github.com/Daniyalofficial/IronClad-Sentinel-v2"
SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SARIF_LEVEL_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def build_sarif(result: ScanResult) -> Dict:
    rules_seen = {}
    sarif_results = []

    for finding in result.sorted_findings():
        if finding.rule_id not in rules_seen:
            rules_seen[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "helpUri": finding.references[0] if finding.references else f"{TOOL_URI}/rules",
                "properties": {
                    "category": finding.category,
                    "cwe": finding.cwe,
                    "owasp": finding.owasp,
                    "security-severity": str(finding.severity.weight),
                },
            }

        sarif_results.append({
            "ruleId": finding.rule_id,
            "level": SARIF_LEVEL_MAP.get(finding.severity.value, "warning"),
            "message": {"text": finding.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location.file_path.replace("\\", "/")},
                    "region": {
                        "startLine": max(1, finding.location.start_line),
                        "endLine": max(1, finding.location.end_line),
                    },
                }
            }],
            "partialFingerprints": {"ironcladFingerprint/v1": finding.fingerprint},
            "properties": {"severity": finding.severity.value, "confidence": finding.confidence},
        })

    return {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "IronClad Sentinel",
                    "organization": "Daniyalofficial",
                    "informationUri": TOOL_URI,
                    "version": result.tool_version,
                    "rules": list(rules_seen.values()),
                }
            },
            "results": sarif_results,
        }],
    }


def render_sarif(result: ScanResult) -> str:
    return json.dumps(build_sarif(result), indent=2)
