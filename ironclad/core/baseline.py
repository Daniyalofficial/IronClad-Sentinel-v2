"""
Baseline management for suppressing already-triaged findings.

Real codebases scanned for the first time often surface hundreds of
pre-existing issues. Forcing a team to fix all of them before they can
turn on CI gating is how security tools get disabled in week one.
Instead, IronClad Sentinel supports baselining: snapshot the current
findings' fingerprints, commit that file, and future scans only report
NEW findings (or fail CI only on new findings) while the backlog is
worked down on its own timeline.
"""
from __future__ import annotations

import json
import os
import time
from typing import Dict, List, Set

from ironclad.core.models import Finding


def load_baseline_fingerprints(path: str) -> Set[str]:
    if not path or not os.path.isfile(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return set(data.get("fingerprints", []))
    except (OSError, json.JSONDecodeError):
        return set()


def write_baseline(path: str, findings: List[Finding]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    payload = {
        "generated_at": time.time(),
        "tool": "IronClad Sentinel",
        "count": len(findings),
        "fingerprints": sorted({f.fingerprint for f in findings}),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def apply_baseline(findings: List[Finding], baseline_fingerprints: Set[str]):
    """
    Returns (kept_findings, suppressed_count). Findings whose fingerprint
    already exists in the baseline are suppressed from the "new findings"
    view but the caller may still choose to include them in the full
    report with a `baselined: true` marker.
    """
    if not baseline_fingerprints:
        return findings, 0
    kept = [f for f in findings if f.fingerprint not in baseline_fingerprints]
    suppressed = len(findings) - len(kept)
    return kept, suppressed
