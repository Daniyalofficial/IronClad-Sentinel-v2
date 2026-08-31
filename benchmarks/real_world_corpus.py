#!/usr/bin/env python3
"""Measure dependency detection against real open-source repositories.

The synthetic corpus in ``benchmarks/corpus_metrics.py`` proves the detector
fires on patterns we wrote ourselves. That is not evidence about real
projects, so this script clones real repositories and reports what the
dependency engine actually does with their manifests.

What it measures, and what it deliberately does not claim:

* **Every reported finding is on a pinned version.** A manifest declaring
  ``urllib3>=1.26,<3`` does not say what is installed, so a finding there
  would be a false positive; the invariant is asserted, not assumed.
* **True positives** are findings whose advisory id is a real GHSA
  identifier and whose package version is genuinely pinned in the
  repository. Both halves are checked.
* **False positives** would be findings on an unpinned range, or on a
  version the advisory does not actually cover. Both are counted.
* **Recall is NOT measured here.** That needs an independent, labelled set
  of vulnerable revisions; scoring against the same advisory database the
  scanner reads would be circular. Say so rather than publish a number that
  looks like recall.

Requires network access to github.com. Exits 0 with a SKIP notice when the
network is unavailable, so it can be wired into CI without making it flaky.

    python benchmarks/real_world_corpus.py
    python benchmarks/real_world_corpus.py --repos pallets/flask psf/requests
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ironclad.core.config import IronCladConfig  # noqa: E402
from ironclad.core.engine import run_scan  # noqa: E402
from ironclad.scanners.dependency import _satisfies_affected_range  # noqa: E402
from ironclad.scanners.advisories import BundledAdvisorySource  # noqa: E402

DEFAULT_REPOS = [
    "pallets/flask",
    "pallets/click",
    "pallets/jinja",
    "psf/requests",
    "encode/httpx",
    "encode/uvicorn",
]

GHSA_ID = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")


def clone(repo: str, dest: str) -> bool:
    try:
        subprocess.run(["git", "clone", "--depth", "1", "-q",
                        f"https://github.com/{repo}", dest],
                       check=True, capture_output=True, timeout=300)
        return True
    except (subprocess.SubprocessError, OSError):
        return False


def audit(repo_root: str):
    """Return (findings, false_positives) for one checked-out repository."""
    source = BundledAdvisorySource()
    result = run_scan(IronCladConfig(target=repo_root, enabled_engines={"dependency"}))
    findings = [f for f in result.findings if f.category == "vulnerable-dependency"]
    false_positives = []
    for finding in findings:
        extra = finding.extra
        advisory_id = str(extra.get("advisory_id") or "")
        if not extra.get("is_pinned"):
            false_positives.append(f"{extra.get('package')}: reported on an unpinned range")
            continue
        if not GHSA_ID.match(advisory_id):
            false_positives.append(f"{extra.get('package')}: id {advisory_id!r} is not a GHSA id")
            continue
        # Re-check the match independently of the scanner's own code path.
        advisories = source.lookup(extra.get("ecosystem"), extra.get("package"))
        matched = [a for a in advisories if a["id"] == advisory_id
                   and _satisfies_affected_range(str(extra.get("installed_version")),
                                                 str(a.get("affected", "")))]
        if not matched:
            false_positives.append(
                f"{extra.get('package')}@{extra.get('installed_version')}: "
                f"{advisory_id} does not actually cover that version")
    return findings, false_positives


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repos", nargs="*", default=DEFAULT_REPOS)
    parser.add_argument("--as-json", action="store_true")
    parser.add_argument("--keep", action="store_true", help="Keep the cloned repositories")
    args = parser.parse_args()

    workdir = tempfile.mkdtemp(prefix="ironclad-corpus-")
    rows = []
    cloned = 0
    try:
        for repo in args.repos:
            dest = os.path.join(workdir, repo.replace("/", "__"))
            if not clone(repo, dest):
                continue
            cloned += 1
            findings, false_positives = audit(dest)
            rows.append({
                "repo": repo,
                "findings": len(findings),
                "false_positives": len(false_positives),
                "packages": sorted({f.extra.get("package") for f in findings}),
                "advisories": sorted({str(f.extra.get("advisory_id")) for f in findings}),
                "fp_detail": false_positives,
            })
    finally:
        if args.keep:
            print(f"kept clones in {workdir}", file=sys.stderr)
        else:
            shutil.rmtree(workdir, ignore_errors=True)

    if not cloned:
        print("SKIP: github.com is unreachable from this environment; "
              "no real-world measurement was performed.")
        return 0

    total = sum(r["findings"] for r in rows)
    total_fp = sum(r["false_positives"] for r in rows)
    if args.as_json:
        print(json.dumps({"repositories": cloned, "findings": total,
                          "false_positives": total_fp, "detail": rows}, indent=2))
        return 0 if total_fp == 0 else 1

    print(f"# real-world dependency corpus -- {cloned} repositories")
    for row in rows:
        print(f"  {row['repo']:<24} {row['findings']:>3} findings "
              f"{row['false_positives']:>2} false positives  {row['packages']}")
    print(f"total findings={total} false_positives={total_fp}")
    print("recall is not measured here: scoring against the same advisory "
          "database the scanner reads would be circular.")
    return 0 if total_fp == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
