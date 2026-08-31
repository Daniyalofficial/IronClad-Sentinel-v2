#!/usr/bin/env python3
"""Score the dependency engine against an independently maintained feed.

`benchmarks/pipeline_recall.py` checks the scanner against the advisory data
it ships with, which cannot detect a hole in that data. This script scores
against `pypa/advisory-database` instead: a different team, `PYSEC-`
identifiers, and an NVD-derived lineage rather than GitHub's review process.

    python benchmarks/independent_recall.py --source /path/to/pypa/vulns

Honesty about what this can and cannot prove:

* The bundled database is now built from *both* GHSA and PyPA, so a 100%
  score is partly circular -- PyPA's own advisories are in the data being
  scored. This script's lasting value is as a **regression harness**: if the
  database is regenerated and coverage silently drops, this fails.
* When it first ran, before PyPA was merged, it scored **97/104 = 93.27%**
  and every miss was real: the database had *zero* advisories for `click`,
  and was missing `CVE-2025-49142` (jinja2) and `CVE-2022-29361` (werkzeug).
  That is the measurement that justified merging a second feed.
* Ground truth is built here from the PyPA YAML directly, and pinned versions
  are extracted with a trivial regex -- neither uses the production parsers,
  so a bug in them shows up as a disagreement.
* CVE is the join key, because the two feeds use different identifiers for
  the same vulnerability.

Requires network access to github.com for the checkout; self-skips (exit 0)
when the source directory is absent.
"""
from __future__ import annotations

import argparse
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

TARGETS = [
    ("pallets/flask", "2.0.0"),
    ("pallets/flask", "2.2.0"),
    ("pallets/jinja", "3.0.0"),
    ("psf/requests", "v2.9.1"),
]

PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([^\s;#]+)")


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def load_ground_truth(source_dir: str):
    """package -> [(cve, affected_spec, pysec_id)] from the PyPA YAML."""
    import yaml

    truth = {}
    for dirpath, _dirs, files in os.walk(source_dir):
        for filename in files:
            if not filename.endswith((".yaml", ".yml")):
                continue
            try:
                with open(os.path.join(dirpath, filename), encoding="utf-8") as fh:
                    record = yaml.safe_load(fh)
            except (OSError, ValueError):
                continue
            if not isinstance(record, dict):
                continue
            cve = next((a for a in (record.get("aliases") or [])
                        if str(a).startswith("CVE-")), None)
            if not cve:
                continue
            for affected in record.get("affected") or []:
                package = affected.get("package") or {}
                if package.get("ecosystem") != "PyPI":
                    continue
                raw_ranges = affected.get("ranges") or []
                versions = affected.get("versions") or []
                if not raw_ranges and not versions:
                    # No version information at all, so the record asserts
                    # nothing about any version and cannot be scored. This is
                    # not leniency toward the scanner: PYSEC-2025-74 is a
                    # Nautobot advisory that names jinja2 and carries no
                    # ranges, and treating it as "every jinja2 release is
                    # vulnerable" would be inventing data on both sides.
                    continue
                comparators = []
                for rng in raw_ranges:
                    if str(rng.get("type", "")).upper() == "GIT":
                        continue
                    for event in rng.get("events") or []:
                        if event.get("introduced"):
                            comparators.append(f">={event['introduced']}")
                        if event.get("fixed"):
                            comparators.append(f"<{event['fixed']}")
                        if event.get("last_affected"):
                            comparators.append(f"<={event['last_affected']}")
                spec = ", ".join(comparators) if comparators else ">=0"
                truth.setdefault(pep503(str(package.get("name", ""))), []).append(
                    (cve, spec, record.get("id")))
    return truth


def pinned_versions(root: str):
    pins = {}
    for dirpath, _dirs, files in os.walk(root):
        if os.sep + ".git" in dirpath:
            continue
        for filename in files:
            if not filename.endswith(".txt"):
                continue
            if not (filename.startswith("requirements")
                    or os.path.basename(dirpath).startswith("requirements")):
                continue
            try:
                with open(os.path.join(dirpath, filename), encoding="utf-8",
                          errors="replace") as fh:
                    for line in fh:
                        match = PIN.match(line)
                        if match:
                            pins.setdefault(pep503(match.group(1)), match.group(2))
            except OSError:
                continue
    return pins


def checkout(repo: str, ref: str, dest: str) -> bool:
    try:
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout",
                        f"https://github.com/{repo}", dest],
                       check=True, capture_output=True, timeout=600)
        subprocess.run(["git", "-C", dest, "checkout", "-q", ref],
                       check=True, capture_output=True, timeout=600)
        return True
    except (subprocess.SubprocessError, OSError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=os.environ.get("IRONCLAD_PYPA_VULNS", ""),
                        help="Directory of PyPA advisory YAML (the 'vulns' checkout).")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    if not args.source or not os.path.isdir(args.source):
        print("SKIP: no PyPA advisory source. Clone it with:\n"
              "  git clone --depth 1 --filter=blob:none --sparse "
              "https://github.com/pypa/advisory-database /tmp/pypa\n"
              "  git -C /tmp/pypa sparse-checkout set vulns\n"
              "then pass --source /tmp/pypa/vulns")
        return 0

    truth = load_ground_truth(args.source)
    print(f"# independent recall -- {len(truth)} PyPA packages with a CVE alias")

    workdir = tempfile.mkdtemp(prefix="ironclad-independent-")
    total_expected = total_found = 0
    misses = []
    checked = 0
    try:
        for repo, ref in TARGETS:
            dest = os.path.join(workdir, repo.replace("/", "__") + ref)
            if not checkout(repo, ref, dest):
                continue
            checked += 1
            pins = pinned_versions(dest)
            expected = {}
            for name, version in pins.items():
                for cve, spec, pysec_id in truth.get(name, []):
                    if _satisfies_affected_range(version, spec):
                        expected[(name, cve)] = (version, pysec_id)
            result = run_scan(IronCladConfig(target=dest, enabled_engines={"dependency"}))
            found = {(f.extra.get("package"), f.extra.get("cve"))
                     for f in result.findings if f.category == "vulnerable-dependency"}
            hit = expected.keys() & found
            total_expected += len(expected)
            total_found += len(hit)
            misses.extend((repo, ref, name, cve, expected[(name, cve)])
                          for name, cve in sorted(expected.keys() - found))
            print(f"  {repo}@{ref:<10} pins={len(pins):<4} "
                  f"PyPA-says={len(expected):<4} found={len(hit):<4} "
                  f"missed={len(expected) - len(hit)}")
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)

    if not checked:
        print("SKIP: github.com is unreachable; no measurement performed.")
        return 0

    recall = total_found / total_expected if total_expected else 1.0
    print(f"independent recall = {total_found}/{total_expected} = {recall:.4f}")
    if misses:
        print("missed (the bundled database has no advisory for these):")
        for repo, ref, name, cve, (version, pysec_id) in misses[:30]:
            print(f"  {repo}@{ref}  {name}=={version}  {cve} ({pysec_id})")
    print("note: the bundled database is built from GHSA *and* PyPA, so a "
          "perfect score is partly circular; this is a regression guard.")
    return 0 if recall >= 0.99 else 1


if __name__ == "__main__":
    sys.exit(main())
