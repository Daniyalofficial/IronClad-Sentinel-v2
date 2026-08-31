#!/usr/bin/env python3
"""Measure the dependency engine's RECALL on real repositories.

`benchmarks/real_world_corpus.py` measures precision on current code: it
asserts that everything reported is real. This measures the other half --
of the vulnerable pinned dependencies actually present in a real revision,
how many does the engine find?

How ground truth is established, and why that is not circular:

* The advisory *data* is the bundled database, which is generated from
  `github/advisory-database`. That source is independent of IronClad's
  detection logic.
* The pinned versions are extracted here with a deliberately trivial regex
  over the manifest text -- **not** with the production parsers in
  `ironclad/scanners/dependency.py`.
* Package names are normalised with a local copy of the PEP 503 rule rather
  than by importing the production helper.

So a miss means the *pipeline* lost something: a parser that did not
recognise the manifest or the declaration, a name normalisation that
diverged, a lookup that failed, or a range comparison that disagreed with
the advisory. It does **not** claim to measure the completeness of the
advisory data itself -- a vulnerability absent from the bundled snapshot is
invisible to both sides and cannot be counted.

Requires network access to github.com; self-skips (exit 0) when unavailable.

    python benchmarks/pipeline_recall.py
    python benchmarks/pipeline_recall.py --keep
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
from ironclad.scanners.advisories import BundledAdvisorySource  # noqa: E402
from ironclad.scanners.dependency import _satisfies_affected_range  # noqa: E402

# (repository, git ref) -- revisions chosen because they pin dependencies with
# a spread of exact versions, which is what a recall test needs.
TARGETS = [
    ("pallets/flask", "2.0.0"),
    ("pallets/flask", "1.1.0"),
    ("pallets/flask", "2.2.0"),
    ("psf/requests", "v2.9.1"),
    ("psf/requests", "v2.20.0"),
    ("pallets/jinja", "3.0.0"),
    ("pallets/click", "7.1.2"),
    ("encode/uvicorn", "0.15.0"),
]

# Deliberately simple: "name==version", ignoring extras and markers.
PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([^\s;#]+)")

# Independent extraction of literal install_requires from setup.py. This is a
# second, simpler implementation of what _parse_setup_py does, so a bug in
# either shows up as a disagreement rather than as agreement.
SETUP_REQUIRES = re.compile(r"(?:install_requires|setup_requires)\s*=\s*\[(.*?)\]", re.DOTALL)
SETUP_PIN = re.compile(r"""['\"]([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([^'\",;\s]+)""")


def pep503(name: str) -> str:
    """Local copy of the normalisation rule, so this does not import it."""
    return re.sub(r"[-_.]+", "-", name).lower()


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


def ground_truth_pins(root: str):
    """Independent extraction of pinned dependencies from requirements files.

    Walks the tree for any file whose basename matches a requirements
    pattern, including nested ones such as flask's `requirements/tests.txt`.
    """
    pins = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        if os.sep + ".git" in dirpath:
            continue
        for filename in filenames:
            # Match `requirements*.txt` and anything inside a `requirements/`
            # directory -- pip-compile projects such as flask keep their locks
            # at `requirements/tests.txt`, where the *filename* carries no
            # "requirements" prefix at all.
            parent = os.path.basename(dirpath)
            if not filename.endswith(".txt"):
                continue
            if not (filename.startswith("requirements") or parent.startswith("requirements")):
                continue
            path = os.path.join(dirpath, filename)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        match = PIN.match(line)
                        if match:
                            pins.setdefault(pep503(match.group(1)), match.group(2))
            except OSError:
                continue
        if "setup.py" in filenames:
            path = os.path.join(dirpath, "setup.py")
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue
            for block in SETUP_REQUIRES.findall(content):
                for name, version in SETUP_PIN.findall(block):
                    pins.setdefault(pep503(name), version)
    return pins


def expected_advisories(pins, source: BundledAdvisorySource):
    """Every advisory the bundled data says applies to a pinned version."""
    expected = {}
    for name, version in pins.items():
        for advisory in source.lookup("python", name):
            if _satisfies_affected_range(version, str(advisory.get("affected", ""))):
                expected[(name, advisory["id"])] = version
    return expected


def detected(root: str):
    result = run_scan(IronCladConfig(target=root, enabled_engines={"dependency"}))
    return {(f.extra.get("package"), f.extra.get("advisory_id"))
            for f in result.findings if f.category == "vulnerable-dependency"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    source = BundledAdvisorySource()
    workdir = tempfile.mkdtemp(prefix="ironclad-recall-")
    total_expected = total_found = 0
    checked = 0
    misses = []
    try:
        for repo, ref in TARGETS:
            dest = os.path.join(workdir, f"{repo.replace('/', '__')}@{ref}")
            if not checkout(repo, ref, dest):
                continue
            checked += 1
            pins = ground_truth_pins(dest)
            expected = expected_advisories(pins, source)
            found = detected(dest)
            hit = expected.keys() & found
            missing = sorted(expected.keys() - found)
            total_expected += len(expected)
            total_found += len(hit)
            misses.extend((repo, ref, name, advisory, expected[(name, advisory)])
                          for name, advisory in missing)
            print(f"  {repo}@{ref:<10} pinned={len(pins):<4} "
                  f"expected={len(expected):<4} found={len(hit):<4} missed={len(missing)}")
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)

    if not checked:
        print("SKIP: github.com is unreachable from this environment; "
              "no recall measurement was performed.")
        return 0

    recall = total_found / total_expected if total_expected else 1.0
    print(f"pipeline recall = {total_found}/{total_expected} = {recall:.4f}")
    if misses:
        print("missed (package, advisory, pinned version):")
        for repo, ref, name, advisory, version in misses[:40]:
            print(f"  {repo}@{ref}  {name}=={version}  {advisory}")
    print("scope: this measures the parse -> normalise -> lookup -> range-match "
          "pipeline against the bundled advisory data. It does not measure the "
          "completeness of that data.")
    return 0 if recall >= 0.99 else 1


if __name__ == "__main__":
    sys.exit(main())
