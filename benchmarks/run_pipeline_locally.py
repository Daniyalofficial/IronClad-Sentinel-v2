#!/usr/bin/env python3
"""Execute the staged CI pipeline locally, step by step.

Parses ``deploy/ci/verify.yml`` and runs each step's real ``run:`` block in
bash, so what is verified here is literally what GitHub Actions would run --
not a paraphrase of it.

Steps whose name contains a marker in SKIP are not executed (no PostgreSQL
server or Docker in this environment); they are reported as SKIPPED rather
than silently counted as passing.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

import yaml

PIPELINE = "deploy/ci/verify.yml"
SKIP_MARKERS = ("PostgreSQL", "wheel")  # no pg server; wheel verified separately


def main() -> int:
    with open(PIPELINE, encoding="utf-8") as fh:
        workflow = yaml.safe_load(fh)

    results = []
    for job_name, job in workflow["jobs"].items():
        env = dict(job.get("env") or {})
        print(f"\n{'=' * 72}\nJOB: {job_name}\n{'=' * 72}")
        for step in job["steps"]:
            name = step.get("name") or step.get("uses") or "(unnamed)"
            run = step.get("run")
            if run is None:
                print(f"  - {name}: (action {step.get('uses')}) -> n/a locally")
                continue
            if any(marker.lower() in name.lower() for marker in SKIP_MARKERS):
                print(f"  - {name}: SKIPPED (unavailable in this sandbox)")
                results.append((job_name, name, "SKIPPED", 0.0))
                continue

            started = time.perf_counter()
            proc = subprocess.run(["bash", "-e", "-c", run], env={**os.environ, **env},
                                  capture_output=True, text=True)
            elapsed = time.perf_counter() - started
            status = "PASS" if proc.returncode == 0 else "FAIL"
            results.append((job_name, name, status, elapsed))
            print(f"  - {name}: {status} ({elapsed:.1f}s)")
            if proc.returncode != 0:
                tail = (proc.stdout + proc.stderr).strip().splitlines()[-25:]
                print("    " + "\n    ".join(tail))

    print(f"\n{'=' * 72}\nSUMMARY\n{'=' * 72}")
    counts = {"PASS": 0, "FAIL": 0, "SKIPPED": 0}
    for job_name, name, status, elapsed in results:
        counts[status] += 1
        print(f"  [{status:7}] {job_name}/{name}")
    print(f"\n  {counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIPPED']} skipped")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
