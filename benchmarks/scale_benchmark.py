"""Scale and throughput benchmark.

Generates synthetic repositories of a known size and measures what actually
matters operationally:

  * wall-clock duration and files/second
  * peak resident memory (RSS) of the scanning process
  * bytes scanned per second
  * finding count (so a "fast" run that silently found nothing is visible)

The generated corpus is a realistic mix rather than identical files: a
majority of clean modules, a slice with real vulnerability patterns, plus
manifests, IaC and noise files, so the measurement is not dominated by one
code path.

Usage:
    python benchmarks/scale_benchmark.py            # 1k / 10k default tiers
    python benchmarks/scale_benchmark.py --tiers 1000,10000,100000
    python benchmarks/scale_benchmark.py --tiers 1000 --keep /tmp/corpus

Numbers are machine-specific. This script reports them; it does not assert
a pass/fail threshold, because a benchmark that fails only on slower CI
hardware teaches people to ignore it.
"""
from __future__ import annotations

import argparse
import gc
import os
import resource
import shutil
import sys
import tempfile
import time
from pathlib import Path

from ironclad.core.config import IronCladConfig
from ironclad.core.engine import run_scan

CLEAN_MODULE = '''"""Clean module {index}."""
from dataclasses import dataclass


@dataclass
class Record:
    id: int
    name: str


def normalise(records):
    return [Record(r.id, r.name.strip().lower()) for r in records]


def total(records):
    return sum(r.id for r in records)
'''

VULNERABLE_MODULE = '''"""Module with planted issues ({index})."""
import os
import sqlite3

import requests
from flask import request


def lookup(user_input):
    conn = sqlite3.connect(":memory:")
    query = "SELECT * FROM accounts WHERE email = '%s'" % user_input
    return conn.execute(query).fetchall()


def fetch():
    return requests.get(request.args.get("url"), verify=False).text


def read_file(user_input):
    return open(os.path.join("/var/data", user_input)).read()
'''

MANIFEST = """jinja2==3.1.2
requests==2.30.0
flask==2.3.2
"""

DOCKERFILE = """FROM python:3.11
RUN pip install -r requirements.txt
ENV API_TOKEN=abcdef0123456789abcdef
CMD ["python", "app.py"]
"""

K8S_MANIFEST = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: service
spec:
  template:
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: app:latest
          securityContext:
            privileged: true
"""

NOISE_FILE = "// generated fixture\nexport const VALUE_%d = %d;\n"


def _peak_rss_mb() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KiB, macOS reports bytes.
    return usage / 1024.0 if sys.platform.startswith("linux") else usage / (1024.0 * 1024.0)


def generate_corpus(root: Path, file_count: int) -> dict:
    """Create a corpus of exactly ``file_count`` files. Returns its shape."""
    root.mkdir(parents=True, exist_ok=True)
    python_files = int(file_count * 0.70)
    vulnerable = max(1, int(python_files * 0.05))
    noise = file_count - python_files - 4

    written = 0
    for index in range(python_files):
        package = root / f"pkg{index // 50}"
        package.mkdir(parents=True, exist_ok=True)
        body = VULNERABLE_MODULE if index < vulnerable else CLEAN_MODULE
        (package / f"module_{index}.py").write_text(body.format(index=index), encoding="utf-8")
        written += 1

    for index in range(max(0, noise)):
        directory = root / "web" / f"chunk{index // 100}"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"asset_{index}.js").write_text(NOISE_FILE % (index, index), encoding="utf-8")
        written += 1

    (root / "requirements.txt").write_text(MANIFEST, encoding="utf-8")
    (root / "Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
    (root / "deployment.yaml").write_text(K8S_MANIFEST, encoding="utf-8")
    (root / "package.json").write_text(
        '{"name": "bench", "dependencies": {"lodash": "4.17.11"}}\n', encoding="utf-8")
    written += 4

    return {"files": written, "python": python_files, "vulnerable": vulnerable, "noise": max(0, noise)}


def measure(target: Path) -> dict:
    gc.collect()
    config = IronCladConfig(target=str(target))
    started = time.perf_counter()
    result = run_scan(config)
    elapsed = time.perf_counter() - started

    total_bytes = sum(
        os.path.getsize(os.path.join(dirpath, name))
        for dirpath, _dirs, names in os.walk(target)
        for name in names
    )
    return {
        "files_scanned": result.stats.files_scanned,
        "files_skipped": result.stats.files_skipped,
        "lines_scanned": result.stats.lines_scanned,
        "findings": len(result.findings),
        "severity_counts": result.severity_counts(),
        "elapsed_seconds": elapsed,
        "files_per_second": result.stats.files_scanned / elapsed if elapsed > 0 else 0.0,
        "bytes": total_bytes,
        "mb_per_second": (total_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0.0,
        "peak_rss_mb": _peak_rss_mb(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tiers", default="1000,10000",
                        help="comma-separated file counts to generate and scan")
    parser.add_argument("--keep", default=None, help="write the largest corpus here instead of a temp dir")
    args = parser.parse_args()

    tiers = [int(t) for t in args.tiers.split(",") if t.strip()]
    print(f"# ironclad scale benchmark  (python {sys.version.split()[0]}, {sys.platform})")
    print(f"# tiers: {tiers}")

    for tier in tiers:
        if args.keep and tier == max(tiers):
            root = Path(args.keep)
            if root.exists():
                shutil.rmtree(root)
            cleanup = False
        else:
            root = Path(tempfile.mkdtemp(prefix=f"ironclad-bench-{tier}-"))
            cleanup = True
        try:
            shape = generate_corpus(root, tier)
            stats = measure(root)
            print(f"tier_files_requested={tier}")
            print(f"tier_files_generated={shape['files']}")
            print(f"tier_python_modules={shape['python']}")
            print(f"tier_vulnerable_modules={shape['vulnerable']}")
            for key, value in stats.items():
                if isinstance(value, float):
                    print(f"{key}={value:.3f}")
                else:
                    print(f"{key}={value}")
            print("---")
        finally:
            if cleanup:
                shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
