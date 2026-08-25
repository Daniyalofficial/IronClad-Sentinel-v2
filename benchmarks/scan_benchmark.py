"""Small deterministic benchmark for IronClad scan throughput.

Usage: python benchmarks/scan_benchmark.py [path]
The benchmark reports wall-clock time and files scanned; it is a measurement
helper, not a performance gate with a machine-specific hard limit.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

from ironclad.core.config import IronCladConfig
from ironclad.core.engine import run_scan


def main() -> int:
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/security_corpus").resolve()
    config = IronCladConfig(target=str(target))
    started = time.perf_counter()
    result = run_scan(config)
    elapsed = time.perf_counter() - started
    files = result.stats.files_scanned
    rate = files / elapsed if elapsed > 0 else 0.0
    print(f"benchmark_target={target}")
    print(f"files_scanned={files}")
    print(f"findings={len(result.findings)}")
    print(f"elapsed_seconds={elapsed:.4f}")
    print(f"files_per_second={rate:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
