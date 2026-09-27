#!/usr/bin/env python3
"""Fail a release when its offline advisory snapshot is old or behind its feeds.

    python scripts/check_advisory_freshness.py
    python scripts/check_advisory_freshness.py --offline  # age only; NOT a release gate

The default checks *both* the build timestamp and the currently published Git
heads for the two independently maintained feeds. No live network request is
made by the product's scanners; this is a release-time operator check.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Optional

DEFAULT_DB = Path(__file__).resolve().parents[1] / "ironclad" / "data" / "vuln_db.json"
SOURCE_REPOS = {
    "github/advisory-database": "https://github.com/github/advisory-database.git",
    "pypa/advisory-database": "https://github.com/pypa/advisory-database.git",
}
SOURCE_PATTERN = re.compile(r"(?P<repo>github/advisory-database|pypa/advisory-database)@(?P<sha>[0-9a-f]{12,40})\b")


class FreshnessError(ValueError):
    """The snapshot cannot establish freshness at release time."""


@dataclass(frozen=True)
class SnapshotReport:
    age_hours: float
    generated_at: datetime
    sources: dict
    heads_verified: bool


def inspect_snapshot(path: Path, *, now: Optional[datetime] = None,
                     max_age_hours: float = 24.0,
                     upstream_heads: Optional[Mapping[str, str]] = None) -> SnapshotReport:
    if max_age_hours <= 0:
        raise ValueError("max_age_hours must be positive")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    try:
        with open(path, encoding="utf-8") as fh:
            metadata = json.load(fh)["_meta"]
        raw_date = metadata["generated_at"]
        if not isinstance(raw_date, str) or not raw_date:
            raise ValueError("no build timestamp")
        built_at = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
        if built_at.tzinfo is None:
            raise ValueError("build timestamp has no timezone")
        labels = metadata["sources"]
        if not isinstance(labels, list) or len(labels) != 1 or not isinstance(labels[0], str):
            raise ValueError("ambiguous feed provenance")
        found = SOURCE_PATTERN.findall(labels[0])
        sources = dict(found)
        if len(found) != 2 or set(sources) != set(SOURCE_REPOS):
            raise FreshnessError("snapshot must pin both GHSA and PyPA source commits")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, FreshnessError):
            raise
        raise FreshnessError("missing or invalid snapshot provenance/timestamp") from exc

    age = (now - built_at).total_seconds() / 3600
    if age < -5 / 60:
        raise FreshnessError("snapshot build timestamp is in the future")
    if age > max_age_hours:
        raise FreshnessError(f"snapshot is {age:.2f}h old (limit {max_age_hours:.2f}h)")
    if upstream_heads is not None:
        for repo, pinned in sources.items():
            published = upstream_heads.get(repo, "")
            if not re.fullmatch(r"[0-9a-f]{40}", published):
                raise FreshnessError(f"current upstream head for {repo} was not verified")
            if not published.startswith(pinned):
                raise FreshnessError(f"snapshot is behind {repo}: pinned {pinned}, head {published[:12]}")
    return SnapshotReport(age_hours=max(age, 0), generated_at=built_at,
                          sources=sources, heads_verified=upstream_heads is not None)


def upstream_heads() -> dict:
    heads = {}
    for repo, url in SOURCE_REPOS.items():
        try:
            process = subprocess.run(["git", "ls-remote", "--exit-code", url, "HEAD"],
                                     check=True, capture_output=True, text=True, timeout=30)
            heads[repo] = process.stdout.split()[0]
        except (subprocess.SubprocessError, OSError, IndexError) as exc:
            raise FreshnessError(f"cannot verify current upstream head of {repo}") from exc
    return heads


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--max-age-hours", type=float, default=24.0)
    parser.add_argument("--offline", action="store_true",
                        help="only check age (not enough to certify a release)")
    args = parser.parse_args(argv)
    try:
        report = inspect_snapshot(args.db, max_age_hours=args.max_age_hours,
                                  upstream_heads=None if args.offline else upstream_heads())
    except FreshnessError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"Snapshot built {report.generated_at.isoformat()} ({report.age_hours:.2f}h old)")
    for repo, sha in report.sources.items():
        print(f"  {repo}@{sha}")
    if not report.heads_verified:
        print("PARTIAL: upstream heads not checked; do not certify release from this result")
    else:
        print("PASS: snapshot within age limit and both upstream heads match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
