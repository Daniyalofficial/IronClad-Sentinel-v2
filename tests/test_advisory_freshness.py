"""Release-time bundled advisory age and upstream-head gate.

These tests never assert that a committed snapshot remains fresh forever:
that check must be rerun when creating a release, not in a timeless suite.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from scripts.check_advisory_freshness import FreshnessError, inspect_snapshot

NOW = datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone.utc)
GH = "a" * 40
PYPA = "b" * 40


def _snapshot(path, built_at, sources=None):
    payload = {"_meta": {"generated_at": built_at,
                         "sources": sources if sources is not None else [
                             f"github/advisory-database@{GH[:12]} + "
                             f"pypa/advisory-database@{PYPA[:12]}"]},
               "python": {}}
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_snapshot_age_and_both_pinned_source_heads_are_checked(tmp_path):
    path = _snapshot(tmp_path / "fresh.json", (NOW - timedelta(hours=23)).isoformat())
    report = inspect_snapshot(path, now=NOW, upstream_heads={
        "github/advisory-database": GH, "pypa/advisory-database": PYPA,
    })
    assert report.age_hours == 23
    assert report.heads_verified is True
    assert report.sources["github/advisory-database"] == GH[:12]


@pytest.mark.parametrize("build_time", [
    (NOW - timedelta(hours=24, seconds=1)).isoformat(),
    (NOW + timedelta(minutes=6)).isoformat(),
    "not-a-timestamp",
    "",
])
def test_missing_future_or_old_snapshot_fails_closed(tmp_path, build_time):
    path = _snapshot(tmp_path / "stale.json", build_time)
    with pytest.raises(FreshnessError):
        inspect_snapshot(path, now=NOW, upstream_heads={
            "github/advisory-database": GH, "pypa/advisory-database": PYPA,
        })


def test_release_refuses_pinned_feed_when_newer_commit_exists(tmp_path):
    path = _snapshot(tmp_path / "behind.json", NOW.isoformat())
    with pytest.raises(FreshnessError, match="behind"):
        inspect_snapshot(path, now=NOW, upstream_heads={
            "github/advisory-database": "c" * 40, "pypa/advisory-database": PYPA,
        })


def test_missing_feed_is_not_a_fresh_complete_snapshot(tmp_path):
    path = _snapshot(tmp_path / "partial.json", NOW.isoformat(),
                     sources=[f"github/advisory-database@{GH[:12]}"])
    with pytest.raises(FreshnessError, match="both"):
        inspect_snapshot(path, now=NOW)


def test_offline_age_check_is_explicitly_not_upstream_verified(tmp_path):
    path = _snapshot(tmp_path / "offline.json", NOW.isoformat())
    report = inspect_snapshot(path, now=NOW)
    assert report.age_hours == 0 and report.heads_verified is False
