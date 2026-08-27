"""Baseline management for suppressing already-triaged findings.

Real codebases scanned for the first time often surface hundreds of
pre-existing issues. Forcing a team to fix all of them before they can
turn on CI gating is how security tools get disabled in week one.
Instead, IronClad Sentinel supports baselining: snapshot the current
findings, commit that file, and future scans only gate on NEW findings.

Schema v2 (current)
-------------------
Each baselined finding is stored as an *entry* rather than a bare
fingerprint, which is what makes the feature auditable instead of a
blanket "ignore everything" switch:

    {
      "schema_version": 2,
      "generated_at": "2026-01-01T00:00:00Z",
      "tool": "IronClad Sentinel",
      "tool_version": "1.1.0",
      "entries": [
        {
          "fingerprint": "9c1f...",
          "rule_id": "PY-AST-SQL-INJECTION",
          "file": "app/db.py",
          "line": 42,
          "severity": "critical",
          "reason": "TICKET-1234 tracked; internal admin tool",
          "created_at": "2026-01-01T00:00:00Z",
          "expires_at": "2026-07-01T00:00:00Z",
          "created_by": "ci@example.com"
        }
      ]
    }

Abuse prevention
----------------
* Entries **expire**. ``ironclad baseline create --expires-in-days N``
  stamps every entry, and an expired entry stops suppressing -- the
  finding resurfaces and gates CI again. A baseline is a runway, not a
  permanent waiver.
* ``ironclad baseline prune`` removes entries whose findings no longer
  exist, so the file cannot silently grow into a blanket suppression list.
* ``ironclad baseline create`` refuses to run without ``--force`` when it
  would baseline critical findings without a reason, and records
  ``created_by`` so a reviewer can see who accepted the debt.

Schema v1 files (a flat ``fingerprints`` list) are still readable; they
are treated as non-expiring entries and reported as legacy by
``ironclad baseline list``.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ironclad import __version__
from ironclad.core.models import Finding

SCHEMA_VERSION = 2
ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _format_ts(value: Optional[datetime]) -> Optional[str]:
    return value.strftime(ISO_FORMAT) if value else None


def _parse_ts(value) -> Optional[datetime]:
    """Parse a timestamp written by any IronClad version.

    v1 baselines stored ``generated_at`` as an epoch float from
    ``time.time()``; v2 stores an ISO-8601 UTC string. Both are accepted.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    try:
        parsed = datetime.strptime(str(value), ISO_FORMAT)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass
class BaselineEntry:
    fingerprint: str
    rule_id: str = ""
    file: str = ""
    line: int = 0
    severity: str = ""
    reason: str = ""
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_by: str = ""

    @classmethod
    def from_finding(cls, finding: Finding, *, reason: str = "", expires_at: Optional[datetime] = None,
                     created_by: str = "", created_at: Optional[datetime] = None) -> "BaselineEntry":
        return cls(
            fingerprint=finding.fingerprint,
            rule_id=finding.rule_id,
            file=finding.location.file_path,
            line=finding.location.start_line,
            severity=finding.severity.value,
            reason=reason,
            created_at=created_at or _utcnow(),
            expires_at=expires_at,
            created_by=created_by,
        )

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        return bool(self.expires_at and self.expires_at <= (now or _utcnow()))

    def to_dict(self) -> Dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "severity": self.severity,
            "reason": self.reason,
            "created_at": _format_ts(self.created_at),
            "expires_at": _format_ts(self.expires_at),
            "created_by": self.created_by,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "BaselineEntry":
        return cls(
            fingerprint=str(data.get("fingerprint", "")),
            rule_id=str(data.get("rule_id", "")),
            file=str(data.get("file", "")),
            line=int(data.get("line") or 0),
            severity=str(data.get("severity", "")),
            reason=str(data.get("reason", "")),
            created_at=_parse_ts(data.get("created_at")),  # type: ignore[arg-type]
            expires_at=_parse_ts(data.get("expires_at")),  # type: ignore[arg-type]
            created_by=str(data.get("created_by", "")),
        )


@dataclass
class Baseline:
    entries: List[BaselineEntry] = field(default_factory=list)
    generated_at: Optional[datetime] = None
    tool_version: str = __version__
    source_path: Optional[str] = None
    schema_version: int = SCHEMA_VERSION
    legacy: bool = False

    # ------------------------------------------------------------- loading
    @classmethod
    def load(cls, path: Optional[str]) -> "Baseline":
        if not path or not os.path.isfile(path):
            return cls()
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError(f"baseline {path} must contain a JSON object")
        generated_at = _parse_ts(data.get("generated_at"))
        raw_entries = data.get("entries")
        if raw_entries is None and isinstance(data.get("fingerprints"), list):
            # Schema v1: flat fingerprint list.
            entries = [BaselineEntry(fingerprint=str(fp)) for fp in data["fingerprints"]]
            return cls(entries=entries, generated_at=generated_at,
                       tool_version=str(data.get("tool_version", "1.0.0")),
                       source_path=path, schema_version=1, legacy=True)
        if raw_entries is None:
            raise ValueError(f"baseline {path} has neither 'entries' nor 'fingerprints'")
        entries = [BaselineEntry.from_dict(e) for e in raw_entries if isinstance(e, dict)]
        return cls(entries=entries, generated_at=generated_at,
                   tool_version=str(data.get("tool_version", "1.0.0")),
                   source_path=path, schema_version=int(data.get("schema_version", SCHEMA_VERSION)))

    # ------------------------------------------------------------- helpers
    def active_fingerprints(self, now: Optional[datetime] = None) -> Set[str]:
        return {e.fingerprint for e in self.entries if not e.is_expired(now)}

    def expired_entries(self, now: Optional[datetime] = None) -> List[BaselineEntry]:
        return [e for e in self.entries if e.is_expired(now)]

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": "IronClad Sentinel",
            "tool_version": self.tool_version,
            "generated_at": _format_ts(self.generated_at or _utcnow()),
            "count": len(self.entries),
            "entries": sorted(
                (e.to_dict() for e in self.entries),
                key=lambda d: (str(d["file"]), str(d["rule_id"]), str(d["fingerprint"])),
            ),
        }

    def save(self, path: str) -> str:
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, sort_keys=False)
            fh.write("\n")
        self.source_path = path
        return path


# --------------------------------------------------------------------------- #
# Construction & diffing
# --------------------------------------------------------------------------- #
def create_baseline(
    findings: List[Finding],
    *,
    reason: str = "",
    expires_in_days: Optional[int] = None,
    created_by: str = "",
    require_reason_for: Iterable[str] = ("critical",),
    force: bool = False,
    now: Optional[datetime] = None,
) -> Baseline:
    """Build a baseline from a finding set.

    Refuses (raises ``BaselineError``) when a critical finding would be
    baselined without an explicit reason unless ``force=True`` -- the one
    guard rail that keeps baselines from becoming a "mute everything" file.
    """
    now = now or _utcnow()
    expires_at = now + timedelta(days=expires_in_days) if expires_in_days else None
    require = {s.lower() for s in require_reason_for}
    if not reason and not force:
        unreasoned = [f for f in findings if f.severity.value in require]
        if unreasoned:
            raise BaselineError(
                f"refusing to baseline {len(unreasoned)} {sorted(require)} finding(s) without --reason "
                f"(use --force to override). Example rule IDs: "
                f"{sorted({f.rule_id for f in unreasoned})[:5]}"
            )
    entries = [
        BaselineEntry.from_finding(f, reason=reason, expires_at=expires_at,
                                   created_by=created_by, created_at=now)
        for f in findings
    ]
    # De-duplicate on fingerprint, keeping the first occurrence (findings are
    # already de-duplicated by the engine, but be defensive).
    seen: Set[str] = set()
    unique: List[BaselineEntry] = []
    for entry in entries:
        if entry.fingerprint in seen:
            continue
        seen.add(entry.fingerprint)
        unique.append(entry)
    return Baseline(entries=unique, generated_at=now)


class BaselineError(RuntimeError):
    """Raised when a baseline operation is refused for safety reasons."""


@dataclass
class BaselineDiff:
    new: List[Finding] = field(default_factory=list)
    suppressed: List[Finding] = field(default_factory=list)
    expired: List[Finding] = field(default_factory=list)
    fixed: List[BaselineEntry] = field(default_factory=list)

    @property
    def suppressed_count(self) -> int:
        return len(self.suppressed)


def diff_baseline(findings: List[Finding], baseline: Baseline,
                  now: Optional[datetime] = None) -> BaselineDiff:
    """Split findings into new / suppressed / resurfaced-after-expiry.

    Also reports baselined entries whose finding no longer appears, so
    ``ironclad baseline prune`` can shrink the file.
    """
    now = now or _utcnow()
    active = baseline.active_fingerprints(now)
    expired = {e.fingerprint for e in baseline.expired_entries(now)}
    diff = BaselineDiff()
    present: Set[str] = set()
    for finding in findings:
        present.add(finding.fingerprint)
        if finding.fingerprint in active:
            diff.suppressed.append(finding)
        elif finding.fingerprint in expired:
            # Was accepted, acceptance lapsed: treat as new so CI re-gates.
            diff.expired.append(finding)
            diff.new.append(finding)
        else:
            diff.new.append(finding)
    diff.fixed = [e for e in baseline.entries if e.fingerprint not in present]
    return diff


def prune_baseline(baseline: Baseline, findings: List[Finding]) -> Tuple[Baseline, int]:
    present = {f.fingerprint for f in findings}
    kept = [e for e in baseline.entries if e.fingerprint in present]
    removed = len(baseline.entries) - len(kept)
    return Baseline(entries=kept, generated_at=baseline.generated_at,
                    tool_version=baseline.tool_version, source_path=baseline.source_path), removed


# --------------------------------------------------------------------------- #
# Backwards-compatible helpers used by the engine
# --------------------------------------------------------------------------- #
def load_baseline_fingerprints(path: Optional[str]) -> Set[str]:
    """Active (non-expired) fingerprints from a baseline file.

    Returns an empty set for a missing file. A malformed file raises rather
    than silently behaving like "no baseline", because silently re-gating a
    whole backlog (or silently suppressing it) are both bad outcomes that
    an operator must see.
    """
    return Baseline.load(path).active_fingerprints()


def write_baseline(path: str, findings: List[Finding], **kwargs) -> str:
    """Write a baseline file from a finding list (v1-compatible signature)."""
    return create_baseline(findings, **kwargs).save(path)


def apply_baseline(findings: List[Finding], baseline_fingerprints: Set[str]):
    """Legacy tuple API: (kept_findings, suppressed_count)."""
    if not baseline_fingerprints:
        return findings, 0
    kept = [f for f in findings if f.fingerprint not in baseline_fingerprints]
    return kept, len(findings) - len(kept)
