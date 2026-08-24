"""
Core data models shared across every scanning engine in IronClad Sentinel.

Keeping a single canonical `Finding` representation means every engine
(AST analyzer, rule engine, secrets detector, dependency matcher, IaC
scanner) can feed into the same de-duplication, baseline-diff, scoring,
and reporting pipeline without special-casing.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]

    @property
    def rank(self) -> int:
        # Lower rank = more severe. Useful for sorting.
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        return order.index(self)


class Engine(str, Enum):
    AST_PYTHON = "ast-python"
    RULE_ENGINE = "rule-engine"
    SECRETS = "secrets"
    DEPENDENCY = "dependency"
    IAC = "iac"
    LICENSE = "license-compliance"


@dataclass
class CodeLocation:
    file_path: str
    start_line: int
    end_line: int = 0
    start_col: int = 0
    end_col: int = 0
    snippet: str = ""

    def __post_init__(self):
        if self.end_line == 0:
            self.end_line = self.start_line

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_col": self.start_col,
            "end_col": self.end_col,
            "snippet": self.snippet,
        }


@dataclass
class Finding:
    """
    A single normalized security finding produced by any engine.

    `fingerprint` is a stable content-hash used for:
      - de-duplication across engines/rules
      - baseline diffing (suppress known/accepted findings across runs)
      - stable finding IDs across re-scans even if line numbers shift a bit
    """
    rule_id: str
    title: str
    description: str
    severity: Severity
    engine: Engine
    location: CodeLocation
    category: str = "general"
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    confidence: str = "medium"  # low | medium | high
    extra: Dict[str, Any] = field(default_factory=dict)
    fingerprint: str = field(default="", init=True)

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def compute_fingerprint(self) -> str:
        """
        Stable hash based on rule id, file, normalized code snippet, and
        category -- deliberately *not* based on exact line number so that
        a finding survives minor file edits above it (unlike naive
        line-based dedupe used by weaker scanners).
        """
        normalized_snippet = "".join(self.location.snippet.split())
        basis = "|".join([
            self.rule_id,
            self.location.file_path,
            normalized_snippet[:400],
            self.category,
        ])
        return hashlib.sha256(basis.encode("utf-8", errors="ignore")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "engine": self.engine.value,
            "category": self.category,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "remediation": self.remediation,
            "references": self.references,
            "confidence": self.confidence,
            "location": self.location.to_dict(),
            "extra": self.extra,
        }


@dataclass
class ScanStats:
    files_scanned: int = 0
    files_skipped: int = 0
    lines_scanned: int = 0
    duration_seconds: float = 0.0
    engines_run: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "lines_scanned": self.lines_scanned,
            "duration_seconds": round(self.duration_seconds, 3),
            "engines_run": self.engines_run,
        }


@dataclass
class ScanResult:
    target: str
    findings: List[Finding]
    stats: ScanStats
    new_findings: List[Finding] = field(default_factory=list)
    baseline_suppressed: int = 0
    generated_at: float = field(default_factory=time.time)
    tool_version: str = "1.0.0"

    def severity_counts(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def risk_score(self) -> int:
        """
        Weighted composite risk score (0-100+, uncapped internally but
        displayed capped at 100 in reports). Lets an enterprise set a
        single CI gate threshold instead of juggling per-severity counts.
        """
        raw = sum(f.severity.weight for f in self.findings)
        return raw

    def risk_score_capped(self) -> int:
        return min(100, self.risk_score())

    def grade(self) -> str:
        score = self.risk_score()
        if score == 0:
            return "A+"
        if score <= 10:
            return "A"
        if score <= 25:
            return "B"
        if score <= 50:
            return "C"
        if score <= 90:
            return "D"
        return "F"

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (f.severity.rank, f.location.file_path, f.location.start_line))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "IronClad Sentinel",
            "tool_version": self.tool_version,
            "target": self.target,
            "generated_at": self.generated_at,
            "stats": self.stats.to_dict(),
            "risk_score": self.risk_score(),
            "risk_score_capped": self.risk_score_capped(),
            "grade": self.grade(),
            "severity_counts": self.severity_counts(),
            "baseline_suppressed": self.baseline_suppressed,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)
