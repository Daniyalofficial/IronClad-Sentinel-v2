"""
JUnit XML report generator.

Nearly every CI system (Jenkins, GitLab CI, CircleCI, Azure Pipelines,
GitHub Actions test-reporter action) can natively render JUnit XML as a
test-results panel with pass/fail counts and inline annotations. Mapping
each rule into a synthetic "test class" makes IronClad Sentinel's output
show up as first-class CI test results with zero plugin installation.
"""
from __future__ import annotations

from xml.sax.saxutils import escape

from ironclad.core.models import ScanResult, Severity

FAILING_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}


def render_junit(result: ScanResult) -> str:
    findings = result.sorted_findings()
    failures = sum(1 for f in findings if f.severity in FAILING_SEVERITIES)

    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append(
        f'<testsuite name="IronCladSentinel" tests="{len(findings) if findings else 1}" '
        f'failures="{failures}" errors="0" time="{result.stats.duration_seconds}">'
    )

    if not findings:
        lines.append('  <testcase classname="IronCladSentinel" name="no_findings" time="0"/>')
    else:
        for f in findings:
            classname = escape(f"IronCladSentinel.{f.category}")
            name = escape(f"{f.rule_id}::{f.location.file_path}:{f.location.start_line}")
            lines.append(f'  <testcase classname="{classname}" name="{name}" time="0">')
            if f.severity in FAILING_SEVERITIES:
                message = escape(f.title)
                body = escape(f"{f.description}\n\nRemediation: {f.remediation}")
                lines.append(f'    <failure message="{message}" type="{f.severity.value}">{body}</failure>')
            lines.append('  </testcase>')

    lines.append('</testsuite>')
    return "\n".join(lines)
