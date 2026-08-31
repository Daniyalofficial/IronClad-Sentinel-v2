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


_ATTR_ENTITIES = {'"': "&quot;", "'": "&apos;"}


def _attr(value: str) -> str:
    """Escape a value for use inside a double-quoted XML attribute.

    ``xml.sax.saxutils.escape`` alone is not enough: it covers ``& < >`` but
    not the quote characters, so a scanned file named
    ``a" onmouseover="alert(1).py`` broke out of the ``name`` attribute and
    injected a live event-handler attribute into the document. Escaping is
    done explicitly rather than with ``quoteattr`` so the delimiter is always
    a double quote -- some consumers of JUnit XML mishandle single-quoted
    attributes.
    """
    return escape(str(value), _ATTR_ENTITIES)


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
            classname = _attr(f"IronCladSentinel.{f.category}")
            name = _attr(f"{f.rule_id}::{f.location.file_path}:{f.location.start_line}")
            lines.append(f'  <testcase classname="{classname}" name="{name}" time="0">')
            if f.severity in FAILING_SEVERITIES:
                message = _attr(f.title)
                severity = _attr(f.severity.value)
                body = escape(f"{f.description}\n\nRemediation: {f.remediation}")
                lines.append(f'    <failure message="{message}" type="{severity}">{body}</failure>')
            lines.append('  </testcase>')

    lines.append('</testsuite>')
    return "\n".join(lines)
