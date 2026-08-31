"""Markdown report generator, ideal for posting as a PR/MR comment in CI."""
from __future__ import annotations

import re

from ironclad.core.models import ScanResult, Severity

SEVERITY_EMOJI = {
    Severity.CRITICAL: "\U0001F534",
    Severity.HIGH: "\U0001F7E0",
    Severity.MEDIUM: "\U0001F7E1",
    Severity.LOW: "\U0001F535",
    Severity.INFO: "\u26AA",
}




_BACKTICK_RUN = re.compile(r"`+")


def md_code(value: object) -> str:
    """Wrap a value in a Markdown code span that its own content cannot escape.

    The naive form -- a single backtick either side -- is breakable: a scanned
    file named ``a`<img src=x onerror=alert(9)>.py`` closes the span with its
    own backtick and the rest renders as live HTML in any Markdown-to-HTML
    viewer (a CI job posting this report as a PR comment, for example).
    CommonMark's rule is that a code span is delimited by a run of backticks
    longer than any run inside it, so that is what this emits.
    """
    text = str(value)
    longest = max((len(run) for run in _BACKTICK_RUN.findall(text)), default=0)
    fence = "`" * (longest + 1)
    if text[:1] in {"`", " "} or text[-1:] in {"`", " "}:
        # A space is needed so a leading/trailing backtick is not swallowed.
        return f"{fence} {text} {fence}"
    return f"{fence}{text}{fence}"


def md_text(value: object) -> str:
    """Neutralise a value used as plain Markdown prose.

    Finding titles embed data taken from the scanned repository (a dependency
    finding's title contains the package name from the manifest), so they are
    not trusted. Raw ``<`` would be live HTML in a rendered view, and a ``|``
    would break the table row.
    """
    return (str(value)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("|", "\\|"))


def render_markdown(result: ScanResult, max_findings: int = 50) -> str:
    counts = result.severity_counts()
    lines = []
    lines.append(f"# \U0001F6E1\uFE0F IronClad Sentinel Scan Report")
    lines.append("")
    lines.append(f"**Target:** {md_code(result.target)}  ")
    lines.append(f"**Grade:** `{result.grade()}`  **Risk Score:** `{result.risk_score()}`  ")
    lines.append(f"**Files scanned:** {result.stats.files_scanned}  **Duration:** {result.stats.duration_seconds}s")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in Severity:
        lines.append(f"| {SEVERITY_EMOJI[sev]} {sev.value.title()} | {counts[sev.value]} |")
    lines.append("")

    if result.baseline_suppressed:
        lines.append(f"_{result.baseline_suppressed} previously-baselined findings were suppressed from this view._")
        lines.append("")

    if not result.findings:
        lines.append("No findings. \u2705")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    lines.append("| Severity | Rule | File | Line | Title |")
    lines.append("|---|---|---|---|---|")
    for f in result.sorted_findings()[:max_findings]:
        lines.append(
            f"| {SEVERITY_EMOJI[f.severity]} {f.severity.value} | {md_code(f.rule_id)} | "
            f"{md_code(f.location.file_path)} | {f.location.start_line} | {md_text(f.title)} |"
        )

    remaining = len(result.findings) - max_findings
    if remaining > 0:
        lines.append("")
        lines.append(f"_...and {remaining} more findings. See the full JSON/HTML report for details._")

    lines.append("")
    lines.append("---")
    lines.append("*Generated entirely offline by IronClad Sentinel -- no source code left this machine.*")
    return "\n".join(lines)
