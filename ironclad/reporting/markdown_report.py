"""Markdown report generator, ideal for posting as a PR/MR comment in CI."""
from __future__ import annotations

from ironclad.core.models import ScanResult, Severity

SEVERITY_EMOJI = {
    Severity.CRITICAL: "\U0001F534",
    Severity.HIGH: "\U0001F7E0",
    Severity.MEDIUM: "\U0001F7E1",
    Severity.LOW: "\U0001F535",
    Severity.INFO: "\u26AA",
}


def render_markdown(result: ScanResult, max_findings: int = 50) -> str:
    counts = result.severity_counts()
    lines = []
    lines.append(f"# \U0001F6E1\uFE0F IronClad Sentinel Scan Report")
    lines.append("")
    lines.append(f"**Target:** `{result.target}`  ")
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
            f"| {SEVERITY_EMOJI[f.severity]} {f.severity.value} | `{f.rule_id}` | "
            f"`{f.location.file_path}` | {f.location.start_line} | {f.title} |"
        )

    remaining = len(result.findings) - max_findings
    if remaining > 0:
        lines.append("")
        lines.append(f"_...and {remaining} more findings. See the full JSON/HTML report for details._")

    lines.append("")
    lines.append("---")
    lines.append("*Generated entirely offline by IronClad Sentinel -- no source code left this machine.*")
    return "\n".join(lines)
