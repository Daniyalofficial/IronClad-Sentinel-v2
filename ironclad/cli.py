"""
IronClad Sentinel command-line interface.

Usage examples:
    ironclad scan .
    ironclad scan ./my-service --format json,html,sarif --fail-on high
    ironclad scan . --baseline .ironclad/baseline.json --update-baseline
    ironclad sbom . --out sbom.json
    ironclad license status
    ironclad license verify --license-file ./license.json

This is the single binary/entry-point a customer runs entirely on their
own infrastructure. Nothing in this module makes a network call.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import List, Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from ironclad import __version__
from ironclad.core.config import IronCladConfig
from ironclad.core.engine import run_scan
from ironclad.core.models import Severity
from ironclad.licensing.keygen import find_license_file, verify_license
from ironclad.reporting import write_reports
from ironclad.scanners.sbom import build_sbom
from ironclad.core.walker import discover
from ironclad.core.baseline import write_baseline

console = Console()

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "cyan",
    "info": "dim",
}

TRIAL_GRACE_ENGINES = ["ast-python", "rule-engine", "secrets"]  # what runs unlicensed


def _print_banner():
    console.print(Panel.fit(
        f"[bold indigo1]IronClad Sentinel[/] [dim]v{__version__}[/]\n"
        f"[dim]Offline Application Security Scanning -- zero telemetry, zero network calls[/]",
        border_style="bright_blue",
    ))


def _check_license_and_warn(license_file: Optional[str]) -> bool:
    """Returns True if fully licensed; prints a status line either way and
    never blocks execution outright for the free/trial engine subset --
    the CLI still *runs* without a license (trial-limited engines only),
    which lowers friction for evaluation while creating a natural
    upgrade path for full-engine + CI-integration usage."""
    status = verify_license(license_file)
    if status.valid:
        console.print(f"[green]\u2713[/] Licensed to [bold]{status.terms.customer}[/] "
                       f"([bold]{status.terms.tier}[/] tier, {status.days_remaining} days remaining)")
        return True
    else:
        console.print(f"[yellow]\u26A0 Running in TRIAL mode[/] ({status.reason})")
        console.print("[dim]  Trial mode runs the AST + rule-engine + secrets scanners only. "
                       "Full license unlocks dependency/IaC/license-compliance engines, "
                       "unlimited scan size, and CI report formats (SARIF/JUnit).[/]")
        return False


@click.group()
@click.version_option(version=__version__, prog_name="IronClad Sentinel")
def main():
    """IronClad Sentinel -- offline, self-hosted application security scanning."""
    pass


@main.command()
@click.argument("target", default=".")
@click.option("--format", "formats", default="json", help="Comma-separated report formats: json,sarif,html,markdown,junit")
@click.option("--output-dir", default=".ironclad/reports", help="Directory to write reports into")
@click.option("--min-severity", default="info", type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--fail-on", default=None, type=click.Choice(["critical", "high", "medium", "low"]), help="Exit non-zero if any finding at/above this severity is present")
@click.option("--max-risk-score", default=None, type=int, help="Exit non-zero if the composite risk score exceeds this value")
@click.option("--baseline", "baseline_file", default=None, help="Path to a baseline file; findings already present there are suppressed from gating")
@click.option("--update-baseline", is_flag=True, help="Write current findings as the new baseline instead of gating on them")
@click.option("--ignore-rule", "ignore_rules", multiple=True, help="Rule ID to ignore (repeatable)")
@click.option("--license-file", default=None, help="Path to license.json (defaults to standard search paths)")
@click.option("--quiet", is_flag=True, help="Only print the final summary table")
def scan(target, formats, output_dir, min_severity, fail_on, max_risk_score, baseline_file,
          update_baseline, ignore_rules, license_file, quiet):
    """Run a full security scan against TARGET (default: current directory)."""
    if not quiet:
        _print_banner()

    licensed = _check_license_and_warn(license_file)

    overrides = {
        "min_severity": min_severity,
        "ignore_rule_ids": list(ignore_rules),
        "baseline_file": baseline_file,
        "report_formats": [f.strip() for f in formats.split(",") if f.strip()],
        "output_dir": output_dir,
    }
    if not licensed:
        overrides["enabled_engines"] = TRIAL_GRACE_ENGINES

    config = IronCladConfig.load(target, overrides)

    def progress(msg):
        if not quiet:
            console.print(f"[dim]\u2192[/] {msg}")

    result = run_scan(config, progress_callback=progress)

    if update_baseline:
        baseline_path = baseline_file or os.path.join(output_dir, "baseline.json")
        write_baseline(baseline_path, result.findings)
        console.print(f"[green]\u2713[/] Baseline written to {baseline_path} ({len(result.findings)} findings recorded)")

    written = write_reports(result, config.report_formats, output_dir)

    _print_summary_table(result)

    for fmt, path in written.items():
        console.print(f"[dim]  report ({fmt}):[/] {path}")

    exit_code = _compute_exit_code(result, fail_on, max_risk_score)
    sys.exit(exit_code)


def _print_summary_table(result):
    counts = result.severity_counts()
    table = Table(box=box.ROUNDED, title=f"Scan Summary -- Grade {result.grade()} -- Risk Score {result.risk_score()}")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in ["critical", "high", "medium", "low", "info"]:
        table.add_row(f"[{SEVERITY_STYLE[sev]}]{sev.upper()}[/]", str(counts[sev]))
    console.print(table)
    console.print(f"Files scanned: [bold]{result.stats.files_scanned}[/]  "
                   f"Skipped: {result.stats.files_skipped}  "
                   f"Duration: {result.stats.duration_seconds:.2f}s")
    if result.baseline_suppressed:
        console.print(f"[dim]{result.baseline_suppressed} finding(s) suppressed by baseline[/]")


def _compute_exit_code(result, fail_on: Optional[str], max_risk_score: Optional[int]) -> int:
    if max_risk_score is not None and result.risk_score() > max_risk_score:
        console.print(f"[bold red]FAIL[/]: risk score {result.risk_score()} exceeds threshold {max_risk_score}")
        return 1
    if fail_on:
        threshold = Severity(fail_on)
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        min_rank = order.index(threshold)
        offending = [f for f in result.findings if order.index(f.severity) >= min_rank]
        if offending:
            console.print(f"[bold red]FAIL[/]: {len(offending)} finding(s) at or above severity '{fail_on}'")
            return 1
    return 0


@main.command()
@click.argument("target", default=".")
@click.option("--out", default="sbom.json")
@click.option("--project-name", default=None)
def sbom(target, out, project_name):
    """Generate a CycloneDX SBOM for TARGET from discovered dependency manifests."""
    config = IronCladConfig.load(target, {})
    fileset = discover(config)
    name = project_name or os.path.basename(os.path.abspath(target))
    doc = build_sbom(fileset.dependency_manifests(), project_name=name)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    console.print(f"[green]\u2713[/] SBOM written to {out} ({len(doc['components'])} components)")


@main.group()
def license():
    """Manage and inspect the offline commercial license."""
    pass


@license.command("status")
@click.option("--license-file", default=None)
def license_status(license_file):
    """Show current license status."""
    status = verify_license(license_file)
    path = license_file or find_license_file() or "(none found)"
    console.print(f"License file: [dim]{path}[/]")
    if status.valid:
        console.print(f"[green]VALID[/] -- {status.terms.customer} ({status.terms.tier}), "
                       f"{status.terms.seats} seats, {status.days_remaining} days remaining, "
                       f"id={status.terms.license_id}")
    else:
        console.print(f"[yellow]NOT LICENSED[/] -- {status.reason}")


if __name__ == "__main__":
    main()
