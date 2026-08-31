"""
IronClad Sentinel command-line interface.

Usage examples:
    ironclad scan .
    ironclad scan ./my-service --format json,html,sarif --fail-on high
    ironclad scan . --policy policy.yaml
    ironclad baseline create . --out .ironclad/baseline.json --reason TICKET-1234
    ironclad sbom . --out sbom.json --format cyclonedx
    ironclad policy validate policy.yaml
    ironclad doctor

This is the single binary/entry-point a customer runs entirely on their
own infrastructure. Nothing in this module makes a network call.

Exit codes are stable and documented in `ironclad/core/exit_codes.py`.
"""
from __future__ import annotations

import json
import os
import sys
import traceback
from typing import Dict, List, Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from ironclad import __version__
from ironclad.core import exit_codes as ec
from ironclad.core.baseline import (
    Baseline,
    BaselineError,
    create_baseline,
    diff_baseline,
    prune_baseline,
)
from ironclad.core.config import IronCladConfig
from ironclad.core.engine import run_scan
from ironclad.core.models import ScanResult, Severity
from ironclad.core.policy import (
    Policy,
    PolicyError,
    evaluate_policy,
    write_example_policy,
)
from ironclad.core.walker import discover
from ironclad.licensing.keygen import find_license_file, verify_license
from ironclad.reporting import write_reports
from ironclad.scanners.sbom import build_sbom

console = Console()
err_console = Console(stderr=True)

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


def _die(message: str, code: int) -> None:
    err_console.print(f"[bold red]error[/]: {message}")
    sys.exit(code)


def _check_license_and_warn(license_file: Optional[str], quiet: bool = False) -> bool:
    """Returns True if fully licensed; prints a status line either way and
    never blocks execution outright for the free/trial engine subset --
    the CLI still *runs* without a license (trial-limited engines only),
    which lowers friction for evaluation while creating a natural
    upgrade path for full-engine + CI-integration usage."""
    status = verify_license(license_file)
    if quiet:
        return status.valid
    if status.valid:
        console.print(f"[green]\u2713[/] Licensed to [bold]{status.terms.customer}[/] "
                      f"([bold]{status.terms.tier}[/] tier, {status.days_remaining} days remaining)")
        return True
    console.print(f"[yellow]\u26A0 Running in TRIAL mode[/] ({status.reason})")
    console.print("[dim]  Trial mode runs the AST + rule-engine + secrets scanners only. "
                  "Full license unlocks dependency/IaC/license-compliance engines, "
                  "unlimited scan size, and CI report formats (SARIF/JUnit).[/]")
    return False


def _load_policy_or_die(path: str) -> Policy:
    try:
        return Policy.load(path)
    except PolicyError as exc:
        err_console.print("[bold red]invalid policy:[/]")
        for problem in exc.problems:
            err_console.print(f"  - {problem}")
        sys.exit(ec.CONFIG_ERROR)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="IronClad Sentinel")
def main():
    """IronClad Sentinel -- offline, self-hosted application security scanning."""


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
@main.command()
@click.argument("target", default=".")
@click.option("--format", "formats", default="json",
              help="Comma-separated report formats: json,sarif,html,markdown,junit,cyclonedx")
@click.option("--output-dir", default=".ironclad/reports", help="Directory to write reports into")
@click.option("--min-severity", default=None,
              type=click.Choice(["critical", "high", "medium", "low", "info"]))
@click.option("--fail-on", default=None,
              type=click.Choice(["critical", "high", "medium", "low", "any", "none"]),
              help="Exit non-zero if any finding at/above this severity is present")
@click.option("--max-risk-score", default=None, type=int,
              help="Exit non-zero if the composite risk score exceeds this value")
@click.option("--policy", "policy_file", default=None,
              help="Path to an organization policy.yaml (see `ironclad policy init`)")
@click.option("--baseline", "baseline_file", default=None,
              help="Path to a baseline file; findings already present there are suppressed from gating")
@click.option("--update-baseline", is_flag=True,
              help="Write current findings as the new baseline instead of gating on them")
@click.option("--baseline-reason", default="", help="Reason recorded against every baselined finding")
@click.option("--baseline-expires-in-days", default=None, type=int,
              help="Baseline entries lapse after N days and start gating again")
@click.option("--ignore-rule", "ignore_rules", multiple=True, help="Rule ID to ignore (repeatable)")
@click.option("--license-file", default=None, help="Path to license.json (defaults to standard search paths)")
@click.option("--quiet", is_flag=True, help="Only print the final summary table")
@click.option("--json-summary", is_flag=True, help="Print a machine-readable JSON summary to stdout")
def scan(target, formats, output_dir, min_severity, fail_on, max_risk_score, policy_file,
         baseline_file, update_baseline, baseline_reason, baseline_expires_in_days,
         ignore_rules, license_file, quiet, json_summary):
    """Run a full security scan against TARGET (default: current directory)."""
    if not os.path.exists(target):
        _die(f"scan target does not exist: {target}", ec.TARGET_ERROR)

    policy = _load_policy_or_die(policy_file) if policy_file else None

    if not quiet:
        _print_banner()
    licensed = _check_license_and_warn(license_file, quiet=quiet)

    overrides = {
        "ignore_rule_ids": list(ignore_rules),
        "report_formats": [f.strip() for f in formats.split(",") if f.strip()],
        "output_dir": output_dir,
    }
    if min_severity:
        overrides["min_severity"] = min_severity
    if baseline_file:
        overrides["baseline_file"] = baseline_file
    if not licensed:
        overrides["enabled_engines"] = TRIAL_GRACE_ENGINES

    config = IronCladConfig.load(target, overrides)

    def progress(msg):
        if not quiet:
            console.print(f"[dim]\u2192[/] {msg}")

    result = run_scan(config, progress_callback=progress, policy=policy)

    if update_baseline:
        baseline_path = baseline_file or (policy.baseline_path if policy else None) \
            or os.path.join(output_dir, "baseline.json")
        try:
            baseline = create_baseline(result.findings, reason=baseline_reason,
                                       expires_in_days=baseline_expires_in_days, force=True)
        except BaselineError as exc:  # pragma: no cover - force=True bypasses
            _die(str(exc), ec.CONFIG_ERROR)
        baseline.save(baseline_path)
        console.print(f"[green]\u2713[/] Baseline written to {baseline_path} "
                      f"({len(baseline.entries)} findings recorded)")

    written = write_reports(result, config.report_formats, output_dir)

    decision = evaluate_policy(result, policy) if policy else None
    if json_summary:
        console.print_json(json.dumps({
            "summary": result.to_dict()["severity_counts"],
            "risk_score": result.risk_score(),
            "grade": result.grade(),
            "files_scanned": result.stats.files_scanned,
            "findings": len(result.findings),
            "new_findings": len(result.new_findings),
            "baseline_suppressed": result.baseline_suppressed,
            "baseline_expired": result.baseline_expired,
            "reports": written,
            "policy": decision.to_dict() if decision else None,
        }))
    else:
        _print_summary_table(result)
        if decision:
            _print_policy_decision(decision)
        for fmt, path in written.items():
            console.print(f"[dim]  report ({fmt}):[/] {path}")

    if decision:
        sys.exit(decision.exit_code)
    sys.exit(_compute_exit_code(result, fail_on, max_risk_score))


def _print_summary_table(result: ScanResult):
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
    if result.baseline_expired:
        console.print(f"[yellow]{result.baseline_expired} finding(s) resurfaced because their "
                      f"baseline acceptance expired[/]")


def _print_policy_decision(decision) -> None:
    if decision.passed:
        console.print(f"[green]POLICY PASS[/] ({decision.policy_name})")
        return
    console.print(f"[bold red]POLICY FAIL[/] ({decision.policy_name}) -- "
                  f"{len(decision.violations)} violation(s)")
    shown = decision.violations[:20]
    for violation in shown:
        console.print(f"  [red]\u2717[/] [{violation.kind}] {violation.message}")
    if len(decision.violations) > len(shown):
        console.print(f"  [dim]... and {len(decision.violations) - len(shown)} more[/]")


def _compute_exit_code(result: ScanResult, fail_on: Optional[str], max_risk_score: Optional[int]) -> int:
    if max_risk_score is not None and result.risk_score() > max_risk_score:
        console.print(f"[bold red]FAIL[/]: risk score {result.risk_score()} exceeds threshold {max_risk_score}")
        return ec.GATE_FAILED
    if fail_on and fail_on != "none":
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        gated = result.gating_findings()
        if fail_on == "any":
            offending = [f for f in gated if f.severity is not Severity.INFO]
        else:
            min_rank = order.index(Severity(fail_on))
            offending = [f for f in gated if order.index(f.severity) >= min_rank]
        if offending:
            console.print(f"[bold red]FAIL[/]: {len(offending)} finding(s) at or above severity '{fail_on}'")
            return ec.GATE_FAILED
    return ec.SUCCESS


# --------------------------------------------------------------------------- #
# version / doctor / init / config
# --------------------------------------------------------------------------- #
@main.command()
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable version info")
def version(as_json):
    """Print version and runtime information."""
    info = {
        "product": "IronClad Sentinel",
        "version": __version__,
        "python": sys.version.split()[0],
        "platform": sys.platform,
    }
    if as_json:
        console.print_json(json.dumps(info))
    else:
        console.print(f"IronClad Sentinel {__version__} (python {info['python']}, {sys.platform})")
    sys.exit(ec.SUCCESS)


@main.command()
@click.option("--json", "as_json", is_flag=True)
def doctor(as_json):
    """Verify the local installation is healthy and ready to scan."""
    checks: List[dict] = []

    def check(name: str, ok: bool, detail: str, warning: bool = False) -> None:
        # `warning` marks a check that is not healthy-but-usable: it does not
        # make `doctor` fail, because trial mode is a supported way to run.
        checks.append({"check": name, "ok": bool(ok), "detail": detail, "warning": bool(warning)})

    check("python >= 3.9", sys.version_info >= (3, 9), sys.version.split()[0])

    for module_name in ("click", "yaml", "rich", "jinja2", "cryptography"):
        try:
            __import__(module_name)
            check(f"dependency {module_name}", True, "importable")
        except Exception as exc:  # pragma: no cover - environment specific
            check(f"dependency {module_name}", False, str(exc))

    from ironclad.rules.schema import load_rule_packs
    pack_dir = os.path.join(os.path.dirname(__file__), "rules", "packs")
    try:
        rules = load_rule_packs([pack_dir])
        check("bundled rule packs", len(rules) > 0, f"{len(rules)} rules from {pack_dir}")
    except Exception as exc:
        check("bundled rule packs", False, str(exc))

    for data_file in ("vuln_db.json", "license_db.json"):
        path = os.path.join(os.path.dirname(__file__), "data", data_file)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            entries = sum(len(v) for k, v in payload.items() if isinstance(v, dict))
            check(f"data/{data_file}", entries > 0, f"{entries} entries")
        except Exception as exc:
            check(f"data/{data_file}", False, str(exc))

    template = os.path.join(os.path.dirname(__file__), "reporting", "templates", "report.html.j2")
    check("html report template", os.path.isfile(template), template)

    status = verify_license(None)
    check("commercial license", True,
          f"{status.terms.customer} ({status.terms.tier})" if status.valid else f"trial mode: {status.reason}",
          warning=not status.valid)

    if os.path.isfile(".ironclad.yml"):
        try:
            IronCladConfig.load(".")
            check(".ironclad.yml", True, "parses")
        except Exception as exc:
            check(".ironclad.yml", False, str(exc))
    else:
        check(".ironclad.yml", True, "not present (using defaults)")

    healthy = all(c["ok"] for c in checks)
    warnings = [c for c in checks if c.get("warning")]
    if as_json:
        console.print_json(json.dumps({"healthy": healthy, "warnings": len(warnings), "checks": checks}))
    else:
        table = Table(box=box.SIMPLE, title="IronClad Sentinel doctor")
        table.add_column("Check")
        table.add_column("Status")
        table.add_column("Detail")
        for item in checks:
            mark = "[yellow]WARN[/]" if item.get("warning") else ("[green]OK[/]" if item["ok"] else "[red]FAIL[/]")
            table.add_row(item["check"], mark, item["detail"])
        console.print(table)
        if not healthy:
            console.print("[red]Installation has problems.[/]")
        elif warnings:
            console.print(f"[green]Installation healthy[/] ({len(warnings)} warning(s)).")
        else:
            console.print("[green]Installation healthy.[/]")
    sys.exit(ec.SUCCESS if healthy else ec.INTERNAL_ERROR)


@main.command()
@click.argument("target", default=".")
@click.option("--with-policy/--no-policy", default=True, help="Also write an example policy.yaml")
def init(target, with_policy):
    """Create starter IronClad configuration in TARGET."""
    os.makedirs(target, exist_ok=True)
    written = []
    config_path = os.path.join(target, ".ironclad.yml")
    if not os.path.exists(config_path):
        with open(config_path, "w", encoding="utf-8") as fh:
            fh.write(_EXAMPLE_CONFIG)
        written.append(config_path)
    if with_policy:
        policy_path = os.path.join(target, "policy.yaml")
        if not os.path.exists(policy_path):
            write_example_policy(policy_path)
            written.append(policy_path)
    if written:
        console.print(f"[green]\u2713[/] Wrote {', '.join(written)}")
    else:
        console.print("[yellow]Nothing written; configuration already present.[/]")
    sys.exit(ec.SUCCESS)


_EXAMPLE_CONFIG = """\
# IronClad Sentinel project configuration.
# Precedence (highest wins): CLI flags > environment variables >
# this file > organization policy defaults > built-in defaults.
min_severity: info
report_formats: [json]
output_dir: .ironclad/reports
max_file_size_kb: 2048
entropy_threshold: 4.3
ignore_paths:
  - "**/vendor/**"
  - "**/*_pb2.py"
"""


@main.group()
def config():
    """Inspect and manage IronClad configuration."""


@config.command("show")
@click.argument("target", default=".")
@click.option("--json", "as_json", is_flag=True)
def config_show(target, as_json):
    """Show the effective configuration for TARGET with its precedence chain."""
    if not os.path.exists(target):
        _die(f"target does not exist: {target}", ec.TARGET_ERROR)
    cfg = IronCladConfig.load(target, {})
    source = "project .ironclad.yml" if os.path.isfile(os.path.join(target, ".ironclad.yml")) else "built-in defaults"
    payload = {
        "target": cfg.target,
        "source": source,
        "env_overrides": _env_overrides(),
        "enabled_engines": cfg.enabled_engines,
        "min_severity": cfg.min_severity,
        "max_file_size_kb": cfg.max_file_size_kb,
        "entropy_threshold": cfg.entropy_threshold,
        "ignore_paths": sorted(cfg.ignore_paths),
        "exclude_dirs": sorted(cfg.exclude_dirs),
        "custom_rules_dirs": cfg.custom_rules_dirs,
    }
    if as_json:
        console.print_json(json.dumps(payload))
    else:
        table = Table(box=box.SIMPLE, title=f"Effective configuration (from {source})")
        table.add_column("Key")
        table.add_column("Value")
        for key, value in payload.items():
            table.add_row(key, str(value))
        console.print(table)
        console.print("[dim]Precedence: CLI flags > IRONCLAD_* environment variables > "
                      ".ironclad.yml > defaults[/]")
    sys.exit(ec.SUCCESS)


@config.command("init")
@click.argument("target", default=".")
def config_init(target):
    """Write a starter .ironclad.yml into TARGET."""
    os.makedirs(target, exist_ok=True)
    path = os.path.join(target, ".ironclad.yml")
    if os.path.exists(path):
        _die(f"{path} already exists", ec.CONFIG_ERROR)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_EXAMPLE_CONFIG)
    console.print(f"[green]\u2713[/] Wrote {path}")
    sys.exit(ec.SUCCESS)


def _env_overrides() -> dict:
    prefix = "IRONCLAD_"
    return {k: v for k, v in os.environ.items() if k.startswith(prefix)}


# --------------------------------------------------------------------------- #
# policy
# --------------------------------------------------------------------------- #
@main.group()
def policy():
    """Validate and inspect organization security policies."""


@policy.command("validate")
@click.argument("path")
@click.option("--json", "as_json", is_flag=True)
def policy_validate(path, as_json):
    """Validate a policy document. Exit 0 if valid, 3 if not."""
    try:
        loaded = Policy.load(path)
    except PolicyError as exc:
        if as_json:
            console.print_json(json.dumps({"valid": False, "problems": exc.problems}))
        else:
            err_console.print(f"[bold red]INVALID[/] {path}")
            for problem in exc.problems:
                err_console.print(f"  - {problem}")
        sys.exit(ec.CONFIG_ERROR)
    if as_json:
        console.print_json(json.dumps({"valid": True, "policy": loaded.to_dict()}))
    else:
        console.print(f"[green]VALID[/] {path} -- policy '{loaded.name}' "
                      f"(fail_on={loaded.fail_on}, {len(loaded.ignore_rules)} ignored rules, "
                      f"{len(loaded.severity_gates)} severity gates)")
    sys.exit(ec.SUCCESS)


@policy.command("show")
@click.argument("path")
def policy_show(path):
    """Print the parsed policy as normalized JSON."""
    loaded = _load_policy_or_die(path)
    console.print_json(json.dumps(loaded.to_dict()))
    sys.exit(ec.SUCCESS)


@policy.command("init")
@click.option("--out", default="policy.yaml", help="Where to write the example policy")
def policy_init(out):
    """Write a commented example policy.yaml."""
    write_example_policy(out)
    console.print(f"[green]\u2713[/] Wrote {out}")
    console.print("[dim]Validate it with: ironclad policy validate " + out + "[/]")
    sys.exit(ec.SUCCESS)


# --------------------------------------------------------------------------- #
# baseline
# --------------------------------------------------------------------------- #
@main.group()
def baseline():
    """Create, inspect and prune finding baselines."""


@baseline.command("create")
@click.argument("target", default=".")
@click.option("--out", required=True, help="Baseline file to write")
@click.option("--reason", default="", help="Why these findings are accepted (ticket link, owner, ...)")
@click.option("--expires-in-days", default=None, type=int,
              help="Entries lapse after N days; expired findings gate CI again")
@click.option("--created-by", default="", help="Recorded as the accepting identity")
@click.option("--force", is_flag=True, help="Allow baselining critical findings without a reason")
@click.option("--license-file", default=None)
def baseline_create(target, out, reason, expires_in_days, created_by, force, license_file):
    """Scan TARGET and write its current findings as a baseline."""
    if not os.path.exists(target):
        _die(f"scan target does not exist: {target}", ec.TARGET_ERROR)
    licensed = _check_license_and_warn(license_file, quiet=True)
    overrides = {} if licensed else {"enabled_engines": TRIAL_GRACE_ENGINES}
    cfg = IronCladConfig.load(target, overrides)
    result = run_scan(cfg)
    try:
        snapshot = create_baseline(result.findings, reason=reason, expires_in_days=expires_in_days,
                                   created_by=created_by, force=force)
    except BaselineError as exc:
        _die(str(exc), ec.CONFIG_ERROR)
    snapshot.save(out)
    console.print(f"[green]\u2713[/] Baseline written to {out} ({len(snapshot.entries)} findings)")
    if expires_in_days:
        console.print(f"[dim]Entries expire in {expires_in_days} days.[/]")
    sys.exit(ec.SUCCESS)


@baseline.command("list")
@click.argument("path")
@click.option("--json", "as_json", is_flag=True)
def baseline_list(path, as_json):
    """List the findings recorded in a baseline file."""
    try:
        snapshot = Baseline.load(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        _die(f"cannot read baseline: {exc}", ec.CONFIG_ERROR)
    expired = snapshot.expired_entries()
    if as_json:
        console.print_json(json.dumps({
            "schema_version": snapshot.schema_version,
            "legacy": snapshot.legacy,
            "generated_at": snapshot.generated_at.isoformat() if snapshot.generated_at else None,
            "count": len(snapshot.entries),
            "expired": len(expired),
            "entries": [e.to_dict() for e in snapshot.entries],
        }))
    else:
        table = Table(box=box.SIMPLE, title=f"Baseline {path} ({len(snapshot.entries)} entries)")
        table.add_column("Rule")
        table.add_column("File")
        table.add_column("Line", justify="right")
        table.add_column("Severity")
        table.add_column("Expires")
        table.add_column("Reason")
        for entry in sorted(snapshot.entries, key=lambda e: (e.file, e.rule_id)):
            expires = entry.expires_at.strftime("%Y-%m-%d") if entry.expires_at else "-"
            table.add_row(entry.rule_id or "-", entry.file or "-", str(entry.line),
                          entry.severity or "-", expires, entry.reason or "-")
        console.print(table)
        if snapshot.legacy:
            console.print("[yellow]Legacy v1 baseline (fingerprint list only); "
                          "re-create it to gain reasons and expiry.[/]")
        if expired:
            console.print(f"[yellow]{len(expired)} entry/entries expired.[/]")
    sys.exit(ec.SUCCESS)


@baseline.command("diff")
@click.argument("target", default=".")
@click.option("--baseline", "baseline_file", required=True)
@click.option("--license-file", default=None)
def baseline_diff(target, baseline_file, license_file):
    """Show which findings are new, suppressed, or resurfaced after expiry."""
    if not os.path.exists(target):
        _die(f"scan target does not exist: {target}", ec.TARGET_ERROR)
    try:
        snapshot = Baseline.load(baseline_file)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        _die(f"cannot read baseline: {exc}", ec.CONFIG_ERROR)
    licensed = _check_license_and_warn(license_file, quiet=True)
    overrides = {} if licensed else {"enabled_engines": TRIAL_GRACE_ENGINES}
    cfg = IronCladConfig.load(target, overrides)
    result = run_scan(cfg)
    diff = diff_baseline(result.findings, snapshot)
    console.print(f"[green]new:[/] {len(diff.new)}   "
                  f"[dim]suppressed:[/] {diff.suppressed_count}   "
                  f"[yellow]expired (re-gating):[/] {len(diff.expired)}   "
                  f"[cyan]fixed since baseline:[/] {len(diff.fixed)}")
    for finding in diff.new[:20]:
        console.print(f"  [red]+[/] {finding.rule_id} {finding.location.file_path}:"
                      f"{finding.location.start_line}")
    sys.exit(ec.SUCCESS if not diff.new else ec.GATE_FAILED)


@baseline.command("prune")
@click.argument("target", default=".")
@click.option("--baseline", "baseline_file", required=True)
@click.option("--write", is_flag=True, help="Rewrite the baseline file in place")
@click.option("--license-file", default=None)
def baseline_prune(target, baseline_file, write, license_file):
    """Drop baseline entries whose findings no longer exist."""
    if not os.path.exists(target):
        _die(f"scan target does not exist: {target}", ec.TARGET_ERROR)
    try:
        snapshot = Baseline.load(baseline_file)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        _die(f"cannot read baseline: {exc}", ec.CONFIG_ERROR)
    licensed = _check_license_and_warn(license_file, quiet=True)
    overrides = {} if licensed else {"enabled_engines": TRIAL_GRACE_ENGINES}
    cfg = IronCladConfig.load(target, overrides)
    result = run_scan(cfg)
    pruned, removed = prune_baseline(snapshot, result.findings)
    if write:
        pruned.save(baseline_file)
        console.print(f"[green]\u2713[/] Removed {removed} stale entries; "
                      f"{len(pruned.entries)} remain in {baseline_file}")
    else:
        console.print(f"Would remove {removed} stale entries ({len(pruned.entries)} would remain). "
                      f"Re-run with --write to apply.")
    sys.exit(ec.SUCCESS)


# --------------------------------------------------------------------------- #
# sbom / license / report
# --------------------------------------------------------------------------- #
@main.command()
@click.argument("target", default=".")
@click.option("--out", default="sbom.json")
@click.option("--format", "fmt", default="cyclonedx", type=click.Choice(["cyclonedx", "spdx"]))
@click.option("--project-name", default=None)
def sbom(target, out, fmt, project_name):
    """Generate an SBOM (CycloneDX 1.5 or SPDX 2.3) for TARGET."""
    if not os.path.exists(target):
        _die(f"scan target does not exist: {target}", ec.TARGET_ERROR)
    cfg = IronCladConfig.load(target, {})
    fileset = discover(cfg)
    name = project_name or os.path.basename(os.path.abspath(target))
    if fmt == "spdx":
        from ironclad.scanners.spdx import build_spdx

        doc = build_spdx(fileset.dependency_manifests(), project_name=name)
    else:
        doc = build_sbom(fileset.dependency_manifests(), project_name=name)
    os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    count_key = "components" if fmt == "cyclonedx" else "packages"
    console.print(f"[green]\u2713[/] {fmt.upper()} SBOM written to {out} ({len(doc[count_key])} components)")
    sys.exit(ec.SUCCESS)


@main.group("license")
def license_group():
    """Manage and inspect the offline commercial license."""


@license_group.command("status")
@click.option("--license-file", default=None)
@click.option("--json", "as_json", is_flag=True)
def license_status(license_file, as_json):
    """Show current license status."""
    status = verify_license(license_file)
    path = license_file or find_license_file() or "(none found)"
    payload = {
        "path": path,
        "valid": status.valid,
        "reason": status.reason,
        "customer": status.terms.customer if status.valid else None,
        "tier": status.terms.tier if status.valid else None,
        "days_remaining": status.days_remaining if status.valid else 0,
    }
    if as_json:
        console.print_json(json.dumps(payload))
    else:
        console.print(f"License file: [dim]{path}[/]")
        if status.valid:
            console.print(f"[green]VALID[/] -- {status.terms.customer} ({status.terms.tier}), "
                          f"{status.terms.seats} seats, {status.days_remaining} days remaining, "
                          f"id={status.terms.license_id}")
        else:
            console.print(f"[yellow]NOT LICENSED[/] -- {status.reason}")
    sys.exit(ec.SUCCESS)


@license_group.command("verify")
@click.option("--license-file", required=True)
def license_verify(license_file):
    """Verify a license file's signature and terms. Exit 1 when invalid."""
    status = verify_license(license_file)
    if status.valid:
        console.print(f"[green]VALID[/] {status.terms.customer} ({status.terms.tier})")
        sys.exit(ec.SUCCESS)
    console.print(f"[red]INVALID[/] {status.reason}")
    sys.exit(ec.GATE_FAILED)


@main.group()
def report():
    """Re-render reports from a stored JSON scan result."""


@report.command("convert")
@click.argument("input_file")
@click.option("--format", "formats", default="html", help="Comma-separated: json,sarif,html,markdown,junit")
@click.option("--output-dir", default=".ironclad/reports")
def report_convert(input_file, formats, output_dir):
    """Convert a saved JSON scan result into other report formats."""
    try:
        with open(input_file, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        _die(f"cannot read {input_file}: {exc}", ec.CONFIG_ERROR)
    try:
        result = ScanResult.from_dict(payload)
    except (KeyError, ValueError) as exc:
        _die(f"{input_file} is not a valid IronClad JSON report: {exc}", ec.CONFIG_ERROR)
    wanted = [f.strip() for f in formats.split(",") if f.strip() and f.strip() != "json"]
    written = write_reports(result, wanted, output_dir) if wanted else {}
    console.print(f"[green]\u2713[/] Re-rendered {len(result.findings)} findings into "
                  f"{', '.join(written) or '(json only)'}")
    for fmt, path in written.items():
        console.print(f"[dim]  report ({fmt}):[/] {path}")
    sys.exit(ec.SUCCESS)


# --------------------------------------------------------------------------- #
# server (API + dashboard + worker)
# --------------------------------------------------------------------------- #
@main.group("server")
def server_group():
    """Manage the self-hosted IronClad server (API, dashboard, worker)."""


@server_group.command("init")
@click.option("--database-url", default=None, help="SQLAlchemy URL (default: IRONCLAD_DATABASE_URL or local SQLite)")
@click.option("--org-name", default="My Organization")
@click.option("--org-slug", default=None)
@click.option("--admin-email", required=True)
@click.option("--admin-password", required=True, help="Must satisfy the password policy")
@click.option("--json", "as_json", is_flag=True)
def server_init(database_url, org_name, org_slug, admin_email, admin_password, as_json):
    """Create the database schema and the first organization + owner."""
    from ironclad.platform.database import build_engine, run_migrations, session_scope
    from ironclad.platform.scanning import bootstrap_organization
    from ironclad.platform.security import SecurityError, password_problems

    problems = password_problems(admin_password)
    if problems:
        _die(f"admin password rejected: {'; '.join(problems)}", ec.CONFIG_ERROR)
    try:
        engine = build_engine(database_url)
        run_migrations(engine)
        with session_scope(engine) as session:
            org, owner = bootstrap_organization(
                session, name=org_name, slug=(org_slug or org_name.lower().replace(" ", "-")),
                admin_email=admin_email, password=admin_password)
            payload = {"organization_id": org.id, "slug": org.slug, "owner_email": owner.email,
                       "owner_role": owner.role, "database": str(engine.url).split("://", 1)[0]}
    except SecurityError as exc:
        _die(str(exc), ec.CONFIG_ERROR)
    except Exception as exc:  # noqa: BLE001 - surfaced as a config error, not a traceback
        _die(f"could not initialise server storage: {exc}", ec.CONFIG_ERROR)
    if as_json:
        console.print_json(json.dumps(payload))
    else:
        console.print(f"[green]\u2713[/] Organization '{payload['slug']}' created "
                      f"(owner: {payload['owner_email']}, backend: {payload['database']})")
        console.print("[dim]Start the API with: ironclad serve[/]")
    sys.exit(ec.SUCCESS)


@server_group.command("worker")
@click.option("--database-url", default=None)
@click.option("--poll-interval", default=0.5, type=float)
@click.option("--max-jobs", default=None, type=int, help="Process N jobs then exit (for tests/CI)")
def server_worker(database_url, poll_interval, max_jobs):
    """Run the background scan worker."""
    from ironclad.platform.database import build_engine, session_factory
    from ironclad.platform.jobs import JobQueue, Worker
    from ironclad.platform.worker_jobs import register_job_handlers

    engine = build_engine(database_url)
    queue = JobQueue()
    register_job_handlers(queue, engine)
    worker = Worker(queue, poll_interval=poll_interval)
    console.print("[dim]Worker started. Ctrl-C to stop.[/]")
    processed = worker.run(session_factory(engine), max_jobs=max_jobs)
    console.print(f"[green]\u2713[/] Worker stopped after processing {processed} job(s)")
    sys.exit(ec.SUCCESS)


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8000, show_default=True, type=int)
@click.option("--database-url", default=None)
@click.option("--reload", is_flag=True)
def serve(host, port, database_url, reload):
    """Run the API + dashboard with uvicorn."""
    try:
        import uvicorn
    except ImportError:
        _die("the server extra is not installed. Run: pip install 'ironclad-sentinel[server]'",
             ec.CONFIG_ERROR)
    if database_url:
        os.environ.setdefault("IRONCLAD_DATABASE_URL", database_url)
    console.print(f"[dim]Serving IronClad Sentinel on http://{host}:{port}[/]")
    uvicorn.run("ironclad.api.app:create_app", factory=True, host=host, port=port, reload=reload)
    sys.exit(ec.SUCCESS)


# --------------------------------------------------------------------------- #
# advisories
# --------------------------------------------------------------------------- #
@main.group("advisories")
def advisories_group():
    """Build and inspect the offline advisory database."""


@advisories_group.command("import-osv")
@click.option("--source", required=True,
              help="Directory of OSV records (osv.dev dump or github/advisory-database).")
@click.option("--output", required=True, help="Path for the generated IronClad database JSON.")
@click.option("--ecosystems", default="",
              help="Comma-separated IronClad ecosystems to keep (default: all supported).")
@click.option("--limit", default=0, type=int,
              help="Cap advisories per package (0 = no cap). Keeps the database bounded.")
@click.option("--source-label", default="",
              help="Free-text provenance recorded in _meta (e.g. the upstream repo and commit).")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON")
def advisories_import_osv(source, output, ecosystems, limit, source_label, as_json):
    """Convert an OSV dump into IronClad's offline advisory database.

    Runs entirely offline: point --source at a directory of OSV JSON records
    (an osv.dev dump, or a checkout of github/advisory-database) and this
    writes a database you can ship or point `advisory_path` at. GIT ranges
    and ecosystems IronClad has no manifest parser for are dropped, and the
    counts of each are reported so a narrow import is never silent.
    """
    from ironclad.scanners import osv

    if not os.path.isdir(source):
        _die(f"--source is not a directory: {source}", ec.TARGET_ERROR)
    wanted = {e.strip().lower() for e in ecosystems.split(",") if e.strip()}
    unknown = sorted(wanted - set(osv.ECOSYSTEM_TO_OSV))
    if unknown:
        _die(f"unknown ecosystem(s): {', '.join(unknown)}. "
             f"Supported: {', '.join(sorted(osv.ECOSYSTEM_TO_OSV))}", ec.CONFIG_ERROR)

    records = 0
    unreadable = 0
    database: Dict[str, Dict[str, List[Dict[str, object]]]] = {}
    for root, _dirs, files in os.walk(source):
        for filename in files:
            if not filename.endswith(".json"):
                continue
            path = os.path.join(root, filename)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    payload = json.load(fh)
            except (OSError, json.JSONDecodeError):
                unreadable += 1
                continue
            for record in osv.iter_records(payload):
                records += 1
                for eco, name, advisory in osv.record_to_entries(record):
                    if wanted and eco not in wanted:
                        continue
                    # Keys must be lowercased: the scanner normalises package
                    # names (PEP 503 for Python, lowercase elsewhere) before
                    # looking them up, so a mixed-case key such as "PyYAML" or
                    # "github.com/Traefik/traefik" would never be found.
                    bucket = database.setdefault(eco, {}).setdefault(name.lower(), [])
                    if any(existing.get("id") == advisory["id"] for existing in bucket):
                        continue
                    bucket.append(advisory)

    if limit > 0:
        for packages in database.values():
            for name, entries in packages.items():
                packages[name] = entries[:limit]

    packages = sum(len(v) for v in database.values())
    advisories = sum(len(a) for v in database.values() for a in v.values())
    payload_out = {
        "_meta": {
            "description": "IronClad Sentinel offline advisory database, generated "
                           "from OSV records by `ironclad advisories import-osv`.",
            "schema_version": 1,
            "generator_version": __version__,
            "source": source_label or os.path.abspath(source),
            "osv_records_read": records,
            "unreadable_files": unreadable,
            "ecosystems": sorted(database),
            "package_count": packages,
            "advisory_count": advisories,
            "per_package_limit": limit or None,
        },
    }
    payload_out.update({eco: database[eco] for eco in sorted(database)})

    os.makedirs(os.path.dirname(os.path.abspath(output)) or ".", exist_ok=True)
    with open(output, "w", encoding="utf-8") as fh:
        json.dump(payload_out, fh, indent=1, sort_keys=True)
        fh.write("\n")

    summary = {
        "source": source_label or os.path.abspath(source),
        "output": os.path.abspath(output),
        "osv_records_read": records,
        "unreadable_files": unreadable,
        "ecosystems": {eco: len(database[eco]) for eco in sorted(database)},
        "package_count": packages,
        "advisory_count": advisories,
        "size_bytes": os.path.getsize(output),
    }
    if as_json:
        console.print_json(json.dumps(summary))
    else:
        console.print(f"[green]\u2713[/] read {records} OSV records from {source}")
        if unreadable:
            console.print(f"[yellow]![/] skipped {unreadable} unreadable file(s)")
        for eco in sorted(database):
            console.print(f"    {eco:<12} {len(database[eco]):>6} packages")
        console.print(f"[green]\u2713[/] wrote {packages} packages / {advisories} advisories "
                      f"to {output} ({summary['size_bytes']:,} bytes)")
    sys.exit(ec.SUCCESS)


@advisories_group.command("stats")
@click.option("--database", "database_path", default=None,
              help="Database to inspect (default: the bundled one).")
@click.option("--json", "as_json", is_flag=True)
def advisories_stats(database_path, as_json):
    """Show what the active advisory database actually covers."""
    from ironclad.scanners.advisories import BundledAdvisorySource

    source = BundledAdvisorySource(path=database_path) if database_path else BundledAdvisorySource()
    data = source._load()
    per_eco = {eco: len(pkgs) for eco, pkgs in sorted(data.items())
               if not eco.startswith("_") and isinstance(pkgs, dict)}
    summary = {
        "path": source.path,
        "ecosystems": per_eco,
        "package_count": sum(per_eco.values()),
        "advisory_count": sum(
            len(v) for eco, pkgs in data.items() if not eco.startswith("_")
            and isinstance(pkgs, dict) for entries in pkgs.values()
            if isinstance(entries, list) for v in [entries]),
        "warnings": source.warnings,
    }
    if as_json:
        console.print_json(json.dumps(summary))
    else:
        for eco, count in per_eco.items():
            console.print(f"    {eco:<12} {count:>6} packages")
        console.print(f"[green]\u2713[/] {summary['package_count']} packages / "
                      f"{summary['advisory_count']} advisories")
        for warning in source.warnings:
            console.print(f"[yellow]![/] {warning}")
    sys.exit(ec.SUCCESS)


def _safe_main() -> None:  # pragma: no cover - thin wrapper for entry point
    try:
        main(standalone_mode=True)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - top-level guard
        err_console.print(f"[bold red]internal error[/]: {exc}")
        err_console.print("[dim]" + traceback.format_exc() + "[/]")
        sys.exit(ec.INTERNAL_ERROR)


if __name__ == "__main__":
    _safe_main()
