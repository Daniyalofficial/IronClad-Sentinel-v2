"""Scan orchestration engine."""
from __future__ import annotations

import os
import time
from typing import List

from ironclad.core.baseline import Baseline, diff_baseline
from ironclad.core.config import IronCladConfig
from ironclad.core.models import Finding, ScanResult, ScanStats, Severity
from ironclad.core.policy import Policy, filter_findings_for_policy
from ironclad.core.walker import discover
from ironclad.rules.schema import load_rule_packs
from ironclad.scanners.advisories import AdvisorySourceError, build_source
from ironclad.scanners.ast_python import scan_python_file
from ironclad.scanners.dependency import scan_dependencies
from ironclad.scanners.python_flows import scan_python_flows
from ironclad.scanners.iac import scan_iac_files
from ironclad.scanners.iac_extended import scan_extended_iac
from ironclad.scanners.rule_engine import scan_file_with_rules
from ironclad.scanners.sbom import build_sbom, scan_license_compliance
from ironclad.scanners.secrets import scan_file_for_secrets

BUILTIN_RULE_PACK_DIR = os.path.join(os.path.dirname(__file__), "..", "rules", "packs")
SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _severity_at_least(sev: Severity, minimum: str) -> bool:
    try:
        min_sev = Severity(minimum)
    except ValueError:
        return True
    return SEVERITY_ORDER.index(sev) >= SEVERITY_ORDER.index(min_sev)


def run_scan(config: IronCladConfig, progress_callback=None, policy: Policy = None) -> ScanResult:
    """Execute every enabled engine over a target and return one ScanResult.

    When a ``policy`` is supplied it is folded into the configuration first
    (additive ignores/excludes/confidence floor), and the returned result's
    findings are post-filtered through the same policy so that CLI, API and
    worker all observe exactly the same finding set.
    """
    start_time = time.time()
    if policy is not None:
        config = policy.apply_to_config(config)

    def report_progress(message: str):
        if progress_callback:
            progress_callback(message)

    report_progress("Discovering files...")
    fileset = discover(config)
    rule_pack_dirs = [BUILTIN_RULE_PACK_DIR] + list(config.custom_rules_dirs)
    rules = load_rule_packs(rule_pack_dirs)

    all_findings: List[Finding] = []
    lines_scanned = 0
    for discovered in fileset.files:
        try:
            with open(discovered.path, "r", encoding="utf-8", errors="ignore") as fh:
                lines_scanned += sum(1 for _ in fh)
        except OSError:
            pass
    engines_run: List[str] = []

    if "ast-python" in config.enabled_engines:
        report_progress("Running deep Python AST analyzer...")
        engines_run.append("ast-python")
        for f in fileset.by_language("python"):
            all_findings.extend(scan_python_file(f.path, f.rel_path))
            # Flow-based detectors (path traversal, SSRF, XSS, open redirect,
            # template injection) plus structural crypto/XML checks. They
            # share the ast-python engine identity so existing CI engine
            # switches keep working.
            all_findings.extend(scan_python_flows(f.path, f.rel_path))

    if "rule-engine" in config.enabled_engines:
        report_progress(f"Running multi-language rule engine ({len(rules)} rules loaded)...")
        engines_run.append("rule-engine")
        for f in fileset.files:
            if f.language == "other" and not f.iac_kind:
                continue
            all_findings.extend(scan_file_with_rules(f, rules))

    if "secrets" in config.enabled_engines:
        report_progress("Scanning for hardcoded secrets & high-entropy credentials...")
        engines_run.append("secrets")
        for f in fileset.files:
            all_findings.extend(scan_file_for_secrets(f, entropy_threshold=config.entropy_threshold))

    if "dependency" in config.enabled_engines:
        try:
            advisory_source = build_source(config.advisory_source, path=config.advisory_path,
                                           endpoint=config.advisory_endpoint)
        except AdvisorySourceError as exc:
            raise ValueError(f"advisory source misconfigured: {exc}") from exc
        report_progress(f"Matching dependencies against advisory source '{advisory_source.name}'...")
        engines_run.append("dependency")
        all_findings.extend(scan_dependencies(fileset.dependency_manifests(), source=advisory_source))
        for warning in advisory_source.warnings:
            report_progress(f"advisory source warning: {warning}")

    if "iac" in config.enabled_engines:
        report_progress("Scanning Infrastructure-as-Code files...")
        engines_run.append("iac")
        iac_files = fileset.iac_files()
        all_findings.extend(scan_iac_files(iac_files))
        for f in iac_files:
            all_findings.extend(scan_extended_iac(f))

    if "license-compliance" in config.enabled_engines:
        report_progress("Checking open-source license compliance...")
        engines_run.append("license-compliance")
        all_findings.extend(scan_license_compliance(fileset.dependency_manifests()))

    filtered = []
    for finding in all_findings:
        if finding.rule_id in config.ignore_rule_ids:
            continue
        if not _severity_at_least(finding.severity, config.min_severity):
            continue
        filtered.append(finding)

    if policy is not None:
        filtered = filter_findings_for_policy(filtered, policy)

    seen = set()
    deduped: List[Finding] = []
    for finding in filtered:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        deduped.append(finding)

    baseline = Baseline.load(config.baseline_file) if config.baseline_file else Baseline()
    diff = diff_baseline(deduped, baseline)
    for finding in diff.suppressed:
        finding.extra["baselined"] = True
    new_findings = diff.new
    suppressed_count = diff.suppressed_count
    expired_count = len(diff.expired)
    duration = time.time() - start_time

    stats = ScanStats(
        files_scanned=len(fileset.files), files_skipped=fileset.skipped,
        lines_scanned=lines_scanned, duration_seconds=duration, engines_run=engines_run,
    )
    sbom_doc = None
    if "cyclonedx" in config.report_formats:
        report_progress("Building CycloneDX component inventory...")
        sbom_doc = build_sbom(fileset.dependency_manifests(),
                              project_name=os.path.basename(os.path.abspath(config.target)))

    report_progress(f"Scan complete in {duration:.2f}s -- {len(deduped)} findings ({suppressed_count} baselined).")
    return ScanResult(target=config.target, findings=deduped, stats=stats, sbom=sbom_doc,
                      new_findings=new_findings, baseline_suppressed=suppressed_count,
                      baseline_expired=expired_count, baseline_applied=bool(config.baseline_file),
                      policy_name=policy.name if policy else None)
