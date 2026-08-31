"""Bridge between the scanning engine and the persistence layer.

This is the only place a scan result becomes database rows, which is what
keeps the API, the worker and the CLI-consistent: one code path, one set of
invariants.

Security boundary
-----------------
The API accepts a *target path* from a caller. Executing a scanner against
an arbitrary filesystem path chosen by a remote user would be an arbitrary
file-read primitive, so :func:`resolve_target` confines every target to
``IRONCLAD_SCAN_ROOT`` (default: the current working directory) and refuses
symlinks that escape it. There is no shell anywhere in this path -- the
scanner parses files, it never executes them.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from ironclad.core.config import IronCladConfig
from ironclad.core.engine import run_scan
from ironclad.core.models import ScanResult
from ironclad.core.policy import Policy, PolicyDecision, evaluate_policy
from ironclad.core.spdx_expr import default_policy
from ironclad.platform import audit, events
from ironclad.platform.models import (
    Component,
    Finding,
    FindingEvent,
    Organization,
    Policy as PolicyRow,
    Project,
    Scan,
    Sbom,
    User,
    utcnow,
)
from ironclad.platform.observability import (
    FILES_SCANNED,
    FINDINGS_TOTAL,
    SCAN_DURATION,
    SCAN_FAILURES,
    SCAN_TOTAL,
    registry,
)
from ironclad.platform.security import hash_password
from ironclad.scanners.sbom import build_sbom

# Path confinement lives in `ironclad.core.paths` so the CLI can use it
# without the database stack. Re-exported here because the API and worker
# already import these names from this module.
from ironclad.core.paths import SCAN_ROOT_ENV, TargetError, resolve_target, scan_root

__all__ = ["SCAN_ROOT_ENV", "TargetError", "resolve_target", "scan_root",
           "ScanOutcome", "bootstrap_organization", "perform_scan", "resolve_policy",
           "latest_sbom", "license_summary", "finding_trend", "dashboard_summary"]


# --------------------------------------------------------------------------- #
# Bootstrapping
# --------------------------------------------------------------------------- #
def bootstrap_organization(session: Session, *, name: str, slug: str, admin_email: str,
                           password: str) -> Tuple[Organization, User]:
    """Create an organization and its owner. Used by first-run setup."""
    org = Organization(name=name, slug=slug, settings="{}")
    session.add(org)
    session.flush()
    owner = User(org_id=org.id, email=admin_email.lower(), password_hash=hash_password(password),
                 full_name=admin_email.split("@")[0], role="owner")
    session.add(owner)
    session.flush()
    audit.record(session, org_id=org.id, action="organization.created", actor=admin_email,
                 actor_id=owner.id, target_type="organization", target_id=str(org.id),
                 metadata={"slug": slug})
    audit.record(session, org_id=org.id, action="user.created", actor=admin_email,
                 actor_id=owner.id, target_type="user", target_id=str(owner.id),
                 metadata={"role": "owner"})
    return org, owner


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
@dataclass
class ScanOutcome:
    scan: Scan
    result: ScanResult
    decision: Optional[PolicyDecision]
    new_findings: int
    resolved_findings: int


def policy_from_document(document: Dict[str, Any]) -> Policy:
    return Policy.from_dict(document)


def _policy_for_scan(session: Session, org_id: int, policy_id: Optional[int],
                     policy_document: Optional[Dict[str, Any]]) -> Optional[Policy]:
    """Resolve which policy a scan should be gated on.

    Precedence: an explicit inline document, then an explicit policy id,
    then the organization's default policy, then no policy at all (findings
    are recorded but nothing is gated).
    """
    if policy_document is not None:
        return Policy.from_dict(policy_document)
    if policy_id is None:
        row = session.execute(
            select(PolicyRow).where(PolicyRow.org_id == org_id, PolicyRow.is_default.is_(True))
        ).scalar_one_or_none()
    else:
        row = session.execute(
            select(PolicyRow).where(PolicyRow.org_id == org_id, PolicyRow.id == policy_id)
        ).scalar_one_or_none()
    if row is None:
        return None
    return Policy.from_dict(json.loads(row.document))


def perform_scan(
    session: Session,
    *,
    org_id: int,
    project_id: int,
    scan_row: Scan,
    target: str,
    policy: Optional[Policy] = None,
    actor: str = "system",
    correlation_id: str = "",
    store_sbom: bool = True,
) -> ScanOutcome:
    """Run the engine against ``target`` and persist everything.

    Always leaves the scan row in a terminal state (``succeeded`` or
    ``failed``) -- a crashed worker must not leave a scan looking queued
    forever, and a scanner exception must not lose the scan record.
    """
    scan_row.status = "running"
    scan_row.started_at = utcnow()
    scan_row.target_path = target
    scan_row.policy_document = json.dumps(policy.to_dict(), sort_keys=True) if policy else ""
    session.flush()
    events.default_bus.publish(session, events.SCAN_STARTED, org_id,
                               {"scan_id": scan_row.id}, subject_id=str(scan_row.id),
                               correlation_id=correlation_id)

    # Re-validate at execution time: the API checked the path when the job
    # was queued, but a queued job can sit for a while and the directory may
    # be gone by then. Silently "succeeding" with zero findings would report
    # a clean scan of a tree that no longer exists.
    try:
        resolve_target(target)
    except TargetError as exc:
        scan_row.status = "failed"
        scan_row.finished_at = utcnow()
        scan_row.error = f"TargetError: {exc}"[:2000]
        registry.inc(SCAN_FAILURES, 1, "Scans that failed")
        registry.inc(SCAN_TOTAL, 1, "Scans executed")
        events.default_bus.publish(session, events.SCAN_FAILED, org_id,
                                   {"scan_id": scan_row.id, "error": scan_row.error},
                                   subject_id=str(scan_row.id), correlation_id=correlation_id)
        session.flush()
        return ScanOutcome(scan=scan_row, result=None, decision=None,
                           new_findings=0, resolved_findings=0)

    config = IronCladConfig.load(target, {"report_formats": ["json"]})
    try:
        with registry.timer(SCAN_DURATION, "End-to-end scan duration"):
            result = run_scan(config, policy=policy)
    except Exception as exc:  # noqa: BLE001 - recorded on the scan row, never lost
        scan_row.status = "failed"
        scan_row.finished_at = utcnow()
        scan_row.error = f"{type(exc).__name__}: {exc}"[:2000]
        registry.inc(SCAN_FAILURES, 1, "Scans that failed")
        registry.inc(SCAN_TOTAL, 1, "Scans executed")
        events.default_bus.publish(session, events.SCAN_FAILED, org_id,
                                   {"scan_id": scan_row.id, "error": scan_row.error},
                                   subject_id=str(scan_row.id), correlation_id=correlation_id)
        raise

    resolved = _resolve_previous_findings(session, org_id=org_id, project_id=project_id,
                                          current={f.fingerprint for f in result.findings},
                                          exclude_scan_id=scan_row.id, actor=actor)
    persisted = _persist_findings(session, org_id=org_id, project_id=project_id,
                                  scan_row=scan_row, result=result, actor=actor)
    component_count = 0
    if store_sbom:
        component_count = _persist_sbom(session, org_id=org_id, project_id=project_id,
                                        scan_row=scan_row, target=target, result=result,
                                        policy=policy)

    decision = evaluate_policy(result, policy) if policy is not None else None

    scan_row.status = "succeeded"
    scan_row.finished_at = utcnow()
    scan_row.duration_seconds = float(result.stats.duration_seconds)
    scan_row.files_scanned = int(result.stats.files_scanned)
    scan_row.lines_scanned = int(result.stats.lines_scanned)
    scan_row.engines = json.dumps(sorted(result.stats.engines_run))
    scan_row.risk_score = int(result.risk_score())
    scan_row.grade = result.grade()
    scan_row.baseline_suppressed = int(result.baseline_suppressed)
    scan_row.baseline_expired = int(result.baseline_expired)
    scan_row.policy_passed = bool(decision.passed) if decision else None
    scan_row.error = ""
    session.flush()

    registry.inc(SCAN_TOTAL, 1, "Scans executed")
    registry.inc(FILES_SCANNED, scan_row.files_scanned, "Files scanned")
    registry.inc(FINDINGS_TOTAL, len(persisted), "Findings persisted")

    events.default_bus.publish(session, events.SCAN_COMPLETED, org_id, {
        "scan_id": scan_row.id,
        "finding_count": len(persisted),
        "risk_score": scan_row.risk_score,
        "files_scanned": scan_row.files_scanned,
        "component_count": component_count,
    }, subject_id=str(scan_row.id), correlation_id=correlation_id)

    if decision is not None:
        if decision.passed:
            events.default_bus.publish(session, events.POLICY_PASSED, org_id,
                                       {"scan_id": scan_row.id, "policy": decision.policy_name},
                                       subject_id=str(scan_row.id), correlation_id=correlation_id)
        else:
            events.default_bus.publish(session, events.POLICY_FAILED, org_id, {
                "scan_id": scan_row.id,
                "policy": decision.policy_name,
                "violation_count": len(decision.violations),
            }, subject_id=str(scan_row.id), correlation_id=correlation_id)

    return ScanOutcome(scan=scan_row, result=result, decision=decision,
                       new_findings=len(persisted), resolved_findings=resolved)


def _persist_findings(session: Session, *, org_id: int, project_id: int, scan_row: Scan,
                      result: ScanResult, actor: str) -> List[Finding]:
    baselined = {f.fingerprint for f in result.findings if f.extra.get("baselined")}
    rows: List[Finding] = []
    for finding in result.findings:
        row = Finding(
            org_id=org_id,
            scan_id=scan_row.id,
            project_id=project_id,
            fingerprint=finding.fingerprint,
            rule_id=finding.rule_id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity.value,
            engine=finding.engine.value,
            category=finding.category,
            cwe=finding.cwe or "",
            owasp=finding.owasp or "",
            confidence=finding.confidence,
            remediation=finding.remediation,
            file_path=finding.location.file_path,
            start_line=finding.location.start_line,
            end_line=finding.location.end_line,
            snippet=finding.location.snippet[:2000],
            extra=json.dumps(finding.extra, sort_keys=True, default=str),
            status="open",
            baselined=finding.fingerprint in baselined,
            first_seen_at=utcnow(),
            last_seen_at=utcnow(),
        )
        session.add(row)
        session.flush()
        session.add(FindingEvent(org_id=org_id, finding_id=row.id, event_type="finding.created",
                                 actor=actor, detail=json.dumps({"scan_id": scan_row.id})))
        events.default_bus.publish(session, events.FINDING_CREATED, org_id, {
            "finding_id": row.id,
            "rule_id": row.rule_id,
            "severity": row.severity,
            "scan_id": scan_row.id,
        }, subject_id=str(row.id))
        rows.append(row)
    return rows


def _resolve_previous_findings(session: Session, *, org_id: int, project_id: int,
                               current: set, exclude_scan_id: int, actor: str) -> int:
    """Mark findings from earlier scans that no longer appear as resolved.

    This is what makes "fixed findings" a real number on the dashboard
    rather than a counter that only ever goes up.
    """
    previous = session.execute(
        select(Finding).where(
            Finding.org_id == org_id,
            Finding.project_id == project_id,
            Finding.scan_id != exclude_scan_id,
            Finding.status == "open",
        )
    ).scalars().all()
    resolved = 0
    for row in previous:
        if row.fingerprint in current:
            continue
        row.status = "resolved"
        row.resolved_at = utcnow()
        session.add(FindingEvent(org_id=org_id, finding_id=row.id, event_type="finding.resolved",
                                 actor=actor, detail=json.dumps({"reason": "not present in latest scan"})))
        events.default_bus.publish(session, events.FINDING_RESOLVED, org_id,
                                   {"finding_id": row.id}, subject_id=str(row.id))
        resolved += 1
    return resolved


def _persist_sbom(session: Session, *, org_id: int, project_id: int, scan_row: Scan,
                  target: str, result: ScanResult, policy: Optional[Policy]) -> int:
    from ironclad.core.walker import discover
    from ironclad.scanners.sbom import collect_components

    fileset = discover(IronCladConfig(target=target))
    document = build_sbom(fileset.dependency_manifests(),
                          project_name=os.path.basename(target) or "project")
    row = Sbom(org_id=org_id, project_id=project_id, scan_id=scan_row.id,
               format="cyclonedx", document=json.dumps(document, sort_keys=True),
               component_count=len(document.get("components", [])))
    session.add(row)
    session.flush()

    license_policy = policy.license_policy if policy is not None else None
    for component in collect_components(fileset.dependency_manifests()):
        license_id = component["license"]
        classifier = license_policy if license_policy is not None else default_policy()
        classification = classifier.classify(license_id)
        session.add(Component(
            org_id=org_id, sbom_id=row.id, purl=component["purl"], name=component["name"],
            version=component["version"], ecosystem=component["ecosystem"],
            license=license_id, license_class=classification, bom_ref=component["purl"],
        ))
    session.flush()
    return len(document.get("components", []))


def latest_sbom(session: Session, org_id: int, project_id: int) -> Optional[Sbom]:
    return session.execute(
        select(Sbom).where(Sbom.org_id == org_id, Sbom.project_id == project_id)
        .order_by(Sbom.id.desc()).limit(1)
    ).scalar_one_or_none()


def resolve_policy(session: Session, org_id: int, policy_id: Optional[int] = None,
                   policy_document: Optional[Dict[str, Any]] = None) -> Optional[Policy]:
    """Public wrapper around :func:`_policy_for_scan`."""
    return _policy_for_scan(session, org_id, policy_id, policy_document)


def license_summary(session: Session, org_id: int, project_id: int) -> Dict[str, int]:
    """Count components per license classification for the current SBOM."""
    sbom = latest_sbom(session, org_id, project_id)
    summary = {"allowed": 0, "warning": 0, "blocked": 0, "unknown": 0}
    if sbom is None:
        return summary
    for component in session.execute(
        select(Component).where(Component.org_id == org_id, Component.sbom_id == sbom.id)
    ).scalars().all():
        summary[component.license_class] = summary.get(component.license_class, 0) + 1
    return summary


def finding_trend(session: Session, org_id: int, project_id: Optional[int] = None,
                  limit: int = 20) -> List[Dict[str, Any]]:
    """Per-scan severity counts, oldest first -- the dashboard risk trend.

    Computed from stored scans, never synthesised.
    """
    statement = select(Scan).where(Scan.org_id == org_id, Scan.status == "succeeded")
    if project_id is not None:
        statement = statement.where(Scan.project_id == project_id)
    scans = list(session.execute(statement.order_by(Scan.id.desc()).limit(max(1, min(limit, 200)))).scalars().all())
    scans.reverse()
    points = []
    for scan in scans:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for severity, in session.execute(
            select(Finding.severity).where(Finding.scan_id == scan.id, Finding.org_id == org_id)
        ).all():
            counts[severity] = counts.get(severity, 0) + 1
        points.append({
            "scan_id": scan.id,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "risk_score": scan.risk_score,
            "grade": scan.grade,
            "counts": counts,
        })
    return points


def dashboard_summary(session: Session, org_id: int) -> Dict[str, Any]:
    """Everything the dashboard home page shows, from real stored data."""
    projects = session.execute(
        select(Project).where(Project.org_id == org_id, Project.archived_at.is_(None))
    ).scalars().all()
    latest_by_project: Dict[int, Scan] = {}
    for project in projects:
        scan = session.execute(
            select(Scan).where(Scan.org_id == org_id, Scan.project_id == project.id,
                               Scan.status == "succeeded")
            .order_by(Scan.id.desc()).limit(1)
        ).scalar_one_or_none()
        if scan is not None:
            latest_by_project[project.id] = scan

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    secret_findings = 0
    iac_findings = 0
    for scan in latest_by_project.values():
        for severity, category in session.execute(
            select(Finding.severity, Finding.category)
            .where(Finding.scan_id == scan.id, Finding.org_id == org_id, Finding.status == "open")
        ).all():
            counts[severity] = counts.get(severity, 0) + 1
            if category == "secrets":
                secret_findings += 1
            if category in {"iac", "misconfiguration"}:
                iac_findings += 1

    resolved = session.execute(
        select(Finding).where(Finding.org_id == org_id, Finding.status == "resolved")
    ).scalars().all()

    scans_total = session.execute(
        select(Scan).where(Scan.org_id == org_id)
    ).scalars().all()

    return {
        "projects": len(projects),
        "scans_total": len(scans_total),
        "scans_succeeded": sum(1 for s in scans_total if s.status == "succeeded"),
        "scans_failed": sum(1 for s in scans_total if s.status == "failed"),
        "scans_running": sum(1 for s in scans_total if s.status in ("queued", "running")),
        "open_findings": sum(counts.values()),
        "severity_counts": counts,
        "secret_findings": secret_findings,
        "iac_findings": iac_findings,
        "resolved_findings": len(resolved),
        "policies_failing": sum(1 for s in latest_by_project.values() if s.policy_passed is False),
    }
