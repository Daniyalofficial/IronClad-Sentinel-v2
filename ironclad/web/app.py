"""Server-rendered dashboard.

Deliberately server-side Jinja2 with no JavaScript build step:

* it installs and runs in an air-gapped environment with zero CDN access;
* every number on a page is read from the database at render time -- there
  are no synthetic or placeholder metrics anywhere in the templates;
* there is no client-side state to keep in sync with the API.

Authentication reuses the API's session tokens, delivered as an
``HttpOnly`` ``SameSite=Lax`` cookie. Mutating actions (suppress/resolve a
finding, change a role) post to the JSON API routes, so authorization is
enforced in exactly one place.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session as DbSession

from ironclad import __version__
from ironclad.api.deps import _authenticate, get_db
from ironclad.platform import audit
from ironclad.platform.models import (
    Component,
    Finding,
    Integration,
    Organization,
    Policy as PolicyRow,
    Project,
    Scan,
    Sbom,
    Session as SessionRow,
    User,
    utcnow,
)
from ironclad.platform.rbac import describe_roles
from ironclad.platform.scanning import dashboard_summary, finding_trend, latest_sbom, license_summary
from ironclad.platform.security import (
    SESSION_TTL_SECONDS,
    generate_session_token,
    hash_token,
    lockout_decision,
    verify_password,
)

COOKIE_NAME = "ironclad_session"
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

templates = Jinja2Templates(directory=TEMPLATE_DIR)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _web_principal(request: Request, session: DbSession):
    """Authenticate from the session cookie. Returns None when anonymous."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    principal, _kind = _authenticate(session, token)
    return principal


def _require_web(request: Request, session: DbSession):
    principal = _web_principal(request, session)
    if principal is None:
        raise HTTPException(status.HTTP_307_TEMPORARY_REDIRECT,
                            headers={"Location": "/login"}, detail="login required")
    return principal


def _nav(active: str, org: Optional[Organization], principal) -> Dict[str, Any]:
    return {
        "active": active,
        "org": org,
        "user": {"email": principal.email, "role": principal.role} if principal else None,
        "version": __version__,
        # Named "links", not "items": Jinja resolves nav.items to dict.items().
        "links": [
            ("Overview", "/", "overview"),
            ("Projects", "/projects", "projects"),
            ("Findings", "/findings", "findings"),
            ("Policies", "/policies", "policies"),
            ("Integrations", "/integrations", "integrations"),
            ("Audit log", "/audit", "audit"),
            ("Settings", "/settings", "settings"),
        ],
    }


def mount_dashboard(app) -> None:
    """Attach the dashboard router to an existing FastAPI application."""
    from fastapi.staticfiles import StaticFiles

    if os.path.isdir(STATIC_DIR):
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(_build_router())


def _build_router() -> APIRouter:
    router = APIRouter(tags=["dashboard"], include_in_schema=False)

    # ------------------------------------------------------------------ auth
    @router.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, error: str = "", session: DbSession = Depends(get_db)):
        return templates.TemplateResponse(request, "login.html", {
            "request": request, "error": error, "version": __version__,
        })

    @router.post("/login")
    def login_submit(request: Request, email: str = Form(...), password: str = Form(...),
                     session: DbSession = Depends(get_db)):
        user = session.execute(select(User).where(User.email == email.strip().lower())).scalars().first()
        if user is None:
            return RedirectResponse("/login?error=invalid", status_code=status.HTTP_303_SEE_OTHER)
        decision = lockout_decision(user.failed_logins,
                                    user.locked_until.timestamp() if user.locked_until else None)
        if not decision.allowed:
            return RedirectResponse("/login?error=locked", status_code=status.HTTP_303_SEE_OTHER)
        if not verify_password(password, user.password_hash):
            user.failed_logins += 1
            audit.record(session, org_id=user.org_id, action="auth.login_failed", actor=user.email,
                         actor_id=user.id, metadata={"failures": user.failed_logins})
            session.commit()
            return RedirectResponse("/login?error=invalid", status_code=status.HTTP_303_SEE_OTHER)
        if not user.is_active:
            return RedirectResponse("/login?error=inactive", status_code=status.HTTP_303_SEE_OTHER)
        token, token_hash = generate_session_token()
        session.add(SessionRow(user_id=user.id, org_id=user.org_id, token_hash=token_hash,
                               expires_at=utcnow() + _delta(SESSION_TTL_SECONDS),
                               user_agent=(request.headers.get("user-agent") or "")[:200]))
        user.failed_logins = 0
        user.last_login_at = utcnow()
        audit.record(session, org_id=user.org_id, action="auth.login", actor=user.email,
                     actor_id=user.id, metadata={"via": "dashboard"})
        session.commit()
        response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(COOKIE_NAME, token, max_age=SESSION_TTL_SECONDS, httponly=True,
                            samesite="lax", secure=os.environ.get("IRONCLAD_COOKIE_SECURE", "0") == "1",
                            path="/")
        return response

    @router.post("/logout")
    def logout(request: Request, session: DbSession = Depends(get_db)):
        token = request.cookies.get(COOKIE_NAME)
        if token:
            row = session.execute(
                select(SessionRow).where(SessionRow.token_hash == hash_token(token))
            ).scalar_one_or_none()
            if row is not None:
                row.revoked_at = utcnow()
                audit.record(session, org_id=row.org_id, action="auth.logout", actor="dashboard")
                session.commit()
        response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie(COOKIE_NAME, path="/")
        return response

    # ------------------------------------------------------------- overview
    @router.get("/", response_class=HTMLResponse)
    def overview(request: Request, session: DbSession = Depends(get_db)):
        principal = _require_web(request, session)
        org = session.get(Organization, principal.org_id)
        summary = dashboard_summary(session, principal.org_id)
        trend = finding_trend(session, principal.org_id, limit=15)
        recent = session.execute(
            select(Scan).where(Scan.org_id == principal.org_id).order_by(desc(Scan.id)).limit(8)
        ).scalars().all()
        projects = {p.id: p for p in session.execute(
            select(Project).where(Project.org_id == principal.org_id)).scalars().all()}
        from ironclad.platform.observability import registry

        return templates.TemplateResponse(request, "overview.html", {
            "request": request, "nav": _nav("overview", org, principal),
            "summary": summary, "trend": trend,
            "recent_scans": [_scan_view(s, projects.get(s.project_id)) for s in recent],
            "metrics": registry.snapshot(),
            "queue": request.app.state.queue.depth(session),
        })

    # -------------------------------------------------------------- projects
    @router.get("/projects", response_class=HTMLResponse)
    def projects_page(request: Request, session: DbSession = Depends(get_db)):
        principal = _require_web(request, session)
        org = session.get(Organization, principal.org_id)
        rows = session.execute(
            select(Project).where(Project.org_id == principal.org_id,
                                  Project.archived_at.is_(None)).order_by(Project.name)
        ).scalars().all()
        views = []
        for project in rows:
            latest = session.execute(
                select(Scan).where(Scan.org_id == principal.org_id, Scan.project_id == project.id,
                                   Scan.status == "succeeded").order_by(desc(Scan.id)).limit(1)
            ).scalar_one_or_none()
            open_count = 0
            if latest is not None:
                open_count = int(session.execute(
                    select(func.count(Finding.id)).where(Finding.scan_id == latest.id,
                                                         Finding.org_id == principal.org_id,
                                                         Finding.status == "open")
                ).scalar_one())
            views.append({"project": project, "latest": latest, "open_findings": open_count,
                          "licenses": license_summary(session, principal.org_id, project.id)})
        return templates.TemplateResponse(request, "projects.html", {
            "request": request, "nav": _nav("projects", org, principal), "views": views})

    @router.get("/projects/{project_id}", response_class=HTMLResponse)
    def project_detail(project_id: int, request: Request, session: DbSession = Depends(get_db)):
        principal = _require_web(request, session)
        org = session.get(Organization, principal.org_id)
        project = session.execute(
            select(Project).where(Project.org_id == principal.org_id, Project.id == project_id)
        ).scalar_one_or_none()
        if project is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        scans = session.execute(
            select(Scan).where(Scan.org_id == principal.org_id, Scan.project_id == project.id)
            .order_by(desc(Scan.id)).limit(25)
        ).scalars().all()
        latest = next((s for s in scans if s.status == "succeeded"), None)
        findings: List[Finding] = []
        if latest is not None:
            findings = list(session.execute(
                select(Finding).where(Finding.scan_id == latest.id, Finding.org_id == principal.org_id)
                .order_by(Finding.severity, Finding.file_path, Finding.start_line).limit(200)
            ).scalars().all())
        sbom = latest_sbom(session, principal.org_id, project.id)
        components: List[Component] = []
        if sbom is not None:
            components = list(session.execute(
                select(Component).where(Component.org_id == principal.org_id, Component.sbom_id == sbom.id)
                .order_by(Component.name)
            ).scalars().all())
        return templates.TemplateResponse(request, "project.html", {
            "request": request, "nav": _nav("projects", org, principal), "project": project,
            "scans": [_scan_view(s, project) for s in scans], "latest": latest,
            "findings": findings, "sbom": sbom, "components": components,
            "licenses": license_summary(session, principal.org_id, project.id),
            "trend": finding_trend(session, principal.org_id, project.id, limit=15),
            "severity_order": SEVERITY_ORDER,
        })

    # -------------------------------------------------------------- findings
    @router.get("/findings", response_class=HTMLResponse)
    def findings_page(request: Request, severity: str = "", rule: str = "",
                      finding_status: str = "open", project_id: int = 0,
                      session: DbSession = Depends(get_db)):
        principal = _require_web(request, session)
        org = session.get(Organization, principal.org_id)
        statement = select(Finding).where(Finding.org_id == principal.org_id)
        if severity:
            statement = statement.where(Finding.severity == severity)
        if rule:
            statement = statement.where(Finding.rule_id == rule)
        if finding_status:
            statement = statement.where(Finding.status == finding_status)
        if project_id:
            statement = statement.where(Finding.project_id == project_id)
        rows = list(session.execute(statement.order_by(desc(Finding.id)).limit(200)).scalars().all())
        rule_counts = {}
        for row in rows:
            rule_counts[row.rule_id] = rule_counts.get(row.rule_id, 0) + 1
        projects = {p.id: p.name for p in session.execute(
            select(Project).where(Project.org_id == principal.org_id)).scalars().all()}
        return templates.TemplateResponse(request, "findings.html", {
            "request": request, "nav": _nav("findings", org, principal), "findings": rows,
            "projects": projects, "severity_order": SEVERITY_ORDER,
            "filters": {"severity": severity, "rule": rule, "status": finding_status,
                        "project_id": project_id},
            "rule_counts": sorted(rule_counts.items(), key=lambda kv: -kv[1]),
            "can_manage": principal.can("finding.manage"),
        })

    @router.get("/findings/{finding_id}", response_class=HTMLResponse)
    def finding_detail(finding_id: int, request: Request, session: DbSession = Depends(get_db)):
        principal = _require_web(request, session)
        org = session.get(Organization, principal.org_id)
        finding = session.execute(
            select(Finding).where(Finding.org_id == principal.org_id, Finding.id == finding_id)
        ).scalar_one_or_none()
        if finding is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
        from ironclad.platform.models import FindingEvent

        history = list(session.execute(
            select(FindingEvent).where(FindingEvent.org_id == principal.org_id,
                                       FindingEvent.finding_id == finding.id)
            .order_by(FindingEvent.id)
        ).scalars().all())
        project = session.get(Project, finding.project_id)
        scan = session.get(Scan, finding.scan_id)
        return templates.TemplateResponse(request, "finding.html", {
            "request": request, "nav": _nav("findings", org, principal), "finding": finding,
            "history": history, "project": project, "scan": scan,
            "extra": _safe_json(finding.extra),
            "can_manage": principal.can("finding.manage"),
        })

    # -------------------------------------------------------------- policies
    @router.get("/policies", response_class=HTMLResponse)
    def policies_page(request: Request, session: DbSession = Depends(get_db)):
        principal = _require_web(request, session)
        org = session.get(Organization, principal.org_id)
        rows = list(session.execute(
            select(PolicyRow).where(PolicyRow.org_id == principal.org_id).order_by(PolicyRow.name)
        ).scalars().all())
        return templates.TemplateResponse(request, "policies.html", {
            "request": request, "nav": _nav("policies", org, principal), "policies": rows,
            "documents": {row.id: _safe_json(row.document) for row in rows},
            "can_manage": principal.can("policy.manage"),
        })

    # ---------------------------------------------------------- integrations
    @router.get("/integrations", response_class=HTMLResponse)
    def integrations_page(request: Request, session: DbSession = Depends(get_db)):
        principal = _require_web(request, session)
        org = session.get(Organization, principal.org_id)
        rows = list(session.execute(
            select(Integration).where(Integration.org_id == principal.org_id).order_by(Integration.name)
        ).scalars().all())
        return templates.TemplateResponse(request, "integrations.html", {
            "request": request, "nav": _nav("integrations", org, principal),
            "integrations": [{"row": r, "config": _safe_json(r.config)} for r in rows],
            "can_manage": principal.can("integration.manage"),
        })

    # ----------------------------------------------------------------- audit
    @router.get("/audit", response_class=HTMLResponse)
    def audit_page(request: Request, action: str = "", session: DbSession = Depends(get_db)):
        principal = _require_web(request, session)
        org = session.get(Organization, principal.org_id)
        if not principal.can("audit.read"):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "audit log requires the audit.read permission")
        rows = audit.list_for_org(session, principal.org_id, action=action or None, limit=200)
        return templates.TemplateResponse(request, "audit.html", {
            "request": request, "nav": _nav("audit", org, principal),
            "entries": [audit.to_dict(row) for row in rows], "action_filter": action,
        })

    # -------------------------------------------------------------- settings
    @router.get("/settings", response_class=HTMLResponse)
    def settings_page(request: Request, session: DbSession = Depends(get_db)):
        principal = _require_web(request, session)
        org = session.get(Organization, principal.org_id)
        users = list(session.execute(
            select(User).where(User.org_id == principal.org_id).order_by(User.email)
        ).scalars().all())
        return templates.TemplateResponse(request, "settings.html", {
            "request": request, "nav": _nav("settings", org, principal), "users": users,
            "roles": describe_roles(),
            "can_manage_users": principal.can("user.manage"),
            "scan_root": os.environ.get("IRONCLAD_SCAN_ROOT") or os.getcwd(),
            "database": str(request.app.state.engine.url).split("://", 1)[0],
            "advisory_source": os.environ.get("IRONCLAD_ADVISORY_SOURCE", "bundled"),
        })

    return router


def _delta(seconds: int):
    from datetime import timedelta

    return timedelta(seconds=seconds)


def _safe_json(raw: str) -> Any:
    try:
        return json.loads(raw or "{}")
    except ValueError:
        return {}


def _scan_view(scan: Scan, project: Optional[Project]) -> Dict[str, Any]:
    return {
        "scan": scan,
        "project_name": project.name if project else f"project #{scan.project_id}",
    }
