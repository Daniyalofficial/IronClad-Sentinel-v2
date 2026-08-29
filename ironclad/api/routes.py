"""HTTP API routes.

Layout conventions:

* Every tenant-scoped route resolves rows through
  ``ironclad.platform.tenancy`` with the authenticated principal's
  ``org_id``. A row belonging to another organization is a **404**, never a
  403, so object ids cannot be probed across tenants.
* Every mutating route records an audit entry.
* Nothing here shells out. ``POST /scan`` accepts a path, and that path is
  confined to the scan root by ``scanning.resolve_target`` before anything
  reads it.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session as DbSession

from ironclad import __version__
from ironclad.api import schemas
from ironclad.api.deps import (
    RequestContext,
    admin_required,
    get_context,
    get_db,
    require_principal,
)
from ironclad.core.policy import Policy, PolicyError
from ironclad.platform import audit, events
from ironclad.platform.jobs import JobQueue, JobSpec
from ironclad.platform.observability import registry
from ironclad.platform.observability import RATE_LIMITED
from ironclad.platform import egress, password_reset
from ironclad.platform.integrations import egress_allowlist
from ironclad.platform.ratelimit import Decision, client_ip
from ironclad.platform.models import (
    ApiToken,
    Baseline as BaselineRow,
    Component,
    Finding,
    FindingEvent,
    Integration,
    Job,
    Organization,
    Policy as PolicyRow,
    Project,
    Scan,
    Sbom,
    Session as SessionRow,
    User,
    utcnow,
)
from ironclad.platform.rbac import (
    ALL_PERMISSIONS,
    AUDIT_READ,
    ORGANIZATION_MANAGE,
    ORGANIZATION_READ,
    FINDING_MANAGE,
    FINDING_READ,
    INTEGRATION_MANAGE,
    INTEGRATION_READ,
    LICENSE_READ,
    ORGANIZATION_READ,
    POLICY_MANAGE,
    POLICY_READ,
    PROJECT_MANAGE,
    PROJECT_READ,
    SBOM_READ,
    SCAN_CANCEL,
    SCAN_CREATE,
    SCAN_READ,
    TOKEN_MANAGE,
    USER_MANAGE,
    USER_READ,
    describe_roles,
    normalize_scope,
    role_at_least,
)
from ironclad.platform.scanning import (
    TargetError,
    dashboard_summary,
    finding_trend,
    latest_sbom,
    license_summary,
    perform_scan,
    resolve_target,
)
from ironclad.platform.security import (
    SESSION_TTL_SECONDS,
    generate_api_token,
    generate_session_token,
    lockout_decision,
    password_problems,
    verify_password,
)
from ironclad.platform.tenancy import TenantError, get_for_org, org_query

auth_router = APIRouter(prefix="/auth", tags=["auth"])
users_router = APIRouter(prefix="/users", tags=["users"])
org_router = APIRouter(prefix="/org", tags=["organization"])
projects_router = APIRouter(prefix="/projects", tags=["projects"])
scan_router = APIRouter(tags=["scans"])
findings_router = APIRouter(prefix="/findings", tags=["findings"])
sbom_router = APIRouter(tags=["sbom"])
policy_router = APIRouter(prefix="/policies", tags=["policies"])
baseline_router = APIRouter(prefix="/baselines", tags=["baselines"])
integration_router = APIRouter(prefix="/integrations", tags=["integrations"])
audit_router = APIRouter(prefix="/audit", tags=["audit"])


def _too_many_requests(decision: Decision, what: str) -> HTTPException:
    """A 429 that tells the client what to do, with standard headers."""
    return HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        f"too many {what}; retry in {decision.retry_after}s",
        headers=decision.headers(),
    )


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _scan_out(session: DbSession, scan: Scan) -> schemas.ScanOut:
    count = session.execute(
        select(func.count(Finding.id)).where(Finding.scan_id == scan.id, Finding.org_id == scan.org_id)
    ).scalar_one()
    try:
        engines = json.loads(scan.engines or "[]")
    except ValueError:
        engines = []
    return schemas.ScanOut(
        id=scan.id, org_id=scan.org_id, project_id=scan.project_id, status=scan.status,
        target_path=scan.target_path, revision=scan.revision, created_at=_iso(scan.created_at),
        started_at=_iso(scan.started_at), finished_at=_iso(scan.finished_at),
        duration_seconds=scan.duration_seconds, files_scanned=scan.files_scanned,
        lines_scanned=scan.lines_scanned, engines=engines, risk_score=scan.risk_score,
        grade=scan.grade, policy_passed=scan.policy_passed,
        baseline_suppressed=scan.baseline_suppressed, baseline_expired=scan.baseline_expired,
        finding_count=int(count), error=scan.error,
    )


def _finding_out(finding: Finding) -> schemas.FindingOut:
    try:
        extra = json.loads(finding.extra or "{}")
    except ValueError:
        extra = {}
    return schemas.FindingOut(
        id=finding.id, scan_id=finding.scan_id, project_id=finding.project_id,
        fingerprint=finding.fingerprint, rule_id=finding.rule_id, title=finding.title,
        description=finding.description, severity=finding.severity, engine=finding.engine,
        category=finding.category, cwe=finding.cwe, owasp=finding.owasp,
        confidence=finding.confidence, remediation=finding.remediation,
        file_path=finding.file_path, start_line=finding.start_line, end_line=finding.end_line,
        snippet=finding.snippet, status=finding.status, baselined=bool(finding.baselined),
        extra=extra, first_seen_at=_iso(finding.first_seen_at), last_seen_at=_iso(finding.last_seen_at),
        resolved_at=_iso(finding.resolved_at),
    )


def _require_project(session: DbSession, org_id: int, project_id: int) -> Project:
    project = get_for_org(session, Project, org_id, project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    return project


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
@auth_router.post("/login", response_model=schemas.TokenResponse)
def login(body: schemas.LoginRequest, request: Request, session: DbSession = Depends(get_db)):
    limiter = request.app.state.limiter
    ip_decision = limiter.check_login(client_ip(request))
    if not ip_decision.allowed:
        # Deliberately NOT written to the audit log: this happens before
        # authentication, so there is no tenant to attribute it to, and
        # audit_events.org_id is a foreign key. Volume-based rejection is
        # observable through the limiter counter and the metrics endpoint
        # instead. Account-level lockout below *does* have an org and is
        # audited there.
        registry.inc(RATE_LIMITED, 1, "Requests rejected by rate limiting")
        raise _too_many_requests(ip_decision, "login attempts from this address")

    # Per-account volume limit, so an attacker cannot spend the full per-IP
    # budget guessing against one address either. Checked before the password
    # comparison so it costs the server nothing to reject.
    account_decision = limiter.check_login_account(body.email)
    if not account_decision.allowed:
        raise _too_many_requests(account_decision, "login attempts for this account")

    user = session.execute(
        select(User).where(User.email == body.email.lower())
    ).scalars().first()

    # A single generic error for "no such user" and "wrong password" so the
    # endpoint cannot be used to enumerate accounts.
    invalid = HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid email or password")
    if user is None:
        raise invalid

    decision = lockout_decision(user.failed_logins,
                                user.locked_until.timestamp() if user.locked_until else None)
    if not decision.allowed:
        audit.record(session, org_id=user.org_id, action="auth.login_blocked", actor=user.email,
                     actor_id=user.id, metadata={"reason": decision.reason})
        session.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many failed attempts; try again later")

    if not verify_password(body.password, user.password_hash):
        user.failed_logins += 1
        if user.failed_logins >= 5:
            user.locked_until = utcnow() + timedelta(seconds=900)
        audit.record(session, org_id=user.org_id, action="auth.login_failed", actor=user.email,
                     actor_id=user.id, metadata={"failures": user.failed_logins})
        session.commit()
        raise invalid

    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "account deactivated")

    token, token_hash = generate_session_token()
    session.add(SessionRow(user_id=user.id, org_id=user.org_id, token_hash=token_hash,
                           expires_at=utcnow() + timedelta(seconds=SESSION_TTL_SECONDS),
                           user_agent=(request.headers.get("user-agent") or "")[:200]))
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    limiter.reset_login_account(user.email)
    audit.record(session, org_id=user.org_id, action="auth.login", actor=user.email, actor_id=user.id)
    events.default_bus.publish(session, events.AUTH_LOGIN, user.org_id, {"user_id": user.id})
    session.commit()
    return schemas.TokenResponse(
        access_token=token, expires_in=SESSION_TTL_SECONDS,
        user=schemas.UserOut(id=user.id, email=user.email, full_name=user.full_name, role=user.role,
                             is_active=bool(user.is_active), org_id=user.org_id,
                             created_at=_iso(user.created_at), last_login_at=_iso(user.last_login_at)),
    )


@auth_router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, context: RequestContext = Depends(require_principal),
           session: DbSession = Depends(get_db),
           authorization: Optional[str] = None):
    from ironclad.api.deps import _extract_bearer
    from ironclad.platform.security import hash_token

    token = _extract_bearer(request.headers.get("authorization"))
    if token:
        row = session.execute(
            select(SessionRow).where(SessionRow.token_hash == hash_token(token),
                                     SessionRow.user_id == context.principal.user_id)
        ).scalar_one_or_none()
        if row is not None:
            row.revoked_at = utcnow()
    context.audit("auth.logout", target_type="user", target_id=str(context.principal.user_id))
    events.default_bus.publish(session, events.AUTH_LOGOUT, context.org_id,
                               {"user_id": context.principal.user_id})
    session.commit()
    return None


@auth_router.get("/me", response_model=schemas.UserOut)
def me(context: RequestContext = Depends(require_principal), session: DbSession = Depends(get_db)):
    user = session.get(User, context.principal.user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return schemas.UserOut(id=user.id, email=user.email, full_name=user.full_name, role=user.role,
                           is_active=bool(user.is_active), org_id=user.org_id,
                           created_at=_iso(user.created_at), last_login_at=_iso(user.last_login_at))


@auth_router.get("/permissions", response_model=Dict[str, List[str]])
def permissions(context: RequestContext = Depends(require_principal)):
    """Role -> permission matrix, so a UI can hide what the user cannot do."""
    return describe_roles()


@auth_router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(body: schemas.PasswordChangeRequest, request: Request,
                    context: RequestContext = Depends(require_principal),
                    session: DbSession = Depends(get_db)):
    from ironclad.platform.security import hash_password, needs_rehash

    user = session.get(User, context.principal.user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    pw_decision = request.app.state.limiter.check_password_change(user.id)
    if not pw_decision.allowed:
        raise _too_many_requests(pw_decision, "password change attempts")
    if not verify_password(body.current_password, user.password_hash):
        context.audit("auth.password_change_failed", target_type="user", target_id=str(user.id))
        session.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "current password is incorrect")
    problems = password_problems(body.new_password)
    if problems:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"new password rejected: {'; '.join(problems)}")
    user.password_hash = hash_password(body.new_password)
    # Changing a password invalidates every other session.
    session.execute(
        SessionRow.__table__.update()
        .where(SessionRow.user_id == user.id, SessionRow.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
    context.audit("auth.password_changed", target_type="user", target_id=str(user.id))
    session.commit()
    return None


@auth_router.post("/password-reset/request", response_model=schemas.PasswordResetRequestOut)
def request_password_reset(body: schemas.PasswordResetRequestIn, request: Request,
                           session: DbSession = Depends(get_db)):
    """Request a password reset link.

    Unauthenticated by design. The response is identical whether or not the
    address exists, and the unknown-address path burns comparable time, so
    this endpoint cannot be used to enumerate accounts.
    """
    limiter = request.app.state.limiter
    ip = client_ip(request)
    decision = limiter.check_password_reset_request(ip)
    if not decision.allowed:
        raise _too_many_requests(decision, "password reset requests from this address")

    outcome = password_reset.request_reset(
        session, email=body.email, transport=request.app.state.mail, request_ip=ip)
    session.commit()
    # `outcome.token` is never returned -- it exists only for tests and local
    # development via reveal_token, which this endpoint never sets.
    return schemas.PasswordResetRequestOut(accepted=outcome.accepted, message=outcome.message)


@auth_router.post("/password-reset/confirm", response_model=schemas.PasswordResetConfirmOut)
def confirm_password_reset(body: schemas.PasswordResetConfirmIn, request: Request,
                           session: DbSession = Depends(get_db)):
    """Redeem a reset token. Always returns 200; `ok` carries the result.

    Returning 200 with ok=false rather than a 4xx keeps every failure mode --
    unknown, expired, reused -- indistinguishable to a caller probing tokens.
    """
    limiter = request.app.state.limiter
    ip = client_ip(request)
    decision = limiter.check_password_reset_redeem(ip)
    if not decision.allowed:
        raise _too_many_requests(decision, "password reset confirmations from this address")

    outcome = password_reset.redeem_reset(
        session, token=body.token, new_password=body.new_password, request_ip=ip)
    session.commit()
    return schemas.PasswordResetConfirmOut(ok=outcome.ok, message=outcome.message)


@auth_router.post("/tokens", response_model=schemas.ApiTokenSecret, status_code=status.HTTP_201_CREATED)
def create_api_token(body: schemas.ApiTokenCreate, request: Request,
                     context: RequestContext = Depends(require_principal),
                     session: DbSession = Depends(get_db)):
    context.require(TOKEN_MANAGE)
    token_decision = request.app.state.limiter.check_token_create(context.principal.user_id)
    if not token_decision.allowed:
        raise _too_many_requests(token_decision, "API tokens created")
    token, token_hash, prefix = generate_api_token(body.name)
    requested = [normalize_scope(scope) for scope in body.scopes]
    unknown = sorted({scope for scope in requested if scope not in ALL_PERMISSIONS})
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown permission scope(s): {unknown}")
    scopes = ",".join(sorted(set(requested))) or "scan.read,scan.create,finding.read"
    row = ApiToken(org_id=context.org_id, user_id=context.principal.user_id, name=body.name,
                   token_hash=token_hash, token_prefix=prefix, scopes=scopes)
    session.add(row)
    session.flush()
    context.audit("token.created", target_type="api_token", target_id=str(row.id),
                  metadata={"name": row.name, "scopes": scopes})
    session.commit()
    return schemas.ApiTokenSecret(
        token=token,
        detail=schemas.ApiTokenOut(id=row.id, name=row.name, token_prefix=row.token_prefix,
                                   scopes=scopes.split(","), created_at=_iso(row.created_at),
                                   last_used_at=None, revoked_at=None),
    )


@auth_router.get("/tokens", response_model=List[schemas.ApiTokenOut])
def list_api_tokens(context: RequestContext = Depends(require_principal),
                    session: DbSession = Depends(get_db)):
    context.require(TOKEN_MANAGE)
    rows = session.execute(org_query(session, ApiToken, context.org_id)).scalars().all()
    return [schemas.ApiTokenOut(id=r.id, name=r.name, token_prefix=r.token_prefix,
                                scopes=(r.scopes or "").split(","), created_at=_iso(r.created_at),
                                last_used_at=_iso(r.last_used_at), revoked_at=_iso(r.revoked_at))
            for r in rows]


@auth_router.delete("/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_api_token(token_id: int, context: RequestContext = Depends(require_principal),
                     session: DbSession = Depends(get_db)):
    context.require(TOKEN_MANAGE)
    row = get_for_org(session, ApiToken, context.org_id, token_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    row.revoked_at = utcnow()
    context.audit("token.revoked", target_type="api_token", target_id=str(row.id))
    session.commit()
    return None


# --------------------------------------------------------------------------- #
# Organization / users
# --------------------------------------------------------------------------- #
@org_router.get("", response_model=schemas.OrganizationOut)
def get_org(context: RequestContext = Depends(require_principal), session: DbSession = Depends(get_db)):
    context.require(ORGANIZATION_READ)
    org = session.get(Organization, context.org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")
    return schemas.OrganizationOut(id=org.id, name=org.name, slug=org.slug, created_at=_iso(org.created_at))


@org_router.get("/egress-policy", response_model=schemas.EgressPolicyOut)
def get_egress_policy(context: RequestContext = Depends(require_principal),
                      session: DbSession = Depends(get_db)):
    """Read this organization's outbound egress policy."""
    context.require(ORGANIZATION_READ)
    org = session.get(Organization, context.org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")
    policy = egress.policy_from_settings(org.id, org.settings)
    global_allowlist = egress_allowlist()
    effective = egress.effective_allowlist(policy.as_allowlist())
    return schemas.EgressPolicyOut(
        org_id=org.id,
        enabled=policy.enabled,
        entries=sorted(policy.entries),
        effective=sorted(effective) if effective is not None else None,
        global_allowlist=sorted(global_allowlist) if global_allowlist is not None else None,
    )


@org_router.put("/egress-policy", response_model=schemas.EgressPolicyOut)
def put_egress_policy(body: schemas.EgressPolicyUpdate, request: Request,
                      context: RequestContext = Depends(require_principal),
                      session: DbSession = Depends(get_db)):
    """Replace this organization's egress allowlist.

    An empty list removes the policy. Every entry is validated up front and
    all problems are returned at once, so a caller can fix them in one pass.
    The change is audited because it governs outbound network reach.
    """
    context.require(ORGANIZATION_MANAGE)
    org = session.get(Organization, context.org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization not found")

    problems = egress.validate_allowlist(body.entries)
    if problems:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, problems)

    entries = sorted({egress.normalise_entry(e) for e in body.entries if e.strip()})
    previous = sorted(egress.policy_from_settings(org.id, org.settings).entries)
    org.settings = egress.settings_with_policy(org.settings, entries)

    context.audit("org.egress_policy_updated", target_type="organization",
                  target_id=str(org.id),
                  metadata={"previous": previous, "entries": entries})
    session.commit()

    policy = egress.policy_from_settings(org.id, org.settings)
    effective = egress.effective_allowlist(policy.as_allowlist())
    global_allowlist = egress_allowlist()
    return schemas.EgressPolicyOut(
        org_id=org.id, enabled=policy.enabled, entries=sorted(policy.entries),
        effective=sorted(effective) if effective is not None else None,
        global_allowlist=sorted(global_allowlist) if global_allowlist is not None else None,
    )


@users_router.get("", response_model=List[schemas.UserOut])
def list_users(context: RequestContext = Depends(require_principal), session: DbSession = Depends(get_db)):
    context.require(USER_READ)
    rows = session.execute(org_query(session, User, context.org_id)).scalars().all()
    return [schemas.UserOut(id=u.id, email=u.email, full_name=u.full_name, role=u.role,
                            is_active=bool(u.is_active), org_id=u.org_id,
                            created_at=_iso(u.created_at), last_login_at=_iso(u.last_login_at))
            for u in rows]


@users_router.post("", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: schemas.UserCreate, context: RequestContext = Depends(admin_required),
                session: DbSession = Depends(get_db)):
    from ironclad.platform.security import hash_password

    problems = password_problems(body.password)
    if problems:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"password rejected: {'; '.join(problems)}")
    existing = session.execute(
        select(User).where(User.org_id == context.org_id, User.email == body.email.lower())
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "a user with that email already exists")
    user = User(org_id=context.org_id, email=body.email.lower(), password_hash=hash_password(body.password),
                full_name=body.full_name, role=body.role)
    session.add(user)
    session.flush()
    context.audit("user.created", target_type="user", target_id=str(user.id), metadata={"role": user.role})
    session.commit()
    return schemas.UserOut(id=user.id, email=user.email, full_name=user.full_name, role=user.role,
                           is_active=True, org_id=user.org_id, created_at=_iso(user.created_at),
                           last_login_at=None)


@users_router.patch("/{user_id}/role", response_model=schemas.UserOut)
def change_role(user_id: int, body: schemas.RoleUpdate,
                context: RequestContext = Depends(admin_required),
                session: DbSession = Depends(get_db)):
    user = get_for_org(session, User, context.org_id, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    # Privilege escalation guard: only an owner may grant owner.
    if body.role == "owner" and not role_at_least(context.principal.role, "owner"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only an owner can grant the owner role")
    if user.id == context.principal.user_id and not role_at_least(body.role, "admin"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "you cannot demote yourself below admin")
    previous = user.role
    user.role = body.role
    context.audit("user.role_changed", target_type="user", target_id=str(user.id),
                  metadata={"from": previous, "to": body.role})
    session.commit()
    return schemas.UserOut(id=user.id, email=user.email, full_name=user.full_name, role=user.role,
                           is_active=bool(user.is_active), org_id=user.org_id,
                           created_at=_iso(user.created_at), last_login_at=_iso(user.last_login_at))


# --------------------------------------------------------------------------- #
# Projects
# --------------------------------------------------------------------------- #
@projects_router.get("", response_model=List[schemas.ProjectOut])
def list_projects(context: RequestContext = Depends(require_principal),
                  session: DbSession = Depends(get_db)):
    context.require(PROJECT_READ)
    rows = session.execute(
        org_query(session, Project, context.org_id).where(Project.archived_at.is_(None))
        .order_by(Project.name)
    ).scalars().all()
    return [schemas.ProjectOut(id=p.id, name=p.name, slug=p.slug, description=p.description,
                               default_branch=p.default_branch, archived_at=_iso(p.archived_at),
                               created_at=_iso(p.created_at)) for p in rows]


@projects_router.post("", response_model=schemas.ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(body: schemas.ProjectCreate, context: RequestContext = Depends(require_principal),
                   session: DbSession = Depends(get_db)):
    context.require(PROJECT_MANAGE)
    slug = body.name.strip().lower().replace(" ", "-")[:80] or "project"
    existing = session.execute(
        select(Project).where(Project.org_id == context.org_id, Project.slug == slug)
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "a project with that name already exists")
    project = Project(org_id=context.org_id, name=body.name, slug=slug,
                      description=body.description, default_branch=body.default_branch)
    session.add(project)
    session.flush()
    context.audit("project.created", target_type="project", target_id=str(project.id),
                  metadata={"slug": slug})
    session.commit()
    return schemas.ProjectOut(id=project.id, name=project.name, slug=project.slug,
                              description=project.description, default_branch=project.default_branch,
                              archived_at=None, created_at=_iso(project.created_at))


@projects_router.get("/{project_id}", response_model=schemas.ProjectOut)
def get_project(project_id: int, context: RequestContext = Depends(require_principal),
                session: DbSession = Depends(get_db)):
    context.require(PROJECT_READ)
    project = _require_project(session, context.org_id, project_id)
    return schemas.ProjectOut(id=project.id, name=project.name, slug=project.slug,
                              description=project.description, default_branch=project.default_branch,
                              archived_at=_iso(project.archived_at), created_at=_iso(project.created_at))


@projects_router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def archive_project(project_id: int, context: RequestContext = Depends(require_principal),
                    session: DbSession = Depends(get_db)):
    """Archive rather than delete: findings and audit history must survive."""
    context.require(PROJECT_MANAGE)
    project = _require_project(session, context.org_id, project_id)
    project.archived_at = utcnow()
    context.audit("project.archived", target_type="project", target_id=str(project.id))
    session.commit()
    return None


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #
@scan_router.post("/scan", response_model=schemas.ScanOut, status_code=status.HTTP_202_ACCEPTED)
def request_scan(body: schemas.ScanRequest, request: Request,
                 context: RequestContext = Depends(require_principal),
                 session: DbSession = Depends(get_db)):
    """Queue a scan. Returns 202 immediately unless ``wait`` is set."""
    context.require(SCAN_CREATE)
    _require_project(session, context.org_id, body.project_id)
    try:
        target = resolve_target(body.target)
    except TargetError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    policy_document = body.policy
    if policy_document is not None:
        try:
            Policy.from_dict(policy_document)
        except PolicyError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, exc.problems) from exc
    if body.policy_id is not None and get_for_org(session, PolicyRow, context.org_id, body.policy_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "policy not found")

    if body.idempotency_key:
        existing = session.execute(
            select(Scan).where(Scan.org_id == context.org_id, Scan.idempotency_key == body.idempotency_key)
        ).scalar_one_or_none()
        if existing is not None:
            # Idempotent replay: same key returns the same scan, no duplicate work.
            return _scan_out(session, existing)

    scan = Scan(org_id=context.org_id, project_id=body.project_id, status="queued",
                target_path=target, revision=body.revision, requested_by=context.principal.user_id,
                idempotency_key=body.idempotency_key, policy_id=body.policy_id)
    session.add(scan)
    session.flush()

    payload = {"scan_id": scan.id, "org_id": context.org_id, "project_id": body.project_id,
               "target": target, "policy_id": body.policy_id, "policy_document": policy_document,
               "actor": context.principal.email}
    queue: JobQueue = request.app.state.queue
    queue.enqueue(session, JobSpec(kind="scan.run", org_id=context.org_id, payload=payload))
    events.default_bus.publish(session, events.SCAN_CREATED, context.org_id,
                               {"scan_id": scan.id, "project_id": body.project_id},
                               subject_id=str(scan.id))
    context.audit("scan.created", target_type="scan", target_id=str(scan.id),
                  metadata={"project_id": body.project_id, "target": target})
    session.commit()

    if body.wait:
        _run_scan_inline(request, session, context, scan.id, payload)
        session.refresh(scan)
    return _scan_out(session, scan)


def _run_scan_inline(request: Request, session: DbSession, context: RequestContext,
                     scan_id: int, payload: Dict[str, Any]) -> None:
    """Execute a queued scan synchronously (small repos, CI, tests)."""
    from ironclad.platform.scanning import resolve_policy

    scan = get_for_org(session, Scan, context.org_id, scan_id)
    if scan is None or scan.status not in ("queued", "running"):
        return
    policy = resolve_policy(session, context.org_id, payload.get("policy_id"),
                            payload.get("policy_document"))
    try:
        perform_scan(session, org_id=context.org_id, project_id=scan.project_id, scan_row=scan,
                     target=payload["target"], policy=policy, actor=payload.get("actor", "api"),
                     correlation_id=context.request_id)
    except Exception as exc:  # noqa: BLE001 - surfaced as a failed scan, not a 500
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"scan failed: {exc}") from exc
    session.commit()


@scan_router.get("/scan/{scan_id}", response_model=schemas.ScanOut)
def get_scan(scan_id: int, context: RequestContext = Depends(require_principal),
             session: DbSession = Depends(get_db)):
    context.require(SCAN_READ)
    scan = get_for_org(session, Scan, context.org_id, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return _scan_out(session, scan)


@scan_router.get("/scans", response_model=List[schemas.ScanOut])
def list_scans(project_id: Optional[int] = None,
               limit: int = Query(default=50, ge=1, le=schemas.MAX_PAGE_SIZE),
               offset: int = Query(default=0, ge=0),
               context: RequestContext = Depends(require_principal),
               session: DbSession = Depends(get_db)):
    context.require(SCAN_READ)
    statement = org_query(session, Scan, context.org_id)
    if project_id is not None:
        statement = statement.where(Scan.project_id == project_id)
    statement = statement.order_by(desc(Scan.id)).limit(limit).offset(offset)
    return [_scan_out(session, s) for s in session.execute(statement).scalars().all()]


@scan_router.post("/scan/{scan_id}/cancel", response_model=schemas.ScanOut)
def cancel_scan(scan_id: int, request: Request, context: RequestContext = Depends(require_principal),
                session: DbSession = Depends(get_db)):
    context.require(SCAN_CANCEL)
    scan = get_for_org(session, Scan, context.org_id, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    if scan.status in ("succeeded", "failed", "cancelled"):
        raise HTTPException(status.HTTP_409_CONFLICT, f"scan already {scan.status}")
    scan.status = "cancelled"
    scan.finished_at = utcnow()
    job = session.execute(
        select(Job).where(Job.org_id == context.org_id, Job.status.in_(("queued", "running")),
                          Job.kind == "scan.run")
    ).scalars().all()
    for candidate in job:
        try:
            if json.loads(candidate.payload or "{}").get("scan_id") == scan.id:
                request.app.state.queue.cancel(session, candidate)
        except ValueError:
            continue
    events.default_bus.publish(session, events.SCAN_CANCELLED, context.org_id, {"scan_id": scan.id},
                               subject_id=str(scan.id))
    context.audit("scan.cancelled", target_type="scan", target_id=str(scan.id))
    session.commit()
    return _scan_out(session, scan)


@scan_router.get("/scan/{scan_id}/findings", response_model=List[schemas.FindingOut])
def scan_findings(scan_id: int, severity: Optional[str] = None,
                  limit: int = Query(default=200, ge=1, le=schemas.MAX_PAGE_SIZE),
                  offset: int = Query(default=0, ge=0),
                  context: RequestContext = Depends(require_principal),
                  session: DbSession = Depends(get_db)):
    context.require(FINDING_READ)
    scan = get_for_org(session, Scan, context.org_id, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    statement = org_query(session, Finding, context.org_id).where(Finding.scan_id == scan.id)
    if severity:
        statement = statement.where(Finding.severity == severity)
    statement = statement.order_by(Finding.severity, Finding.file_path, Finding.start_line).limit(limit).offset(offset)
    return [_finding_out(f) for f in session.execute(statement).scalars().all()]


@scan_router.get("/scan/{scan_id}/result", response_model=schemas.ScanResultOut)
def scan_result(scan_id: int, context: RequestContext = Depends(require_principal),
                session: DbSession = Depends(get_db)):
    """Scan plus its policy decision, recomputed deterministically."""
    context.require(SCAN_READ)
    scan = get_for_org(session, Scan, context.org_id, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    decision = None
    document = None
    if scan.policy_document:
        document = json.loads(scan.policy_document)
    elif scan.policy_id:
        policy_row = get_for_org(session, PolicyRow, context.org_id, scan.policy_id)
        document = json.loads(policy_row.document) if policy_row is not None else None
    if document is not None:
        from ironclad.core.policy import evaluate_policy
        from ironclad.core.models import CodeLocation, Engine, Finding as CoreFinding
        from ironclad.core.models import ScanResult as CoreScanResult
        from ironclad.core.models import ScanStats, Severity

        rows = session.execute(
            org_query(session, Finding, context.org_id).where(Finding.scan_id == scan.id)
        ).scalars().all()
        findings = [
            CoreFinding(rule_id=r.rule_id, title=r.title, description=r.description,
                        severity=Severity(r.severity), engine=Engine(r.engine),
                        location=CodeLocation(file_path=r.file_path, start_line=r.start_line,
                                              end_line=r.end_line, snippet=r.snippet),
                        category=r.category, cwe=r.cwe or None, owasp=r.owasp or None,
                        remediation=r.remediation, confidence=r.confidence,
                        extra={**r.extra_dict(), "ecosystem": r.extra_dict().get("ecosystem", "*")},
                        fingerprint=r.fingerprint)
            for r in rows if not r.baselined
        ]
        result = CoreScanResult(target=scan.target_path, findings=findings, stats=ScanStats())
        outcome = evaluate_policy(result, Policy.from_dict(document))
        decision = schemas.PolicyDecisionOut(
            passed=outcome.passed, policy=outcome.policy_name,
            violation_count=len(outcome.violations),
            violations=[schemas.PolicyViolationOut(**v.to_dict()) for v in outcome.violations],
            summary=outcome.summary,
        )
    return schemas.ScanResultOut(scan=_scan_out(session, scan), decision=decision)


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@findings_router.get("", response_model=List[schemas.FindingOut])
def list_findings(project_id: Optional[int] = None, severity: Optional[str] = None,
                  finding_status: Optional[str] = Query(default=None, alias="status"),
                  rule_id: Optional[str] = None,
                  limit: int = Query(default=100, ge=1, le=schemas.MAX_PAGE_SIZE),
                  offset: int = Query(default=0, ge=0),
                  context: RequestContext = Depends(require_principal),
                  session: DbSession = Depends(get_db)):
    context.require(FINDING_READ)
    statement = org_query(session, Finding, context.org_id)
    if project_id is not None:
        statement = statement.where(Finding.project_id == project_id)
    if severity:
        statement = statement.where(Finding.severity == severity)
    if finding_status:
        statement = statement.where(Finding.status == finding_status)
    if rule_id:
        statement = statement.where(Finding.rule_id == rule_id)
    statement = statement.order_by(desc(Finding.id)).limit(limit).offset(offset)
    return [_finding_out(f) for f in session.execute(statement).scalars().all()]


@findings_router.get("/{finding_id}", response_model=schemas.FindingOut)
def get_finding(finding_id: int, context: RequestContext = Depends(require_principal),
                session: DbSession = Depends(get_db)):
    context.require(FINDING_READ)
    finding = get_for_org(session, Finding, context.org_id, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return _finding_out(finding)


@findings_router.get("/{finding_id}/events", response_model=List[schemas.FindingEventOut])
def finding_events(finding_id: int, context: RequestContext = Depends(require_principal),
                   session: DbSession = Depends(get_db)):
    context.require(FINDING_READ)
    if get_for_org(session, Finding, context.org_id, finding_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    rows = session.execute(
        org_query(session, FindingEvent, context.org_id).where(FindingEvent.finding_id == finding_id)
        .order_by(FindingEvent.id)
    ).scalars().all()
    out = []
    for row in rows:
        try:
            detail = json.loads(row.detail or "{}")
        except ValueError:
            detail = {}
        out.append(schemas.FindingEventOut(id=row.id, event_type=row.event_type, actor=row.actor,
                                           detail=detail, created_at=_iso(row.created_at)))
    return out


@findings_router.patch("/{finding_id}", response_model=schemas.FindingOut)
def update_finding(finding_id: int, body: schemas.FindingUpdate,
                   context: RequestContext = Depends(require_principal),
                   session: DbSession = Depends(get_db)):
    """Suppress or resolve a finding. Both are auditable state changes."""
    context.require(FINDING_MANAGE)
    finding = get_for_org(session, Finding, context.org_id, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    if body.status == "suppressed" and not body.reason.strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "a reason is required to suppress a finding")
    previous = finding.status
    finding.status = body.status
    if body.status in ("resolved", "suppressed"):
        finding.resolved_at = utcnow()
        finding.suppressed_by = context.principal.email
        finding.suppressed_reason = body.reason
    else:
        finding.resolved_at = None
    event_type = {"resolved": "finding.resolved", "suppressed": "finding.suppressed"}.get(
        body.status, "finding.reopened")
    session.add(FindingEvent(org_id=context.org_id, finding_id=finding.id, event_type=event_type,
                             actor=context.principal.email,
                             detail=json.dumps({"from": previous, "to": body.status,
                                                "reason": body.reason})))
    if event_type == "finding.suppressed":
        events.default_bus.publish(session, events.FINDING_SUPPRESSED, context.org_id,
                                   {"finding_id": finding.id, "reason": body.reason},
                                   subject_id=str(finding.id))
    elif event_type == "finding.resolved":
        events.default_bus.publish(session, events.FINDING_RESOLVED, context.org_id,
                                   {"finding_id": finding.id}, subject_id=str(finding.id))
    context.audit(f"finding.{body.status}", target_type="finding", target_id=str(finding.id),
                  metadata={"from": previous, "reason": body.reason})
    session.commit()
    return _finding_out(finding)


# --------------------------------------------------------------------------- #
# SBOM / licenses
# --------------------------------------------------------------------------- #
@sbom_router.get("/sbom", response_model=schemas.SbomOut)
def get_sbom(project_id: int, context: RequestContext = Depends(require_principal),
             session: DbSession = Depends(get_db)):
    context.require(SBOM_READ)
    _require_project(session, context.org_id, project_id)
    sbom = latest_sbom(session, context.org_id, project_id)
    if sbom is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no SBOM for this project yet")
    return schemas.SbomOut(id=sbom.id, project_id=sbom.project_id, scan_id=sbom.scan_id,
                           format=sbom.format, component_count=sbom.component_count,
                           created_at=_iso(sbom.created_at))


@sbom_router.get("/sbom/document")
def get_sbom_document(project_id: int, context: RequestContext = Depends(require_principal),
                      session: DbSession = Depends(get_db)):
    """Return the raw CycloneDX document so it can be uploaded unchanged."""
    context.require(SBOM_READ)
    sbom = latest_sbom(session, context.org_id, project_id)
    if sbom is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no SBOM for this project yet")
    try:
        return json.loads(sbom.document)
    except ValueError as exc:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "stored SBOM is corrupt") from exc


@sbom_router.get("/sbom/components", response_model=List[schemas.ComponentOut])
def list_components(project_id: int, license_class: Optional[str] = None,
                    context: RequestContext = Depends(require_principal),
                    session: DbSession = Depends(get_db)):
    context.require(SBOM_READ)
    sbom = latest_sbom(session, context.org_id, project_id)
    if sbom is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no SBOM for this project yet")
    statement = org_query(session, Component, context.org_id).where(Component.sbom_id == sbom.id)
    if license_class:
        statement = statement.where(Component.license_class == license_class)
    rows = session.execute(statement.order_by(Component.name)).scalars().all()
    return [schemas.ComponentOut(id=c.id, purl=c.purl, name=c.name, version=c.version,
                                 ecosystem=c.ecosystem, license=c.license, license_class=c.license_class)
            for c in rows]


@sbom_router.get("/licenses", response_model=schemas.LicenseSummaryOut)
def get_licenses(project_id: int, context: RequestContext = Depends(require_principal),
                 session: DbSession = Depends(get_db)):
    context.require(LICENSE_READ)
    _require_project(session, context.org_id, project_id)
    sbom = latest_sbom(session, context.org_id, project_id)
    blocked: List[schemas.ComponentOut] = []
    unknown: List[schemas.ComponentOut] = []
    if sbom is not None:
        for row in session.execute(
            org_query(session, Component, context.org_id)
            .where(Component.sbom_id == sbom.id,
                   or_(Component.license_class == "blocked", Component.license_class == "unknown"))
            .order_by(Component.name)
        ).scalars().all():
            item = schemas.ComponentOut(id=row.id, purl=row.purl, name=row.name, version=row.version,
                                        ecosystem=row.ecosystem, license=row.license,
                                        license_class=row.license_class)
            (blocked if row.license_class == "blocked" else unknown).append(item)
    return schemas.LicenseSummaryOut(project_id=project_id,
                                     counts=license_summary(session, context.org_id, project_id),
                                     blocked=blocked, unknown=unknown)


# --------------------------------------------------------------------------- #
# Policies / baselines
# --------------------------------------------------------------------------- #
@policy_router.get("", response_model=List[schemas.PolicyOut])
def list_policies(context: RequestContext = Depends(require_principal),
                  session: DbSession = Depends(get_db)):
    context.require(POLICY_READ)
    rows = session.execute(org_query(session, PolicyRow, context.org_id).order_by(PolicyRow.name)).scalars().all()
    return [schemas.PolicyOut(id=p.id, name=p.name, version=p.version, is_default=bool(p.is_default),
                              document=json.loads(p.document), created_at=_iso(p.created_at),
                              updated_at=_iso(p.updated_at)) for p in rows]


@policy_router.post("", response_model=schemas.PolicyOut, status_code=status.HTTP_201_CREATED)
def upsert_policy(body: schemas.PolicyUpsert, context: RequestContext = Depends(require_principal),
                  session: DbSession = Depends(get_db)):
    context.require(POLICY_MANAGE)
    try:
        Policy.from_dict(body.document)
    except PolicyError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, exc.problems) from exc
    row = session.execute(
        select(PolicyRow).where(PolicyRow.org_id == context.org_id, PolicyRow.name == body.name)
    ).scalar_one_or_none()
    document = json.dumps(body.document, sort_keys=True)
    if row is None:
        row = PolicyRow(org_id=context.org_id, name=body.name, version=1, document=document,
                        is_default=body.is_default, created_by=context.principal.user_id)
        session.add(row)
        action = "policy.created"
    else:
        row.document = document
        row.version += 1
        row.is_default = body.is_default
        row.updated_at = utcnow()
        action = "policy.updated"
    if body.is_default:
        session.execute(
            PolicyRow.__table__.update()
            .where(PolicyRow.org_id == context.org_id, PolicyRow.name != body.name)
            .values(is_default=False)
        )
    session.flush()
    context.audit(action, target_type="policy", target_id=str(row.id),
                  metadata={"name": row.name, "version": row.version, "is_default": row.is_default})
    session.commit()
    return schemas.PolicyOut(id=row.id, name=row.name, version=row.version,
                             is_default=bool(row.is_default), document=json.loads(row.document),
                             created_at=_iso(row.created_at), updated_at=_iso(row.updated_at))


@policy_router.post("/validate")
def validate_policy(body: schemas.PolicyUpsert, context: RequestContext = Depends(require_principal)):
    context.require(POLICY_READ)
    try:
        parsed = Policy.from_dict(body.document)
    except PolicyError as exc:
        return {"valid": False, "problems": exc.problems}
    return {"valid": True, "problems": [], "policy": parsed.to_dict()}


@policy_router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_policy(policy_id: int, context: RequestContext = Depends(require_principal),
                  session: DbSession = Depends(get_db)):
    context.require(POLICY_MANAGE)
    row = get_for_org(session, PolicyRow, context.org_id, policy_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "policy not found")
    context.audit("policy.deleted", target_type="policy", target_id=str(row.id),
                  metadata={"name": row.name})
    session.delete(row)
    session.commit()
    return None


@baseline_router.get("", response_model=List[schemas.BaselineOut])
def list_baselines(project_id: Optional[int] = None,
                   context: RequestContext = Depends(require_principal),
                   session: DbSession = Depends(get_db)):
    context.require(PROJECT_READ)
    statement = org_query(session, BaselineRow, context.org_id)
    if project_id is not None:
        statement = statement.where(BaselineRow.project_id == project_id)
    rows = session.execute(statement.order_by(BaselineRow.id)).scalars().all()
    return [schemas.BaselineOut(id=b.id, project_id=b.project_id, name=b.name, reason=b.reason,
                                created_by=b.created_by, count=b.count, created_at=_iso(b.created_at),
                                expires_at=_iso(b.expires_at)) for b in rows]


# --------------------------------------------------------------------------- #
# Integrations
# --------------------------------------------------------------------------- #
@integration_router.get("", response_model=List[schemas.IntegrationOut])
def list_integrations(context: RequestContext = Depends(require_principal),
                      session: DbSession = Depends(get_db)):
    context.require(INTEGRATION_READ)
    rows = session.execute(org_query(session, Integration, context.org_id)).scalars().all()
    return [_integration_out(row) for row in rows]


def _integration_out(row: Integration) -> schemas.IntegrationOut:
    try:
        config = json.loads(row.config or "{}")
    except ValueError:
        config = {}
    # Never echo a stored secret back to a caller.
    return schemas.IntegrationOut(id=row.id, kind=row.kind, name=row.name, config=config,
                                  enabled=bool(row.enabled), last_status=row.last_status,
                                  last_run_at=_iso(row.last_run_at), last_error=row.last_error,
                                  has_secret=bool(row.secret))


@integration_router.post("", response_model=schemas.IntegrationOut, status_code=status.HTTP_201_CREATED)
def create_integration(body: schemas.IntegrationCreate,
                       context: RequestContext = Depends(require_principal),
                       session: DbSession = Depends(get_db)):
    context.require(INTEGRATION_MANAGE)
    from ironclad.platform.integrations import validate_config

    problems = validate_config(body.kind, body.config)
    if problems:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, problems)
    row = Integration(org_id=context.org_id, kind=body.kind, name=body.name,
                      config=json.dumps(body.config, sort_keys=True), secret=body.secret,
                      enabled=body.enabled)
    session.add(row)
    session.flush()
    context.audit("integration.created", target_type="integration", target_id=str(row.id),
                  metadata={"kind": row.kind, "name": row.name})
    session.commit()
    return _integration_out(row)


@integration_router.delete("/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_integration(integration_id: int, context: RequestContext = Depends(require_principal),
                       session: DbSession = Depends(get_db)):
    context.require(INTEGRATION_MANAGE)
    row = get_for_org(session, Integration, context.org_id, integration_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "integration not found")
    context.audit("integration.deleted", target_type="integration", target_id=str(row.id),
                  metadata={"kind": row.kind, "name": row.name})
    session.delete(row)
    session.commit()
    return None


@integration_router.post("/{integration_id}/test", response_model=schemas.IntegrationOut)
def test_integration(integration_id: int, context: RequestContext = Depends(require_principal),
                     session: DbSession = Depends(get_db)):
    """Deliver a real test payload and record the outcome."""
    context.require(INTEGRATION_MANAGE)
    row = get_for_org(session, Integration, context.org_id, integration_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "integration not found")
    from ironclad.platform.integrations import deliver

    outcome = deliver(row, {"event": "integration.test", "integration": row.name,
                            "organization_id": row.org_id})
    row.last_status = "ok" if outcome.ok else "failed"
    row.last_run_at = utcnow()
    row.last_error = "" if outcome.ok else outcome.error[:500]
    if outcome.ok:
        events.default_bus.publish(session, events.INTEGRATION_SUCCEEDED, context.org_id,
                                   {"integration_id": row.id}, subject_id=str(row.id))
    else:
        events.default_bus.publish(session, events.INTEGRATION_FAILED, context.org_id,
                                   {"integration_id": row.id, "error": outcome.error},
                                   subject_id=str(row.id))
    context.audit("integration.tested", target_type="integration", target_id=str(row.id),
                  metadata={"ok": outcome.ok})
    session.commit()
    return _integration_out(row)


# --------------------------------------------------------------------------- #
# Audit / jobs
# --------------------------------------------------------------------------- #
@audit_router.get("/export")
def export_audit(format: str = Query(default="jsonl", pattern="^(jsonl|csv)$"),
                 action: Optional[str] = None,
                 actor: Optional[str] = None,
                 since: Optional[str] = None,
                 until: Optional[str] = None,
                 context: RequestContext = Depends(require_principal),
                 session: DbSession = Depends(get_db)):
    """Export the full audit trail for an auditor.

    The paged listing caps at 200 records, which is unusable as compliance
    evidence. This streams the whole trail as newline-delimited JSON or CSV.
    """
    context.require(AUDIT_READ)

    parsed_since = _parse_iso_filter(since, "since")
    parsed_until = _parse_iso_filter(until, "until")
    if parsed_since and parsed_until and parsed_since > parsed_until:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "'since' is after 'until'")

    filters = {"action": action, "actor": actor, "since": parsed_since, "until": parsed_until}
    if format == "csv":
        body = audit.export_csv(session, context.org_id, **filters)
        media = "text/csv; charset=utf-8"
        extension = "csv"
    else:
        body = audit.export_json_lines(session, context.org_id, **filters)
        media = "application/x-ndjson; charset=utf-8"
        extension = "jsonl"

    records = body.count("\n") if body else 0
    context.audit("audit.exported", target_type="audit_events",
                  metadata={"format": format, "records": records})
    session.commit()

    from fastapi.responses import Response

    return Response(
        content=body,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="ironclad-audit.{extension}"',
            "X-Audit-Records": str(records),
        },
    )


@audit_router.get("/retention", response_model=schemas.RetentionPreview)
def audit_retention_preview(retention_days: int = Query(ge=0, le=36500),
                            context: RequestContext = Depends(require_principal),
                            session: DbSession = Depends(get_db)):
    """Preview what a retention policy would remove. Nothing is deleted."""
    context.require(AUDIT_READ)
    return schemas.RetentionPreview(
        **audit.retention_summary(session, context.org_id, retention_days=retention_days))


@audit_router.post("/retention/purge", response_model=schemas.RetentionPreview)
def audit_retention_purge(body: schemas.RetentionPurgeRequest, request: Request,
                          context: RequestContext = Depends(require_principal),
                          session: DbSession = Depends(get_db)):
    """Delete audit records older than the retention window.

    Irreversible, so it requires the strongest audit permission and the purge
    is itself audited before the delete runs.
    """
    context.require(AUDIT_READ)
    if not role_at_least(context.principal.role, "admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "purging audit history requires the admin role")
    summary = audit.purge_expired(session, context.org_id,
                                  retention_days=body.retention_days,
                                  actor=context.principal.email,
                                  request_id=context.request_id)
    session.commit()
    return schemas.RetentionPreview(**summary)


def _parse_iso_filter(value: Optional[str], name: str):
    if not value:
        return None
    from datetime import datetime

    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                        f"'{name}' must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS")


@audit_router.get("", response_model=List[schemas.AuditOut])
def list_audit(action: Optional[str] = None,
               limit: int = Query(default=100, ge=1, le=schemas.MAX_PAGE_SIZE),
               offset: int = Query(default=0, ge=0),
               context: RequestContext = Depends(require_principal),
               session: DbSession = Depends(get_db)):
    context.require(AUDIT_READ)
    rows = audit.list_for_org(session, context.org_id, action=action, limit=limit, offset=offset)
    return [schemas.AuditOut(**audit.to_dict(row)) for row in rows]


@scan_router.get("/jobs", response_model=List[schemas.JobOut])
def list_jobs(context: RequestContext = Depends(require_principal), session: DbSession = Depends(get_db)):
    context.require(SCAN_READ)
    rows = session.execute(
        org_query(session, Job, context.org_id).order_by(desc(Job.id)).limit(100)
    ).scalars().all()
    return [schemas.JobOut(id=j.id, kind=j.kind, status=j.status, attempts=j.attempts,
                           max_attempts=j.max_attempts, scheduled_at=_iso(j.scheduled_at),
                           started_at=_iso(j.started_at), finished_at=_iso(j.finished_at),
                           error=j.error) for j in rows]


@scan_router.get("/dashboard", response_model=schemas.DashboardOut)
def dashboard(project_id: Optional[int] = None, context: RequestContext = Depends(require_principal),
              session: DbSession = Depends(get_db)):
    """Every number on the dashboard home page, computed from stored data."""
    context.require(PROJECT_READ)
    summary = dashboard_summary(session, context.org_id)
    trend = finding_trend(session, context.org_id, project_id)
    counts: Dict[str, int] = {"allowed": 0, "warning": 0, "blocked": 0, "unknown": 0}
    if project_id is not None:
        counts = license_summary(session, context.org_id, project_id)
    return schemas.DashboardOut(summary=summary, trend=trend, license_counts=counts)


ALL_ROUTERS = [auth_router, users_router, org_router, projects_router, scan_router,
               findings_router, sbom_router, policy_router, baseline_router,
               integration_router, audit_router]
