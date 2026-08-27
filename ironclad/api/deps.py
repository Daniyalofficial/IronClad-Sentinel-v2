"""API dependencies: authentication, authorization and request context.

Two credential types are accepted:

* **Session bearer tokens** issued by ``POST /auth/login`` and stored
  server-side in the ``sessions`` table (hashed). Revoking a session takes
  effect on the next request.
* **API tokens** (``ics_…``) for CI and integrations. Also stored hashed,
  and a token's scopes can only *narrow* the owning user's permissions.

Everything else is denied: no anonymous write path, no "trust the
X-Org-Id header", no implicit admin.
"""
from __future__ import annotations

import os
from typing import Optional

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from ironclad.platform import audit
from ironclad.platform.database import session_factory, session_scope
from ironclad.platform.models import ApiToken, Session as SessionRow, User, utcnow
from ironclad.platform.observability import request_scope, set_request_context
from ironclad.platform.rbac import PermissionDenied, Principal
from ironclad.platform.security import constant_time_equals, hash_token


class RequestContext:
    """Bundles the database session, principal and request id for one call."""

    def __init__(self, session: DbSession, principal: Optional[Principal], request_id: str,
                 auth_kind: str = "anonymous"):
        self.session = session
        self.principal = principal
        self.request_id = request_id
        self.auth_kind = auth_kind

    @property
    def org_id(self) -> int:
        if self.principal is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
        return self.principal.org_id

    def require(self, permission: str) -> Principal:
        if self.principal is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
        try:
            return self.principal.require(permission)
        except PermissionDenied as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc

    def audit(self, action: str, *, target_type: str = "", target_id: str = "",
              metadata: Optional[dict] = None, org_id: Optional[int] = None) -> None:
        """Append an audit record inside the current request's transaction."""
        if self.session is None:
            raise RuntimeError(
                "audit() called without a database session; the route must depend on get_db")
        if self.principal is None and org_id is None:
            return
        audit.record(self.session, org_id=org_id or self.org_id, action=action,
                     actor=self.principal.email if self.principal else "anonymous",
                     actor_id=self.principal.user_id if self.principal else None,
                     target_type=target_type, target_id=target_id, metadata=metadata,
                     request_id=self.request_id)


def _extract_bearer(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None


def _authenticate(session: DbSession, token: str) -> tuple[Optional[Principal], str]:
    if token.startswith("ics_"):
        row = session.execute(
            select(ApiToken).where(ApiToken.token_hash == hash_token(token))
        ).scalar_one_or_none()
        if row is None or row.revoked_at is not None:
            return None, "api-token"
        user = session.get(User, row.user_id)
        if user is None or not user.is_active:
            return None, "api-token"
        row.last_used_at = utcnow()
        scopes = frozenset(s.strip() for s in (row.scopes or "").split(",") if s.strip())
        return Principal(user_id=user.id, org_id=user.org_id, email=user.email, role=user.role,
                         is_active=bool(user.is_active), token_scopes=scopes), "api-token"

    row = session.execute(
        select(SessionRow).where(SessionRow.token_hash == hash_token(token))
    ).scalar_one_or_none()
    if row is None or row.revoked_at is not None:
        return None, "session"
    if row.expires_at is not None and row.expires_at < utcnow():
        return None, "session"
    user = session.get(User, row.user_id)
    if user is None or not user.is_active:
        return None, "session"
    return Principal(user_id=user.id, org_id=user.org_id, email=user.email, role=user.role,
                     is_active=bool(user.is_active)), "session"


def get_context(request: Request,
                authorization: Optional[str] = Header(default=None)) -> RequestContext:
    """Resolve the request context. Unauthenticated requests still get a
    context (so ``/health`` and ``/auth/login`` work) with ``principal=None``.
    """
    engine = request.app.state.engine
    request_id = getattr(request.state, "request_id", "") or ""
    token = _extract_bearer(authorization)
    with session_scope(engine) as session:
        principal, kind = (None, "anonymous")
        if token:
            principal, kind = _authenticate(session, token)
            if principal is None:
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired credentials")
        if principal is not None:
            set_request_context(request_id=request_id, org_id=principal.org_id)
        request.state.principal = principal
    return RequestContext(session=None, principal=principal, request_id=request_id, auth_kind=kind)  # type: ignore[arg-type]


def get_db(request: Request, context: RequestContext = Depends(get_context)):
    """Open the one session used by this request and close it afterwards.

    The session is also attached to the request context so that
    ``context.audit(...)`` writes into the same transaction as the route
    body -- an audit record must never be committed separately from the
    change it describes, and must never be written to a ``None`` session.

    Committing stays explicit at the call site (``session.commit()``) so a
    route that fails validation cannot half-write.
    """
    session = session_factory(request.app.state.engine)()
    context.session = session
    try:
        yield session
    finally:
        context.session = None
        session.close()


# Backwards-compatible alias.
db_session = get_db


def require_principal(context: RequestContext = Depends(get_context)) -> RequestContext:
    if context.principal is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    return context


def admin_required(context: RequestContext = Depends(require_principal)) -> RequestContext:
    from ironclad.platform.rbac import role_at_least

    if not role_at_least(context.principal.role, "admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "administrator role required")
    return context


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify an ``sha256=<hex>`` HMAC signature in constant time."""
    import hashlib
    import hmac

    if not signature or not secret:
        return False
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    provided = signature.split("=", 1)[-1].strip()
    return constant_time_equals(expected, provided)


def cors_allowed_origins() -> list:
    """Explicit allowlist; the API never reflects an arbitrary Origin."""
    raw = os.environ.get("IRONCLAD_CORS_ORIGINS", "")
    return [origin.strip() for origin in raw.split(",") if origin.strip()]
