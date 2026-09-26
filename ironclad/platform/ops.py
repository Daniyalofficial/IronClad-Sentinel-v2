"""Local operator recovery for accounts without working email delivery.

These commands need direct database access, not an unauthenticated HTTP
endpoint. They deliberately refuse a missing SQLite file so a typo cannot
silently create a second, empty database and report a false recovery.
"""
from __future__ import annotations

import os
from typing import Optional

from sqlalchemy import select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from ironclad.platform.audit import record as audit_record
from ironclad.platform.database import (
    DEFAULT_SQLITE_URL, SQLITE_URL_ENV, build_engine, detect_dialect, session_scope,
)
from ironclad.platform.models import (
    ApiToken, Organization, PasswordResetToken, Session as SessionRow, User, utcnow,
)
from ironclad.platform.security import hash_password, password_problems


class OperationsError(ValueError):
    """An operator request is unsafe or cannot be completed."""


def _existing_engine(database_url: Optional[str]):
    url = database_url or os.environ.get(SQLITE_URL_ENV) or DEFAULT_SQLITE_URL
    try:
        dialect = detect_dialect(url)
        parsed = make_url(url)
    except Exception as exc:  # noqa: BLE001 - reject an invalid operator-supplied URL
        raise OperationsError(f"invalid database URL: {exc}") from exc
    if dialect == "sqlite":
        path = parsed.database
        if not path or path == ":memory:" or not os.path.isfile(path):
            location = os.path.abspath(path) if path and path != ":memory:" else str(path)
            raise OperationsError(
                f"database not initialized at {location}; check --database-url and run server init")
    engine = None
    try:
        engine = build_engine(url)
        with engine.connect() as connection:
            connection.execute(text("SELECT 1 FROM organizations LIMIT 1"))
    except Exception as exc:  # noqa: BLE001 - connection/schema errors must include a recovery hint
        if engine is not None:
            engine.dispose()
        raise OperationsError(
            f"database not initialized or unreachable; check --database-url: {type(exc).__name__}"
        ) from exc
    return engine


def _account(session: Session, org_slug: str, email: str) -> User:
    org = session.execute(select(Organization).where(
        Organization.slug == org_slug.strip())).scalar_one_or_none()
    if org is None:
        raise OperationsError(f"organization {org_slug!r} not found")
    user = session.execute(select(User).where(
        User.org_id == org.id, User.email == email.strip().lower())).scalar_one_or_none()
    if user is None:
        raise OperationsError(f"account {email!r} not found in organization {org_slug!r}")
    if not user.is_active:
        raise OperationsError("account is deactivated; recovery will not reactivate it")
    return user


def reset_password(*, database_url: Optional[str], org_slug: str,
                   email: str, new_password: str) -> int:
    """Reset one account, revoke credentials and outstanding reset links.

    The database transaction includes the password, lockout, session/token
    revocation and audit entry. A failure cannot leave half of those behind.
    """
    problems = password_problems(new_password)
    if problems:
        raise OperationsError(f"password rejected: {'; '.join(problems)}")

    engine = _existing_engine(database_url)
    try:
        with session_scope(engine) as session:
            user = _account(session, org_slug, email)
            now = utcnow()
            user.password_hash = hash_password(new_password)
            user.failed_logins = 0
            user.locked_until = None
            sessions = session.execute(update(SessionRow).where(
                SessionRow.user_id == user.id, SessionRow.revoked_at.is_(None))
                .values(revoked_at=now)).rowcount
            tokens = session.execute(update(ApiToken).where(
                ApiToken.user_id == user.id, ApiToken.revoked_at.is_(None))
                .values(revoked_at=now)).rowcount
            session.execute(update(PasswordResetToken).where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used_at.is_(None)).values(used_at=now))
            audit_record(session, org_id=user.org_id, action="auth.password_reset_operator",
                         actor="local-operator", target_type="user", target_id=str(user.id),
                         metadata={"email": user.email, "sessions_revoked": sessions,
                                   "api_credentials_revoked": tokens})
            return user.id
    finally:
        engine.dispose()


def unlock(*, database_url: Optional[str], org_slug: str, email: str) -> int:
    """Clear lockout only; leave the password and existing sessions intact."""
    engine = _existing_engine(database_url)
    try:
        with session_scope(engine) as session:
            user = _account(session, org_slug, email)
            user.failed_logins = 0
            user.locked_until = None
            audit_record(session, org_id=user.org_id, action="auth.unlock_operator",
                         actor="local-operator", target_type="user", target_id=str(user.id),
                         metadata={"email": user.email})
            return user.id
    finally:
        engine.dispose()
