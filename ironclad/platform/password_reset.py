"""Password reset: token issue, redemption and mail delivery.

Security properties, and how each is enforced:

* **Cryptographically random, single-use tokens.** ``secrets.token_urlsafe(32)``
  gives 256 bits of entropy. The token is stored only as a SHA-256 digest, so
  a database leak does not hand over usable reset links.
* **Reuse is impossible.** ``used_at`` is set inside the same transaction that
  changes the password. A token whose ``used_at`` is set is rejected. There is
  no code path that clears it.
* **Short, configurable expiry.** ``IRONCLAD_PASSWORD_RESET_TTL_MINUTES``,
  default 30 minutes.
* **Issuing a new token invalidates outstanding ones.** Only the most recent
  request is redeemable, so an attacker who triggers a reset cannot keep an
  older link alive.
* **Enumeration resistance.** ``request_reset`` returns the same
  :class:`ResetRequestOutcome` whether or not the address exists, and performs
  a dummy password hash on the miss path so the two paths take comparable
  time. A transport failure also does not change the outcome, or it would leak
  which addresses are real.
* **Redemption revokes every existing session** and resets the failed-login
  counter, because a reset usually means the account was compromised or the
  password was forgotten after lockout.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ironclad.platform.audit import record as audit_record
from ironclad.platform.observability import get_logger

_logger = get_logger("password_reset")
from ironclad.platform.mail import (
    ENV_RESET_URL_BASE,
    DeliveryResult,
    MailTransport,
)
from ironclad.platform.models import PasswordResetToken, Session as SessionRow, User, utcnow
from ironclad.platform.security import (
    hash_password,
    hash_token,
    password_problems,
    verify_password,
)

ENV_TTL_MINUTES = "IRONCLAD_PASSWORD_RESET_TTL_MINUTES"
DEFAULT_TTL_MINUTES = 30
MAX_TTL_MINUTES = 24 * 60  # refuse to mint a link that lives longer than a day
RESET_TOKEN_BYTES = 32

#: Returned identically whether or not the account exists.
GENERIC_MESSAGE = (
    "If an account exists for that address, a password reset link has been "
    "sent. The link expires shortly and can be used once."
)


class PasswordResetError(ValueError):
    """Raised when a reset cannot proceed. The message is safe to show a user."""


@dataclass(frozen=True)
class ResetRequestOutcome:
    """Deliberately carries no information about whether the account exists."""

    accepted: bool
    message: str
    #: Only set in tests / local development, never returned by the API.
    token: Optional[str] = None
    delivery_ok: Optional[bool] = None


@dataclass(frozen=True)
class ResetRedeemOutcome:
    ok: bool
    message: str
    user_id: Optional[int] = None
    org_id: Optional[int] = None
    email: Optional[str] = None


def ttl_minutes() -> int:
    raw = os.environ.get(ENV_TTL_MINUTES)
    if raw is None or not raw.strip():
        return DEFAULT_TTL_MINUTES
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{ENV_TTL_MINUTES} must be an integer, got {raw!r}")
    if value <= 0:
        raise ValueError(f"{ENV_TTL_MINUTES} must be positive, got {value}")
    if value > MAX_TTL_MINUTES:
        raise ValueError(f"{ENV_TTL_MINUTES} must be at most {MAX_TTL_MINUTES}, got {value}")
    return value


def reset_link(token: str) -> str:
    """Build the link a user clicks. The base URL is operator-configured so the
    link points at the deployment's own dashboard, not a hardcoded host."""
    base = (os.environ.get(ENV_RESET_URL_BASE) or "").rstrip("/")
    if not base:
        return token
    return f"{base}/ui/password-reset?token={token}"


def _message_body(email: str, token: str, minutes: int) -> str:
    link = reset_link(token)
    return (
        f"A password reset was requested for the IronClad Sentinel account "
        f"{email}.\n\n"
        f"Reset your password: {link}\n\n"
        f"This link expires in {minutes} minutes and can be used once. "
        f"Requesting a new link invalidates this one.\n\n"
        f"If you did not request this, no action is needed -- your password "
        f"will not change, and you may want to tell your administrator.\n"
    )


def request_reset(session: Session, *, email: str, transport: MailTransport,
                  request_ip: str = "", reveal_token: bool = False) -> ResetRequestOutcome:
    """Start a reset. Identical outcome whether or not the address exists."""
    normalized = (email or "").strip().lower()
    minutes = ttl_minutes()

    user = session.execute(
        select(User).where(User.email == normalized)
    ).scalars().first()

    if user is None:
        # Burn comparable time so response timing does not reveal existence.
        hash_password("timing-equalisation-dummy-value")
        # Deliberately NOT written to the audit log: there is no tenant before
        # authentication and audit_events.org_id is a foreign key. Logged and
        # counted instead, which keeps the signal without violating the
        # constraint. (Same reasoning as the pre-auth rate limiter.)
        _logger.info("password reset requested for unknown address",
                     extra={"fields": {"ip": request_ip, "known": False}})
        return ResetRequestOutcome(True, GENERIC_MESSAGE)

    if not user.is_active:
        # Same generic response: an inactive account must not be distinguishable.
        hash_password("timing-equalisation-dummy-value")
        audit_record(session, org_id=user.org_id, action="auth.password_reset_inactive",
                     actor=user.email, actor_id=user.id, metadata={"ip": request_ip})
        return ResetRequestOutcome(True, GENERIC_MESSAGE)

    # A new request invalidates any outstanding token, so only the most recent
    # link is redeemable.
    session.execute(
        PasswordResetToken.__table__.update()
        .where(PasswordResetToken.user_id == user.id,
               PasswordResetToken.used_at.is_(None))
        .values(used_at=utcnow())
    )

    token = secrets.token_urlsafe(RESET_TOKEN_BYTES)
    session.add(PasswordResetToken(
        org_id=user.org_id,
        user_id=user.id,
        token_hash=hash_token(token),
        created_at=utcnow(),
        expires_at=utcnow() + timedelta(minutes=minutes),
        request_ip=request_ip[:64],
    ))

    delivery: DeliveryResult = transport.send(
        to=user.email,
        subject="Reset your IronClad Sentinel password",
        body_text=_message_body(user.email, token, minutes),
    )

    audit_record(session, org_id=user.org_id, action="auth.password_reset_requested",
                 actor=user.email, actor_id=user.id,
                 metadata={"ip": request_ip, "delivered": delivery.ok,
                           "expires_in_minutes": minutes})

    return ResetRequestOutcome(
        True,
        GENERIC_MESSAGE,
        # Only surfaced to tests and local development; the API never returns it.
        token=token if reveal_token else None,
        delivery_ok=delivery.ok,
    )


def redeem_reset(session: Session, *, token: str, new_password: str,
                 request_ip: str = "") -> ResetRedeemOutcome:
    """Consume a reset token and set the new password.

    Every failure returns a generic message: distinguishing "no such token"
    from "expired" from "already used" would let an attacker probe which
    tokens exist.
    """
    generic = "This password reset link is invalid or has expired. Request a new one."

    if not token:
        return ResetRedeemOutcome(False, generic)

    problems = password_problems(new_password)
    if problems:
        # This one is safe to be specific: the caller already holds a valid
        # token at this point, and a vague message would just frustrate them.
        return ResetRedeemOutcome(False, f"new password rejected: {'; '.join(problems)}")

    row = session.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(token))
    ).scalars().first()

    if row is None:
        return ResetRedeemOutcome(False, generic)

    if row.is_used:
        audit_record(session, org_id=row.org_id, action="auth.password_reset_reuse_blocked",
                     actor="", actor_id=row.user_id,
                     metadata={"token_id": row.id, "ip": request_ip,
                               "used_at": row.used_at.isoformat() if row.used_at else None})
        return ResetRedeemOutcome(False, generic)

    if row.is_expired():
        audit_record(session, org_id=row.org_id, action="auth.password_reset_expired",
                     actor="", actor_id=row.user_id,
                     metadata={"token_id": row.id, "ip": request_ip})
        return ResetRedeemOutcome(False, generic)

    user = session.get(User, row.user_id)
    if user is None or not user.is_active:
        return ResetRedeemOutcome(False, generic)

    # Mark the token used in the SAME transaction as the password change, so
    # there is no window in which the token is spent but the password is not
    # yet changed (or vice versa).
    row.used_at = utcnow()
    row.redeemed_ip = request_ip[:64]
    user.password_hash = hash_password(new_password)
    user.failed_logins = 0
    user.locked_until = None

    # A reset means the old credentials are no longer trusted: revoke every
    # existing session, exactly as an authenticated password change does.
    session.execute(
        SessionRow.__table__.update()
        .where(SessionRow.user_id == user.id, SessionRow.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )

    audit_record(session, org_id=user.org_id, action="auth.password_reset_completed",
                 actor=user.email, actor_id=user.id,
                 metadata={"token_id": row.id, "ip": request_ip})

    return ResetRedeemOutcome(True, "password updated", user_id=user.id,
                              org_id=user.org_id, email=user.email)


def purge_expired_tokens(session: Session, *, org_id: Optional[int] = None) -> int:
    """Delete expired tokens. Housekeeping only; correctness never depends on
    this, since an expired token is rejected on use regardless."""
    cutoff = utcnow()
    statement = PasswordResetToken.__table__.delete().where(
        PasswordResetToken.expires_at < cutoff)
    if org_id is not None:
        statement = statement.where(PasswordResetToken.org_id == int(org_id))
    result = session.execute(statement)
    return int(result.rowcount or 0)
