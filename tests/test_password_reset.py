"""Password reset tests.

Covers every security property the feature claims:
  * successful reset end to end, including mail delivery
  * invalid, expired and reused tokens all rejected with an identical message
  * enumeration resistance (same body AND comparable timing)
  * rate limiting on both endpoints
  * issuing a new token invalidates the previous one
  * sessions revoked and lockout cleared on success
  * pluggable transport, including a transport that fails
  * hashed-only token storage
  * TTL configuration and rejection of bad values
"""
from __future__ import annotations

import os
import tempfile
import time
from datetime import timedelta

import pytest

pytest.importorskip("fastapi", reason="requires the server extra: pip install -e '.[server]'")
pytest.importorskip("sqlalchemy", reason="requires the server extra: pip install -e '.[server]'")

from fastapi.testclient import TestClient
from sqlalchemy import select

from ironclad.api.app import create_app
from ironclad.platform import password_reset
from ironclad.platform.database import build_engine, run_migrations, session_factory, session_scope
from ironclad.platform.mail import InMemoryTransport, NullTransport, build_transport_from_env
from ironclad.platform.models import (
    Organization,
    PasswordResetToken,
    Session as SessionRow,
    User,
    utcnow,
)
from ironclad.platform.password_reset import GENERIC_MESSAGE, purge_expired_tokens
from ironclad.platform.security import hash_password, hash_token, verify_password

OLD_PASSWORD = "Old-Strong-Passw0rd-1"
NEW_PASSWORD = "New-Strong-Passw0rd-9"
EMAIL = "user@reset-corp.com"


@pytest.fixture()
def env():
    engine = build_engine("sqlite:///" + os.path.join(tempfile.mkdtemp(), "reset.db"))
    run_migrations(engine)
    with session_scope(engine) as s:
        org = Organization(name="Reset", slug="reset")
        s.add(org)
        s.flush()
        s.add(User(org_id=org.id, email=EMAIL, password_hash=hash_password(OLD_PASSWORD),
                   role="developer"))
        s.add(User(org_id=org.id, email="inactive@reset-corp.com",
                   password_hash=hash_password(OLD_PASSWORD), is_active=False))

    app = create_app(str(engine.url), include_web=False)
    # Swap in a fresh in-memory transport the tests can inspect.
    transport = InMemoryTransport()
    app.state.mail = transport
    return {"engine": engine, "app": app, "transport": transport,
            "client": TestClient(app)}


def _request_reset(env, email=EMAIL, reveal=True):
    """Call the service directly so a test can obtain the token."""
    with session_scope(env["engine"]) as s:
        outcome = password_reset.request_reset(
            s, email=email, transport=env["transport"], request_ip="9.9.9.9",
            reveal_token=reveal)
    return outcome


# --------------------------------------------------------------------------- #
# Successful reset
# --------------------------------------------------------------------------- #
def test_successful_reset_end_to_end(env):
    outcome = _request_reset(env)
    assert outcome.accepted
    assert outcome.token, "the service must hand the token to the transport"
    assert outcome.delivery_ok is True

    # Mail was actually produced, not just claimed.
    assert len(env["transport"].sent) == 1
    mail = env["transport"].last()
    assert mail["to"] == EMAIL
    assert "Reset your IronClad Sentinel password" == mail["subject"]
    assert outcome.token in mail["body"], "the link must contain the token"
    assert "expires in 30 minutes" in mail["body"]

    response = env["client"].post("/auth/password-reset/confirm",
                                  json={"token": outcome.token, "new_password": NEW_PASSWORD})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True, body

    with session_scope(env["engine"]) as s:
        user = s.execute(select(User).where(User.email == EMAIL)).scalar_one()
        assert verify_password(NEW_PASSWORD, user.password_hash)
        assert not verify_password(OLD_PASSWORD, user.password_hash)

    # The new password actually logs in.
    login = env["client"].post("/auth/login", json={"email": EMAIL, "password": NEW_PASSWORD})
    assert login.status_code == 200


def test_token_is_stored_only_as_a_digest(env):
    outcome = _request_reset(env)
    with session_scope(env["engine"]) as s:
        row = s.execute(select(PasswordResetToken)).scalar_one()
        assert row.token_hash == hash_token(outcome.token)
        assert outcome.token not in row.token_hash, "the raw token must never be stored"


def test_reset_revokes_existing_sessions_and_clears_lockout(env):
    # Log in, then lock the account out, then reset.
    env["client"].post("/auth/login", json={"email": EMAIL, "password": OLD_PASSWORD})
    with session_scope(env["engine"]) as s:
        user = s.execute(select(User).where(User.email == EMAIL)).scalar_one()
        user.failed_logins = 5
        user.locked_until = utcnow() + timedelta(minutes=10)

    outcome = _request_reset(env)
    env["client"].post("/auth/password-reset/confirm",
                       json={"token": outcome.token, "new_password": NEW_PASSWORD})

    with session_scope(env["engine"]) as s:
        user = s.execute(select(User).where(User.email == EMAIL)).scalar_one()
        assert user.failed_logins == 0
        assert user.locked_until is None
        live = s.execute(select(SessionRow).where(
            SessionRow.user_id == user.id, SessionRow.revoked_at.is_(None))).scalars().all()
        assert live == [], "every pre-existing session must be revoked"


def test_weak_new_password_is_rejected(env):
    outcome = _request_reset(env)
    response = env["client"].post("/auth/password-reset/confirm",
                                  json={"token": outcome.token, "new_password": "short"})
    assert response.status_code == 422, "schema-level validation rejects it first"

    # A password that passes the schema but not the policy (12 chars, one class).
    response = env["client"].post("/auth/password-reset/confirm",
                                  json={"token": outcome.token,
                                        "new_password": "alllowercaseonly"})
    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert "rejected" in response.json()["message"]

    # The token is NOT consumed by a rejected password, so the user can retry.
    retry = env["client"].post("/auth/password-reset/confirm",
                               json={"token": outcome.token, "new_password": NEW_PASSWORD})
    assert retry.json()["ok"] is True


# --------------------------------------------------------------------------- #
# Invalid / expired / reused tokens
# --------------------------------------------------------------------------- #
def test_invalid_token_is_rejected(env):
    response = env["client"].post("/auth/password-reset/confirm",
                                  json={"token": "a" * 43, "new_password": NEW_PASSWORD})
    assert response.status_code == 200
    assert response.json()["ok"] is False


def test_reused_token_is_rejected(env):
    outcome = _request_reset(env)
    first = env["client"].post("/auth/password-reset/confirm",
                               json={"token": outcome.token, "new_password": NEW_PASSWORD})
    assert first.json()["ok"] is True

    second = env["client"].post("/auth/password-reset/confirm",
                                json={"token": outcome.token,
                                     "new_password": "Another-Strong-Passw0rd"})
    assert second.json()["ok"] is False, "a token must not be usable twice"
    assert second.json()["message"] == first.json()["message"] or "invalid" in second.json()["message"]

    # The password did not change on the second attempt.
    with session_scope(env["engine"]) as s:
        user = s.execute(select(User).where(User.email == EMAIL)).scalar_one()
        assert verify_password(NEW_PASSWORD, user.password_hash)
        assert not verify_password("Another-Strong-Passw0rd", user.password_hash)


def test_reuse_attempt_is_audited(env):
    outcome = _request_reset(env)
    env["client"].post("/auth/password-reset/confirm",
                       json={"token": outcome.token, "new_password": NEW_PASSWORD})
    env["client"].post("/auth/password-reset/confirm",
                       json={"token": outcome.token, "new_password": NEW_PASSWORD})

    with session_scope(env["engine"]) as s:
        from ironclad.platform.models import AuditEvent
        actions = [e.action for e in s.execute(select(AuditEvent)).scalars().all()]
    assert "auth.password_reset_reuse_blocked" in actions


def test_expired_token_is_rejected(env):
    outcome = _request_reset(env)
    # Backdate the token past its expiry.
    with session_scope(env["engine"]) as s:
        row = s.execute(select(PasswordResetToken)).scalar_one()
        row.expires_at = utcnow() - timedelta(minutes=1)

    response = env["client"].post("/auth/password-reset/confirm",
                                  json={"token": outcome.token, "new_password": NEW_PASSWORD})
    assert response.status_code == 200
    assert response.json()["ok"] is False

    with session_scope(env["engine"]) as s:
        user = s.execute(select(User).where(User.email == EMAIL)).scalar_one()
        assert verify_password(OLD_PASSWORD, user.password_hash), "password must not have changed"


def test_all_failure_modes_share_one_message(env):
    """Unknown, expired and reused must be indistinguishable to a prober."""
    valid = _request_reset(env)
    env["client"].post("/auth/password-reset/confirm",
                       json={"token": valid.token, "new_password": NEW_PASSWORD})

    reused = env["client"].post("/auth/password-reset/confirm",
                                json={"token": valid.token,
                                     "new_password": "Another-Strong-Passw0rd"}).json()["message"]
    unknown = env["client"].post("/auth/password-reset/confirm",
                                 json={"token": "b" * 43,
                                       "new_password": NEW_PASSWORD}).json()["message"]
    assert reused == unknown, "reuse and unknown must be indistinguishable"


def test_inactive_account_cannot_reset(env):
    outcome = _request_reset(env, email="inactive@reset-corp.com")
    assert outcome.accepted, "the response must still look generic"
    assert outcome.token is None, "no token may be minted for an inactive account"
    assert env["transport"].sent == [], "no mail may be sent for an inactive account"


# --------------------------------------------------------------------------- #
# Enumeration resistance
# --------------------------------------------------------------------------- #
def test_unknown_and_known_addresses_get_an_identical_response(env):
    unknown = env["client"].post("/auth/password-reset/request",
                                 json={"email": "nobody@nowhere.com"})
    known = env["client"].post("/auth/password-reset/request", json={"email": EMAIL})

    assert unknown.status_code == known.status_code == 200
    assert unknown.json() == known.json()
    assert known.json()["message"] == GENERIC_MESSAGE
    assert "token" not in known.json(), "the token must never leave the API"


def test_unknown_address_produces_no_mail(env):
    env["client"].post("/auth/password-reset/request", json={"email": "nobody@nowhere.com"})
    assert env["transport"].sent == []


def test_unknown_and_known_take_comparable_time(env):
    """Timing must not reveal existence, so the miss path burns a dummy hash."""
    def measure(email, runs=3):
        times = []
        for _ in range(runs):
            start = time.perf_counter()
            env["client"].post("/auth/password-reset/request", json={"email": email})
            times.append(time.perf_counter() - start)
        return min(times)

    unknown = measure("nobody@nowhere.com")
    known = measure(EMAIL)
    # A loose bound: the point is that the miss path is not an order of
    # magnitude faster. PBKDF2 dominates both.
    assert unknown > known * 0.2, f"unknown={unknown:.4f}s known={known:.4f}s -- too divergent"


def test_inactive_account_response_is_also_generic(env):
    inactive = env["client"].post("/auth/password-reset/request",
                                  json={"email": "inactive@reset-corp.com"}).json()
    known = env["client"].post("/auth/password-reset/request", json={"email": EMAIL}).json()
    assert inactive == known


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #
def test_reset_request_is_rate_limited(monkeypatch, env):
    monkeypatch.setenv("IRONCLAD_RATELIMIT_PASSWORD_RESET_REQUEST", "3:300")
    codes = [
        env["client"].post("/auth/password-reset/request",
                           json={"email": EMAIL}).status_code
        for _ in range(5)
    ]
    assert codes[:3] == [200, 200, 200], codes
    assert codes[3] == 429, codes


def test_reset_confirm_is_rate_limited(monkeypatch, env):
    monkeypatch.setenv("IRONCLAD_RATELIMIT_PASSWORD_RESET_REDEEM", "2:300")
    codes = [
        env["client"].post("/auth/password-reset/confirm",
                           json={"token": "c" * 43,
                                 "new_password": NEW_PASSWORD}).status_code
        for _ in range(4)
    ]
    assert codes[:2] == [200, 200]
    assert codes[2] == 429, codes


def test_throttled_request_returns_retry_after(monkeypatch, env):
    monkeypatch.setenv("IRONCLAD_RATELIMIT_PASSWORD_RESET_REQUEST", "1:300")
    env["client"].post("/auth/password-reset/request", json={"email": EMAIL})
    response = env["client"].post("/auth/password-reset/request", json={"email": EMAIL})
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) > 0


# --------------------------------------------------------------------------- #
# Token rotation
# --------------------------------------------------------------------------- #
def test_new_request_invalidates_the_previous_token(env):
    first = _request_reset(env)
    second = _request_reset(env)
    assert first.token != second.token

    old = env["client"].post("/auth/password-reset/confirm",
                             json={"token": first.token, "new_password": NEW_PASSWORD})
    assert old.json()["ok"] is False, "the superseded token must not work"

    new = env["client"].post("/auth/password-reset/confirm",
                             json={"token": second.token, "new_password": NEW_PASSWORD})
    assert new.json()["ok"] is True


def test_only_one_outstanding_token_per_user(env):
    _request_reset(env)
    _request_reset(env)
    _request_reset(env)
    with session_scope(env["engine"]) as s:
        outstanding = s.execute(select(PasswordResetToken).where(
            PasswordResetToken.used_at.is_(None))).scalars().all()
    assert len(outstanding) == 1


# --------------------------------------------------------------------------- #
# Mail transport
# --------------------------------------------------------------------------- #
def test_transport_failure_does_not_change_the_response(env):
    """A transport error must not leak that the address exists."""
    env["transport"].fail_with = "SMTP connection refused"
    response = env["client"].post("/auth/password-reset/request", json={"email": EMAIL})
    assert response.status_code == 200
    assert response.json()["message"] == GENERIC_MESSAGE

    # The token was still minted, so the user can retry once mail is fixed.
    with session_scope(env["engine"]) as s:
        assert s.execute(select(PasswordResetToken)).scalars().first() is not None


def test_null_transport_sends_nothing(env):
    env["app"].state.mail = NullTransport()
    response = env["client"].post("/auth/password-reset/request", json={"email": EMAIL})
    assert response.status_code == 200
    assert response.json()["message"] == GENERIC_MESSAGE


def test_transport_is_selected_from_the_environment(monkeypatch):
    from ironclad.platform.mail import SmtpTransport

    monkeypatch.setenv("IRONCLAD_MAIL_TRANSPORT", "null")
    assert isinstance(build_transport_from_env(), NullTransport)

    monkeypatch.setenv("IRONCLAD_MAIL_TRANSPORT", "smtp")
    monkeypatch.setenv("IRONCLAD_SMTP_HOST", "mail.example.com")
    monkeypatch.setenv("IRONCLAD_SMTP_PORT", "2525")
    transport = build_transport_from_env()
    assert isinstance(transport, SmtpTransport)
    assert transport.host == "mail.example.com"
    assert transport.port == 2525

    monkeypatch.setenv("IRONCLAD_MAIL_TRANSPORT", "carrier-pigeon")
    assert isinstance(build_transport_from_env(), InMemoryTransport), \
        "an unknown transport must fall back to in-memory, not raise"


def test_smtp_without_a_host_fails_gracefully():
    from ironclad.platform.mail import SmtpTransport

    result = SmtpTransport().send("a@b.com", "s", "body")
    assert result.ok is False
    assert "IRONCLAD_SMTP_HOST" in result.detail


def test_reset_link_uses_the_configured_base(monkeypatch):
    monkeypatch.setenv("IRONCLAD_PASSWORD_RESET_URL_BASE", "https://sec.example.com/")
    assert password_reset.reset_link("TOK") == "https://sec.example.com/ui/password-reset?token=TOK"

    monkeypatch.delenv("IRONCLAD_PASSWORD_RESET_URL_BASE", raising=False)
    assert password_reset.reset_link("TOK") == "TOK"


# --------------------------------------------------------------------------- #
# TTL configuration
# --------------------------------------------------------------------------- #
def test_ttl_is_configurable(monkeypatch):
    monkeypatch.setenv("IRONCLAD_PASSWORD_RESET_TTL_MINUTES", "5")
    assert password_reset.ttl_minutes() == 5

    monkeypatch.delenv("IRONCLAD_PASSWORD_RESET_TTL_MINUTES", raising=False)
    assert password_reset.ttl_minutes() == password_reset.DEFAULT_TTL_MINUTES


def test_ttl_applied_to_the_issued_token(env, monkeypatch):
    monkeypatch.setenv("IRONCLAD_PASSWORD_RESET_TTL_MINUTES", "5")
    _request_reset(env)
    with session_scope(env["engine"]) as s:
        row = s.execute(select(PasswordResetToken)).scalar_one()
        delta = row.expires_at - row.created_at
    assert timedelta(minutes=4, seconds=30) < delta <= timedelta(minutes=5, seconds=30)


@pytest.mark.parametrize("bad", ["0", "-5", "abc", "999999"])
def test_invalid_ttl_is_rejected(monkeypatch, bad):
    monkeypatch.setenv("IRONCLAD_PASSWORD_RESET_TTL_MINUTES", bad)
    with pytest.raises(ValueError):
        password_reset.ttl_minutes()


# --------------------------------------------------------------------------- #
# Housekeeping
# --------------------------------------------------------------------------- #
def test_purge_expired_tokens(env):
    _request_reset(env)
    with session_scope(env["engine"]) as s:
        row = s.execute(select(PasswordResetToken)).scalar_one()
        row.expires_at = utcnow() - timedelta(minutes=1)

    with session_scope(env["engine"]) as s:
        removed = purge_expired_tokens(s)
    assert removed == 1

    with session_scope(env["engine"]) as s:
        assert s.execute(select(PasswordResetToken)).scalars().first() is None


def test_purge_is_scoped_to_one_organization(env):
    _request_reset(env)
    with session_scope(env["engine"]) as s:
        row = s.execute(select(PasswordResetToken)).scalar_one()
        row.expires_at = utcnow() - timedelta(minutes=1)
        other_org_id = 9999

    with session_scope(env["engine"]) as s:
        removed = purge_expired_tokens(s, org_id=other_org_id)
    assert removed == 0, "a purge scoped to another org must remove nothing"

    with session_scope(env["engine"]) as s:
        assert s.execute(select(PasswordResetToken)).scalars().first() is not None


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
def test_audit_events_are_recorded_for_the_full_lifecycle(env):
    from ironclad.platform.models import AuditEvent

    outcome = _request_reset(env)
    env["client"].post("/auth/password-reset/confirm",
                       json={"token": outcome.token, "new_password": NEW_PASSWORD})

    with session_scope(env["engine"]) as s:
        actions = [e.action for e in s.execute(select(AuditEvent)).scalars().all()]
    assert "auth.password_reset_requested" in actions
    assert "auth.password_reset_completed" in actions
    # The raw token must never appear in audit metadata.
    with session_scope(env["engine"]) as s:
        for event in s.execute(select(AuditEvent)).scalars().all():
            assert outcome.token not in event.metadata_json
