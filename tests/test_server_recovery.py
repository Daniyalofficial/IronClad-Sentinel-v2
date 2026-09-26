"""Operator recovery when the sole owner is locked out and SMTP is unavailable."""
from __future__ import annotations

from datetime import timedelta

import pytest

pytest.importorskip("sqlalchemy", reason="requires the server extra")
pytest.importorskip("fastapi", reason="requires the server extra")

from click.testing import CliRunner
from fastapi.testclient import TestClient
from sqlalchemy import select

from ironclad.api.app import create_app
from ironclad.cli import main
from ironclad.platform.database import session_scope
from ironclad.platform.models import (
    AuditEvent, Organization, PasswordResetToken, Session as SessionRow, User, utcnow,
)
from ironclad.platform.scanning import bootstrap_organization
from ironclad.platform.security import hash_token, verify_password


EMAIL = "owner@recovery.example.com"
OLD = "Str0ng!Passw0rd-99"
NEW = "N3w!Recovery-Passphrase-52"


@pytest.fixture()
def installation(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'recovery.db'}"
    monkeypatch.setenv("IRONCLAD_SIGNING_KEY", "test-signing-key-that-is-long-enough-32ch")
    monkeypatch.setenv("IRONCLAD_MAIL_TRANSPORT", "memory")
    app = create_app(url, include_web=False)
    with session_scope(app.state.engine) as session:
        org, user = bootstrap_organization(session, name="Recover", slug="recover",
                                           admin_email=EMAIL, password=OLD)
        org_id, user_id = org.id, user.id
    yield url, app.state.engine, TestClient(app), org_id, user_id
    app.state.engine.dispose()


def _lock(engine, user_id):
    with session_scope(engine) as session:
        user = session.get(User, user_id)
        user.failed_logins = 5
        user.locked_until = utcnow() + timedelta(minutes=10)


def _invoke_reset(url, *, org="recover", email=EMAIL, new_password=NEW):
    return CliRunner().invoke(main, ["server", "reset-password", "--database-url", url,
                                     "--org", org, "--email", email],
                              input=f"{new_password}\n{new_password}\n")


def test_operator_reset_restores_access_without_smtp_and_revokes_sessions(installation):
    url, engine, client, org_id, user_id = installation
    token = client.post("/auth/login", json={"email": EMAIL, "password": OLD}).json()["access_token"]
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    _lock(engine, user_id)
    assert client.post("/auth/login", json={"email": EMAIL, "password": OLD}).status_code == 429

    outcome = _invoke_reset(url)
    assert outcome.exit_code == 0, outcome.output
    assert NEW not in outcome.output, "do not echo the prompted password"
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert client.post("/auth/login", json={"email": EMAIL, "password": OLD}).status_code == 401
    assert client.post("/auth/login", json={"email": EMAIL, "password": NEW}).status_code == 200
    with session_scope(engine) as session:
        user = session.get(User, user_id)
        assert user.failed_logins == 0 and user.locked_until is None
        assert verify_password(NEW, user.password_hash)
        assert session.execute(select(SessionRow).where(
            SessionRow.user_id == user_id, SessionRow.revoked_at.is_(None))).scalars().all() != []
        assert "auth.password_reset_operator" in [event.action for event in session.execute(
            select(AuditEvent).where(AuditEvent.org_id == org_id)).scalars()]


def test_unlock_only_clears_lockout_and_preserves_password_and_sessions(installation):
    url, engine, client, _, user_id = installation
    token = client.post("/auth/login", json={"email": EMAIL, "password": OLD}).json()["access_token"]
    with session_scope(engine) as session:
        stored = session.get(User, user_id).password_hash
    _lock(engine, user_id)
    outcome = CliRunner().invoke(main, ["server", "unlock", "--database-url", url,
                                         "--org", "recover", "--email", EMAIL], input="y\n")
    assert outcome.exit_code == 0, outcome.output
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert client.post("/auth/login", json={"email": EMAIL, "password": OLD}).status_code == 200
    with session_scope(engine) as session:
        user = session.get(User, user_id)
        assert user.password_hash == stored
        assert user.failed_logins == 0 and user.locked_until is None
        assert "auth.unlock_operator" in [event.action for event in session.execute(
            select(AuditEvent)).scalars()]


def test_reset_invalidates_unredeemed_links(installation):
    url, engine, client, _, user_id = installation
    token = "test-recovery-token-0123456789"
    with session_scope(engine) as session:
        session.add(PasswordResetToken(org_id=session.get(User, user_id).org_id,
                                       user_id=user_id, token_hash=hash_token(token),
                                       expires_at=utcnow() + timedelta(minutes=20)))
    assert _invoke_reset(url).exit_code == 0
    with session_scope(engine) as session:
        assert session.execute(select(PasswordResetToken)).scalar_one().used_at is not None
    confirm = client.post("/auth/password-reset/confirm",
                          json={"token": token, "new_password": "Another-Str0ng-Password!"})
    assert confirm.status_code == 200
    assert confirm.json()["ok"] is False


def test_reset_is_scoped_to_the_explicit_organization(installation):
    url, engine, _, _, user_id = installation
    with session_scope(engine) as session:
        other = Organization(name="Another", slug="another")
        session.add(other)
        session.flush()
        clone = User(org_id=other.id, email=EMAIL, password_hash=session.get(User, user_id).password_hash,
                     role="owner")
        session.add(clone)
        session.flush()
        clone_id = clone.id
    outcome = _invoke_reset(url, org="another")
    assert outcome.exit_code == 0, outcome.output
    with session_scope(engine) as session:
        assert verify_password(OLD, session.get(User, user_id).password_hash)
        assert not verify_password(NEW, session.get(User, user_id).password_hash)
        assert verify_password(NEW, session.get(User, clone_id).password_hash)


def test_reset_rejects_weak_password_without_touching_account(installation):
    url, engine, _, _, user_id = installation
    outcome = _invoke_reset(url, new_password="too-short")
    assert outcome.exit_code != 0
    assert "password rejected" in outcome.output.lower()
    with session_scope(engine) as session:
        assert verify_password(OLD, session.get(User, user_id).password_hash)


def test_recovery_refuses_a_typo_in_database_path_or_organization(installation, tmp_path):
    url, engine, _, _, user_id = installation
    missing = tmp_path / "missing.db"
    outcome = _invoke_reset(f"sqlite:///{missing}")
    assert outcome.exit_code != 0
    assert "not initialized" in outcome.output.lower()
    assert not missing.exists(), "a recovery command must not create an empty database"
    outcome = _invoke_reset(url, org="unknown")
    assert outcome.exit_code != 0
    assert "organization" in outcome.output.lower()
    with session_scope(engine) as session:
        assert verify_password(OLD, session.get(User, user_id).password_hash)
