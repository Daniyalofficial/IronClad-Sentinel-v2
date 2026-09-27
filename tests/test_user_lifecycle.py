"""HTTP deprovisioning: stop SSO users and their long-lived API tokens locally."""
from __future__ import annotations

from datetime import timedelta

import pytest

pytest.importorskip("fastapi", reason="requires the server extra")
pytest.importorskip("sqlalchemy", reason="requires the server extra")

from fastapi.testclient import TestClient
from sqlalchemy import select

from ironclad.api.app import create_app
from ironclad.platform.database import session_scope
from ironclad.platform.models import ApiToken, AuditEvent, PasswordResetToken, Session as SessionRow, utcnow
from ironclad.platform.scanning import bootstrap_organization
from ironclad.platform.security import hash_token

PASSWORD = "Lifecycle-Str0ng-Password-99!"


@pytest.fixture
def lifecycle(tmp_path, monkeypatch):
    monkeypatch.delenv("IRONCLAD_DISABLE_PASSWORD_LOGIN", raising=False)
    app = create_app(f"sqlite:///{tmp_path / 'lifecycle.db'}")
    with session_scope(app.state.engine) as session:
        org, owner = bootstrap_organization(session, name="Alpha", slug="alpha-lifecycle",
                                            admin_email="owner@alpha.example.com", password=PASSWORD)
        other, other_owner = bootstrap_organization(
            session, name="Beta", slug="beta-lifecycle",
            admin_email="owner@beta.example.com", password=PASSWORD)
        owner_id, other_owner_id = owner.id, other_owner.id
    client = TestClient(app, follow_redirects=False)

    def login(email):
        result = client.post("/auth/login", json={"email": email, "password": PASSWORD})
        assert result.status_code == 200, result.text
        return {"Authorization": f"Bearer {result.json()['access_token']}"}

    yield {"app": app, "client": client, "login": login, "owner": login("owner@alpha.example.com"),
           "other_owner": login("owner@beta.example.com"), "owner_id": owner_id,
           "other_owner_id": other_owner_id}
    app.state.engine.dispose()


def test_operator_deactivation_revokes_existing_sessions_tokens_and_reset_links(lifecycle):
    env = lifecycle
    client, owner = env["client"], env["owner"]
    made = client.post("/users", headers=owner, json={
        "email": "sso@alpha.example.com", "password": PASSWORD, "role": "developer"})
    assert made.status_code == 201, made.text
    user_id = made.json()["id"]
    member = env["login"]("sso@alpha.example.com")
    token = client.post("/auth/tokens", headers=member, json={
        "name": "deprovision-test", "scopes": ["scan.read"]})
    assert token.status_code == 201, token.text
    key = {"Authorization": f"Bearer {token.json()['token']}"}
    assert client.get("/auth/me", headers=member).status_code == 200
    assert client.get("/scans", headers=key).status_code == 200
    pending_reset = "disposable-reset-token-before-deprovisioning"
    with session_scope(env["app"].state.engine) as session:
        session.add(PasswordResetToken(org_id=made.json()["org_id"], user_id=user_id,
                                       token_hash=hash_token(pending_reset),
                                       expires_at=utcnow() + timedelta(minutes=20)))

    # Demonstrate the missing endpoint before implementation, rather than
    # accepting a database-only/manual operator workaround as deprovisioning.
    disabled = client.patch(f"/users/{user_id}/active", headers=owner,
                            json={"is_active": False})
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["is_active"] is False
    assert client.get("/auth/me", headers=member).status_code == 401
    assert client.get("/scans", headers=key).status_code == 401
    assert client.post("/auth/login", json={
        "email": "sso@alpha.example.com", "password": PASSWORD}).status_code == 403

    with session_scope(env["app"].state.engine) as session:
        sessions = session.execute(select(SessionRow).where(SessionRow.user_id == user_id)).scalars().all()
        keys = session.execute(select(ApiToken).where(ApiToken.user_id == user_id)).scalars().all()
        assert sessions and all(row.revoked_at is not None for row in sessions)
        assert keys and all(row.revoked_at is not None for row in keys)
        resets = session.execute(select(PasswordResetToken).where(
            PasswordResetToken.user_id == user_id)).scalars().all()
        assert len(resets) == 1 and resets[0].used_at is not None
        assert session.execute(select(AuditEvent).where(
            AuditEvent.action == "user.deactivated", AuditEvent.target_id == str(user_id)
        )).scalar_one()

    enabled = client.patch(f"/users/{user_id}/active", headers=owner,
                           json={"is_active": True})
    assert enabled.status_code == 200 and enabled.json()["is_active"] is True
    assert client.get("/auth/me", headers=member).status_code == 401
    assert client.get("/scans", headers=key).status_code == 401
    reset = client.post("/auth/password-reset/confirm", json={
        "token": pending_reset, "new_password": "No-Reset-After-Disabled-99!"})
    assert reset.status_code == 200 and reset.json()["ok"] is False
    assert env["login"]("sso@alpha.example.com")


def test_deactivation_is_tenant_scoped_rbac_protected_and_cannot_lock_out_owner(lifecycle):
    env = lifecycle
    client = env["client"]
    foreign = client.patch(f"/users/{env['owner_id']}/active", headers=env["other_owner"],
                           json={"is_active": False})
    assert foreign.status_code == 404
    self_disable = client.patch(f"/users/{env['owner_id']}/active", headers=env["owner"],
                                json={"is_active": False})
    assert self_disable.status_code in (400, 409)
    assert client.get("/auth/me", headers=env["owner"]).status_code == 200

    made = client.post("/users", headers=env["owner"], json={
        "email": "read-only@alpha.example.com", "password": PASSWORD, "role": "viewer"})
    assert made.status_code == 201
    viewer = env["login"]("read-only@alpha.example.com")
    assert client.patch(f"/users/{env['owner_id']}/active", headers=viewer,
                        json={"is_active": False}).status_code == 403
    assert client.patch(f"/users/{made.json()['id']}/active", headers=env["owner"],
                        json={"is_active": "false"}).status_code == 422
    # The existing role endpoint must not bypass the last-owner guarantee.
    last_owner_demote = client.patch(f"/users/{env['owner_id']}/role",
                                     headers=env["owner"], json={"role": "admin"})
    assert last_owner_demote.status_code == 409, last_owner_demote.text


def test_admin_cannot_demote_owner_but_owner_can_delegate_before_demoting_self(lifecycle):
    env = lifecycle
    client = env["client"]
    made = client.post("/users", headers=env["owner"], json={
        "email": "admin@alpha.example.com", "password": PASSWORD, "role": "admin"})
    assert made.status_code == 201
    admin = env["login"]("admin@alpha.example.com")
    assert client.patch(f"/users/{env['owner_id']}/role", headers=admin,
                        json={"role": "viewer"}).status_code == 403
    # A different *active* owner in the same org makes an intentional handover safe.
    delegate = client.post("/users", headers=env["owner"], json={
        "email": "delegate@alpha.example.com", "password": PASSWORD, "role": "owner"})
    assert delegate.status_code == 201
    response = client.patch(f"/users/{env['owner_id']}/role", headers=env["owner"],
                            json={"role": "admin"})
    assert response.status_code == 200 and response.json()["role"] == "admin"
    assert client.get("/auth/me", headers=env["owner"]).status_code == 200
