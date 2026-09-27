"""Browser-facing OIDC authorization code flow against a hostile local IdP.

No remote identity provider or external network is required: the mock's URLs
are HTTPS and its discovery, token and JWKS responses are real protocol data.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select

from ironclad.api.app import create_app
from ironclad.platform.database import build_engine, run_migrations, session_scope
from ironclad.platform.models import Session as SessionRow
from ironclad.platform.scanning import bootstrap_organization

ISSUER = "https://idp.example.test/tenant"
APP_URL = "https://app.example.test"
CLIENT_ID = "ironclad-client"
CLIENT_SECRET = "private-client-secret"
EMAIL = "secops@acme.example.com"
PASSWORD = "Str0ng!Passw0rd-99"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture
def oidc_stack(tmp_path, monkeypatch, request):
    if getattr(request, "param", None) is True:
        monkeypatch.setenv("IRONCLAD_DISABLE_PASSWORD_LOGIN", "1")
    if getattr(request, "param", None) == "post":
        monkeypatch.setenv("IRONCLAD_OIDC_TOKEN_AUTH_METHOD", "client_secret_post")
    for key, value in {
        "IRONCLAD_OIDC_ISSUER": ISSUER,
        "IRONCLAD_OIDC_CLIENT_ID": CLIENT_ID,
        "IRONCLAD_OIDC_CLIENT_SECRET": CLIENT_SECRET,
        "IRONCLAD_OIDC_REDIRECT_URI": APP_URL + "/auth/oidc/callback",
        "IRONCLAD_OIDC_ORG_SLUG": "acme",
        "IRONCLAD_SIGNING_KEY": "test-signing-key-that-is-long-enough-32ch",
    }.items():
        monkeypatch.setenv(key, value)
    database_url = f"sqlite:///{tmp_path / 'oidc.db'}"
    engine = build_engine(database_url)
    run_migrations(engine)
    with session_scope(engine) as session:
        org, user = bootstrap_organization(session, name="Acme", slug="acme",
                                           admin_email=EMAIL, password=PASSWORD)
        org_id, user_id = org.id, user.id

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = private_key.public_key().public_numbers()
    jwk = {"kty": "RSA", "kid": "key-one", "use": "sig", "alg": "RS256",
           "n": _b64u(pub.n.to_bytes((pub.n.bit_length() + 7) // 8, "big")),
           "e": _b64u(pub.e.to_bytes((pub.e.bit_length() + 7) // 8, "big"))}
    mock = {"calls": [], "claims": {}, "private_key": private_key, "jwk": jwk}

    def handler(request: httpx.Request) -> httpx.Response:
        mock["calls"].append(request)
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={
                "issuer": mock.get("discovery_issuer", ISSUER),
                "authorization_endpoint": ISSUER + "/authorize",
                "token_endpoint": ISSUER + "/token", "jwks_uri": ISSUER + "/jwks",
            })
        if path.endswith("/jwks"):
            return httpx.Response(200, json={"keys": [mock["jwk"]]})
        if path.endswith("/token"):
            from ironclad.platform.models import OidcState

            with session_scope(engine) as session:
                # In the real callback the state has already been consumed;
                # the test records the nonce before sending the request.
                assert session.execute(select(OidcState)).scalars().all() == []
            form = parse_qs(request.content.decode())
            mock["token_form"] = form
            claims = {
                "iss": ISSUER, "sub": "stable-subject-123", "aud": CLIENT_ID,
                "iat": int(time.time()), "exp": int(time.time()) + 120,
                "nonce": mock["nonce"], "email": EMAIL, "email_verified": True,
            }
            claims.update(mock["claims"])
            algorithm = mock.get("algorithm", "RS256")
            token = jwt.encode(claims, None if algorithm == "none" else mock["private_key"],
                               algorithm=algorithm, headers={"kid": "key-one"})
            mock["last_token_request"] = request
            return httpx.Response(200, json={"id_token": token, "access_token": "never-log-me",
                                              "token_type": "Bearer", "expires_in": 120})
        raise AssertionError(f"unexpected IdP request: {request.method} {request.url}")

    app = create_app(database_url)
    if getattr(app.state, "oidc", None) is not None:
        app.state.oidc.transport = httpx.MockTransport(handler)
    with TestClient(app, base_url=APP_URL, follow_redirects=False) as client:
        yield client, engine, mock, org_id, user_id
    engine.dispose()
    app.state.engine.dispose()


def test_oidc_authorization_code_login_uses_browser_state_and_preprovisioned_role(oidc_stack):
    client, engine, mock, org_id, user_id = oidc_stack
    start = client.get("/auth/oidc/start")
    assert start.status_code == 302, start.text
    assert start.headers["cache-control"] == "no-store"
    assert "httponly" in start.headers["set-cookie"].lower()
    assert "secure" in start.headers["set-cookie"].lower()
    assert "samesite=lax" in start.headers["set-cookie"].lower()
    authorize = parse_qs(urlsplit(start.headers["location"]).query)
    assert authorize["response_type"] == ["code"]
    assert authorize["client_id"] == [CLIENT_ID]
    assert authorize["redirect_uri"] == [APP_URL + "/auth/oidc/callback"]
    assert authorize["scope"] == ["openid email profile"]
    assert authorize["code_challenge_method"] == ["S256"]

    from ironclad.platform.models import OidcState

    with session_scope(engine) as session:
        flow = session.execute(select(OidcState)).scalar_one()
        assert flow.org_id == org_id
        mock["nonce"] = flow.nonce
        assert flow.state_hash == hashlib.sha256(authorize["state"][0].encode()).hexdigest()
        assert authorize["code_challenge"] == [_b64u(hashlib.sha256(flow.code_verifier.encode()).digest())]
    callback = client.get("/auth/oidc/callback", params={
        "state": authorize["state"][0], "code": "code-issued-by-idp",
    })
    assert callback.status_code == 303, callback.text
    assert callback.headers["location"] == "/ui/"
    assert callback.headers["cache-control"] == "no-store"
    assert "code-issued-by-idp" not in callback.headers["location"]
    assert "httponly" in callback.headers["set-cookie"].lower()
    assert "secure" in callback.headers["set-cookie"].lower()
    assert mock["token_form"]["code_verifier"] == [flow.code_verifier]
    assert client.get("/ui/").status_code == 200
    with session_scope(engine) as session:
        assert session.execute(select(OidcState)).scalars().all() == []
        issued = session.execute(select(SessionRow)).scalars().all()
        assert len(issued) == 1 and issued[0].user_id == user_id and issued[0].org_id == org_id

    replay = client.get("/auth/oidc/callback", params={
        "state": authorize["state"][0], "code": "code-issued-by-idp",
    }, cookies={"__Host-ironclad-oidc-state": authorize["state"][0]})
    assert replay.status_code == 400
    assert sum(r.url.path.endswith("/token") for r in mock["calls"]) == 1


def _start_flow(client, engine, mock):
    from ironclad.platform.models import OidcState

    response = client.get("/auth/oidc/start")
    assert response.status_code == 302, response.text
    state = parse_qs(urlsplit(response.headers["location"]).query)["state"][0]
    with session_scope(engine) as session:
        row = session.execute(select(OidcState)).scalar_one()
        mock["nonce"] = row.nonce
    return state


@pytest.mark.parametrize(("overrides", "expected_status"), [
    ({"iss": "https://attacker.example.com"}, 401),
    ({"aud": "other-client"}, 401),
    ({"aud": [CLIENT_ID, "other-client"]}, 401),
    ({"nonce": "attacker-chosen-nonce"}, 401),
    ({"exp": 0}, 401),
    ({"sub": ""}, 401),
    ({"email_verified": False}, 401),
    ({"email_verified": "true"}, 401),
    ({"email": "unknown@example.com"}, 403),
])
def test_oidc_rejects_invalid_tokens_and_unprovisioned_users(oidc_stack, overrides, expected_status):
    client, engine, mock, _, _ = oidc_stack
    state = _start_flow(client, engine, mock)
    mock["claims"] = overrides
    response = client.get("/auth/oidc/callback", params={"state": state, "code": "test-code"})
    assert response.status_code == expected_status, response.text
    assert response.headers["referrer-policy"] == "no-referrer"
    from ironclad.platform.models import OidcIdentity, OidcState

    with session_scope(engine) as session:
        assert session.execute(select(OidcState)).scalars().all() == [], "failed code cannot replay"
        assert session.execute(select(OidcIdentity)).scalars().all() == []
        assert session.execute(select(SessionRow)).scalars().all() == []


def test_oidc_rejects_unsigned_and_wrong_key_tokens(oidc_stack):
    client, engine, mock, _, _ = oidc_stack
    state = _start_flow(client, engine, mock)
    mock["algorithm"] = "none"
    response = client.get("/auth/oidc/callback", params={"state": state, "code": "test-code"})
    assert response.status_code == 401
    with session_scope(engine) as session:
        assert session.execute(select(SessionRow)).scalars().all() == []

    from ironclad.platform.models import OidcState

    # A distinct, signed RSA key with a matching kid must not authenticate.
    other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    mock["algorithm"] = "RS256"
    mock["private_key"] = other_private_key
    state = _start_flow(client, engine, mock)
    response = client.get("/auth/oidc/callback", params={"state": state, "code": "test-code"})
    assert response.status_code == 401
    with session_scope(engine) as session:
        assert session.execute(select(SessionRow)).scalars().all() == []
        assert session.execute(select(OidcState)).scalars().all() == []


def test_oidc_browser_state_mismatch_and_expiration_do_not_exchange_code(oidc_stack):
    client, engine, mock, _, _ = oidc_stack
    state = _start_flow(client, engine, mock)
    from ironclad.api.oidc import STATE_COOKIE
    from ironclad.platform.models import OidcState, utcnow
    from datetime import timedelta

    client.cookies.set(STATE_COOKIE, "forged-cookie", domain="app.example.test", path="/")
    rejected = client.get("/auth/oidc/callback", params={"state": state, "code": "test-code"})
    assert rejected.status_code == 400
    with session_scope(engine) as session:
        assert session.execute(select(OidcState)).scalar_one().state_hash == hashlib.sha256(state.encode()).hexdigest()
    assert not any(r.url.path.endswith("/token") for r in mock["calls"])
    client.cookies.set(STATE_COOKIE, state, domain="app.example.test", path="/")
    with session_scope(engine) as session:
        session.execute(OidcState.__table__.update().values(expires_at=utcnow() - timedelta(seconds=1)))
    expired = client.get("/auth/oidc/callback", params={"state": state, "code": "test-code"})
    assert expired.status_code == 400
    assert not any(r.url.path.endswith("/token") for r in mock["calls"])


def test_oidc_issuer_mismatch_in_discovery_fails_before_storing_state(oidc_stack):
    client, engine, mock, _, _ = oidc_stack
    mock["discovery_issuer"] = "https://attacker.example.com"
    response = client.get("/auth/oidc/start")
    assert response.status_code == 503
    assert "attacker" not in response.text
    from ironclad.platform.models import OidcState

    with session_scope(engine) as session:
        assert session.execute(select(OidcState)).scalars().all() == []


def test_oidc_binding_cannot_be_reassigned_or_change_local_role(oidc_stack):
    from ironclad.platform.models import OidcIdentity, User
    from ironclad.platform.security import hash_password

    client, engine, mock, org_id, _ = oidc_stack
    with session_scope(engine) as session:
        viewer = User(org_id=org_id, email="analyst@example.com",
                      password_hash=hash_password(PASSWORD), role="viewer")
        session.add(viewer)
        session.flush()
        viewer_id = viewer.id
    mock["claims"] = {"email": "analyst@example.com", "role": "owner", "org_id": 999}
    state = _start_flow(client, engine, mock)
    response = client.get("/auth/oidc/callback", params={"state": state, "code": "first-code"})
    assert response.status_code == 303, response.text
    with session_scope(engine) as session:
        bound = session.execute(select(OidcIdentity)).scalar_one()
        assert bound.org_id == org_id and bound.user_id == viewer_id
        assert session.get(User, viewer_id).role == "viewer"
    assert client.get("/ui/").status_code == 200
    # The same pre-provisioned email with a different signed IdP subject must
    # not replace the previously bound identity, even when the email verifies.
    mock["claims"]["sub"] = "different-valid-subject"
    state = _start_flow(client, engine, mock)
    response = client.get("/auth/oidc/callback", params={"state": state, "code": "second-code"})
    assert response.status_code == 403
    with session_scope(engine) as session:
        identities = session.execute(select(OidcIdentity)).scalars().all()
        assert len(identities) == 1 and identities[0].subject == "stable-subject-123"
        assert len(session.execute(select(SessionRow)).scalars().all()) == 1


@pytest.mark.parametrize("oidc_stack", [True], indirect=True)
def test_oidc_only_mode_disables_local_password_sign_in_and_reset(oidc_stack):
    client, engine, mock, _, _ = oidc_stack
    page = client.get("/ui/login")
    assert page.status_code == 200
    assert "/auth/oidc/start" in page.text and 'type="password"' not in page.text
    login = client.post("/auth/login", json={"email": EMAIL, "password": PASSWORD})
    assert login.status_code == 403
    dashboard_login = client.post("/ui/login", data={"email": EMAIL, "password": PASSWORD})
    assert dashboard_login.status_code == 303
    assert dashboard_login.headers["location"].startswith("/ui/login?")
    reset_request = client.post("/auth/password-reset/request", json={"email": EMAIL})
    assert reset_request.status_code == 403
    with session_scope(engine) as session:
        assert session.execute(select(SessionRow)).scalars().all() == []
    state = _start_flow(client, engine, mock)
    signed_login = client.get("/auth/oidc/callback", params={"state": state, "code": "test-code"})
    assert signed_login.status_code == 303
    assert client.get("/ui/").status_code == 200


def test_oidc_configuration_fails_closed_without_https_or_provider(tmp_path, monkeypatch):
    from ironclad.api.oidc import OidcConfig

    monkeypatch.setenv("IRONCLAD_DISABLE_PASSWORD_LOGIN", "1")
    with pytest.raises(ValueError, match="without configured OIDC"):
        create_app(f"sqlite:///{tmp_path / 'no-provider.db'}")
    monkeypatch.setenv("IRONCLAD_OIDC_ISSUER", "http://not-tls.example.com")
    for key, value in {
        "CLIENT_ID": CLIENT_ID, "CLIENT_SECRET": CLIENT_SECRET,
        "REDIRECT_URI": APP_URL + "/auth/oidc/callback", "ORG_SLUG": "acme",
    }.items():
        monkeypatch.setenv("IRONCLAD_OIDC_" + key, value)
    with pytest.raises(ValueError, match="HTTPS"):
        OidcConfig.from_environment()
    monkeypatch.setenv("IRONCLAD_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("IRONCLAD_OIDC_REDIRECT_URI", "https://attacker.example.com/callback")
    with pytest.raises(ValueError, match="callback"):
        OidcConfig.from_environment()


def test_oidc_at_hash_binds_access_token_and_identity_can_log_in_twice(oidc_stack):
    from ironclad.platform.models import OidcIdentity

    client, engine, mock, _, user_id = oidc_stack
    mock["claims"]["at_hash"] = "this-is-not-the-access-token-hash"
    state = _start_flow(client, engine, mock)
    bad = client.get("/auth/oidc/callback", params={"state": state, "code": "first-code"})
    assert bad.status_code == 401
    with session_scope(engine) as session:
        assert session.execute(select(SessionRow)).scalars().all() == []
    mock["claims"]["at_hash"] = _b64u(hashlib.sha256(b"never-log-me").digest()[:16])
    for code in ("second-code", "third-code"):
        state = _start_flow(client, engine, mock)
        response = client.get("/auth/oidc/callback", params={"state": state, "code": code})
        assert response.status_code == 303, response.text
        assert mock["last_token_request"].headers["Authorization"].startswith("Basic ")
        assert mock["token_form"]["code"] == [code]
    with session_scope(engine) as session:
        assert len(session.execute(select(SessionRow)).scalars().all()) == 2
        bound = session.execute(select(OidcIdentity)).scalar_one()
        assert bound.user_id == user_id
    import re
    page = client.get("/ui/")
    csrf = re.search(r'action="/ui/logout"[^>]*>\s*<input type="hidden" name="csrf_token" value="([a-f0-9]{64})"', page.text)
    assert csrf, "OIDC logout must carry the dashboard CSRF form field"
    logout = client.post("/ui/logout", data={"csrf_token": csrf.group(1)})
    assert logout.status_code == 303
    assert client.get("/ui/").status_code == 307


@pytest.mark.parametrize("oidc_stack", ["post"], indirect=True)
def test_oidc_supports_client_secret_post_when_provider_requires_it(oidc_stack):
    client, engine, mock, _, _ = oidc_stack
    state = _start_flow(client, engine, mock)
    response = client.get("/auth/oidc/callback", params={"state": state, "code": "token-code"})
    assert response.status_code == 303, response.text
    assert mock["token_form"]["client_id"] == [CLIENT_ID]
    assert mock["token_form"]["client_secret"] == [CLIENT_SECRET]
    assert "authorization" not in mock["last_token_request"].headers


def test_oidc_deactivated_user_cannot_keep_or_receive_a_dashboard_session(oidc_stack):
    from ironclad.platform.models import OidcIdentity, User

    client, engine, mock, _, user_id = oidc_stack
    state = _start_flow(client, engine, mock)
    logged_in = client.get("/auth/oidc/callback", params={"state": state, "code": "first-code"})
    assert logged_in.status_code == 303
    assert client.get("/ui/").status_code == 200
    with session_scope(engine) as session:
        session.get(User, user_id).is_active = False
    assert client.get("/ui/").status_code == 307
    state = _start_flow(client, engine, mock)
    rejected = client.get("/auth/oidc/callback", params={"state": state, "code": "new-code"})
    assert rejected.status_code == 403
    with session_scope(engine) as session:
        assert session.execute(select(OidcIdentity)).scalar_one().user_id == user_id
        assert len(session.execute(select(SessionRow)).scalars().all()) == 1


def test_sso_only_user_can_manage_scoped_api_token_without_password_or_csrf_bypass(oidc_stack):
    import re
    from ironclad.platform.models import ApiToken, User
    from ironclad.platform.security import hash_token

    client, engine, mock, _, user_id = oidc_stack
    client.app.state.password_login_enabled = False
    state = _start_flow(client, engine, mock)
    signed_in = client.get("/auth/oidc/callback", params={"state": state, "code": "test-code"})
    assert signed_in.status_code == 303
    page = client.get("/ui/settings")
    assert page.status_code == 200
    assert 'action="/ui/settings/tokens"' in page.text
    csrf = re.search(r'name="csrf_token" value="([a-f0-9]{64})"', page.text)
    assert csrf, "show the session-bound CSRF token in the form"
    for bad_csrf in ("", "forged"):
        bad = client.post("/ui/settings/tokens", data={"name": "ci", "csrf_token": bad_csrf})
        assert bad.status_code in (403, 422), bad.text
    with session_scope(engine) as session:
        assert session.execute(select(ApiToken)).scalars().all() == []

    created = client.post("/ui/settings/tokens", data={
        "name": '<script>alert("x")</script>', "csrf_token": csrf.group(1),
    })
    assert created.status_code == 200, created.text
    assert created.headers["cache-control"] == "no-store"
    assert "&lt;script&gt;" in created.text and '<script>alert("x")</script>' not in created.text
    raw = re.search(r"ics_[A-Za-z0-9_-]{30,}", created.text)
    assert raw, "show the secret exactly once"
    token = raw.group(0)
    with session_scope(engine) as session:
        stored = session.execute(select(ApiToken)).scalar_one()
        assert stored.user_id == user_id and stored.token_hash == hash_token(token)
        assert stored.scopes == "finding.read,scan.create,scan.read"
        token_id = stored.id
    assert token not in client.get("/ui/settings").text
    scoped_headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/auth/me", headers=scoped_headers).status_code == 200
    # A narrowed owner token must not inherit the owner's administrator
    # privilege through admin_required, even when the user is an owner.
    assert client.post("/users", headers=scoped_headers, json={
        "email": "intruder@acme.example.com", "password": PASSWORD,
        "role": "owner",
    }).status_code == 403
    assert client.patch(f"/users/{user_id}/active", headers=scoped_headers,
                        json={"is_active": False}).status_code == 403
    assert client.patch(f"/users/{user_id}/role", headers=scoped_headers,
                        json={"role": "admin"}).status_code == 403

    bad_revoke = client.post(f"/ui/settings/tokens/{token_id}/revoke", data={"csrf_token": "forged"})
    assert bad_revoke.status_code == 403
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    revoked = client.post(f"/ui/settings/tokens/{token_id}/revoke",
                          data={"csrf_token": csrf.group(1)})
    assert revoked.status_code == 303
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401

    with session_scope(engine) as session:
        session.get(User, user_id).role = "viewer"
    viewer_page = client.get("/ui/settings")
    assert 'action="/ui/settings/tokens"' not in viewer_page.text
    assert "<h2>Users</h2>" not in viewer_page.text
    forbidden = client.post("/ui/settings/tokens", data={
        "name": "viewer", "csrf_token": csrf.group(1),
    })
    assert forbidden.status_code == 403
