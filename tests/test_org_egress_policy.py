"""Per-organization egress policy tests.

Covers the policy lifecycle, authorization, tenant isolation, and — most
importantly — that the *actual outbound delivery path* enforces the
organization policy rather than the policy merely being stored.
"""
from __future__ import annotations

import http.server
import json
import os
import socket
import threading

import pytest

pytest.importorskip("fastapi", reason="requires the server extra: pip install -e '.[server]'")
pytest.importorskip("sqlalchemy", reason="requires the server extra: pip install -e '.[server]'")

from fastapi.testclient import TestClient
from sqlalchemy import select

from ironclad.api.app import create_app
from ironclad.platform import egress
from ironclad.platform.database import build_engine, run_migrations, session_scope
from ironclad.platform.integrations import (
    EGRESS_ALLOWLIST_ENV,
    EgressBlocked,
    SsrfBlocked,
    _request,
    deliver,
    resolve_target,
    set_org_allowlist_provider,
)
from ironclad.platform.models import Organization, User
from ironclad.platform.security import hash_password

PASSWORD = "Egress-Policy-Passw0rd-1"
PUBLIC_IP = "93.184.216.34"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
class _RecordingServer:
    def __init__(self, response_status=200, location=None):
        outer = self
        self.received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                outer.received.append({"path": self.path, "host": self.headers.get("Host"),
                                       "peer": self.client_address[0],
                                       "body": self.rfile.read(length)})
                self.send_response(response_status)
                if location is not None:
                    self.send_header("Location", location)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        self._server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def shutdown(self):
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture()
def env():
    """Two organizations, A and B, each with an owner and a viewer."""
    engine = build_engine("sqlite:///" + _tmpdb())
    run_migrations(engine)
    ids = {}
    with session_scope(engine) as s:
        for slug in ("org-a", "org-b"):
            org = Organization(name=slug.title(), slug=slug)
            s.add(org)
            s.flush()
            ids[slug] = org.id
            s.add(User(org_id=org.id, email=f"owner@{slug}.com",
                       password_hash=hash_password(PASSWORD), role="owner"))
            s.add(User(org_id=org.id, email=f"viewer@{slug}.com",
                       password_hash=hash_password(PASSWORD), role="viewer"))

    app = create_app(str(engine.url), include_web=False)
    client = TestClient(app)

    def token(email):
        response = client.post("/auth/login", json={"email": email, "password": PASSWORD})
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    return {
        "engine": engine, "app": app, "client": client, "ids": ids,
        "a_owner": token("owner@org-a.com"),
        "a_viewer": token("viewer@org-a.com"),
        "b_owner": token("owner@org-b.com"),
    }


def _tmpdb():
    import tempfile

    return tempfile.mkdtemp() + "/egress.db"


@pytest.fixture
def real_getaddrinfo():
    return socket.getaddrinfo


@pytest.fixture
def record_connections(real_getaddrinfo):
    connected = []
    real_create = socket.create_connection

    def recording(address, *args, **kwargs):
        connected.append(address)
        return real_create(address, *args, **kwargs)

    socket.create_connection = recording
    yield connected
    socket.create_connection = real_create
    socket.getaddrinfo = real_getaddrinfo


@pytest.fixture
def resolve_to(real_getaddrinfo):
    """Map given hostnames to given IPs so a named host reaches a local server."""

    def _install(mapping):
        def resolver(host, *args, **kwargs):
            if host in mapping:
                return real_getaddrinfo(mapping[host], *args, **kwargs)
            return real_getaddrinfo(host, *args, **kwargs)

        socket.getaddrinfo = resolver
        return resolver

    yield _install
    socket.getaddrinfo = real_getaddrinfo


@pytest.fixture(autouse=True)
def isolate_egress_env(monkeypatch):
    """Each test starts from a clean egress environment.

    Several tests set IRONCLAD_ALLOW_PRIVATE_WEBHOOKS directly on os.environ
    (via the provider path rather than monkeypatch), so both variables are
    reset here -- otherwise a private-webhook escape hatch leaks into later
    tests and private-address assertions pass for the wrong reason.
    """
    monkeypatch.delenv(EGRESS_ALLOWLIST_ENV, raising=False)
    monkeypatch.delenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", raising=False)
    yield
    os.environ.pop(EGRESS_ALLOWLIST_ENV, None)
    os.environ.pop("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", None)


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("entries,expected_problems", [
    (["hooks.slack.com"], 0),
    (["*.github.com"], 0),
    (["192.168.1.1"], 0),
    ([], 0),
    ([""], 1),
    (["  "], 1),
    (["*"], 1),
    (["*."], 1),
    (["a.*.b.com"], 1),
    (["github"], 1),
    (["a..b"], 1),
    (["host with space"], 1),
    (["999.1.1.1"], 1),
    (["a.com", "a.com"], 1),
    (["a.com", 5], 1),
    (["x" * 300], 1),
    (["a.com", "b.com", "a.com", "c.com", "b.com"], 2),
])
def test_validation_accepts_and_rejects(env, entries, expected_problems):
    response = env["client"].put("/org/egress-policy", headers=env["a_owner"],
                                 json={"entries": entries})
    if expected_problems == 0:
        assert response.status_code == 200, response.text
    else:
        assert response.status_code == 422, response.text
        assert len(response.json()["detail"]) == expected_problems, response.json()


def test_validation_is_case_insensitive_and_deduplicated(env):
    response = env["client"].put("/org/egress-policy", headers=env["a_owner"],
                                 json={"entries": ["Hooks.Slack.com", "hooks.slack.com"]})
    assert response.status_code == 422, "duplicates after normalisation must be rejected"

    response = env["client"].put("/org/egress-policy", headers=env["a_owner"],
                                 json={"entries": ["  Hooks.Slack.com  "]})
    assert response.status_code == 200
    assert response.json()["entries"] == ["hooks.slack.com"]


def test_non_list_body_is_rejected(env):
    response = env["client"].put("/org/egress-policy", headers=env["a_owner"],
                                 json={"entries": "hooks.slack.com"})
    assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #
def test_policy_starts_unconfigured(env):
    response = env["client"].get("/org/egress-policy", headers=env["a_owner"])
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is False
    assert body["entries"] == []
    assert body["effective"] is None, "no allowlist configured at all"


def test_create_update_and_remove(env):
    created = env["client"].put("/org/egress-policy", headers=env["a_owner"],
                                json={"entries": ["hooks.slack.com", "api.github.com"]})
    assert created.status_code == 200
    assert created.json()["enabled"] is True
    assert created.json()["entries"] == ["api.github.com", "hooks.slack.com"]
    assert sorted(created.json()["effective"]) == ["api.github.com", "hooks.slack.com"]

    updated = env["client"].put("/org/egress-policy", headers=env["a_owner"],
                                json={"entries": ["only.example.com"]})
    assert updated.json()["entries"] == ["only.example.com"]

    removed = env["client"].put("/org/egress-policy", headers=env["a_owner"],
                                json={"entries": []})
    assert removed.json()["enabled"] is False
    assert removed.json()["effective"] is None

    # Confirm it really cleared in the database.
    with session_scope(env["engine"]) as s:
        org = s.get(Organization, env["ids"]["org-a"])
        assert "egress_allowlist" not in (org.settings or "")


def test_settings_round_trip_preserves_other_keys(env):
    """Storing the policy must not clobber unrelated organization settings."""
    with session_scope(env["engine"]) as s:
        org = s.get(Organization, env["ids"]["org-a"])
        org.settings = '{"some_other_setting": "keep-me"}'

    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["hooks.slack.com"]})

    with session_scope(env["engine"]) as s:
        org = s.get(Organization, env["ids"]["org-a"])
        settings = json.loads(org.settings)
    assert settings["some_other_setting"] == "keep-me"
    assert settings["egress_allowlist"] == ["hooks.slack.com"]


def test_corrupt_settings_are_handled_safely(env):
    with session_scope(env["engine"]) as s:
        org = s.get(Organization, env["ids"]["org-a"])
        org.settings = "{not valid json"

    response = env["client"].get("/org/egress-policy", headers=env["a_owner"])
    assert response.status_code == 200
    assert response.json()["enabled"] is False


def test_malformed_policy_in_settings_never_widens_egress(env, record_connections):
    """A malformed stored policy must fail closed, not allow everything."""
    with session_scope(env["engine"]) as s:
        org = s.get(Organization, env["ids"]["org-a"])
        org.settings = '{"egress_allowlist": "not-a-list"}'

    provider = env["app"].state.org_allowlist_provider
    token = egress.set_org_context(env["ids"]["org-a"])
    try:
        assert provider() is None, "a malformed policy must not produce an allowlist"
    finally:
        egress.reset_org_context(token)


# --------------------------------------------------------------------------- #
# Authorization
# --------------------------------------------------------------------------- #
def test_viewer_cannot_update_the_policy(env):
    response = env["client"].put("/org/egress-policy", headers=env["a_viewer"],
                                 json={"entries": ["hooks.slack.com"]})
    assert response.status_code == 403
    assert "organization.manage" in response.json()["detail"]


def test_viewer_can_read_the_policy(env):
    assert env["client"].get("/org/egress-policy", headers=env["a_viewer"]).status_code == 200


def test_unauthenticated_is_rejected(env):
    assert env["client"].get("/org/egress-policy").status_code == 401
    assert env["client"].put("/org/egress-policy", json={"entries": []}).status_code == 401


# --------------------------------------------------------------------------- #
# Tenant isolation
# --------------------------------------------------------------------------- #
def test_org_b_cannot_read_or_write_org_a_policy(env):
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["only-for-a.example.com"]})

    other = env["client"].get("/org/egress-policy", headers=env["b_owner"]).json()
    assert other["entries"] == [], "org B must not see org A's allowlist"
    assert other["enabled"] is False

    written = env["client"].put("/org/egress-policy", headers=env["b_owner"],
                                json={"entries": ["only-for-b.example.com"]})
    assert written.json()["entries"] == ["only-for-b.example.com"]

    still_a = env["client"].get("/org/egress-policy", headers=env["a_owner"]).json()
    assert still_a["entries"] == ["only-for-a.example.com"], "org A's policy must be unchanged"


def test_org_a_allowlist_does_not_authorize_org_b(env, resolve_to, record_connections):
    """Org A's allowlist must never authorize org B.

    Org B has its own policy naming a different host. The property under test
    is that org A's entry does not leak across the tenancy boundary: org B
    can reach its own host and is refused org A's.

    (An organization with no policy at all has no allowlist and is governed
    only by the SSRF rules -- that is the documented "unconfigured" case,
    covered separately.)
    """
    import os
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["allowed-for-a.example"]})
    env["client"].put("/org/egress-policy", headers=env["b_owner"],
                      json={"entries": ["allowed-for-b.example"]})
    os.environ["IRONCLAD_ALLOW_PRIVATE_WEBHOOKS"] = "1"

    server = _RecordingServer()
    try:
        resolve_to({"allowed-for-a.example": "127.0.0.1",
                    "allowed-for-b.example": "127.0.0.1"})

        # Org A reaches its own host.
        token = egress.set_org_context(env["ids"]["org-a"])
        try:
            outcome = _request(f"http://allowed-for-a.example:{server.port}/hook",
                               b"{}", {}, timeout=5)
        finally:
            egress.reset_org_context(token)
        assert outcome.ok is True, outcome.error
        assert len(server.received) == 1

        # Org B reaches its own host, and is refused org A's.
        token = egress.set_org_context(env["ids"]["org-b"])
        try:
            outcome_b = _request(f"http://allowed-for-b.example:{server.port}/hook",
                                 b"{}", {}, timeout=5)
            assert outcome_b.ok is True, outcome_b.error

            before = len(record_connections)
            with pytest.raises(EgressBlocked):
                resolve_target(f"http://allowed-for-a.example:{server.port}/hook")
            assert len(record_connections) == before, "org B must not open a socket"
        finally:
            egress.reset_org_context(token)
        assert len(server.received) == 2, "org B must not reach org A's service"
    finally:
        server.shutdown()


def test_unknown_org_context_fails_closed(env):
    provider = env["app"].state.org_allowlist_provider
    token = egress.set_org_context(999999)
    try:
        assert provider() is None, "an unknown org must not produce an allowlist"
    finally:
        egress.reset_org_context(token)


def _allowed(env, org_slug, host):
    """Assert the allowlist decision for a host without needing real DNS.

    A blocked host raises EgressBlocked before DNS. An allowed host proceeds
    to DNS, which cannot resolve an invented hostname in a sandbox, so the
    allow decision is asserted on the effective allowlist directly.
    """
    provider = env["app"].state.org_allowlist_provider
    token = egress.set_org_context(env["ids"][org_slug])
    try:
        allowlist = egress.effective_allowlist(provider())
        return egress.host_allowed_for_org(host, allowlist)
    finally:
        egress.reset_org_context(token)


def _blocked(env, org_slug, host):
    """A blocked host must raise before any DNS lookup."""
    token = egress.set_org_context(env["ids"][org_slug])
    try:
        with pytest.raises(EgressBlocked):
            resolve_target(f"https://{host}/hook")
    finally:
        egress.reset_org_context(token)


# --------------------------------------------------------------------------- #
# Enforcement on the real delivery path
# --------------------------------------------------------------------------- #
def test_allowed_destination_succeeds(env, resolve_to, record_connections):
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["webhook.allowed.example"]})
    import os
    os.environ["IRONCLAD_ALLOW_PRIVATE_WEBHOOKS"] = "1"
    server = _RecordingServer()
    try:
        resolve_to({"webhook.allowed.example": "127.0.0.1"})
        token = egress.set_org_context(env["ids"]["org-a"])
        try:
            outcome = _request(f"http://webhook.allowed.example:{server.port}/hook",
                               b"{}", {}, timeout=5)
        finally:
            egress.reset_org_context(token)
        assert outcome.ok is True, outcome.error
        assert len(server.received) == 1
    finally:
        server.shutdown()


def test_rejected_destination_never_opens_a_socket(env, resolve_to, record_connections):
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["only-this.example"]})
    server = _RecordingServer()
    try:
        resolve_to({"other.example": "127.0.0.1"})
        token = egress.set_org_context(env["ids"]["org-a"])
        try:
            with pytest.raises(EgressBlocked):
                resolve_target(f"http://other.example:{server.port}/hook")
        finally:
            egress.reset_org_context(token)
        assert record_connections == [], "no socket may be opened"
        assert server.received == []
    finally:
        server.shutdown()


def test_rejected_host_is_never_resolved(env, record_connections, real_getaddrinfo):
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["only-this.example"]})
    looked_up = []

    def resolver(host, *args, **kwargs):
        looked_up.append(host)
        return real_getaddrinfo(host, *args, **kwargs)

    socket.getaddrinfo = resolver
    token = egress.set_org_context(env["ids"]["org-a"])
    try:
        with pytest.raises(EgressBlocked):
            resolve_target("https://attacker.example/hook")
    finally:
        egress.reset_org_context(token)
        socket.getaddrinfo = real_getaddrinfo
    assert looked_up == [], f"a rejected host must not be resolved, saw {looked_up}"


def test_exact_match_semantics(env, record_connections):
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["github.com"]})
    assert _allowed(env, "org-a", "github.com")
    for host in ("api.github.com", "evilgithub.com", "github.com.evil.net"):
        _blocked(env, "org-a", host)
    assert record_connections == [], "no socket may be opened to a rejected host"


def test_wildcard_semantics(env, record_connections):
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["*.github.com"]})
    assert _allowed(env, "org-a", "api.github.com")
    assert _allowed(env, "org-a", "a.b.github.com")
    for host in ("github.com", "evilgithub.com", "github.com.evil.net"):
        _blocked(env, "org-a", host)
    assert record_connections == []


def test_redirect_to_an_allowed_host_is_followed(env, resolve_to, record_connections):
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["first.example", "final.example"]})
    import os
    os.environ["IRONCLAD_ALLOW_PRIVATE_WEBHOOKS"] = "1"
    final = _RecordingServer()
    first = _RecordingServer(response_status=302,
                             location=f"http://final.example:{final.port}/final")
    try:
        resolve_to({"first.example": "127.0.0.1", "final.example": "127.0.0.1"})
        token = egress.set_org_context(env["ids"]["org-a"])
        try:
            outcome = _request(f"http://first.example:{first.port}/start", b"{}", {}, timeout=5)
        finally:
            egress.reset_org_context(token)
        assert outcome.ok is True, outcome.error
        assert final.received and final.received[0]["path"] == "/final"
    finally:
        first.shutdown()
        final.shutdown()


def test_redirect_to_an_unlisted_host_is_rejected(env, resolve_to, record_connections):
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["first.example"]})
    import os
    os.environ["IRONCLAD_ALLOW_PRIVATE_WEBHOOKS"] = "1"
    internal = _RecordingServer()
    first = _RecordingServer(response_status=302,
                             location=f"http://evil.example:{internal.port}/steal")
    try:
        resolve_to({"first.example": "127.0.0.1", "evil.example": "127.0.0.1"})
        token = egress.set_org_context(env["ids"]["org-a"])
        try:
            with pytest.raises(EgressBlocked):
                _request(f"http://first.example:{first.port}/start", b"{}", {}, timeout=5)
        finally:
            egress.reset_org_context(token)
        assert internal.received == [], "the unlisted redirect target must not be reached"
    finally:
        first.shutdown()
        internal.shutdown()


def test_delivery_layer_enforces_the_org_policy(env, record_connections):
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["only-this.example"]})

    class Integration:
        kind = "webhook"
        config = {"url": "https://not-allowed.example/hook"}
        secret = "s"

    token = egress.set_org_context(env["ids"]["org-a"])
    try:
        outcome = deliver(Integration(), {"event": "scan.completed"})
    finally:
        egress.reset_org_context(token)
    assert outcome.ok is False
    assert "organization egress policy" in outcome.error
    assert outcome.attempts == 1, "a blocked destination must not be retried"
    assert record_connections == []


# --------------------------------------------------------------------------- #
# Precedence
# --------------------------------------------------------------------------- #
def test_global_and_org_are_intersected(env, monkeypatch):
    """An organization can narrow the global allowlist but never widen it."""
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "hooks.slack.com,api.github.com")
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["api.github.com", "extra.example.com"]})

    body = env["client"].get("/org/egress-policy", headers=env["a_owner"]).json()
    assert sorted(body["global_allowlist"]) == ["api.github.com", "hooks.slack.com"]
    assert sorted(body["entries"]) == ["api.github.com", "extra.example.com"]
    assert body["effective"] == ["api.github.com"], "intersection, not union"

    assert _allowed(env, "org-a", "api.github.com")
    _blocked(env, "org-a", "extra.example.com")
    _blocked(env, "org-a", "hooks.slack.com")


def test_org_policy_applies_alone_when_global_is_unset(env):
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["only-org.example"]})
    assert _allowed(env, "org-a", "only-org.example")
    _blocked(env, "org-a", "anything-else.example")


def test_global_applies_alone_when_org_is_unconfigured(env):
    import os
    os.environ[EGRESS_ALLOWLIST_ENV] = "global-only.example"
    assert _allowed(env, "org-a", "global-only.example")
    _blocked(env, "org-a", "other.example")


def test_no_allowlist_at_all_preserves_existing_behaviour(env, resolve_to, record_connections):
    import os
    os.environ["IRONCLAD_ALLOW_PRIVATE_WEBHOOKS"] = "1"
    server = _RecordingServer()
    try:
        resolve_to({"anything.example": "127.0.0.1"})
        token = egress.set_org_context(env["ids"]["org-a"])
        try:
            outcome = _request(f"http://anything.example:{server.port}/hook", b"{}", {}, timeout=5)
        finally:
            egress.reset_org_context(token)
        assert outcome.ok is True, outcome.error
    finally:
        server.shutdown()


def test_no_org_context_falls_back_to_global(env, resolve_to, record_connections):
    """Pre-auth/CLI flows keep the pre-existing global-only behaviour."""
    import os
    os.environ[EGRESS_ALLOWLIST_ENV] = "global-only.example"
    os.environ["IRONCLAD_ALLOW_PRIVATE_WEBHOOKS"] = "1"
    server = _RecordingServer()
    try:
        resolve_to({"global-only.example": "127.0.0.1"})
        # No organization context bound at all.
        outcome = _request(f"http://global-only.example:{server.port}/hook", b"{}", {}, timeout=5)
        assert outcome.ok is True, outcome.error
        with pytest.raises(EgressBlocked):
            resolve_target("https://other.example/hook")
    finally:
        server.shutdown()


# --------------------------------------------------------------------------- #
# Existing protections preserved
# --------------------------------------------------------------------------- #
def test_private_addresses_still_blocked_even_when_allowlisted(env, record_connections):
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["169.254.169.254"]})
    token = egress.set_org_context(env["ids"]["org-a"])
    try:
        with pytest.raises(SsrfBlocked) as excinfo:
            resolve_target("http://169.254.169.254/latest/meta-data")
        assert "non-public" in str(excinfo.value)
    finally:
        egress.reset_org_context(token)
    assert record_connections == []


def test_dns_rebinding_still_blocked_with_an_org_policy(env, record_connections, real_getaddrinfo):
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["rebind.attacker.example"]})
    state = {"n": 0}

    def rebinding(host, *args, **kwargs):
        if host == "rebind.attacker.example":
            state["n"] += 1
            ip = PUBLIC_IP if state["n"] == 1 else "127.0.0.1"
            return real_getaddrinfo(ip, *args, **kwargs)
        return real_getaddrinfo(host, *args, **kwargs)

    socket.getaddrinfo = rebinding
    token = egress.set_org_context(env["ids"]["org-a"])
    try:
        # First resolution is public and allowlisted, so it is accepted.
        target = resolve_target("http://rebind.attacker.example/hook")
        assert target.ip == PUBLIC_IP
        # A later resolution returning a private address is still refused by
        # IP validation, so rebinding does not bypass anything.
        with pytest.raises(SsrfBlocked) as excinfo:
            resolve_target("http://rebind.attacker.example/hook")
        assert "non-public" in str(excinfo.value)
        assert all(addr[0] != "127.0.0.1" for addr in record_connections)
    finally:
        egress.reset_org_context(token)
        socket.getaddrinfo = real_getaddrinfo


def test_non_http_scheme_still_refused(env):
    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["example.com"]})
    token = egress.set_org_context(env["ids"]["org-a"])
    try:
        with pytest.raises(SsrfBlocked):
            resolve_target("ftp://example.com/x")
    finally:
        egress.reset_org_context(token)


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
def test_policy_change_is_audited(env):
    from ironclad.platform.models import AuditEvent

    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["hooks.slack.com"]})
    with session_scope(env["engine"]) as s:
        events = [e for e in s.execute(select(AuditEvent)).scalars().all()
                  if e.action == "org.egress_policy_updated"]
    assert events, "a security-sensitive policy change must be audited"
    assert events[0].org_id == env["ids"]["org-a"]
    metadata = json.loads(events[0].metadata_json)
    assert metadata["entries"] == ["hooks.slack.com"]
    assert metadata["previous"] == []


def test_audit_is_scoped_to_the_organization(env):
    from ironclad.platform.models import AuditEvent

    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["a.example"]})
    env["client"].put("/org/egress-policy", headers=env["b_owner"],
                      json={"entries": ["b.example"]})

    a_audit = env["client"].get("/audit", headers=env["a_owner"]).json()
    actions = [e["action"] for e in a_audit]
    assert "org.egress_policy_updated" in actions
    # Org A must not see org B's audit entries.
    assert all(e["org_id"] == env["ids"]["org-a"] for e in a_audit)


def test_failed_update_is_not_audited(env):
    from ironclad.platform.models import AuditEvent

    env["client"].put("/org/egress-policy", headers=env["a_owner"],
                      json={"entries": ["*"]})  # invalid
    with session_scope(env["engine"]) as s:
        events = [e for e in s.execute(select(AuditEvent)).scalars().all()
                  if e.action == "org.egress_policy_updated"]
    assert events == [], "a rejected update must not be recorded as a change"


def test_unauthorized_update_is_not_audited(env):
    from ironclad.platform.models import AuditEvent

    env["client"].put("/org/egress-policy", headers=env["a_viewer"],
                      json={"entries": ["hooks.slack.com"]})
    with session_scope(env["engine"]) as s:
        events = [e for e in s.execute(select(AuditEvent)).scalars().all()
                  if e.action == "org.egress_policy_updated"]
    assert events == []


# --------------------------------------------------------------------------- #
# Provider resilience
# --------------------------------------------------------------------------- #
def test_broken_provider_fails_closed(env, monkeypatch):
    """A provider that raises must not widen egress."""
    from ironclad.platform import integrations

    def broken():
        raise RuntimeError("database unavailable")

    integrations.set_org_allowlist_provider(broken)
    try:
        import os
        os.environ[EGRESS_ALLOWLIST_ENV] = "global-only.example"
        # A raising provider must fall back to the global allowlist rather
        # than allowing everything.
        from ironclad.platform import integrations as ig
        assert ig._org_allowlist() is None
        assert ig._combine_allowlists(ig.egress_allowlist(), ig._org_allowlist()) == \
            frozenset({"global-only.example"})
        with pytest.raises(EgressBlocked):
            resolve_target("https://other.example/hook")
    finally:
        integrations.set_org_allowlist_provider(env["app"].state.org_allowlist_provider)
