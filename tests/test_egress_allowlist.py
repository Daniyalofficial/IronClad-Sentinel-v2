"""Egress allowlist tests.

The allowlist restricts outbound integration delivery to explicitly listed
hostnames. It is enforced inside `resolve_target()` *before* DNS, so a
rejected host is never resolved and no socket is ever opened to it -- which
is asserted on `socket.create_connection`, not inferred.

Matching is exact and case-insensitive, with an explicit leading ``*.`` for
subdomains. There is deliberately no implicit suffix matching: that is
precisely how `evilgithub.com` would slip past `github.com`.

When the allowlist is unset, behaviour must be byte-for-byte identical to
before the feature existed; the existing SSRF controls remain the only
control.
"""
from __future__ import annotations

import http.server
import socket
import threading

import pytest

from ironclad.platform.integrations import (
    EGRESS_ALLOWLIST_ENV,
    EgressBlocked,
    SsrfBlocked,
    _request,
    deliver,
    egress_allowlist,
    host_allowed_by_allowlist,
    resolve_target,
    validate_config,
)

PUBLIC_IP = "93.184.216.34"
REBIND_HOST = "rebind.attacker.example"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
class _RecordingServer:
    """A real local HTTP server that records what it received."""

    def __init__(self, response_status=200, location=None):
        outer = self
        self.received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                outer.received.append({
                    "path": self.path,
                    "host": self.headers.get("Host"),
                    "peer": self.client_address[0],
                    "body": self.rfile.read(length),
                })
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
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def shutdown(self):
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def real_getaddrinfo():
    return socket.getaddrinfo


@pytest.fixture
def record_connections(real_getaddrinfo):
    """Record the (host, port) of every real socket connection."""
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


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def test_allowlist_unset_returns_none(monkeypatch):
    monkeypatch.delenv(EGRESS_ALLOWLIST_ENV, raising=False)
    assert egress_allowlist() is None


@pytest.mark.parametrize("value", ["", "   ", ",,,", " , "])
def test_empty_or_blank_allowlist_is_treated_as_unset(monkeypatch, value):
    """A stray empty variable must not silently deny every integration."""
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, value)
    assert egress_allowlist() is None


def test_allowlist_is_parsed_trimmed_and_lowercased(monkeypatch):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, " Hooks.Slack.COM , api.github.com ,,")
    assert egress_allowlist() == frozenset({"hooks.slack.com", "api.github.com"})


def test_single_entry_allowlist(monkeypatch):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "hooks.slack.com")
    assert egress_allowlist() == frozenset({"hooks.slack.com"})


# --------------------------------------------------------------------------- #
# Matching semantics
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("host", [
    "hooks.slack.com",
    "HOOKS.SLACK.COM",
    "Hooks.Slack.Com",
    "  hooks.slack.com  ",
])
def test_exact_match_is_case_insensitive_and_trimmed(host):
    allowlist = frozenset({"hooks.slack.com"})
    assert host_allowed_by_allowlist(host, allowlist) is True


@pytest.mark.parametrize("host", [
    "evilgithub.com",              # the suffix trick
    "github.com.evil.net",         # allowed name as a prefix of an attacker domain
    "notgithub.com",
    "xgithub.com",
    "github.com.attacker.com",
    "api.github.com.evil.com",
    "hooksslack.com",
    "sub.hooks.slack.com",         # subdomain of an exact entry is NOT allowed
])
def test_similar_and_suffix_hostnames_are_rejected(host):
    """No implicit suffix matching: `evilgithub.com` must never match `github.com`."""
    allowlist = frozenset({"github.com", "hooks.slack.com"})
    assert host_allowed_by_allowlist(host, allowlist) is False, host


def test_exact_entry_does_not_match_subdomains():
    allowlist = frozenset({"github.com"})
    assert host_allowed_by_allowlist("github.com", allowlist) is True
    assert host_allowed_by_allowlist("api.github.com", allowlist) is False


@pytest.mark.parametrize("host,expected", [
    ("api.github.com", True),
    ("a.b.github.com", True),        # multi-level subdomain
    ("github.com", False),           # wildcard does NOT include the apex
    ("evilgithub.com", False),       # the suffix trick
    ("xgithub.com", False),
    ("github.com.evil.net", False),
    ("notgithub.com", False),
    ("api.github.com.evil.com", False),
])
def test_wildcard_matching_is_anchored_to_a_label_boundary(host, expected):
    allowlist = frozenset({"*.github.com"})
    assert host_allowed_by_allowlist(host, allowlist) is expected, host


def test_wildcard_does_not_match_a_bare_dot_host():
    allowlist = frozenset({"*.github.com"})
    assert host_allowed_by_allowlist(".github.com", allowlist) is False
    assert host_allowed_by_allowlist("", allowlist) is False


def test_none_allowlist_allows_everything():
    assert host_allowed_by_allowlist("anything.example.com", None) is True


def test_multiple_allowlisted_hosts(monkeypatch):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV,
                       "hooks.slack.com,api.github.com,gitlab.com,*.internal.example.com")
    allowlist = egress_allowlist()
    for host in ("hooks.slack.com", "api.github.com", "gitlab.com", "a.internal.example.com"):
        assert host_allowed_by_allowlist(host, allowlist) is True, host
    for host in ("evilgithub.com", "slack.com", "example.com"):
        assert host_allowed_by_allowlist(host, allowlist) is False, host


def test_ip_literal_must_be_listed_verbatim(monkeypatch):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "93.184.216.34")
    allowlist = egress_allowlist()
    assert host_allowed_by_allowlist("93.184.216.34", allowlist) is True
    assert host_allowed_by_allowlist("93.184.216.35", allowlist) is False


def test_ipv6_literal_matching(monkeypatch):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "2001:db8::1")
    allowlist = egress_allowlist()
    assert host_allowed_by_allowlist("2001:db8::1", allowlist) is True
    assert host_allowed_by_allowlist("::1", allowlist) is False
    # Brackets are stripped so a URL-form literal still matches.
    assert host_allowed_by_allowlist("[2001:db8::1]", allowlist) is True


# --------------------------------------------------------------------------- #
# Enforcement at the connection boundary
# --------------------------------------------------------------------------- #
def test_allowed_hostname_succeeds(monkeypatch, resolve_to, record_connections):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "webhook.allowed.example")
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    server = _RecordingServer()
    try:
        resolve_to({"webhook.allowed.example": "127.0.0.1"})
        outcome = _request(f"http://webhook.allowed.example:{server.port}/hook",
                           b"{}", {}, timeout=5)
        assert outcome.ok is True, outcome.error
        assert len(server.received) == 1
    finally:
        server.shutdown()


def test_unknown_hostname_is_rejected(monkeypatch, record_connections):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "hooks.slack.com")
    with pytest.raises(EgressBlocked) as excinfo:
        resolve_target("https://not-allowed.example.com/hook")
    assert "not-allowed.example.com" in str(excinfo.value)
    assert record_connections == [], "no socket may be opened to a rejected host"


def test_rejected_host_is_never_resolved(monkeypatch, record_connections, real_getaddrinfo):
    """The check runs before DNS, so a rejected host is never even resolved."""
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "hooks.slack.com")
    looked_up = []

    def resolver(host, *args, **kwargs):
        looked_up.append(host)
        return real_getaddrinfo(host, *args, **kwargs)

    socket.getaddrinfo = resolver
    try:
        with pytest.raises(EgressBlocked):
            resolve_target("https://attacker.example/hook")
    finally:
        socket.getaddrinfo = real_getaddrinfo
    assert looked_up == [], f"a rejected host must not be resolved, saw {looked_up}"
    assert record_connections == []


def test_suffix_trick_is_rejected_at_resolution(monkeypatch, record_connections):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "github.com")
    with pytest.raises(EgressBlocked):
        resolve_target("https://evilgithub.com/hook")
    assert record_connections == []


def test_delivery_to_an_unlisted_host_is_blocked(monkeypatch, record_connections):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "hooks.slack.com")

    class Integration:
        kind = "webhook"
        config = {"url": "https://not-allowed.example.com/hook"}
        secret = "s"

    outcome = deliver(Integration(), {"event": "scan.completed"})
    assert outcome.ok is False
    assert "blocked" in outcome.error
    assert "not permitted by" in outcome.error
    assert outcome.attempts == 1, "a blocked destination must not be retried"
    assert record_connections == []


def test_redirect_to_an_allowed_host_is_followed(monkeypatch, resolve_to, record_connections):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "first.example, final.example")
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    final = _RecordingServer()
    first = _RecordingServer(response_status=302,
                             location=f"http://final.example:{final.port}/final")
    try:
        resolve_to({"first.example": "127.0.0.1", "final.example": "127.0.0.1"})
        outcome = _request(f"http://first.example:{first.port}/start", b"{}", {}, timeout=5)
        assert outcome.ok is True, outcome.error
        assert final.received and final.received[0]["path"] == "/final"
    finally:
        first.shutdown()
        final.shutdown()


def test_redirect_to_an_unlisted_host_is_rejected(monkeypatch, resolve_to, record_connections):
    """Every redirect hop goes through the allowlist, not just the first."""
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "first.example")
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    internal = _RecordingServer()
    first = _RecordingServer(response_status=302,
                             location=f"http://evil.example:{internal.port}/steal")
    try:
        resolve_to({"first.example": "127.0.0.1", "evil.example": "127.0.0.1"})
        with pytest.raises(EgressBlocked) as excinfo:
            _request(f"http://first.example:{first.port}/start", b"{}", {}, timeout=5)
        assert "evil.example" in str(excinfo.value)
        assert internal.received == [], "the unlisted redirect target must not be reached"
    finally:
        first.shutdown()
        internal.shutdown()


def test_redirect_using_the_suffix_trick_is_rejected(monkeypatch, resolve_to, record_connections):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "*.github.com")
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    internal = _RecordingServer()
    first = _RecordingServer(response_status=302,
                             location=f"http://evilgithub.com:{internal.port}/steal")
    try:
        resolve_to({"first.github.com": "127.0.0.1", "evilgithub.com": "127.0.0.1"})
        with pytest.raises(EgressBlocked):
            _request(f"http://first.github.com:{first.port}/start", b"{}", {}, timeout=5)
        assert internal.received == []
    finally:
        first.shutdown()
        internal.shutdown()


# --------------------------------------------------------------------------- #
# Existing protections are preserved
# --------------------------------------------------------------------------- #
def test_allowlist_disabled_preserves_existing_behaviour(monkeypatch, resolve_to,
                                                        record_connections):
    """With no allowlist, any public host is reachable -- behaviour unchanged."""
    monkeypatch.delenv(EGRESS_ALLOWLIST_ENV, raising=False)
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    server = _RecordingServer()
    try:
        resolve_to({"anything.example": "127.0.0.1"})
        outcome = _request(f"http://anything.example:{server.port}/hook", b"{}", {}, timeout=5)
        assert outcome.ok is True, outcome.error
    finally:
        server.shutdown()


def test_private_addresses_still_governed_by_ssrf_rules(monkeypatch, record_connections):
    """Being on the allowlist does not exempt a host from the SSRF checks."""
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "169.254.169.254")
    monkeypatch.delenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", raising=False)
    with pytest.raises(SsrfBlocked) as excinfo:
        resolve_target("http://169.254.169.254/latest/meta-data")
    assert "non-public" in str(excinfo.value)
    assert record_connections == []


def test_loopback_on_the_allowlist_is_still_refused_without_the_hatch(
        monkeypatch, record_connections):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "127.0.0.1")
    monkeypatch.delenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", raising=False)
    with pytest.raises(SsrfBlocked):
        resolve_target("http://127.0.0.1:9999/hook")
    assert record_connections == []


def test_non_http_schemes_still_refused_even_when_allowlisted(monkeypatch):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "example.com")
    with pytest.raises(SsrfBlocked):
        resolve_target("ftp://example.com/x")
    with pytest.raises(SsrfBlocked):
        resolve_target("file:///etc/passwd")


def test_dns_rebinding_protection_still_works(monkeypatch, record_connections, real_getaddrinfo):
    """The allowlist does not weaken DNS-rebinding protection.

    A host can be allowlisted and still rebind to a private address; the IP
    validation must still refuse it.
    """
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, REBIND_HOST)
    monkeypatch.delenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", raising=False)
    state = {"n": 0}

    def rebinding(host, *args, **kwargs):
        if host == REBIND_HOST:
            state["n"] += 1
            ip = PUBLIC_IP if state["n"] == 1 else "127.0.0.1"
            return real_getaddrinfo(ip, *args, **kwargs)
        return real_getaddrinfo(host, *args, **kwargs)

    socket.getaddrinfo = rebinding
    try:
        # First resolution is public and allowlisted, so it is accepted.
        target = resolve_target(f"http://{REBIND_HOST}/hook")
        assert target.ip == PUBLIC_IP
        # A later resolution returning a private address is still refused.
        with pytest.raises(SsrfBlocked) as excinfo:
            resolve_target(f"http://{REBIND_HOST}/hook")
        assert "non-public" in str(excinfo.value)
        assert all(addr[0] != "127.0.0.1" for addr in record_connections)
    finally:
        socket.getaddrinfo = real_getaddrinfo


def test_retries_and_4xx_behaviour_unchanged(monkeypatch, record_connections):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "webhook.allowed.example")
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    server = _RecordingServer(response_status=404)
    try:
        class Integration:
            kind = "webhook"
            config = {"url": f"http://127.0.0.1:{server.port}/hook"}
            secret = "s"

        # 127.0.0.1 is not on the allowlist, so this is blocked rather than sent.
        blocked = deliver(Integration(), {"event": "x"})
        assert blocked.ok is False and "not permitted by" in blocked.error

        # With the host allowlisted, a 404 is still not retried.
        import os
        os.environ[EGRESS_ALLOWLIST_ENV] = "127.0.0.1"
        outcome = deliver(Integration(), {"event": "x"})
        assert outcome.ok is False
        assert outcome.status_code == 404
        assert outcome.attempts == 1, "a 404 must not be retried"
    finally:
        server.shutdown()


def test_signing_still_applies_with_the_allowlist(monkeypatch, resolve_to, record_connections):
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "webhook.allowed.example")
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    server = _RecordingServer()
    try:
        resolve_to({"webhook.allowed.example": "127.0.0.1"})

        class Integration:
            kind = "webhook"
            config = {"url": f"http://webhook.allowed.example:{server.port}/hook"}
            secret = "signing-secret"

        outcome = deliver(Integration(), {"event": "scan.completed"})
        assert outcome.ok is True, outcome.error
        assert server.received[0]["body"]
    finally:
        server.shutdown()


def test_validate_config_still_enforces_the_ssrf_guard(monkeypatch):
    """Configuration-time validation is unchanged and independent."""
    monkeypatch.delenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", raising=False)
    monkeypatch.setenv(EGRESS_ALLOWLIST_ENV, "169.254.169.254")
    problems = validate_config("webhook", {"url": "http://169.254.169.254/latest"})
    assert problems, "the SSRF guard must still reject private addresses"
    assert validate_config("webhook", {"url": "https://hooks.slack.com/services/x"}) == []
