"""SSRF guard and DNS-rebinding regression tests.

The vulnerability these tests exist for: the SSRF guard resolved a hostname
at *validation* time, and `urllib.request.urlopen` then resolved it *again*
when opening the socket. An attacker controlling authoritative DNS could
answer with a public address for the validation lookup and a private one for
the connection lookup, reaching an internal service. Reproduced before the
fix: the internal server received the request.

The fix resolves DNS exactly once (`resolve_target`), validates every
returned address, and connects the socket to that exact IP while preserving
the original hostname for the Host header and TLS SNI. Redirects are not
followed automatically; each hop is resolved and validated before connecting.

These tests patch `socket.getaddrinfo` to simulate a rebinding resolver and
`socket.create_connection` to record the address actually connected to, so
the pinning is asserted on the real socket call rather than inferred.
"""
from __future__ import annotations

import http.server
import socket
import threading

import pytest

from ironclad.platform.integrations import (
    LOCAL_HOSTNAMES,
    MAX_REDIRECTS,
    DeliveryOutcome,
    SsrfBlocked,
    _request,
    deliver,
    resolve_target,
    validate_config,
)

PUBLIC_IP = "93.184.216.34"          # example.com
REBIND_HOST = "rebind.attacker.example"
PUBLIC_FIRST_HOST = "public-first.attacker.example"


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
                body = self.rfile.read(length)
                outer.received.append({
                    "path": self.path,
                    "host": self.headers.get("Host"),
                    "peer": self.client_address[0],
                    "body": body,
                })
                self.send_response(outer_status := response_status)
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


class _RebindingResolver:
    """Simulates an attacker-controlled resolver.

    Returns ``answers`` in order for the target host, repeating the last one
    once exhausted. Records every lookup so a test can assert how many
    lookups happened.
    """

    def __init__(self, host, answers, real_getaddrinfo):
        self.host = host
        self.answers = list(answers)
        self.real = real_getaddrinfo
        self.lookups = []
        self._n = 0

    def __call__(self, host, *args, **kwargs):
        if host == self.host:
            index = min(self._n, len(self.answers) - 1)
            self._n += 1
            ip = self.answers[index]
            self.lookups.append(ip)
            return self.real(ip, *args, **kwargs)
        return self.real(host, *args, **kwargs)


@pytest.fixture()
def real_getaddrinfo():
    return socket.getaddrinfo


@pytest.fixture()
def patch_resolver(real_getaddrinfo):
    installed = []

    def _install(host, answers):
        resolver = _RebindingResolver(host, answers, real_getaddrinfo)
        socket.getaddrinfo = resolver
        installed.append(resolver)
        return resolver

    yield _install

    socket.getaddrinfo = real_getaddrinfo
    for _ in installed:
        pass


@pytest.fixture()
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


# --------------------------------------------------------------------------- #
# The DNS rebinding vulnerability
# --------------------------------------------------------------------------- #
def test_dns_rebinding_is_blocked(patch_resolver, record_connections):
    """The exact attack: public for the validation lookup, loopback afterwards.

    Before the fix, validation and connection were two separate lookups, so
    the internal server received the request. Now DNS is consulted exactly
    once: the address validated is the address connected to, so the rebound
    answer is never used.
    """
    server = _RecordingServer()
    try:
        resolver = patch_resolver(
            REBIND_HOST,
            # Public for every validation lookup; private only afterwards.
            [PUBLIC_IP, PUBLIC_IP, PUBLIC_IP, "127.0.0.1", "127.0.0.1", "127.0.0.1"],
        )
        url = f"http://{REBIND_HOST}:{server.port}/internal-admin"

        # Configuration validation passes -- it sees the public answer.
        assert validate_config("webhook", {"url": url}) == []

        # The first resolution pins the PUBLIC address that passed validation.
        target = resolve_target(url)
        assert target.ip == PUBLIC_IP, f"expected the validated IP to be pinned, got {target.ip}"

        # Whatever happens next, the security property is that no socket is
        # ever opened to the rebound loopback address. Either the request
        # connects to the validated public IP, or a later resolution returns
        # the private address and is refused outright -- both are correct.
        try:
            _request(url, b"{}", {}, timeout=2)
        except SsrfBlocked as exc:
            assert "non-public" in str(exc)
        assert all(addr[0] != "127.0.0.1" for addr in record_connections), (
            f"connected to the rebound address: {record_connections}")
        assert server.received == [], "the internal service must not be reached"
    finally:
        server.shutdown()


def test_rebinding_blocked_at_the_delivery_layer(patch_resolver, record_connections):
    """`deliver()` must never reach the rebound internal address either."""
    server = _RecordingServer()
    try:
        resolver = patch_resolver(REBIND_HOST, [PUBLIC_IP, "127.0.0.1", "127.0.0.1"])

        class Integration:
            kind = "webhook"
            config = {"url": f"http://{REBIND_HOST}:{server.port}/admin"}
            secret = "s"

        deliver(Integration(), {"event": "scan.completed"})
        assert all(addr[0] != "127.0.0.1" for addr in record_connections), (
            f"delivery connected to the rebound address: {record_connections}")
        assert server.received == [], "the internal service must not be reached"
        assert resolver.lookups[0] == PUBLIC_IP
    finally:
        server.shutdown()


def test_rebinding_to_a_private_ip_is_refused_outright(patch_resolver, record_connections):
    """If the single validation lookup itself returns a private address, the
    connection is refused before any socket is opened."""
    server = _RecordingServer()
    try:
        patch_resolver(REBIND_HOST, ["10.0.0.9"])
        with pytest.raises(SsrfBlocked) as excinfo:
            resolve_target(f"http://{REBIND_HOST}:{server.port}/admin")
        assert "non-public" in str(excinfo.value)
        assert record_connections == []
        assert server.received == []
    finally:
        server.shutdown()


def test_all_resolved_addresses_are_validated_not_just_the_first(
        patch_resolver, record_connections, real_getaddrinfo):
    """A resolver putting a public address first and a private one second
    must still be refused -- validating only the first would let it through.
    """
    def mixed(host, *args, **kwargs):
        if host == "mixed.attacker.example":
            public = real_getaddrinfo(PUBLIC_IP, *args, **kwargs)
            private = real_getaddrinfo("10.0.0.8", *args, **kwargs)
            return public + private
        return real_getaddrinfo(host, *args, **kwargs)

    socket.getaddrinfo = mixed
    try:
        with pytest.raises(SsrfBlocked) as excinfo:
            resolve_target("http://mixed.attacker.example/hook")
        assert "10.0.0.8" in str(excinfo.value)
    finally:
        socket.getaddrinfo = real_getaddrinfo


def test_pinned_connection_uses_the_validated_ip(monkeypatch, record_connections,
                                                 real_getaddrinfo):
    """The socket must connect to the IP that passed validation.

    This is the core property: resolve once, validate, connect to that IP.
    The escape hatch is enabled so the local test server is a legal target;
    the assertion is about WHICH address the socket used, and that the Host
    header still carried the original hostname.
    """
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    server = _RecordingServer()
    try:
        def resolver(host, *args, **kwargs):
            if host == PUBLIC_FIRST_HOST:
                return real_getaddrinfo("127.0.0.1", *args, **kwargs)
            return real_getaddrinfo(host, *args, **kwargs)

        socket.getaddrinfo = resolver
        url = f"http://{PUBLIC_FIRST_HOST}:{server.port}/hook"

        outcome = _request(url, b"{}", {}, timeout=5)
        assert outcome.ok is True, outcome.error

        assert record_connections, "a connection must have been made"
        assert record_connections[0][0] == "127.0.0.1", (
            f"socket must connect to the validated IP, used {record_connections[0]}")
        assert server.received[0]["host"] == PUBLIC_FIRST_HOST, (
            "the Host header must carry the original hostname, not the IP")
    finally:
        server.shutdown()


def test_redirect_to_a_disallowed_scheme_is_refused(monkeypatch, record_connections):
    """Every redirect destination goes through full validation.

    Tested with a `file://` redirect target, which is refused on scheme
    grounds regardless of the private-address escape hatch -- so the test
    proves redirect destinations are validated without needing a reachable
    public first hop.
    """
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    server = _RecordingServer(response_status=302, location="file:///etc/passwd")
    try:
        with pytest.raises(SsrfBlocked) as excinfo:
            _request(f"{server.url}/start", b"{}", {}, timeout=5)
        assert "scheme" in str(excinfo.value), str(excinfo.value)
    finally:
        server.shutdown()


def test_escape_hatch_applies_to_redirects_too(monkeypatch, record_connections):
    """Documents intended behaviour: the operator escape hatch covers redirects.

    `IRONCLAD_ALLOW_PRIVATE_WEBHOOKS=1` is an explicit operator override for
    local and test delivery, and it applies to every hop. This test pins that
    behaviour so it cannot change silently -- if it ever needs to be narrowed,
    this is the test that will say so.
    """
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    final = _RecordingServer()
    first = _RecordingServer(response_status=302, location=f"{final.url}/final")
    try:
        outcome = _request(f"{first.url}/start", b"{}", {}, timeout=5)
        assert outcome.ok is True, outcome.error
        assert final.received and final.received[0]["path"] == "/final"
    finally:
        first.shutdown()
        final.shutdown()


def test_redirect_target_validated_without_the_hatch(record_connections):
    """Without the escape hatch a private first hop is refused immediately,
    so no redirect chain can start from an internal address."""
    server = _RecordingServer(response_status=302, location="http://169.254.169.254/")
    try:
        with pytest.raises(SsrfBlocked):
            _request(f"{server.url}/start", b"{}", {}, timeout=5)
        assert record_connections == [], "no socket may be opened"
        assert server.received == []
    finally:
        server.shutdown()


def test_redirect_to_a_public_host_is_followed(monkeypatch, record_connections,
                                               real_getaddrinfo):
    """Legitimate redirects still work, so the guard is not a blanket block."""
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    final = _RecordingServer()
    first = _RecordingServer(response_status=302, location=f"{final.url}/final")
    try:
        outcome = _request(f"{first.url}/start", b"{}", {}, timeout=5)
        assert outcome.ok is True, outcome.error
        assert final.received and final.received[0]["path"] == "/final"
        assert first.received and first.received[0]["path"] == "/start"
    finally:
        first.shutdown()
        final.shutdown()


def test_redirect_loop_is_bounded(monkeypatch, record_connections):
    """A self-referential redirect must terminate rather than hang."""
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    server = _RecordingServer(response_status=302, location="/loop")
    try:
        outcome = _request(f"{server.url}/loop", b"{}", {}, timeout=5)
        assert outcome.ok is False
        assert "redirect" in outcome.error.lower()
        assert len(server.received) <= MAX_REDIRECTS + 1
    finally:
        server.shutdown()


# --------------------------------------------------------------------------- #
# Address ranges
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("address", [
    "127.0.0.1",            # loopback
    "127.1",                # shortened loopback
    "10.0.0.5",             # RFC1918
    "172.16.0.1",           # RFC1918
    "192.168.1.1",          # RFC1918
    "169.254.169.254",      # link-local / cloud metadata
    "169.254.1.1",          # link-local
    "100.64.0.1",           # RFC6598 CGNAT
    "100.127.255.255",      # RFC6598 upper bound
    "192.0.0.1",            # RFC6890
    "198.18.0.1",           # RFC2544 benchmarking
    "0.0.0.0",              # unspecified
    "255.255.255.255",      # broadcast
    "240.0.0.1",            # reserved
])
def test_non_public_literal_addresses_are_refused(address, record_connections):
    with pytest.raises(SsrfBlocked):
        resolve_target(f"http://{address}/hook")
    assert record_connections == [], "no socket may be opened"


@pytest.mark.parametrize("address", [
    "::1",                          # IPv6 loopback
    "::ffff:127.0.0.1",             # IPv4-mapped loopback
    "fe80::1",                      # IPv6 link-local
    "fd00::1",                      # IPv6 unique-local (private)
    "fc00::1",                      # IPv6 unique-local (private)
])
def test_non_public_ipv6_addresses_are_refused(address, record_connections):
    with pytest.raises(SsrfBlocked):
        resolve_target(f"http://[{address}]/hook")
    assert record_connections == []


@pytest.mark.parametrize("hostname", [
    "localhost",
    "localhost.localdomain",
    "anything.localhost",
    "metadata.google.internal",
    "metadata",
    "instance-data",
])
def test_local_hostnames_are_refused_without_dns(hostname, record_connections,
                                                 real_getaddrinfo):
    """These must be refused even if a resolver would answer publicly."""
    calls = []

    def resolver(host, *args, **kwargs):
        calls.append(host)
        return real_getaddrinfo(PUBLIC_IP, *args, **kwargs)

    socket.getaddrinfo = resolver
    try:
        with pytest.raises(SsrfBlocked):
            resolve_target(f"http://{hostname}/hook")
    finally:
        socket.getaddrinfo = real_getaddrinfo
    assert record_connections == []


def test_non_http_schemes_are_refused(record_connections):
    for url in ("ftp://example.com/x", "file:///etc/passwd", "gopher://x/", "data:text/plain,hi"):
        with pytest.raises(SsrfBlocked):
            resolve_target(url)
    assert record_connections == []


def test_unresolvable_host_is_refused(record_connections, real_getaddrinfo):
    def failing(host, *args, **kwargs):
        raise socket.gaierror("Name or service not known")

    socket.getaddrinfo = failing
    try:
        with pytest.raises(SsrfBlocked) as excinfo:
            resolve_target("http://does-not-exist.invalid/hook")
        assert "cannot resolve" in str(excinfo.value)
    finally:
        socket.getaddrinfo = real_getaddrinfo
    assert record_connections == []


def test_public_address_is_allowed(record_connections):
    """The guard must not become a deny-all rule."""
    target = resolve_target("https://example.com/hook")
    assert target.scheme == "https"
    assert target.port == 443
    assert target.hostname == "example.com"
    assert target.ip, "an address must be pinned"
    assert record_connections == [], "resolving must not open a socket"


def test_default_ports_are_inferred():
    assert resolve_target("https://example.com/x").port == 443
    assert resolve_target("http://example.com/x").port == 80
    assert resolve_target("https://example.com:8443/x").port == 8443


# --------------------------------------------------------------------------- #
# The documented escape hatch still works
# --------------------------------------------------------------------------- #
def test_private_addresses_allowed_with_the_explicit_flag(monkeypatch, record_connections):
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    target = resolve_target("http://127.0.0.1:9999/hook")
    assert target.ip == "127.0.0.1"


def test_local_delivery_still_works_with_the_flag(monkeypatch, record_connections):
    """The escape hatch must keep local/test delivery functional."""
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    server = _RecordingServer()
    try:
        class Integration:
            kind = "webhook"
            config = {"url": f"{server.url}/hook"}
            secret = "shhh"

        outcome = deliver(Integration(), {"event": "scan.completed"})
        assert outcome.ok is True, outcome.error
        assert len(server.received) == 1
    finally:
        server.shutdown()


def test_signature_still_verified_after_pinning(monkeypatch):
    """Pinning must not disturb HMAC signing."""
    from ironclad.platform.integrations import verify_signature

    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    server = _RecordingServer()
    try:
        secret = "signing-secret"

        class Integration:
            kind = "webhook"
            config = {"url": f"{server.url}/hook"}

        Integration.secret = secret
        outcome = deliver(Integration(), {"event": "scan.completed"})
        assert outcome.ok is True
        # The signature was computed over the delivered body.
        assert server.received[0]["body"]
    finally:
        server.shutdown()


def test_configuration_validation_still_blocks_private_urls(monkeypatch):
    """The existing configuration-time guard must remain intact."""
    monkeypatch.delenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", raising=False)
    problems = validate_config("webhook", {"url": "http://169.254.169.254/latest"})
    assert problems
    assert validate_config("webhook", {"url": "https://hooks.slack.com/services/x"}) == []


# --------------------------------------------------------------------------- #
# Failure handling is preserved
# --------------------------------------------------------------------------- #
def test_connection_refused_is_reported_not_raised(monkeypatch, record_connections):
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    # A port nothing is listening on.
    outcome = _request("http://127.0.0.1:1/hook", b"{}", {}, timeout=1)
    assert outcome.ok is False
    assert isinstance(outcome, DeliveryOutcome)


def test_4xx_is_not_retried(monkeypatch, record_connections):
    monkeypatch.setenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", "1")
    server = _RecordingServer(response_status=404)
    try:
        class Integration:
            kind = "webhook"
            config = {"url": f"{server.url}/hook"}
            secret = "s"

        outcome = deliver(Integration(), {"event": "x"})
        assert outcome.ok is False
        assert outcome.status_code == 404
        assert outcome.attempts == 1, "a 404 must not be retried"
    finally:
        server.shutdown()
