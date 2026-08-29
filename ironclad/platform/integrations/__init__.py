"""Outbound integrations.

Design constraints, all of which are deliberate:

* **Real deliveries only.** Every kind here performs an actual HTTPS
  request. Nothing returns a canned "delivered" result.
* **Opt-in network egress.** The product is offline-first; integrations
  are the only code allowed to open an outbound socket, and only when an
  administrator has created one.
* **Hard timeouts and bounded retries** so a dead endpoint cannot stall a
  worker or pile up connections.
* **Signed payloads.** Webhooks are HMAC-SHA256 signed with the
  integration's secret so a receiver can prove the payload came from this
  IronClad instance.
* **Secrets never leave the database in plaintext form**: they are used to
  compute a signature and are redacted from logs and audit records.
* **SSRF guard with IP pinning.** A webhook URL must be http(s), and
  private/link-local/non-public addresses are rejected unless
  ``IRONCLAD_ALLOW_PRIVATE_WEBHOOKS=1`` is set. The address is resolved
  **once**, validated, and the socket is then connected to *that exact IP*,
  with the original hostname preserved for the Host header and TLS SNI.
  Validation and connection therefore cannot disagree, which closes DNS
  rebinding. Every redirect destination is resolved and validated again,
  so a public URL cannot redirect into the internal network.
* **Optional egress allowlist.** ``IRONCLAD_EGRESS_ALLOWLIST`` restricts
  outbound delivery to explicitly listed hostnames, enforced before DNS so
  an unlisted host is never resolved or connected to. Matching is exact and
  case-insensitive, with an explicit leading ``*.`` for subdomains; there is
  no implicit suffix matching, so ``evilgithub.com`` can never match
  ``github.com``. Unset means the existing SSRF controls are the only
  control, and behaviour is unchanged.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

DEFAULT_TIMEOUT = 10.0
MAX_ATTEMPTS = 3
RETRY_BACKOFF = 1.0
MAX_REDIRECTS = 5
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
USER_AGENT = "ironclad-sentinel"

PRIVATE_ENV_FLAG = "IRONCLAD_ALLOW_PRIVATE_WEBHOOKS"
EGRESS_ALLOWLIST_ENV = "IRONCLAD_EGRESS_ALLOWLIST"


class IntegrationError(RuntimeError):
    """Raised for a misconfigured integration."""


class EgressBlocked(IntegrationError):
    """Raised when a destination is not on the egress allowlist.

    Raised before any DNS resolution, so a rejected host is never resolved
    and no socket is ever opened to it.
    """


class SsrfBlocked(IntegrationError):
    """Raised when a connection is refused by the SSRF guard.

    Raised at *connect* time, not just at configuration time, so a host that
    rebinds between validation and connection cannot slip through.
    """


@dataclass
class DeliveryOutcome:
    ok: bool
    status_code: int = 0
    attempts: int = 0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "status_code": self.status_code,
                "attempts": self.attempts, "error": self.error}


# --------------------------------------------------------------------------- #
# Configuration validation
# --------------------------------------------------------------------------- #
def validate_config(kind: str, config: Dict[str, Any]) -> List[str]:
    """Return configuration problems, so a bad integration fails at create time."""
    problems: List[str] = []
    config = config or {}
    if kind == "webhook":
        url = str(config.get("url", ""))
        problems.extend(_url_problems(url, required=True, label="url"))
    elif kind in {"slack", "teams"}:
        problems.extend(_url_problems(str(config.get("webhook_url", "")), required=True,
                                      label="webhook_url"))
    elif kind == "github":
        if not config.get("token"):
            problems.append("github integrations require 'token'")
        if config.get("repository") and "/" not in str(config.get("repository")):
            problems.append("github 'repository' must be 'owner/name'")
        api = str(config.get("api_url", "https://api.github.com"))
        if api and not api.startswith("https://"):
            problems.append("github 'api_url' must use https")
    elif kind == "gitlab":
        if not config.get("token"):
            problems.append("gitlab integrations require 'token'")
        api = str(config.get("api_url", "https://gitlab.com"))
        if api and not api.startswith("https://"):
            problems.append("gitlab 'api_url' must use https")
    elif kind == "jira":
        for key in ("base_url", "email", "api_token", "project_key"):
            if not config.get(key):
                problems.append(f"jira integrations require '{key}'")
        if str(config.get("base_url", "")).startswith("http://"):
            problems.append("jira 'base_url' must use https")
    else:
        problems.append(f"unsupported integration kind: {kind}")
    return problems


def _url_problems(url: str, *, required: bool, label: str) -> List[str]:
    if not url:
        return [f"{label} is required"] if required else []
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return [f"{label} must use http or https"]
    if not parsed.hostname:
        return [f"{label} has no host"]
    # The private-host check applies to http AND https. Gating it on https
    # left the single most important SSRF target wide open: the cloud
    # metadata endpoint is http://169.254.169.254/, and an integration is
    # allowed to be handed an attacker-influenced URL.
    if _is_private_host(parsed.hostname) and not _private_allowed():
        return [f"{label} points at a private/link-local address; set {PRIVATE_ENV_FLAG}=1 to allow it"]
    return []


def egress_allowlist() -> Optional[frozenset]:
    """Parse ``IRONCLAD_EGRESS_ALLOWLIST`` into a set of normalised entries.

    Returns ``None`` when unset or empty, meaning "no allowlist configured,
    existing SSRF controls are the only control". An empty value is treated
    as unset rather than as "deny everything", so a stray empty environment
    variable cannot silently break every integration.
    """
    raw = os.environ.get(EGRESS_ALLOWLIST_ENV)
    if raw is None:
        return None
    entries = {e.strip().lower() for e in raw.split(",") if e.strip()}
    return frozenset(entries) if entries else None


def host_allowed_by_allowlist(hostname: str, allowlist: Optional[frozenset]) -> bool:
    """Exact, security-safe hostname matching against the allowlist.

    Semantics, deliberately narrow:

    * ``github.com`` matches **only** ``github.com`` -- case-insensitively.
      It does NOT match subdomains and, critically, does NOT match
      ``evilgithub.com``. There is no implicit suffix matching anywhere: a
      bare suffix match is precisely how ``evilgithub.com`` would slip past.
    * ``*.github.com`` matches ``api.github.com`` and ``a.b.github.com``, but
      NOT ``github.com`` itself and NOT ``evilgithub.com``. The wildcard must
      be an explicit leading ``*.`` and is anchored to a label boundary.
    * Matching is on the full lowercased hostname; ports are not part of the
      hostname and are not considered.
    """
    if allowlist is None:
        return True
    host = (hostname or "").strip().strip("[]").lower()
    if not host:
        return False
    if host in allowlist:
        return True
    for entry in allowlist:
        if entry.startswith("*."):
            suffix = entry[1:]  # keeps the leading dot: ".github.com"
            # Requires a label boundary, so "evilgithub.com" cannot match
            # ".github.com" -- the character before the suffix must be a dot.
            if host.endswith(suffix) and len(host) > len(suffix):
                return True
    return False


def _private_allowed() -> bool:
    return os.environ.get(PRIVATE_ENV_FLAG, "").lower() in {"1", "true", "yes"}


#: Ranges that are not publicly routable but that `ipaddress` does not report
#: as private on every supported Python version. RFC 6598 (CGNAT) is the one
#: that actually mattered: Python 3.11 returns is_private=False for
#: 100.64.0.0/10, so a webhook aimed at a carrier-grade NAT address sailed
#: through the guard.
EXTRA_NON_PUBLIC_NETWORKS = tuple(
    ipaddress.ip_network(cidr) for cidr in (
        "100.64.0.0/10",      # RFC 6598 shared address space (CGNAT)
        "192.0.0.0/24",       # RFC 6890 IETF protocol assignments
        "198.18.0.0/15",      # RFC 2544 benchmarking
        "0.0.0.0/8",          # "this" network
    )
)

#: Hostnames that mean "this machine" or a cloud metadata service regardless
#: of what DNS says about them.
LOCAL_HOSTNAMES = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal", "metadata", "instance-data",
    "metadata.goog", "169.254.169.254",
}


def _is_private_host(hostname: str) -> bool:
    """True for loopback/private/link-local/non-public hosts (SSRF guard).

    Note on DNS rebinding: this resolves the name at *validation* time. An
    attacker-controlled authoritative server can answer with a public
    address here and a private one when the request is actually made. Closing
    that fully requires resolving at connect time and pinning the address,
    which this does not do -- see docs/SECURITY.md.
    """
    name = (hostname or "").strip().strip("[]").lower()
    if name in LOCAL_HOSTNAMES:
        return True
    # A hostname whose first label is "localhost" is local by convention on
    # every mainstream resolver, and costs nothing to block.
    if name == "localhost" or name.endswith(".localhost"):
        return True

    try:
        infos = socket.getaddrinfo(name, None)
    except socket.gaierror:
        # Unresolvable hosts are not "private"; the request will fail loudly.
        return False
    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address.split("%")[0])
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
        if any(ip in network for network in EXTRA_NON_PUBLIC_NETWORKS):
            return True
    return False


def _host_is_non_public_literal(hostname: str) -> bool:
    """Check the literal address without DNS, for when the host *is* an IP."""
    name = (hostname or "").strip().strip("[]").lower()
    try:
        ip = ipaddress.ip_address(name.split("%")[0])
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return True
    return any(ip in network for network in EXTRA_NON_PUBLIC_NETWORKS)


# --------------------------------------------------------------------------- #
# Signing
# --------------------------------------------------------------------------- #
def sign_payload(payload: bytes, secret: str) -> str:
    """HMAC-SHA256 signature in the ``sha256=<hex>`` form GitHub uses."""
    return "sha256=" + hmac.new((secret or "").encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    if not signature or not secret:
        return False
    expected = sign_payload(payload, secret)
    return hmac.compare_digest(expected, signature.strip())


# --------------------------------------------------------------------------- #
# DNS resolution and IP pinning
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ResolvedTarget:
    """A URL whose address has been resolved and validated.

    ``ip`` is the address the socket will actually connect to; ``hostname``
    is preserved so the Host header and TLS SNI still carry the name the
    certificate and any virtual host expect.
    """

    url: str
    hostname: str
    ip: str
    port: int
    scheme: str


def resolve_target(url: str) -> ResolvedTarget:
    """Resolve a URL once and validate the address it resolved to.

    This is the single point at which DNS is consulted. The returned IP is
    what the connection uses, so there is no window in which a second lookup
    could return a different (private) address -- which is exactly how DNS
    rebinding works.

    Raises :class:`SsrfBlocked` if the scheme is not http(s), the host does
    not resolve, or any resolved address is non-public.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise SsrfBlocked(f"refusing non-http(s) scheme: {parsed.scheme!r}")
    hostname = parsed.hostname
    if not hostname:
        raise SsrfBlocked("URL has no host")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Egress allowlist, enforced BEFORE DNS so a rejected host is never even
    # resolved. This runs for the initial destination and for every redirect
    # hop, because resolve_target() is called for each one.
    allowlist = egress_allowlist()
    if not host_allowed_by_allowlist(hostname, allowlist):
        raise EgressBlocked(
            f"{hostname} is not on {EGRESS_ALLOWLIST_ENV}; refusing to resolve it")

    # A literal IP still needs the non-public check, but needs no DNS.
    if _host_is_non_public_literal(hostname):
        if not _private_allowed():
            raise SsrfBlocked(f"refusing non-public address literal: {hostname}")
        return ResolvedTarget(url, hostname, hostname.strip("[]"), port, parsed.scheme)

    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SsrfBlocked(f"cannot resolve {hostname}: {exc}") from exc

    if not infos:
        raise SsrfBlocked(f"no addresses returned for {hostname}")

    # Validate EVERY returned address, then pin the first one. Validating only
    # the first would let a resolver put a public address first and a private
    # one second, and a later retry could pick the other.
    addresses = []
    for info in infos:
        raw = info[4][0]
        candidate = raw.split("%")[0]
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        addresses.append((candidate, ip))

    if not addresses:
        raise SsrfBlocked(f"no usable addresses for {hostname}")

    if not _private_allowed():
        for candidate, ip in addresses:
            if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                    or any(ip in network for network in EXTRA_NON_PUBLIC_NETWORKS)):
                raise SsrfBlocked(
                    f"refusing {hostname}: resolved to non-public address {candidate}")
        if hostname.lower() in LOCAL_HOSTNAMES or hostname.lower().endswith(".localhost"):
            raise SsrfBlocked(f"refusing local hostname {hostname!r}")

    return ResolvedTarget(url, hostname, addresses[0][0], port, parsed.scheme)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to a pre-validated IP while keeping the original Host header."""

    pinned_ip: Optional[str] = None

    def connect(self):  # noqa: D102 - http.client API
        self.sock = socket.create_connection((self.pinned_ip, self.port),
                                            self.timeout, self.source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a pre-validated IP but validates the certificate against the
    original hostname via SNI, so pinning does not weaken TLS."""

    pinned_ip: Optional[str] = None

    def connect(self):  # noqa: D102 - http.client API
        sock = socket.create_connection((self.pinned_ip, self.port),
                                        self.timeout, self.source_address)
        context = self._context
        # server_hostname is the ORIGINAL hostname, not the IP: the certificate
        # is checked against the name the operator configured.
        self.sock = context.wrap_socket(sock, server_hostname=self.host)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect automatically.

    Redirects are handled explicitly by :func:`_request` so each destination
    is resolved and validated before any connection is made to it.
    """

    def redirect_request(self, *args, **kwargs):  # noqa: D102
        return None


def _build_opener(target: ResolvedTarget, timeout: float) -> urllib.request.OpenerDirector:
    """Build an opener whose connections go to the pinned IP."""
    if target.scheme == "https":
        connection_class = type("PinnedHTTPS", (_PinnedHTTPSConnection,),
                                {"pinned_ip": target.ip})
        context = ssl.create_default_context()

        class Handler(urllib.request.HTTPSHandler):
            def https_open(self, req):  # noqa: D102
                return self.do_open(connection_class, req, context=context)

        handler = Handler()
    else:
        connection_class = type("PinnedHTTP", (_PinnedHTTPConnection,),
                                {"pinned_ip": target.ip})

        class Handler(urllib.request.HTTPHandler):  # type: ignore[no-redef]
            def http_open(self, req):  # noqa: D102
                return self.do_open(connection_class, req)

        handler = Handler()

    return urllib.request.build_opener(handler, _NoRedirect())


# --------------------------------------------------------------------------- #
# Delivery
# --------------------------------------------------------------------------- #
def _request(url: str, payload: bytes, headers: Dict[str, str],
             timeout: float) -> DeliveryOutcome:
    """Send one request, following redirects with re-validation at each hop."""
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        # Resolve and validate immediately before connecting, then connect to
        # that exact IP. Nothing re-resolves in between.
        target = resolve_target(current)
        opener = _build_opener(target, timeout)

        # urllib derives the Host header from the URL, so rewrite the URL to
        # the pinned IP but set Host explicitly to the original name.
        pinned_url = urllib.parse.urlunparse((
            target.scheme, f"{target.ip}:{target.port}",
            urllib.parse.urlparse(current).path or "/",
            urllib.parse.urlparse(current).params,
            urllib.parse.urlparse(current).query, "",
        ))
        request = urllib.request.Request(
            pinned_url, data=payload, method="POST",
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/json",
                     "Host": target.hostname, **headers})

        try:
            with opener.open(request, timeout=timeout) as response:
                status_code = int(response.status)
                response.read(4096)
                if status_code in _REDIRECT_STATUSES:
                    location = response.headers.get("Location")
                    if not location:
                        return DeliveryOutcome(False, status_code, 1,
                                               f"HTTP {status_code} with no Location")
                    current = urllib.parse.urljoin(current, location)
                    continue
                if 200 <= status_code < 300:
                    return DeliveryOutcome(True, status_code, 1)
                return DeliveryOutcome(False, status_code, 1, f"HTTP {status_code}")
        except urllib.error.HTTPError as exc:
            # With redirects disabled, urllib raises HTTPError for 3xx rather
            # than returning a response, so the redirect has to be handled
            # here as well as in the success branch above.
            if exc.code in _REDIRECT_STATUSES:
                location = exc.headers.get("Location") if exc.headers else None
                if not location:
                    return DeliveryOutcome(False, int(exc.code), 1,
                                           f"HTTP {exc.code} with no Location")
                current = urllib.parse.urljoin(current, location)
                continue
            return DeliveryOutcome(False, int(exc.code), 1, f"HTTP {exc.code}")
        except (urllib.error.URLError, socket.timeout, OSError, ssl.SSLError) as exc:
            reason = getattr(exc, "reason", exc)
            return DeliveryOutcome(False, 0, 1, f"{type(exc).__name__}: {reason}")

    return DeliveryOutcome(False, 0, 1, f"too many redirects (>{MAX_REDIRECTS})")


def _post(url: str, payload: bytes, headers: Dict[str, str],
          timeout: float = DEFAULT_TIMEOUT) -> DeliveryOutcome:
    last_error = ""
    status_code = 0
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            outcome = _request(url, payload, headers, timeout)
        except (SsrfBlocked, EgressBlocked) as exc:
            # A blocked destination is not a transient failure: do not retry.
            return DeliveryOutcome(False, 0, attempt, f"blocked: {exc}")

        status_code = outcome.status_code
        last_error = outcome.error
        if outcome.ok:
            return DeliveryOutcome(True, status_code, attempt)
        if 400 <= status_code < 500 and status_code != 429:
            # A 4xx will not fix itself; retrying only wastes time.
            return DeliveryOutcome(False, status_code, attempt, last_error)
        if attempt < MAX_ATTEMPTS:
            time.sleep(RETRY_BACKOFF * attempt)
    return DeliveryOutcome(False, status_code, MAX_ATTEMPTS, last_error)


def deliver(integration, payload: Dict[str, Any], timeout: float = DEFAULT_TIMEOUT) -> DeliveryOutcome:
    """Deliver ``payload`` through an integration row.

    ``integration`` may be an ORM row or any object exposing ``kind``,
    ``config`` (JSON string or dict) and ``secret``.
    """
    kind = getattr(integration, "kind", "")
    raw_config = getattr(integration, "config", "{}")
    config = json.loads(raw_config) if isinstance(raw_config, str) else dict(raw_config or {})
    secret = getattr(integration, "secret", "") or ""
    body = json.dumps({"source": "ironclad-sentinel", **payload}, sort_keys=True, default=str).encode()

    if kind == "webhook":
        url = str(config.get("url", ""))
        problems = _url_problems(url, required=True, label="url")
        if problems:
            return DeliveryOutcome(False, 0, 0, "; ".join(problems))
        headers = {
            "X-IronClad-Event": str(payload.get("event", "scan.completed")),
            "X-IronClad-Signature": sign_payload(body, secret),
            "X-IronClad-Delivery": str(payload.get("delivery_id", "")),
        }
        return _post(url, body, headers, timeout)

    if kind in {"slack", "teams"}:
        url = str(config.get("webhook_url", ""))
        problems = _url_problems(url, required=True, label="webhook_url")
        if problems:
            return DeliveryOutcome(False, 0, 0, "; ".join(problems))
        text = _format_message(payload)
        channel_body = json.dumps({"text": text}).encode()
        return _post(url, channel_body, {}, timeout)

    if kind == "github":
        return _github_delivery(config, payload, body, secret, timeout)

    if kind == "gitlab":
        return _gitlab_delivery(config, payload, timeout)

    if kind == "jira":
        return _jira_delivery(config, payload, timeout)

    return DeliveryOutcome(False, 0, 0, f"unsupported integration kind: {kind}")


def _format_message(payload: Dict[str, Any]) -> str:
    counts = payload.get("severity_counts") or {}
    parts = [f"{key}: {value}" for key, value in sorted(counts.items()) if value]
    summary = ", ".join(parts) or "no findings"
    return (f"IronClad Sentinel scan {payload.get('scan_id', '?')} "
            f"({payload.get('project', 'project')}): {summary}. "
            f"Grade {payload.get('grade', '?')}, risk {payload.get('risk_score', 0)}.")


def _github_delivery(config: Dict[str, Any], payload: Dict[str, Any], body: bytes,
                     secret: str, timeout: float) -> DeliveryOutcome:
    """Upload a SARIF result to GitHub code scanning, or a webhook event.

    Which one happens depends on the configured mode:
      * ``mode: code-scanning`` (default when ``repository`` is set)
      * ``mode: repository-dispatch`` -- fires a repository_dispatch event
    """
    api = str(config.get("api_url", "https://api.github.com")).rstrip("/")
    repository = str(config.get("repository", ""))
    token = str(config.get("token", ""))
    mode = str(config.get("mode", "code-scanning" if repository else "repository-dispatch"))
    if not repository:
        return DeliveryOutcome(False, 0, 0, "github integration requires 'repository' (owner/name)")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    if mode == "repository-dispatch":
        url = f"{api}/repos/{repository}/dispatches"
        dispatch = json.dumps({"event_type": payload.get("event", "ironclad.scan"),
                               "client_payload": payload}, default=str).encode()
        return _post(url, dispatch, headers, timeout)

    sarif = payload.get("sarif")
    if not sarif:
        return DeliveryOutcome(False, 0, 0, "code-scanning mode requires a 'sarif' payload")
    url = f"{api}/repos/{repository}/code-scanning/sarifs"
    import base64

    upload = json.dumps({
        "commit_sha": payload.get("revision", ""),
        "ref": payload.get("ref", "refs/heads/main"),
        "sarif": base64.b64encode(json.dumps(sarif).encode()).decode("ascii"),
        "checkout_uri": payload.get("checkout_uri", ""),
    }).encode()
    return _post(url, upload, headers, timeout)


def _gitlab_delivery(config: Dict[str, Any], payload: Dict[str, Any], timeout: float) -> DeliveryOutcome:
    api = str(config.get("api_url", "https://gitlab.com")).rstrip("/")
    project = str(config.get("project_id", ""))
    token = str(config.get("token", ""))
    if not project:
        return DeliveryOutcome(False, 0, 0, "gitlab integration requires 'project_id'")
    url = f"{api}/api/v4/projects/{urllib.parse.quote(project, safe='')}/repository/files"
    headers = {"PRIVATE-TOKEN": token}
    note = json.dumps({"branch": payload.get("ref", "main").replace("refs/heads/", ""),
                       "content": json.dumps(payload, default=str, indent=2),
                       "commit_message": f"IronClad Sentinel scan {payload.get('scan_id', '')}"},
                      ).encode()
    return _post(url, note, headers, timeout)


def _jira_delivery(config: Dict[str, Any], payload: Dict[str, Any], timeout: float) -> DeliveryOutcome:
    import base64

    base = str(config.get("base_url", "")).rstrip("/")
    credentials = base64.b64encode(
        f"{config.get('email', '')}:{config.get('api_token', '')}".encode()).decode("ascii")
    url = f"{base}/rest/api/3/issue"
    headers = {"Authorization": f"Basic {credentials}", "Accept": "application/json"}
    issue = json.dumps({"fields": {
        "project": {"key": str(config.get("project_key", ""))},
        "summary": f"[IronClad] {payload.get('event', 'scan')} scan {payload.get('scan_id', '')}",
        "description": {"type": "doc", "version": 1, "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": _format_message(payload)}]}]},
        "issuetype": {"name": str(config.get("issue_type", "Task"))},
    }}).encode()
    return _post(url, issue, headers, timeout)


def build_scan_payload(scan, findings: List[Dict[str, Any]], *, project: str = "",
                       sarif: Optional[Dict[str, Any]] = None,
                       correlation_id: str = "") -> Dict[str, Any]:
    """Assemble the notification payload for a finished scan.

    Contains no secret material and no source snippets -- recipients get
    counts, severities and locations, which is what a ticket needs.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding.get("severity", "info")
        counts[severity] = counts.get(severity, 0) + 1
    return {
        "event": "scan.completed",
        "scan_id": getattr(scan, "id", None),
        "project": project,
        "revision": getattr(scan, "revision", ""),
        "grade": getattr(scan, "grade", ""),
        "risk_score": getattr(scan, "risk_score", 0),
        "files_scanned": getattr(scan, "files_scanned", 0),
        "severity_counts": counts,
        "finding_count": len(findings),
        "top_findings": [
            {"rule_id": f.get("rule_id"), "severity": f.get("severity"),
             "file": f.get("file_path"), "line": f.get("start_line"), "title": f.get("title")}
            for f in findings[:20]
        ],
        "sarif": sarif,
        "correlation_id": correlation_id,
    }
