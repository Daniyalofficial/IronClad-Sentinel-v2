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
* **SSRF guard.** A webhook URL must be http(s), and private/link-local
  hostnames are rejected unless ``IRONCLAD_ALLOW_PRIVATE_WEBHOOKS=1`` is
  set -- otherwise an integration becomes a proxy into the internal
  network.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

DEFAULT_TIMEOUT = 10.0
MAX_ATTEMPTS = 3
RETRY_BACKOFF = 1.0
USER_AGENT = "ironclad-sentinel"

PRIVATE_ENV_FLAG = "IRONCLAD_ALLOW_PRIVATE_WEBHOOKS"


class IntegrationError(RuntimeError):
    """Raised for a misconfigured integration."""


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


def _private_allowed() -> bool:
    return os.environ.get(PRIVATE_ENV_FLAG, "").lower() in {"1", "true", "yes"}


def _is_private_host(hostname: str) -> bool:
    """True for loopback/private/link-local hosts (SSRF guard)."""
    if hostname.lower() in {"localhost", "metadata.google.internal"}:
        return True
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        # Unresolvable hosts are not "private"; the request will fail loudly.
        return False
    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return True
    return False


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
# Delivery
# --------------------------------------------------------------------------- #
def _post(url: str, payload: bytes, headers: Dict[str, str],
          timeout: float = DEFAULT_TIMEOUT) -> DeliveryOutcome:
    last_error = ""
    status_code = 0
    for attempt in range(1, MAX_ATTEMPTS + 1):
        request = urllib.request.Request(url, data=payload, method="POST",
                                         headers={"User-Agent": USER_AGENT,
                                                  "Content-Type": "application/json", **headers})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - scheme validated above
                status_code = int(response.status)
                response.read(4096)
            if 200 <= status_code < 300:
                return DeliveryOutcome(True, status_code, attempt)
            last_error = f"HTTP {status_code}"
        except urllib.error.HTTPError as exc:
            status_code = int(exc.code)
            last_error = f"HTTP {exc.code}"
            if 400 <= exc.code < 500 and exc.code != 429:
                # A 4xx will not fix itself; retrying only wastes time.
                return DeliveryOutcome(False, status_code, attempt, last_error)
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            last_error = f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
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
