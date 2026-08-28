#!/usr/bin/env python3
"""End-to-end HTTP verification against a running server.

Unlike the pytest API suite (which uses FastAPI's in-process TestClient),
this drives a real uvicorn process over real TCP, against a real
PostgreSQL database, and separately drives the real worker process. It is
the check that a deployment actually works rather than that the ASGI app is
wired correctly.

    export IRONCLAD_E2E_BASE=http://127.0.0.1:8077
    export IRONCLAD_E2E_EMAIL=owner@e2e-corp.com
    export IRONCLAD_E2E_PASSWORD='...'
    python benchmarks/e2e_http_check.py

Exits non-zero on the first failed expectation, printing every check it ran.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("IRONCLAD_E2E_BASE", "http://127.0.0.1:8077").rstrip("/")
EMAIL = os.environ.get("IRONCLAD_E2E_EMAIL", "owner@e2e-corp.com")
PASSWORD = os.environ.get("IRONCLAD_E2E_PASSWORD", "")

CHECKS = []


def check(name, condition, detail=""):
    CHECKS.append((name, bool(condition), detail))
    mark = "PASS" if condition else "FAIL"
    print(f"  [{mark}] {name}" + (f"  -- {detail}" if detail and not condition else ""))
    return bool(condition)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Report 3xx instead of following it -- a redirect we silently follow is
    a redirect we cannot assert on."""

    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def request(method, path, *, token=None, body=None, raw=False, headers=None):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with _OPENER.open(req, timeout=60) as response:
            payload = response.read()
            return response.status, dict(response.headers), (payload if raw else _json(payload))
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        return exc.code, dict(exc.headers), (payload if raw else _json(payload))


def _json(payload):
    try:
        return json.loads(payload)
    except (ValueError, TypeError):
        return None


def main() -> int:
    if not PASSWORD:
        print("set IRONCLAD_E2E_PASSWORD", file=sys.stderr)
        return 2

    print("\n=== 1. health / readiness / version ===")
    status, headers, body = request("GET", "/health")
    check("GET /health -> 200", status == 200, str(status))
    check("health reports ok", (body or {}).get("status") == "ok", str(body))
    check("health probed the database", (body or {}).get("checks", {}).get("database") == "ok")
    status, _, body = request("GET", "/ready")
    check("GET /ready -> 200", status == 200 and (body or {}).get("ready") is True, str(body))
    status, _, body = request("GET", "/version")
    check("GET /version -> 200", status == 200 and (body or {}).get("product") == "IronClad Sentinel")

    print("\n=== 2. security headers on every response ===")
    check("X-Request-Id present", bool(headers.get("x-request-id")))
    check("X-Content-Type-Options: nosniff", headers.get("x-content-type-options") == "nosniff")
    check("X-Frame-Options: DENY", headers.get("x-frame-options") == "DENY")
    check("CSP present", "default-src 'self'" in (headers.get("content-security-policy") or ""))
    check("Referrer-Policy present", bool(headers.get("referrer-policy")))

    echo = request("GET", "/health", headers={"X-Request-Id": "trace-e2e-123"})[1]
    check("supplied request id echoed", echo.get("x-request-id") == "trace-e2e-123",
          str(echo.get("x-request-id")))

    print("\n=== 3. authentication ===")
    status, _, body = request("POST", "/auth/login",
                              body={"email": EMAIL, "password": "definitely-wrong"})
    check("wrong password -> 401", status == 401, str(status))
    check("error body has no stack trace", "Traceback" not in json.dumps(body or {}))

    status, _, body = request("POST", "/auth/login", body={"email": "nobody@nowhere.example",
                                                           "password": "whatever-1234"})
    check("unknown account -> 401", status == 401)
    check("no account enumeration (same message)",
          (body or {}).get("detail") == "invalid email or password", str(body))

    status, _, body = request("POST", "/auth/login",
                              body={"email": "not-an-email", "password": "x"})
    check("malformed email -> 422", status == 422, str(status))

    status, _, body = request("POST", "/auth/login", body={"email": EMAIL, "password": PASSWORD})
    check("valid login -> 200", status == 200, str(status))
    token = (body or {}).get("access_token")
    check("token issued", bool(token))

    status, _, body = request("GET", "/auth/me", token=token)
    check("GET /auth/me -> 200", status == 200 and (body or {}).get("email") == EMAIL, str(body))

    status, _, _ = request("GET", "/projects")
    check("unauthenticated -> 401", status == 401, str(status))
    status, _, _ = request("GET", "/projects", token="bogus-token")
    check("bogus token -> 401", status == 401, str(status))

    print("\n=== 4. project + policy ===")
    status, _, body = request("POST", "/projects", token=token,
                              body={"name": "E2E Payments", "description": "e2e"})
    check("POST /projects -> 201", status == 201, f"{status} {body}")
    project_id = (body or {}).get("id")
    check("project id returned", bool(project_id))

    status, _, body = request("POST", "/projects", token=token, body={"name": "E2E Payments"})
    check("duplicate project -> 409", status == 409, str(status))
    status, _, _ = request("POST", "/projects", token=token, body={"name": ""})
    check("empty name -> 422", status == 422, str(status))
    status, _, _ = request("POST", "/projects", token=token,
                           body={"name": "X", "unexpected": 1})
    check("unknown field rejected (extra=forbid) -> 422", status == 422, str(status))

    policy = {"version": 1, "name": "e2e-gate", "fail_on": "high",
              "severity_gates": {"critical": 0, "high": 0}}
    status, _, body = request("POST", "/policies", token=token,
                              body={"name": "e2e-gate", "document": policy, "is_default": True})
    check("POST /policies -> 201", status == 201, f"{status} {body}")
    policy_id = (body or {}).get("id")

    status, _, body = request("POST", "/policies/validate", token=token,
                              body={"name": "bad", "document": {"version": 1, "fail_on": "nope"}})
    check("invalid policy reports problems", (body or {}).get("valid") is False
          and bool((body or {}).get("problems")), str(body))

    print("\n=== 5. scan root confinement ===")
    status, _, body = request("POST", "/scan", token=token,
                              body={"project_id": project_id, "target": "/etc"})
    check("absolute path outside root -> 400", status == 400, str(status))
    check("rejection names the scan root", "scan root" in json.dumps(body or {}), str(body))
    status, _, _ = request("POST", "/scan", token=token,
                           body={"project_id": project_id, "target": "../../etc"})
    check("traversal -> 400", status == 400, str(status))
    status, _, _ = request("POST", "/scan", token=token,
                           body={"project_id": 999999, "target": "."})
    check("unknown project -> 404", status == 404, str(status))

    print("\n=== 6. scan accepted and queued ===")
    status, _, body = request("POST", "/scan", token=token,
                              body={"project_id": project_id, "target": ".",
                                    "policy_id": policy_id, "idempotency_key": "e2e-run-1"})
    check("POST /scan -> 202", status == 202, f"{status} {body}")
    scan_id = (body or {}).get("id")
    check("scan queued (status=queued)", (body or {}).get("status") == "queued", str(body))

    status, _, again = request("POST", "/scan", token=token,
                               body={"project_id": project_id, "target": ".",
                                     "policy_id": policy_id, "idempotency_key": "e2e-run-1"})
    check("idempotency key replays the same scan", (again or {}).get("id") == scan_id,
          f"{(again or {}).get('id')} vs {scan_id}")

    status, _, jobs = request("GET", "/jobs", token=token)
    check("GET /jobs -> 200 with the queued job",
          status == 200 and any(j.get("kind") == "scan.run" for j in (jobs or [])), str(status))

    print("\n=== 7. dashboard renders (real HTTP, real templates) ===")
    login_page = request("GET", "/ui/login", raw=True)
    check("GET /ui/login -> 200 HTML", login_page[0] == 200
          and b"IronClad" in (login_page[2] or b""), str(login_page[0]))

    status, hdrs, _ = request("GET", "/ui/", raw=True)
    check("unauthenticated /ui/ redirects to login", status == 307
          and (hdrs.get("location") or "").endswith("/ui/login"), f"{status} {hdrs.get('location')}")

    print("\n=== summary ===")
    passed = sum(1 for _, ok, _ in CHECKS if ok)
    print(f"  {passed}/{len(CHECKS)} checks passed")
    if passed != len(CHECKS):
        print("  FAILED CHECKS:")
        for name, ok, detail in CHECKS:
            if not ok:
                print(f"    - {name}: {detail}")
    print(f"\n  scan_id={scan_id} project_id={project_id} policy_id={policy_id}")
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
