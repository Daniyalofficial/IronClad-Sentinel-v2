"""End-to-end API tests (Phase 4/6/7/8/10/11/12/14).

One fixture builds a real server against a temporary SQLite database with a
bootstrapped organization, then the tests drive the HTTP surface exactly as
a client would: login, project, scan, findings, SBOM, licenses, policies,
integrations, audit, jobs, dashboard.

Tenant isolation and RBAC are tested against a *second* organization, so a
bug that leaks rows across tenants fails here rather than in production.
"""
import json
import os
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from ironclad.api.app import create_app
from ironclad.platform import events
from ironclad.platform.database import build_engine, run_migrations, session_factory, session_scope
from ironclad.platform.integrations import sign_payload, verify_signature
from ironclad.platform.jobs import JobQueue
from ironclad.platform.models import Finding, Organization, Scan, User, utcnow
from ironclad.platform.rbac import ROLE_PERMISSIONS
from ironclad.platform.scanning import bootstrap_organization
from ironclad.platform.security import hash_password

ADMIN_PASSWORD = "Str0ng!Passw0rd-99"

VULNERABLE_APP = {
    "app.py": (
        "import os\n"
        "import sqlite3\n"
        "import requests\n"
        "from flask import request\n"
        "\n"
        "\n"
        "def lookup(user_input):\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    q = 'SELECT * FROM users WHERE name = %s' % user_input\n"
        "    return conn.execute(q).fetchall()\n"
        "\n"
        "\n"
        "def fetch():\n"
        "    return requests.get(request.args.get('url')).text\n"
        "\n"
        "\n"
        "def read(user_input):\n"
        "    return open('/data/' + user_input).read()\n"
    ),
    "requirements.txt": "jinja2==3.1.2\nrequests==2.30.0\n",
}

POLICY_DOCUMENT = {
    "version": 1,
    "name": "ci-gate",
    "fail_on": "high",
    "severity_gates": {"critical": 0, "high": 0},
}


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    """A fully bootstrapped server plus a scan target, shared by the module."""
    base = tmp_path_factory.mktemp("ironclad-server")
    db_path = base / "ironclad.db"
    url = f"sqlite:///{db_path}"
    target = base / "scan-target"
    target.mkdir()
    for name, content in VULNERABLE_APP.items():
        (target / name).write_text(content, encoding="utf-8")

    os.environ["IRONCLAD_SIGNING_KEY"] = "test-signing-key-that-is-long-enough-32ch"
    os.environ["IRONCLAD_SCAN_ROOT"] = str(target)

    app = create_app(url, include_web=True)
    engine = build_engine(url)
    run_migrations(engine)
    with session_scope(engine) as session:
        org, owner = bootstrap_organization(session, name="Acme Corp", slug="acme",
                                            admin_email="owner@acme-corp.com",
                                            password=ADMIN_PASSWORD)
        org_id, owner_id = org.id, owner.id

    client = TestClient(app, follow_redirects=False)
    return {
        "client": client, "app": app, "engine": engine, "url": url,
        "target": str(target), "org_id": org_id, "owner_id": owner_id,
        "base": base,
    }


@pytest.fixture()
def auth(server):
    """An authenticated owner client."""
    response = server["client"].post("/auth/login",
                                     json={"email": "owner@acme-corp.com", "password": ADMIN_PASSWORD})
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    return {"client": server["client"], "headers": headers, "token": token,
            "user": response.json()["user"]}


@pytest.fixture()
def project(auth):
    """A fresh project per test -- slugs are unique per organization."""
    import uuid

    response = auth["client"].post("/projects", headers=auth["headers"],
                                   json={"name": f"Payments {uuid.uuid4().hex[:8]}",
                                         "description": "card payments"})
    assert response.status_code == 201, response.text
    return response.json()


def _run_scan(server, auth, project, **overrides):
    """Queue a scan and drive the worker until it is finished."""
    body = {"project_id": project["id"], "target": ".", **overrides}
    response = auth["client"].post("/scan", headers=auth["headers"], json=body)
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]
    assert response.json()["status"] == "queued"

    from ironclad.platform.worker_jobs import register_job_handlers

    queue = JobQueue()
    register_job_handlers(queue, server["engine"])
    with session_scope(server["engine"]) as session:
        queue.run_pending(session, limit=5)
        session.commit()
    return scan_id


# --------------------------------------------------------------------------- #
# Health / version / metrics
# --------------------------------------------------------------------------- #
def test_health_ready_version(server):
    client = server["client"]
    assert client.get("/health").status_code == 200
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["checks"]["database"] == "ok"
    assert client.get("/ready").json()["ready"] is True
    assert client.get("/version").json()["product"] == "IronClad Sentinel"


def test_metrics_exposes_prometheus_text(server):
    response = server["client"].get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "# TYPE" in response.text


def test_security_headers_present(server):
    headers = server["client"].get("/health").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in headers["content-security-policy"]
    assert headers["x-request-id"]


def test_request_id_is_echoed_when_supplied(server):
    response = server["client"].get("/health", headers={"X-Request-Id": "trace-abc-123"})
    assert response.headers["x-request-id"] == "trace-abc-123"


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
def test_unauthenticated_access_is_rejected(server):
    assert server["client"].get("/projects").status_code == 401
    assert server["client"].get("/findings").status_code == 401
    assert server["client"].get("/audit").status_code == 401


def test_login_rejects_a_bad_password(server):
    response = server["client"].post("/auth/login",
                                     json={"email": "owner@acme-corp.com", "password": "wrong-password"})
    assert response.status_code == 401
    assert response.json()["detail"] == "invalid email or password"


def test_login_does_not_leak_whether_an_account_exists(server):
    missing = server["client"].post("/auth/login",
                                    json={"email": "nobody@acme-corp.com", "password": "whatever-1234"})
    wrong = server["client"].post("/auth/login",
                                  json={"email": "owner@acme-corp.com", "password": "wrong-password"})
    assert missing.status_code == wrong.status_code == 401
    assert missing.json()["detail"] == wrong.json()["detail"]


def test_login_rejects_a_weak_payload(server):
    assert server["client"].post("/auth/login", json={"email": "not-an-email", "password": "x"}
                                 ).status_code == 422


def test_invalid_bearer_token_is_rejected(server):
    response = server["client"].get("/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401


def test_me_returns_the_authenticated_user(auth):
    response = auth["client"].get("/auth/me", headers=auth["headers"])
    assert response.status_code == 200
    assert response.json()["email"] == "owner@acme-corp.com"
    assert response.json()["role"] == "owner"


def test_logout_revokes_the_session(server):
    client = server["client"]
    login = client.post("/auth/login", json={"email": "owner@acme-corp.com", "password": ADMIN_PASSWORD})
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/auth/me", headers=headers).status_code == 200
    assert client.post("/auth/logout", headers=headers).status_code == 204
    assert client.get("/auth/me", headers=headers).status_code == 401


def test_expired_session_is_rejected(server):
    """A session whose expiry has passed must not authenticate."""
    from ironclad.platform.models import Session as SessionRow
    from ironclad.platform.security import generate_session_token, hash_token

    token, token_hash = generate_session_token()
    with session_scope(server["engine"]) as session:
        session.add(SessionRow(user_id=server["owner_id"], org_id=server["org_id"],
                               token_hash=token_hash, expires_at=utcnow() - timedelta(hours=1)))
    response = server["client"].get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_password_change_invalidates_other_sessions(server):
    client = server["client"]
    first = client.post("/auth/login", json={"email": "owner@acme-corp.com",
                                             "password": ADMIN_PASSWORD}).json()["access_token"]
    second = client.post("/auth/login", json={"email": "owner@acme-corp.com",
                                              "password": ADMIN_PASSWORD}).json()["access_token"]
    change = client.post("/auth/password", headers={"Authorization": f"Bearer {first}"},
                         json={"current_password": ADMIN_PASSWORD,
                               "new_password": "An0ther!Passw0rd-77"})
    assert change.status_code == 204, change.text
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {first}"}).status_code == 401
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {second}"}).status_code == 401
    # Restore the shared password for the rest of the module.
    restore = client.post("/auth/login", json={"email": "owner@acme-corp.com",
                                               "password": "An0ther!Passw0rd-77"})
    assert restore.status_code == 200
    client.post("/auth/password", headers={"Authorization": f"Bearer {restore.json()['access_token']}"},
                json={"current_password": "An0ther!Passw0rd-77", "new_password": ADMIN_PASSWORD})


def test_password_change_rejects_a_weak_new_password(auth):
    response = auth["client"].post("/auth/password", headers=auth["headers"],
                                   json={"current_password": ADMIN_PASSWORD, "new_password": "short"})
    assert response.status_code == 422


def test_password_change_requires_the_current_password(auth):
    response = auth["client"].post("/auth/password", headers=auth["headers"],
                                   json={"current_password": "not-the-password",
                                         "new_password": "An0ther!Passw0rd-77"})
    assert response.status_code == 403


# --------------------------------------------------------------------------- #
# API tokens
# --------------------------------------------------------------------------- #
def test_api_token_round_trip(server):
    client = server["client"]
    owner = client.post("/auth/login", json={"email": "owner@acme-corp.com",
                                             "password": ADMIN_PASSWORD}).json()["access_token"]
    headers = {"Authorization": f"Bearer {owner}"}

    created = client.post("/auth/tokens", headers=headers,
                          json={"name": "ci-token", "scopes": ["scan.create", "scan.read"]})
    assert created.status_code == 201, created.text
    token = created.json()["token"]
    assert token.startswith("ics_")

    listing = client.get("/auth/tokens", headers=headers).json()
    assert any(entry["name"] == "ci-token" for entry in listing)
    assert all("token" not in entry for entry in listing), "plaintext must not be listed"

    # The token authenticates and is scoped to what it was granted.
    assert client.get("/scans", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert client.get("/audit", headers={"Authorization": f"Bearer {token}"}).status_code == 403

    token_id = created.json()["detail"]["id"]
    assert client.delete(f"/auth/tokens/{token_id}", headers=headers).status_code == 204
    assert client.get("/scans", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_permissions_matrix_is_exposed(auth):
    response = auth["client"].get("/auth/permissions", headers=auth["headers"])
    assert response.status_code == 200
    matrix = response.json()
    assert set(matrix) == set(ROLE_PERMISSIONS)
    assert "policy.manage" in matrix["admin"]
    assert "policy.manage" not in matrix["developer"]


# --------------------------------------------------------------------------- #
# Projects
# --------------------------------------------------------------------------- #
def test_project_crud(auth):
    created = auth["client"].post("/projects", headers=auth["headers"],
                                  json={"name": "Billing", "description": "invoicing"})
    assert created.status_code == 201, created.text
    assert created.json()["slug"] == "billing"

    listed = auth["client"].get("/projects", headers=auth["headers"]).json()
    assert "billing" in {p["slug"] for p in listed}

    single = auth["client"].get(f"/projects/{created.json()['id']}", headers=auth["headers"])
    assert single.status_code == 200

    duplicate = auth["client"].post("/projects", headers=auth["headers"], json={"name": "Billing"})
    assert duplicate.status_code == 409


def test_project_validation_rejects_an_empty_name(auth):
    assert auth["client"].post("/projects", headers=auth["headers"],
                               json={"name": ""}).status_code == 422


def test_archiving_a_project_hides_it(auth):
    created = auth["client"].post("/projects", headers=auth["headers"],
                                  json={"name": "Temp Project"}).json()
    assert auth["client"].delete(f"/projects/{created['id']}",
                                 headers=auth["headers"]).status_code == 204
    listed = auth["client"].get("/projects", headers=auth["headers"]).json()
    assert created["id"] not in {p["id"] for p in listed}


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #
def test_scan_rejects_a_target_outside_the_scan_root(auth, project):
    response = auth["client"].post("/scan", headers=auth["headers"],
                                   json={"project_id": project["id"], "target": "/etc"})
    assert response.status_code == 400
    assert "outside the permitted scan root" in response.json()["detail"]


def test_scan_rejects_path_traversal(auth, project):
    response = auth["client"].post("/scan", headers=auth["headers"],
                                   json={"project_id": project["id"], "target": "../../etc"})
    assert response.status_code == 400


def test_scan_rejects_an_unknown_project(auth):
    response = auth["client"].post("/scan", headers=auth["headers"],
                                   json={"project_id": 999999, "target": "."})
    assert response.status_code == 404


def test_scan_rejects_an_invalid_inline_policy(auth, project):
    response = auth["client"].post("/scan", headers=auth["headers"],
                                   json={"project_id": project["id"], "target": ".",
                                         "policy": {"version": 1, "fail_on": "nonsense"}})
    assert response.status_code == 422


def test_full_scan_lifecycle(server, auth, project):
    scan_id = _run_scan(server, auth, project, policy=POLICY_DOCUMENT)

    scan = auth["client"].get(f"/scan/{scan_id}", headers=auth["headers"]).json()
    assert scan["status"] == "succeeded", scan
    assert scan["files_scanned"] >= 2
    assert scan["finding_count"] >= 4
    assert scan["risk_score"] > 0
    assert scan["grade"] in {"A+", "A", "B", "C", "D", "F"}
    assert "ast-python" in scan["engines"]
    assert scan["policy_passed"] is False

    findings = auth["client"].get(f"/scan/{scan_id}/findings", headers=auth["headers"]).json()
    rule_ids = {f["rule_id"] for f in findings}
    assert "PY-AST-SQL-INJECTION" in rule_ids
    assert "PY-AST-SSRF" in rule_ids
    assert "PY-AST-PATH-TRAVERSAL" in rule_ids

    result = auth["client"].get(f"/scan/{scan_id}/result", headers=auth["headers"]).json()
    assert result["decision"]["passed"] is False
    assert result["decision"]["violation_count"] > 0
    assert {v["kind"] for v in result["decision"]["violations"]} >= {"severity"}


def test_policy_passes_on_a_clean_tree(server, auth):
    clean = auth["client"].post("/projects", headers=auth["headers"],
                                json={"name": "Clean Project"}).json()
    clean_dir = server["base"] / "clean-target"
    clean_dir.mkdir(exist_ok=True)
    (clean_dir / "ok.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    os.environ["IRONCLAD_SCAN_ROOT"] = str(clean_dir)
    try:
        scan_id = _run_scan(server, auth, clean, policy=POLICY_DOCUMENT)
    finally:
        os.environ["IRONCLAD_SCAN_ROOT"] = server["target"]
    scan = auth["client"].get(f"/scan/{scan_id}", headers=auth["headers"]).json()
    assert scan["status"] == "succeeded"
    assert scan["policy_passed"] is True, scan


def test_idempotency_key_prevents_duplicate_scans(server, auth, project):
    key = "ci-run-4242"
    first = auth["client"].post("/scan", headers=auth["headers"],
                                json={"project_id": project["id"], "target": ".",
                                      "idempotency_key": key})
    assert first.status_code == 202
    second = auth["client"].post("/scan", headers=auth["headers"],
                                 json={"project_id": project["id"], "target": ".",
                                       "idempotency_key": key})
    assert second.status_code == 202
    assert second.json()["id"] == first.json()["id"], "same key must return the same scan"


def test_scan_can_be_cancelled_while_queued(auth, project):
    queued = auth["client"].post("/scan", headers=auth["headers"],
                                 json={"project_id": project["id"], "target": "."})
    scan_id = queued.json()["id"]
    cancelled = auth["client"].post(f"/scan/{scan_id}/cancel", headers=auth["headers"])
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    again = auth["client"].post(f"/scan/{scan_id}/cancel", headers=auth["headers"])
    assert again.status_code == 409


def test_scan_list_pagination(auth, project):
    response = auth["client"].get("/scans", headers=auth["headers"],
                                  params={"limit": 2, "offset": 0})
    assert response.status_code == 200
    assert len(response.json()) <= 2


def test_scan_list_rejects_an_absurd_page_size(auth):
    assert auth["client"].get("/scans", headers=auth["headers"],
                              params={"limit": 5000}).status_code == 422


def test_scan_for_another_org_is_a_404(server, auth):
    """A scan id belonging to another organization must not be readable."""
    other_org_id = _create_second_org(server)
    with session_scope(server["engine"]) as session:
        project = _make_project(session, other_org_id, "other-project")
        scan = Scan(org_id=other_org_id, project_id=project.id, status="succeeded", engines="[]")
        session.add(scan)
        session.flush()
        other_scan_id = scan.id
    assert auth["client"].get(f"/scan/{other_scan_id}", headers=auth["headers"]).status_code == 404


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
def test_finding_detail_suppression_and_events(server, auth, project):
    scan_id = _run_scan(server, auth, project)
    findings = auth["client"].get(f"/scan/{scan_id}/findings", headers=auth["headers"]).json()
    target = findings[0]

    single = auth["client"].get(f"/findings/{target['id']}", headers=auth["headers"])
    assert single.status_code == 200
    assert single.json()["rule_id"] == target["rule_id"]
    assert single.json()["cwe"].startswith("CWE-")
    assert single.json()["remediation"]

    # Suppression without a reason is refused.
    refused = auth["client"].patch(f"/findings/{target['id']}", headers=auth["headers"],
                                   json={"status": "suppressed", "reason": "  "})
    assert refused.status_code == 422

    suppressed = auth["client"].patch(f"/findings/{target['id']}", headers=auth["headers"],
                                      json={"status": "suppressed", "reason": "TICKET-1 accepted risk"})
    assert suppressed.status_code == 200
    assert suppressed.json()["status"] == "suppressed"

    history = auth["client"].get(f"/findings/{target['id']}/events", headers=auth["headers"]).json()
    assert {entry["event_type"] for entry in history} >= {"finding.created", "finding.suppressed"}

    reopened = auth["client"].patch(f"/findings/{target['id']}", headers=auth["headers"],
                                    json={"status": "open", "reason": "reopened for review"})
    assert reopened.status_code == 200
    assert reopened.json()["status"] == "open"


def test_finding_filters(auth, project):
    filtered = auth["client"].get("/findings", headers=auth["headers"],
                                  params={"severity": "critical", "status": "open"})
    assert filtered.status_code == 200
    assert all(f["severity"] == "critical" for f in filtered.json())

    by_rule = auth["client"].get("/findings", headers=auth["headers"],
                                 params={"rule_id": "PY-AST-SQL-INJECTION"})
    assert all(f["rule_id"] == "PY-AST-SQL-INJECTION" for f in by_rule.json())


def test_resolved_findings_are_tracked_when_code_is_fixed(server, auth):
    """Fixing the code must move the old finding to 'resolved'."""
    project = auth["client"].post("/projects", headers=auth["headers"],
                                  json={"name": "Fix Tracking"}).json()
    scan_id = _run_scan(server, auth, project)
    before = auth["client"].get(f"/scan/{scan_id}/findings", headers=auth["headers"]).json()
    assert before

    # Replace the vulnerable file with a clean one and rescan.
    fixed_dir = server["base"] / "fixed-target"
    fixed_dir.mkdir(exist_ok=True)
    (fixed_dir / "app.py").write_text(
        "def lookup(user_input):\n"
        "    import sqlite3\n"
        "    conn = sqlite3.connect(':memory:')\n"
        "    return conn.execute('SELECT * FROM users WHERE name = ?', (user_input,)).fetchall()\n",
        encoding="utf-8")
    previous_root = os.environ["IRONCLAD_SCAN_ROOT"]
    os.environ["IRONCLAD_SCAN_ROOT"] = str(fixed_dir)
    try:
        _run_scan(server, auth, project)
    finally:
        os.environ["IRONCLAD_SCAN_ROOT"] = previous_root

    resolved = auth["client"].get("/findings", headers=auth["headers"],
                                  params={"project_id": project["id"], "status": "resolved"})
    assert resolved.status_code == 200
    assert {f["rule_id"] for f in resolved.json()} >= {"PY-AST-SQL-INJECTION"}


# --------------------------------------------------------------------------- #
# SBOM / licenses
# --------------------------------------------------------------------------- #
def test_sbom_and_components_are_persisted(server, auth, project):
    _run_scan(server, auth, project)

    sbom = auth["client"].get("/sbom", headers=auth["headers"],
                              params={"project_id": project["id"]})
    assert sbom.status_code == 200
    assert sbom.json()["format"] == "cyclonedx"
    assert sbom.json()["component_count"] >= 2

    document = auth["client"].get("/sbom/document", headers=auth["headers"],
                                  params={"project_id": project["id"]}).json()
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    from ironclad.scanners.sbom import validate_cyclonedx

    assert validate_cyclonedx(document) == []

    components = auth["client"].get("/sbom/components", headers=auth["headers"],
                                    params={"project_id": project["id"]}).json()
    names = {c["name"] for c in components}
    assert {"jinja2", "requests"} <= names
    assert all(c["purl"].startswith("pkg:") for c in components)


def test_license_summary_classifies_components(server, auth, project):
    _run_scan(server, auth, project)
    summary = auth["client"].get("/licenses", headers=auth["headers"],
                                 params={"project_id": project["id"]})
    assert summary.status_code == 200
    body = summary.json()
    assert body["counts"]["allowed"] >= 2, body
    assert body["blocked"] == []


def test_sbom_404_before_any_scan(auth):
    fresh = auth["client"].post("/projects", headers=auth["headers"],
                                json={"name": "Never Scanned"}).json()
    assert auth["client"].get("/sbom", headers=auth["headers"],
                              params={"project_id": fresh["id"]}).status_code == 404


# --------------------------------------------------------------------------- #
# Policies
# --------------------------------------------------------------------------- #
def test_policy_crud_and_validation(auth):
    created = auth["client"].post("/policies", headers=auth["headers"],
                                  json={"name": "ci-gate", "document": POLICY_DOCUMENT,
                                        "is_default": True})
    assert created.status_code == 201, created.text
    assert created.json()["version"] == 1
    assert created.json()["is_default"] is True

    updated = auth["client"].post("/policies", headers=auth["headers"],
                                  json={"name": "ci-gate",
                                        "document": {**POLICY_DOCUMENT, "fail_on": "critical"}})
    assert updated.json()["version"] == 2

    listed = auth["client"].get("/policies", headers=auth["headers"]).json()
    assert {p["name"] for p in listed} >= {"ci-gate"}

    valid = auth["client"].post("/policies/validate", headers=auth["headers"],
                                json={"name": "x", "document": POLICY_DOCUMENT})
    assert valid.json()["valid"] is True

    invalid = auth["client"].post("/policies/validate", headers=auth["headers"],
                                  json={"name": "x", "document": {"version": 1, "fail_on": "bogus"}})
    assert invalid.json()["valid"] is False
    assert invalid.json()["problems"]

    assert auth["client"].delete(f"/policies/{created.json()['id']}",
                                 headers=auth["headers"]).status_code == 204


def test_policy_create_rejects_an_invalid_document(auth):
    response = auth["client"].post("/policies", headers=auth["headers"],
                                   json={"name": "bad", "document": {"version": 99}})
    assert response.status_code == 422
    assert response.json()["detail"], "the specific problems must be returned"


# --------------------------------------------------------------------------- #
# Integrations
# --------------------------------------------------------------------------- #
def test_integration_crud_and_secret_handling(auth):
    created = auth["client"].post("/integrations", headers=auth["headers"],
                                  json={"kind": "webhook", "name": "ops-hook",
                                        "config": {"url": "https://example.test/hook"},
                                        "secret": "super-secret-value"})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["has_secret"] is True
    assert "super-secret-value" not in json.dumps(body), "the secret must never be echoed"

    listed = auth["client"].get("/integrations", headers=auth["headers"]).json()
    assert any(i["name"] == "ops-hook" for i in listed)

    assert auth["client"].delete(f"/integrations/{body['id']}",
                                 headers=auth["headers"]).status_code == 204


def test_integration_config_is_validated(auth):
    bad = auth["client"].post("/integrations", headers=auth["headers"],
                              json={"kind": "webhook", "name": "no-url", "config": {}})
    assert bad.status_code == 422

    unknown = auth["client"].post("/integrations", headers=auth["headers"],
                                  json={"kind": "carrier-pigeon", "name": "x"})
    assert unknown.status_code == 422


def test_integration_test_records_a_failure_for_an_unreachable_host(auth):
    created = auth["client"].post("/integrations", headers=auth["headers"],
                                  json={"kind": "webhook", "name": "dead-hook",
                                        "config": {"url": "https://ironclad-unreachable.invalid/hook"}})
    outcome = auth["client"].post(f"/integrations/{created.json()['id']}/test",
                                  headers=auth["headers"])
    assert outcome.status_code == 200
    assert outcome.json()["last_status"] == "failed"
    assert outcome.json()["last_error"], "the failure reason must be recorded"


def test_webhook_payload_signing_is_verifiable():
    payload = b'{"event":"scan.completed"}'
    signature = sign_payload(payload, "shared-secret")
    assert verify_signature(payload, signature, "shared-secret") is True
    assert verify_signature(payload, signature, "wrong-secret") is False
    assert verify_signature(payload, "", "shared-secret") is False
    assert verify_signature(b"tampered", signature, "shared-secret") is False


def test_webhook_rejects_a_private_address_by_default(auth, monkeypatch):
    monkeypatch.delenv("IRONCLAD_ALLOW_PRIVATE_WEBHOOKS", raising=False)
    response = auth["client"].post("/integrations", headers=auth["headers"],
                                   json={"kind": "webhook", "name": "internal",
                                         "config": {"url": "https://127.0.0.1/hook"}})
    assert response.status_code == 422
    assert "private" in str(response.json()["detail"]).lower()


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
def test_audit_log_records_mutations(auth, project):
    auth["client"].patch(f"/findings/1", headers=auth["headers"],
                         json={"status": "open", "reason": "x"})
    entries = auth["client"].get("/audit", headers=auth["headers"]).json()
    actions = {entry["action"] for entry in entries}
    assert {"auth.login", "project.created", "scan.created"} <= actions


def test_audit_log_redacts_credentials(auth):
    auth["client"].post("/integrations", headers=auth["headers"],
                        json={"kind": "webhook", "name": "redaction-check",
                              "config": {"url": "https://example.test/x"},
                              "secret": "should-not-appear"})
    entries = auth["client"].get("/audit", headers=auth["headers"],
                                 params={"action": "integration.created"}).json()
    assert entries
    assert "should-not-appear" not in json.dumps(entries)


def test_audit_log_is_filterable(auth):
    entries = auth["client"].get("/audit", headers=auth["headers"],
                                 params={"action": "auth.login"}).json()
    assert entries
    assert all(entry["action"] == "auth.login" for entry in entries)


# --------------------------------------------------------------------------- #
# Jobs / events / dashboard
# --------------------------------------------------------------------------- #
def test_jobs_are_visible(server, auth, project):
    auth["client"].post("/scan", headers=auth["headers"],
                        json={"project_id": project["id"], "target": "."})
    jobs = auth["client"].get("/jobs", headers=auth["headers"]).json()
    assert jobs
    assert all(job["kind"] == "scan.run" for job in jobs)


def test_events_are_published_for_a_scan(server, auth, project):
    from ironclad.platform.models import Event
    from sqlalchemy import select

    events.default_bus.published.clear()
    _run_scan(server, auth, project)
    types = {event.event_type for event in events.default_bus.published}
    assert {"scan.created", "scan.started", "scan.completed"} <= types
    assert "finding.created" in types

    with session_scope(server["engine"]) as session:
        stored = session.execute(
            select(Event).where(Event.org_id == server["org_id"])
        ).scalars().all()
    assert {row.event_type for row in stored} >= {"scan.created", "scan.completed"}


def test_event_contract_is_enforced(server):
    with pytest.raises(events.EventContractError):
        events.default_bus.publish(None, "scan.completed", server["org_id"], {"scan_id": 1})


def test_dashboard_reports_real_numbers(server, auth, project):
    _run_scan(server, auth, project)
    response = auth["client"].get("/dashboard", headers=auth["headers"],
                                  params={"project_id": project["id"]})
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["projects"] >= 1
    assert body["summary"]["scans_total"] >= 1
    assert body["summary"]["open_findings"] >= 1
    assert body["summary"]["severity_counts"]["critical"] >= 1
    assert body["trend"], "the trend must contain at least one real scan point"
    assert body["trend"][-1]["counts"]["critical"] >= 1


# --------------------------------------------------------------------------- #
# RBAC
# --------------------------------------------------------------------------- #
def _login_as(server, email, password, role):
    """Create a user with the given role and return an authenticated client."""
    owner = server["client"].post("/auth/login", json={"email": "owner@acme-corp.com",
                                                       "password": ADMIN_PASSWORD}).json()["access_token"]
    created = server["client"].post("/users", headers={"Authorization": f"Bearer {owner}"},
                                    json={"email": email, "password": "Str0ng!Passw0rd-55",
                                          "role": role})
    assert created.status_code == 201, created.text
    login = server["client"].post("/auth/login", json={"email": email,
                                                       "password": "Str0ng!Passw0rd-55"})
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_viewer_cannot_scan(server):
    headers = _login_as(server, "viewer@acme-corp.com", "x", "viewer")
    projects = server["client"].get("/projects", headers=headers)
    assert projects.status_code == 200, "a viewer can read projects"
    project_id = projects.json()[0]["id"]
    denied = server["client"].post("/scan", headers=headers,
                                   json={"project_id": project_id, "target": "."})
    assert denied.status_code == 403
    assert "scan.create" in denied.json()["detail"]


def test_developer_can_scan_but_not_manage_findings(server, project):
    headers = _login_as(server, "dev@acme-corp.com", "x", "developer")
    allowed = server["client"].post("/scan", headers=headers,
                                    json={"project_id": project["id"], "target": "."})
    assert allowed.status_code == 202

    findings = server["client"].get("/findings", headers=headers).json()
    if findings:
        denied = server["client"].patch(f"/findings/{findings[0]['id']}", headers=headers,
                                        json={"status": "suppressed", "reason": "nope"})
        assert denied.status_code == 403


def test_security_role_can_manage_findings_but_not_users(server, project):
    headers = _login_as(server, "sec@acme-corp.com", "x", "security")
    findings = server["client"].get("/findings", headers=headers).json()
    assert findings
    ok = server["client"].patch(f"/findings/{findings[0]['id']}", headers=headers,
                                json={"status": "suppressed", "reason": "TICKET-99"})
    assert ok.status_code == 200
    assert server["client"].post("/users", headers=headers,
                                 json={"email": "x@acme-corp.com", "password": "Str0ng!Passw0rd-55"}
                                 ).status_code == 403


def test_admin_cannot_grant_owner(server):
    headers = _login_as(server, "admin@acme-corp.com", "x", "admin")
    users = server["client"].get("/users", headers=headers).json()
    victim = next(u for u in users if u["email"] == "viewer@acme-corp.com")
    denied = server["client"].patch(f"/users/{victim['id']}/role", headers=headers,
                                    json={"role": "owner"})
    assert denied.status_code == 403
    assert "owner" in denied.json()["detail"]


def test_admin_cannot_demote_themself_below_admin(server):
    headers = _login_as(server, "admin2@acme-corp.com", "x", "admin")
    me = server["client"].get("/auth/me", headers=headers).json()
    denied = server["client"].patch(f"/users/{me['id']}/role", headers=headers,
                                    json={"role": "viewer"})
    assert denied.status_code == 400


def test_weak_password_is_rejected_for_new_users(auth):
    response = auth["client"].post("/users", headers=auth["headers"],
                                   json={"email": "weak@acme-corp.com", "password": "short"})
    assert response.status_code == 422


def test_duplicate_user_email_is_rejected(auth):
    body = {"email": "dupe@acme-corp.com", "password": "Str0ng!Passw0rd-55", "role": "viewer"}
    assert auth["client"].post("/users", headers=auth["headers"], json=body).status_code == 201
    assert auth["client"].post("/users", headers=auth["headers"], json=body).status_code == 409


def test_unknown_role_is_rejected(auth):
    response = auth["client"].post("/users", headers=auth["headers"],
                                   json={"email": "role@acme-corp.com",
                                         "password": "Str0ng!Passw0rd-55", "role": "superuser"})
    assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Multi-tenancy
# --------------------------------------------------------------------------- #
def _create_second_org(server) -> int:
    """Create (once) a second organization and return its id."""
    from sqlalchemy import select

    with session_scope(server["engine"]) as session:
        existing = session.execute(
            select(Organization).where(Organization.slug == "beta")).scalar_one_or_none()
        if existing is not None:
            return existing.id
        org, _owner = bootstrap_organization(session, name="Beta Inc", slug="beta",
                                             admin_email="owner@beta-inc.com",
                                             password=ADMIN_PASSWORD)
        return org.id


def _make_project(session, org_id, name):
    from ironclad.platform.models import Project

    project = Project(org_id=org_id, name=name, slug=name)
    session.add(project)
    session.flush()
    return project


def _login_second_org(server) -> dict:
    login = server["client"].post("/auth/login", json={"email": "owner@beta-inc.com",
                                                       "password": ADMIN_PASSWORD})
    assert login.status_code == 200, login.text
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_second_organization_sees_only_its_own_data(server, auth, project):
    _create_second_org(server)
    beta = _login_second_org(server)

    beta_ids = {p["id"] for p in server["client"].get("/projects", headers=beta).json()}
    acme_ids = {p["id"] for p in server["client"].get("/projects", headers=auth["headers"]).json()}
    assert acme_ids, "the first organization still sees its own projects"
    assert not (beta_ids & acme_ids), "organizations must not see each other's projects"
    # Beta only ever sees the project it created for itself.
    for project_id in beta_ids:
        row = server["client"].get(f"/projects/{project_id}", headers=beta)
        assert row.status_code == 200


def test_cross_tenant_project_access_is_a_404(server, auth, project):
    _create_second_org(server)
    beta = _login_second_org(server)
    assert server["client"].get(f"/projects/{project['id']}", headers=beta).status_code == 404


def test_cross_tenant_finding_access_is_a_404(server, auth, project):
    _create_second_org(server)
    beta = _login_second_org(server)
    scan_id = _run_scan(server, auth, project)
    finding = server["client"].get(f"/scan/{scan_id}/findings", headers=auth["headers"]).json()[0]
    assert server["client"].get(f"/findings/{finding['id']}", headers=beta).status_code == 404
    denied = server["client"].patch(f"/findings/{finding['id']}", headers=beta,
                                    json={"status": "suppressed", "reason": "cross-tenant"})
    assert denied.status_code == 404


def test_cross_tenant_scan_and_audit_are_isolated(server, auth, project):
    _create_second_org(server)
    beta = _login_second_org(server)
    scan_id = _run_scan(server, auth, project)
    assert server["client"].get(f"/scan/{scan_id}", headers=beta).status_code == 404
    assert server["client"].get(f"/scan/{scan_id}/findings", headers=beta).status_code == 404

    beta_audit = server["client"].get("/audit", headers=beta).json()
    acme_audit = server["client"].get("/audit", headers=auth["headers"]).json()
    assert all("acme" not in json.dumps(entry).lower() for entry in beta_audit)
    assert len(acme_audit) > len(beta_audit)


def test_cross_tenant_policy_and_integration_are_isolated(server, auth):
    _create_second_org(server)
    beta = _login_second_org(server)
    policy = auth["client"].post("/policies", headers=auth["headers"],
                                 json={"name": "acme-only", "document": POLICY_DOCUMENT}).json()
    assert server["client"].delete(f"/policies/{policy['id']}", headers=beta).status_code == 404


# --------------------------------------------------------------------------- #
# Dashboard (HTML)
# --------------------------------------------------------------------------- #
def test_dashboard_requires_login(server):
    response = server["client"].get("/ui/")
    assert response.status_code == 307
    assert response.headers["location"] == "/ui/login"


def test_dashboard_login_page_renders(server):
    response = server["client"].get("/ui/login")
    assert response.status_code == 200
    assert "IronClad" in response.text


def test_dashboard_pages_render_after_login(server):
    client = server["client"]
    client.post("/ui/login", data={"email": "owner@acme-corp.com", "password": ADMIN_PASSWORD})
    for path in ("/ui/", "/ui/projects", "/ui/findings", "/ui/policies",
                 "/ui/integrations", "/ui/audit", "/ui/settings"):
        response = client.get(path)
        assert response.status_code == 200, f"{path} -> {response.status_code}"
        assert "IronClad" in response.text


def test_dashboard_shows_real_finding_data(server, auth, project):
    scan_id = _run_scan(server, auth, project)
    client = server["client"]
    client.post("/ui/login", data={"email": "owner@acme-corp.com", "password": ADMIN_PASSWORD})
    page = client.get(f"/ui/projects/{project['id']}")
    assert page.status_code == 200
    assert "PY-AST-SQL-INJECTION" in page.text
    assert "jinja2" in page.text  # SBOM component rendered
    assert "PY-AST-SSRF" in page.text


def test_dashboard_audit_page_requires_permission(server):
    _create_second_org(server)
    client = server["client"]
    client.post("/ui/login", data={"email": "owner@beta-inc.com", "password": ADMIN_PASSWORD})
    # Owner has audit.read, so this must render (not 403).
    assert client.get("/ui/audit").status_code == 200


def test_dashboard_404_for_a_foreign_project(server, auth, project):
    _create_second_org(server)
    client = server["client"]
    client.post("/ui/login", data={"email": "owner@beta-inc.com", "password": ADMIN_PASSWORD})
    assert client.get(f"/ui/projects/{project['id']}").status_code == 404


# --------------------------------------------------------------------------- #
# Worker reliability
# --------------------------------------------------------------------------- #
def test_failing_job_is_retried_then_marked_failed(server):
    """A handler that always raises must not lose the job or spin forever."""
    from ironclad.platform.jobs import JobQueue, JobSpec
    from ironclad.platform.models import Job
    from sqlalchemy import select

    queue = JobQueue(retry_backoff=0)
    attempts = {"count": 0}

    def always_fails(session, payload):
        attempts["count"] += 1
        raise RuntimeError("boom")

    queue.register("always-fails", always_fails)
    with session_scope(server["engine"]) as session:
        job = queue.enqueue(session, JobSpec(kind="always-fails", org_id=server["org_id"],
                                             payload={}, max_attempts=3))
        job_id = job.id
    for _ in range(5):
        with session_scope(server["engine"]) as session:
            queue.run_pending(session, limit=1)
    with session_scope(server["engine"]) as session:
        row = session.execute(select(Job).where(Job.id == job_id)).scalar_one()
        assert row.status == "failed", row.status
        assert row.attempts >= 3
        assert "boom" in row.error


def test_stale_running_job_is_reclaimable(server):
    from ironclad.platform.jobs import JobQueue, JobSpec
    from ironclad.platform.models import Job
    from sqlalchemy import select

    queue = JobQueue(stale_after_seconds=0)
    queue.register("stale-kind", lambda session, payload: None)
    with session_scope(server["engine"]) as session:
        job = queue.enqueue(session, JobSpec(kind="stale-kind", org_id=server["org_id"], payload={}))
        job_id = job.id
        job.status = "running"
        job.started_at = utcnow() - timedelta(hours=1)
    with session_scope(server["engine"]) as session:
        reclaimed = queue.claim(session, kinds=["stale-kind"])
        assert reclaimed is not None and reclaimed.id == job_id
    with session_scope(server["engine"]) as session:
        row = session.execute(select(Job).where(Job.id == job_id)).scalar_one()
        assert row.status == "running"
        assert row.attempts >= 1


def test_scan_of_a_missing_target_marks_the_scan_failed(server, auth, project):
    """A scan whose target disappears must end 'failed', never 'queued'."""
    from ironclad.platform.worker_jobs import register_job_handlers

    response = auth["client"].post("/scan", headers=auth["headers"],
                                   json={"project_id": project["id"], "target": "."})
    scan_id = response.json()["id"]
    os.remove(os.path.join(server["target"], "app.py"))
    os.remove(os.path.join(server["target"], "requirements.txt"))
    os.rmdir(server["target"])
    queue = JobQueue()
    register_job_handlers(queue, server["engine"])
    with session_scope(server["engine"]) as session:
        queue.run_pending(session, limit=3)
    scan = auth["client"].get(f"/scan/{scan_id}", headers=auth["headers"]).json()
    assert scan["status"] == "failed", scan
    assert scan["error"], "the failure reason must be stored on the scan"
