"""Dashboard tests.

The dashboard is server-rendered with no JavaScript, so its forms post to
dashboard routes rather than to the JSON API. The finding triage form was
posted to ``/findings/{id}``, which is a GET-only JSON API route -- it
returned 405 and the triage UI had never worked. These tests drive the real
rendered pages and forms, including every authorization boundary.
"""
from __future__ import annotations

import os
import tempfile
from urllib.parse import unquote

import pytest

pytest.importorskip("fastapi", reason="requires the server extra: pip install -e '.[server]'")
pytest.importorskip("sqlalchemy", reason="requires the server extra: pip install -e '.[server]'")

from fastapi.testclient import TestClient
from sqlalchemy import select

from ironclad.api.app import create_app
from ironclad.platform.database import build_engine, run_migrations, session_scope
from ironclad.platform.models import (
    AuditEvent,
    Finding,
    FindingEvent,
    Organization,
    Project,
    Scan,
    User,
)
from ironclad.platform.security import hash_password

PASSWORD = "Dash-Board-Passw0rd-1"


@pytest.fixture()
def env():
    engine = build_engine("sqlite:///" + os.path.join(tempfile.mkdtemp(), "dash.db"))
    run_migrations(engine)
    with session_scope(engine) as s:
        org = Organization(name="Dash", slug="dash")
        s.add(org)
        s.flush()
        s.add(User(org_id=org.id, email="owner@dash-corp.com",
                   password_hash=hash_password(PASSWORD), role="owner"))
        s.add(User(org_id=org.id, email="sec@dash-corp.com",
                   password_hash=hash_password(PASSWORD), role="security"))
        s.add(User(org_id=org.id, email="viewer@dash-corp.com",
                   password_hash=hash_password(PASSWORD), role="viewer"))
        project = Project(org_id=org.id, name="Payments", slug="payments")
        s.add(project)
        s.flush()
        scan = Scan(org_id=org.id, project_id=project.id, status="succeeded", risk_score=40)
        s.add(scan)
        s.flush()
        for index, (rule, severity) in enumerate([
            ("PY-AST-SQL-INJECTION", "critical"),
            ("PY-AST-SSRF", "high"),
        ], start=1):
            s.add(Finding(org_id=org.id, scan_id=scan.id, project_id=project.id,
                          fingerprint=f"fp{index}", rule_id=rule, title=rule,
                          severity=severity))

        other = Organization(name="Other", slug="other-dash")
        s.add(other)
        s.flush()
        s.add(User(org_id=other.id, email="owner@other-dash.com",
                   password_hash=hash_password(PASSWORD), role="owner"))
        other_project = Project(org_id=other.id, name="Theirs", slug="theirs")
        s.add(other_project)
        s.flush()
        other_scan = Scan(org_id=other.id, project_id=other_project.id)
        s.add(other_scan)
        s.flush()
        s.add(Finding(org_id=other.id, scan_id=other_scan.id, project_id=other_project.id,
                      fingerprint="other-fp", rule_id="OTHER-RULE", title="Theirs",
                      severity="critical"))
        org_id, other_id = org.id, other.id

    app = create_app(str(engine.url), include_web=True)

    def client(email):
        c = TestClient(app, follow_redirects=False)
        response = c.post("/ui/login", data={"email": email, "password": PASSWORD})
        assert response.status_code == 303, response.text
        return c

    return {
        "engine": engine, "app": app, "org_id": org_id, "other_id": other_id,
        "owner": client("owner@dash-corp.com"),
        "security": client("sec@dash-corp.com"),
        "viewer": client("viewer@dash-corp.com"),
        "other": client("owner@other-dash.com"),
    }


# --------------------------------------------------------------------------- #
# Pages render
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path", [
    "/ui/", "/ui/projects", "/ui/findings", "/ui/policies",
    "/ui/integrations", "/ui/audit", "/ui/settings",
])
def test_pages_render_for_an_authenticated_owner(env, path):
    response = env["owner"].get(path)
    assert response.status_code == 200, f"{path} -> {response.status_code}"
    assert "IronClad" in response.text


def test_project_detail_renders_real_findings(env):
    response = env["owner"].get("/ui/projects/1")
    assert response.status_code == 200
    assert "PY-AST-SQL-INJECTION" in response.text
    assert "PY-AST-SSRF" in response.text


def test_finding_detail_renders(env):
    response = env["owner"].get("/ui/findings/1")
    assert response.status_code == 200
    assert "PY-AST-SQL-INJECTION" in response.text
    assert "Remediation" in response.text


def test_unauthenticated_requests_redirect_to_login(env):
    anonymous = TestClient(env["app"], follow_redirects=False)
    for path in ("/ui/", "/ui/findings", "/ui/findings/1", "/ui/audit"):
        response = anonymous.get(path)
        assert response.status_code == 307, f"{path} -> {response.status_code}"
        assert response.headers["location"] == "/ui/login"


def test_cross_tenant_pages_are_not_reachable(env):
    """The other organization's project and finding must not be reachable."""
    assert env["other"].get("/ui/projects/1").status_code == 404
    assert env["other"].get("/ui/findings/1").status_code == 404


# --------------------------------------------------------------------------- #
# Triage form (the previously broken feature)
# --------------------------------------------------------------------------- #
def test_triage_form_is_rendered_with_the_correct_action(env):
    response = env["owner"].get("/ui/findings/1")
    assert 'action="/ui/findings/1/triage"' in response.text
    assert 'method="post"' in response.text


def test_triage_resolves_a_finding(env):
    response = env["owner"].post("/ui/findings/1/triage",
                                 data={"status": "resolved", "reason": "fixed in abc123"})
    assert response.status_code == 303
    assert "updated=1" in response.headers["location"]

    with session_scope(env["engine"]) as s:
        finding = s.get(Finding, 1)
        assert finding.status == "resolved"
        assert finding.suppressed_reason == "fixed in abc123"

    page = env["owner"].get(response.headers["location"])
    assert "Finding updated." in page.text


def test_triage_suppress_requires_a_reason(env):
    response = env["owner"].post("/ui/findings/1/triage",
                                 data={"status": "suppressed", "reason": ""})
    assert response.status_code == 303
    location = unquote(response.headers["location"])
    assert "reason is required" in location

    page = env["owner"].get(response.headers["location"])
    assert "reason is required" in page.text, "the error must be surfaced to the user"

    with session_scope(env["engine"]) as s:
        assert s.get(Finding, 1).status == "open", "status must not change on a rejected update"


def test_triage_suppress_with_a_reason_succeeds(env):
    response = env["owner"].post("/ui/findings/1/triage",
                                 data={"status": "suppressed", "reason": "TICKET-42 accepted risk"})
    assert response.status_code == 303
    with session_scope(env["engine"]) as s:
        finding = s.get(Finding, 1)
        assert finding.status == "suppressed"
        assert finding.suppressed_reason == "TICKET-42 accepted risk"
        assert finding.suppressed_by == "owner@dash-corp.com"


def test_triage_can_reopen(env):
    env["owner"].post("/ui/findings/1/triage", data={"status": "resolved", "reason": "x"})
    response = env["owner"].post("/ui/findings/1/triage", data={"status": "open", "reason": ""})
    assert response.status_code == 303
    with session_scope(env["engine"]) as s:
        finding = s.get(Finding, 1)
        assert finding.status == "open"
        assert finding.suppressed_reason == ""


def test_triage_rejects_an_invalid_status(env):
    response = env["owner"].post("/ui/findings/1/triage",
                                 data={"status": "wontfix", "reason": "x"})
    assert response.status_code == 303
    assert "status must be one of" in unquote(response.headers["location"])
    with session_scope(env["engine"]) as s:
        assert s.get(Finding, 1).status == "open"


# --------------------------------------------------------------------------- #
# Triage authorization
# --------------------------------------------------------------------------- #
def test_viewer_cannot_triage(env):
    response = env["viewer"].post("/ui/findings/1/triage",
                                  data={"status": "resolved", "reason": "x"})
    assert response.status_code == 303
    assert "forbidden" in response.headers["location"]
    with session_scope(env["engine"]) as s:
        assert s.get(Finding, 1).status == "open"


def test_security_role_can_triage(env):
    response = env["security"].post("/ui/findings/1/triage",
                                    data={"status": "resolved", "reason": "verified fixed"})
    assert response.status_code == 303
    assert "updated=1" in response.headers["location"]


def test_anonymous_cannot_triage(env):
    anonymous = TestClient(env["app"], follow_redirects=False)
    response = anonymous.post("/ui/findings/1/triage",
                              data={"status": "resolved", "reason": "x"})
    assert response.status_code == 303
    assert response.headers["location"] == "/ui/login"
    with session_scope(env["engine"]) as s:
        assert s.get(Finding, 1).status == "open"


def test_cross_tenant_triage_is_refused(env):
    """Another organization must not be able to triage this finding."""
    response = env["other"].post("/ui/findings/1/triage",
                                 data={"status": "resolved", "reason": "steal"})
    assert response.status_code == 303
    assert response.headers["location"] == "/ui/findings"
    with session_scope(env["engine"]) as s:
        assert s.get(Finding, 1).status == "open", "the finding must be untouched"


def test_triage_on_a_missing_finding_redirects_safely(env):
    response = env["owner"].post("/ui/findings/9999/triage",
                                 data={"status": "resolved", "reason": "x"})
    assert response.status_code == 303
    assert response.headers["location"] == "/ui/findings"


# --------------------------------------------------------------------------- #
# Shared logic and audit
# --------------------------------------------------------------------------- #
def test_triage_is_audited(env):
    env["owner"].post("/ui/findings/1/triage", data={"status": "suppressed", "reason": "TICKET-1"})
    with session_scope(env["engine"]) as s:
        events = [e for e in s.execute(select(AuditEvent)).scalars().all()
                  if e.action == "finding.suppressed"]
    assert events, "a triage change must be audited"
    assert events[0].actor == "owner@dash-corp.com"
    assert events[0].org_id == env["org_id"]


def test_triage_writes_a_finding_event(env):
    env["owner"].post("/ui/findings/1/triage", data={"status": "resolved", "reason": "done"})
    with session_scope(env["engine"]) as s:
        events = s.execute(select(FindingEvent)).scalars().all()
    assert [e.event_type for e in events] == ["finding.resolved"]


def test_rejected_triage_is_not_audited(env):
    env["owner"].post("/ui/findings/1/triage", data={"status": "suppressed", "reason": ""})
    with session_scope(env["engine"]) as s:
        events = [e for e in s.execute(select(AuditEvent)).scalars().all()
                  if e.action.startswith("finding.")]
    assert events == [], "a rejected update must not be recorded"


def test_dashboard_and_api_triage_share_one_implementation():
    """The two entry points must not be able to diverge on authorization."""
    import inspect

    from ironclad.api import routes
    from ironclad.platform import triage
    from ironclad.web import app as web_app

    api_source = inspect.getsource(routes.update_finding)
    web_source = inspect.getsource(web_app)
    assert "triage.apply_triage" in api_source, "the API must use the shared service"
    assert "triage.apply_triage" in web_source, "the dashboard must use the shared service"
    assert triage.VALID_STATUSES == ("open", "resolved", "suppressed")


# --------------------------------------------------------------------------- #
# Every rendered form must actually submit somewhere that exists
# --------------------------------------------------------------------------- #
def _rendered_pages(env):
    """Render every dashboard page and return (path, html) pairs."""
    owner = env["owner"]
    return [
        ("/ui/login", TestClient(env["app"], follow_redirects=False).get("/ui/login").text),
        ("/ui/", owner.get("/ui/").text),
        ("/ui/projects", owner.get("/ui/projects").text),
        ("/ui/projects/1", owner.get("/ui/projects/1").text),
        ("/ui/findings", owner.get("/ui/findings").text),
        ("/ui/findings/1", owner.get("/ui/findings/1").text),
        ("/ui/policies", owner.get("/ui/policies").text),
        ("/ui/integrations", owner.get("/ui/integrations").text),
        ("/ui/audit", owner.get("/ui/audit").text),
        ("/ui/settings", owner.get("/ui/settings").text),
    ]


def _form_actions(html):
    """Extract every (method, action) pair from rendered HTML."""
    import re

    found = []
    for form in re.findall(r"<form\b[^>]*>", html):
        action = re.search(r'action="([^"]*)"', form)
        method = re.search(r'method="([^"]*)"', form)
        found.append(((method.group(1) if method else "get").upper(),
                      action.group(1) if action else ""))
    return found


def test_every_rendered_form_action_resolves_to_a_real_route(env):
    """Two dead controls were found this way: the login form posted to
    /login (404) and the triage form posted to the JSON API route (405).

    A form that submits nowhere is a broken feature that looks implemented,
    so every form action rendered by the dashboard is POSTed/GETed and must
    not return 404 or 405.
    """
    client = env["owner"]
    checked = 0
    problems = []
    for page_path, html in _rendered_pages(env):
        for method, action in _form_actions(html):
            assert action, f"{page_path} renders a form with no action"
            assert action.startswith("/ui/"), (
                f"{page_path} renders a form posting to {action!r}, outside the "
                f"dashboard namespace -- dashboard forms must post to /ui/ routes")
            if method == "POST":
                response = client.post(action, data={"status": "open", "reason": "probe",
                                                     "email": "probe@example.com",
                                                     "password": "probe-password"})
            else:
                response = client.get(action)
            checked += 1
            if response.status_code in (404, 405):
                problems.append(f"{page_path} -> {method} {action} -> {response.status_code}")
    assert checked >= 3, f"expected several forms, found {checked}"
    assert not problems, "dead form controls: " + "; ".join(problems)


def test_login_form_posts_to_the_login_route(env):
    """The login form specifically -- it posted to /login and returned 404."""
    anonymous = TestClient(env["app"], follow_redirects=False)
    html = anonymous.get("/ui/login").text
    actions = _form_actions(html)
    assert ("POST", "/ui/login") in actions, actions

    response = anonymous.post("/ui/login", data={"email": "owner@dash-corp.com",
                                                 "password": PASSWORD})
    assert response.status_code == 303
    assert response.headers["location"] == "/ui/"


def test_login_form_rejects_bad_credentials(env):
    anonymous = TestClient(env["app"], follow_redirects=False)
    response = anonymous.post("/ui/login", data={"email": "owner@dash-corp.com",
                                                 "password": "wrong-password"})
    assert response.status_code == 303
    assert "error" in response.headers["location"]
