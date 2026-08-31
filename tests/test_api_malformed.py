"""Malformed-input robustness for the HTTP surface.

The contract under test is narrow and absolute: **no request body, query
parameter or path segment may produce a 5xx.** A validation failure is a
4xx; a 5xx means an exception escaped a handler, which in a multi-tenant
API is both an availability bug and a potential information leak (tracebacks
in error responses, half-committed transactions).

Every case below is a body or parameter that a client can legitimately send
-- a confused CI script, a hand-written curl, a fuzzer, or an attacker
probing for stack traces.
"""
from __future__ import annotations

import json
import os
import uuid

import pytest
from fastapi.testclient import TestClient

from ironclad.api.app import create_app
from ironclad.platform.database import build_engine, run_migrations, session_scope
from ironclad.platform.scanning import bootstrap_organization

ADMIN_PASSWORD = "Adm1n-Correct-Horse-Battery"

# Bodies a client can send that are structurally wrong in different ways.
MALFORMED_BODIES = {
    "empty-object": {},
    "json-array": [1, 2, 3],
    "json-null": None,
    "json-string": "not-an-object",
    "json-number": 42,
    "nested-null": {"a": {"b": None}},
    "wrong-types": {"email": 12345, "password": ["x"], "name": {"a": 1}, "role": 7.5},
    "negative-numbers": {"id": -1, "expires_in_days": -99999, "limit": -5},
    "float-where-int": {"id": 1.5, "org_id": 2.7},
    "huge-string": {"email": "a" * 100_000, "name": "b" * 100_000},
    "unicode-and-control": {"email": "🦀\u0000\u001b@x.com", "name": "\u202eevil"},
    "sql-shaped": {"email": "owner@acme-corp.com' OR '1'='1", "name": "'; DROP TABLE users;--"},
    "path-traversal-shaped": {"target": "../../../../etc/passwd", "name": "../../x"},
    "unknown-fields": {"totally_unexpected": True, "__proto__": {"polluted": True}},
}

MALFORMED_RAW = [
    b"",                       # empty body
    b"{",                      # truncated JSON
    b'{"a": }',                # invalid JSON
    b"\x00\x01\x02",           # binary
    b"[]",                     # array where object expected
    b'"string"',               # scalar
    b"email=x&password=y",     # form-encoded with no form declared
]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    base = tmp_path_factory.mktemp("ironclad-malformed")
    db_path = base / "ironclad.db"
    url = f"sqlite:///{db_path}"
    target = base / "scan-target"
    target.mkdir()
    (target / "app.py").write_text("import os\nos.system('id')\n", encoding="utf-8")

    os.environ["IRONCLAD_SIGNING_KEY"] = "malformed-test-signing-key-32-chars!!"
    os.environ["IRONCLAD_SCAN_ROOT"] = str(target)

    app = create_app(url, include_web=True)
    engine = build_engine(url)
    run_migrations(engine)
    with session_scope(engine) as session:
        org, owner = bootstrap_organization(session, name="Malformed Corp", slug="malformed",
                                            admin_email="owner@malformed-corp.com",
                                            password=ADMIN_PASSWORD)
        org_id, owner_id = org.id, owner.id

    client = TestClient(app, follow_redirects=False, raise_server_exceptions=False)
    return {"client": client, "app": app, "engine": engine, "url": url,
            "target": str(target), "org_id": org_id, "owner_id": owner_id}


@pytest.fixture()
def auth(server):
    response = server["client"].post("/auth/login",
                                     json={"email": "owner@malformed-corp.com",
                                           "password": ADMIN_PASSWORD})
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    return {"client": server["client"], "headers": {"Authorization": f"Bearer {token}"}}


# Endpoints that accept a JSON body, exercised both unauthenticated and (where
# they require auth) authenticated. The point is the status class, not which
# specific 4xx each returns.
BODY_ENDPOINTS = [
    ("POST", "/auth/login"),
    ("POST", "/auth/password"),
    ("POST", "/auth/password-reset/request"),
    ("POST", "/auth/password-reset/confirm"),
    ("POST", "/auth/tokens"),
    ("POST", "/users"),
    ("POST", "/projects"),
    ("POST", "/scan"),
    ("POST", "/policies"),
    ("POST", "/policies/validate"),
    ("POST", "/integrations"),
    ("PUT", "/org/egress-policy"),
    ("POST", "/audit/retention/purge"),
    ("PATCH", "/findings/1"),
    ("PATCH", "/users/1/role"),
    ("POST", "/integrations/1/test"),
]


@pytest.mark.parametrize("method,path", BODY_ENDPOINTS)
@pytest.mark.parametrize("label", sorted(MALFORMED_BODIES))
def test_malformed_json_body_never_causes_a_5xx(server, auth, method, path, label):
    response = auth["client"].request(method, path, headers=auth["headers"],
                                      json=MALFORMED_BODIES[label])
    assert response.status_code < 500, (
        f"{method} {path} with {label!r} returned {response.status_code}: "
        f"{response.text[:300]}")


@pytest.mark.parametrize("method,path", BODY_ENDPOINTS)
def test_undecodable_raw_body_never_causes_a_5xx(server, auth, method, path):
    for raw in MALFORMED_RAW:
        response = auth["client"].request(
            method, path, content=raw,
            headers={**auth["headers"], "Content-Type": "application/json"})
        assert response.status_code < 500, (
            f"{method} {path} with raw body {raw!r} returned {response.status_code}: "
            f"{response.text[:300]}")


MALFORMED_PATH_SEGMENTS = ["0", "-1", "abc", "1.5", "99999999999999999999",
                           "1%00", "%2e%2e%2f", " ", "' OR 1=1--"]

PATH_ENDPOINTS = [
    ("GET", "/findings/{seg}"),
    ("GET", "/findings/{seg}/events"),
    ("PATCH", "/findings/{seg}"),
    ("GET", "/scan/{seg}"),
    ("GET", "/scan/{seg}/findings"),
    ("GET", "/scan/{seg}/result"),
    ("POST", "/scan/{seg}/cancel"),
    ("GET", "/projects/{seg}"),
    ("DELETE", "/projects/{seg}"),
    ("PATCH", "/users/{seg}/role"),
    ("DELETE", "/integrations/{seg}"),
    ("DELETE", "/auth/tokens/{seg}"),
]


@pytest.mark.parametrize("method,template", PATH_ENDPOINTS)
@pytest.mark.parametrize("seg", MALFORMED_PATH_SEGMENTS)
def test_malformed_path_segment_never_causes_a_5xx(server, auth, method, template, seg):
    response = auth["client"].request(method, template.format(seg=seg),
                                      headers=auth["headers"], json={"role": "viewer"})
    assert response.status_code < 500, (
        f"{method} {template.format(seg=seg)} returned {response.status_code}: "
        f"{response.text[:300]}")


MALFORMED_QUERIES = [
    "status=not-a-status",
    "severity=999",
    "limit=-1",
    "limit=99999999999999999999",
    "offset=abc",
    "since=not-a-date",
    "until=1970-13-45T99:99:99Z",
    "since=2024-01-01&until=2020-01-01",
    "project_id=abc",
    "q=" + "x" * 10000,
    "sort_by=DROP+TABLE",
    "rule_id=" + "%00" * 10,
]


@pytest.mark.parametrize("path", ["/findings", "/scans", "/audit", "/jobs",
                                  "/audit/export", "/sbom/components"])
@pytest.mark.parametrize("query", MALFORMED_QUERIES)
def test_malformed_query_string_never_causes_a_5xx(server, auth, path, query):
    response = auth["client"].get(f"{path}?{query}", headers=auth["headers"])
    assert response.status_code < 500, (
        f"GET {path}?{query} returned {response.status_code}: {response.text[:300]}")


def test_authentication_header_garbage_never_causes_a_5xx(server):
    for header in ["Bearer ", "Bearer not-a-jwt", "Basic ", "Token x",
                   "Bearer " + "A" * 5000, "\x00\x01", "Bearer \u0000"]:
        response = server["client"].get("/projects", headers={"Authorization": header})
        assert response.status_code < 500, f"{header!r} -> {response.status_code}"


def test_cookie_garbage_never_causes_a_5xx(server):
    for value in ["", "not-a-token", "a" * 5000, "\x00", "%00", "' OR 1=1--"]:
        response = server["client"].get("/ui/", headers={"Cookie": f"ironclad_session={value}"})
        assert response.status_code < 500, f"cookie {value!r} -> {response.status_code}"


def test_error_responses_do_not_leak_tracebacks(server, auth):
    """A 4xx must not carry a stack trace or a raw SQL statement."""
    response = auth["client"].post("/projects", headers=auth["headers"], json={"name": 12345})
    assert response.status_code < 500
    body = response.text.lower()
    for needle in ("traceback (most recent call last)", "sqlalchemy", "sqlite3.",
                   "line \", in \"", "psycopg2"):
        assert needle not in body, f"error response leaks {needle!r}: {response.text[:300]}"


def test_server_is_still_healthy_after_the_abuse(server, auth):
    """Everything above must leave the API usable, not just non-crashing."""
    ready = server["client"].get("/ready")
    assert ready.status_code == 200, ready.text
    projects = auth["client"].get("/projects", headers=auth["headers"])
    assert projects.status_code == 200, projects.text
    created = auth["client"].post("/projects", headers=auth["headers"],
                                  json={"name": f"Still works {uuid.uuid4().hex[:8]}"})
    assert created.status_code == 201, created.text


def test_numeric_overflow_is_mapped_to_a_4xx_not_a_5xx(server):
    """The backstop behind the bounded path parameters.

    ``EntityId`` rejects an oversized identifier with a 422 before it reaches
    the database. This asserts the second line of defence directly: SQLite
    raises ``OverflowError`` and PostgreSQL raises ``DataError`` for a value
    too wide for the column, and both must become a 4xx rather than a 500.
    """
    import asyncio
    from types import SimpleNamespace

    from sqlalchemy import exc as sqlalchemy_exc

    handlers = server["app"].exception_handlers
    assert OverflowError in handlers, "no handler for OverflowError"
    assert sqlalchemy_exc.DataError in handlers, "no handler for DataError"
    assert handlers[OverflowError] is handlers[sqlalchemy_exc.DataError]

    handler = handlers[OverflowError]
    request = SimpleNamespace(url=SimpleNamespace(path="/projects/99999999999999999999"))
    for exc in (OverflowError("Python int too large to convert to SQLite INTEGER"),
                sqlalchemy_exc.DataError("stmt", {}, Exception("out of range"), None)):
        response = asyncio.new_event_loop().run_until_complete(handler(request, exc))
        assert response.status_code == 422, response.status_code
        assert b"internal error" not in response.body


@pytest.mark.parametrize("path", ["/sbom", "/sbom/document", "/sbom/components", "/licenses"])
@pytest.mark.parametrize("value", ["99999999999999999999", "-1", "0", "1.5"])
def test_identifier_query_parameter_is_bounded(server, auth, path, value):
    """The SBOM/license routes take project_id as a query parameter.

    These were briefly annotated with the path variant, which silently made
    the parameter required-but-absent; they use the query variant instead.
    Both are bounded, so an out-of-range identifier is a 422 and never
    reaches the database driver.
    """
    response = auth["client"].get(f"{path}?project_id={value}", headers=auth["headers"])
    assert response.status_code == 422, (
        f"GET {path}?project_id={value} -> {response.status_code}: {response.text[:200]}")


def test_valid_identifier_query_parameter_still_works(server, auth):
    """Guard against the bound rejecting legitimate values."""
    created = auth["client"].post("/projects", headers=auth["headers"],
                                  json={"name": f"SBOM bound {uuid.uuid4().hex[:8]}"})
    assert created.status_code == 201, created.text
    project_id = created.json()["id"]
    response = auth["client"].get(f"/sbom?project_id={project_id}", headers=auth["headers"])
    # A freshly created project has no SBOM yet, so 404 is correct here. The
    # point is that a legitimate identifier is accepted by the bound rather
    # than rejected with a 422.
    assert response.status_code == 404, response.text
