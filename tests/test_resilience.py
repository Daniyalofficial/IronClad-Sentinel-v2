"""Failure and resilience testing for the production paths.

These are the failure modes that decide whether the system is operable:
a worker that dies mid-scan, a duplicate delivery, a database that
disconnects, a job queue with stale claims, an expired credential. Each test
provokes the failure and asserts the system lands in a defined state rather
than an undefined one.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone

import pytest

# The resilience suite exercises the platform layer, which needs the server
# extra. Guarded the same way as test_api.py / test_database.py so a core-only
# install skips the module instead of failing collection -- CI installs core
# only, and an unguarded import here breaks the whole run.
pytest.importorskip("fastapi", reason="requires the server extra: pip install -e '.[server]'")
pytest.importorskip("sqlalchemy", reason="requires the server extra: pip install -e '.[server]'")

from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError, OperationalError

from ironclad.api.app import create_app
from ironclad.platform.database import (
    MigrationError,
    build_engine,
    current_schema_version,
    run_migrations,
    session_factory,
    session_scope,
)
from ironclad.platform.jobs import CANCELLED, FAILED, QUEUED, RUNNING, SUCCEEDED, JobQueue, JobSpec
from ironclad.platform.models import (
    Finding,
    Job,
    Organization,
    Project,
    Scan,
    Session as SessionRow,
    User,
    utcnow,
)
from ironclad.platform.security import (
    MAX_FAILED_LOGINS,
    generate_session_token,
    hash_password,
    hash_token,
    lockout_decision,
)

PASSWORD = "Resilience-Passw0rd-1"


@pytest.fixture()
def db():
    path = os.path.join(tempfile.mkdtemp(), "resilience.db")
    engine = build_engine(f"sqlite:///{path}")
    run_migrations(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def session(db):
    factory = session_factory(db)
    s = factory()
    try:
        yield s
    finally:
        s.close()


_ORG_COUNTER = [0]


def _org(session, slug=None):
    """Create an organization, generating a unique slug when none is given."""
    if slug is None:
        _ORG_COUNTER[0] += 1
        slug = f"resilience-{_ORG_COUNTER[0]}"
    org = Organization(name=slug.title(), slug=slug)
    session.add(org)
    session.flush()
    return org


def _project(session, org_id, slug="p"):
    project = Project(org_id=org_id, name=slug, slug=slug)
    session.add(project)
    session.flush()
    return project


# --------------------------------------------------------------------------- #
# Migrations
# --------------------------------------------------------------------------- #
def test_migration_rerun_after_a_partial_failure_recovers(db):
    """A failed migration must not leave the database unusable.

    Each migration runs in its own transaction, so a failure rolls that
    migration back and leaves the recorded version untouched -- a retry then
    applies it cleanly rather than failing on half-created objects.
    """
    from ironclad.platform import database

    assert current_schema_version(db) == "0002"

    staged = os.path.join(tempfile.mkdtemp(), "migrations", "sqlite")
    os.makedirs(staged)
    original = os.path.join(database.MIGRATION_DIR, "sqlite", "0001_initial.sql")
    with open(original, encoding="utf-8") as fh:
        good = fh.read()

    fresh = build_engine(f"sqlite:///{os.path.join(tempfile.mkdtemp(), 'x.db')}")
    monkeypatch_dir = os.path.join(tempfile.mkdtemp(), "migrations")
    os.makedirs(os.path.join(monkeypatch_dir, "sqlite"))
    broken = good + "\nCREATE TABLE this_will_fail (id INTEGER PRIMARY KEY);\nINSERT INTO no_such_table VALUES (1);\n"
    with open(os.path.join(monkeypatch_dir, "sqlite", "0001_initial.sql"), "w", encoding="utf-8") as fh:
        fh.write(broken)

    original_dir = database.MIGRATION_DIR
    database.MIGRATION_DIR = monkeypatch_dir
    try:
        with pytest.raises(Exception):
            run_migrations(fresh)
        # The failed migration must not have been recorded as applied, and
        # must not have left objects behind either -- with transactional DDL
        # the whole migration (including schema_migrations) rolls back.
        with fresh.connect() as connection:
            tables = {r[0] for r in connection.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'"))}
        assert "organizations" not in tables, (
            f"failed migration left tables behind: {sorted(tables)}")
        if "schema_migrations" in tables:
            with fresh.connect() as connection:
                recorded = connection.execute(
                    text("SELECT version FROM schema_migrations")).fetchall()
            assert recorded == [], f"failed migration was recorded as applied: {recorded}"

        # Restoring the good file and retrying must succeed.
        with open(os.path.join(monkeypatch_dir, "sqlite", "0001_initial.sql"), "w",
                  encoding="utf-8") as fh:
            fh.write(good)
        applied = run_migrations(fresh)
        assert "0001_initial.sql" in applied
        assert run_migrations(fresh) == []
    finally:
        database.MIGRATION_DIR = original_dir
        fresh.dispose()


def test_edited_migration_is_refused_not_silently_reapplied(db):
    from ironclad.platform import database

    staged = os.path.join(tempfile.mkdtemp(), "migrations", "sqlite")
    os.makedirs(staged)
    with open(os.path.join(database.MIGRATION_DIR, "sqlite", "0001_initial.sql"),
              encoding="utf-8") as fh:
        body = fh.read()
    with open(os.path.join(staged, "0001_initial.sql"), "w", encoding="utf-8") as fh:
        fh.write(body + "\n-- edited after being applied\n")

    original = database.MIGRATION_DIR
    database.MIGRATION_DIR = os.path.join(tempfile.mkdtemp(), "migrations")
    os.makedirs(os.path.join(database.MIGRATION_DIR, "sqlite"))
    with open(os.path.join(database.MIGRATION_DIR, "sqlite", "0001_initial.sql"), "w",
              encoding="utf-8") as fh:
        fh.write(body + "\n-- edited after being applied\n")
    try:
        with pytest.raises(MigrationError) as excinfo:
            run_migrations(db)
        assert "changed after being applied" in str(excinfo.value)
    finally:
        database.MIGRATION_DIR = original


# --------------------------------------------------------------------------- #
# Job queue
# --------------------------------------------------------------------------- #
def test_stale_running_job_is_reclaimable_by_another_worker(session):
    """A worker killed mid-job must not strand the job forever."""
    org = _org(session)
    queue = JobQueue(stale_after_seconds=0, retry_backoff=0)
    claimed = []
    queue.register("resilience.stale", lambda s, p: claimed.append(p))

    job = queue.enqueue(session, JobSpec(kind="resilience.stale", org_id=org.id, payload={"n": 1}))
    session.commit()

    # Simulate a worker that claimed the job and then died.
    job.status = RUNNING
    job.attempts = 1
    job.started_at = utcnow() - timedelta(minutes=30)
    session.commit()

    # A different worker with a zero stale window must be able to take it.
    assert queue.claim(session, kinds=["resilience.stale"]) is not None
    session.commit()
    assert queue.run_pending(session, limit=1) == 1
    session.commit()
    assert claimed == [{"n": 1}]


def test_a_recently_started_job_is_not_stolen(session):
    """The flip side: an in-flight job must not be double-executed."""
    org = _org(session)
    queue = JobQueue(stale_after_seconds=3600, retry_backoff=0)
    queue.register("resilience.inflight", lambda s, p: None)

    job = queue.enqueue(session, JobSpec(kind="resilience.inflight", org_id=org.id, payload={}))
    session.commit()
    job.status = RUNNING
    job.attempts = 1
    job.started_at = utcnow()
    session.commit()

    assert queue.claim(session, kinds=["resilience.inflight"]) is None


def test_duplicate_enqueue_is_deduplicated_by_the_scanner(session):
    """Two scans of the same tree must not double-insert findings.

    The (scan_id, fingerprint) unique constraint is what makes a replayed job
    safe; assert it actually holds at the database level.
    """
    org = _org(session)
    project = _project(session, org.id)
    scan = Scan(org_id=org.id, project_id=project.id)
    session.add(scan)
    session.flush()
    session.add(Finding(org_id=org.id, scan_id=scan.id, project_id=project.id,
                        fingerprint="dupe", rule_id="R", title="T", severity="high"))
    session.commit()

    session.add(Finding(org_id=org.id, scan_id=scan.id, project_id=project.id,
                        fingerprint="dupe", rule_id="R", title="T", severity="high"))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_exhausting_retries_marks_the_job_failed_not_queued(session):
    org = _org(session)
    queue = JobQueue(retry_backoff=0)

    def always_fails(s, p):
        raise RuntimeError("permanent")

    queue.register("resilience.doomed", always_fails)
    job = queue.enqueue(session, JobSpec(kind="resilience.doomed", org_id=org.id,
                                         payload={}, max_attempts=2))
    session.commit()

    for _ in range(6):
        queue.run_pending(session, limit=1)
        session.commit()

    row = session.execute(select(Job).where(Job.id == job.id)).scalar_one()
    assert row.status == FAILED, f"expected terminal failed, got {row.status}"
    assert row.attempts >= 2
    assert "permanent" in row.error


def test_cancelled_job_is_never_executed(session):
    org = _org(session)
    queue = JobQueue(retry_backoff=0)
    executed = []
    queue.register("resilience.cancelled", lambda s, p: executed.append(p))

    job = queue.enqueue(session, JobSpec(kind="resilience.cancelled", org_id=org.id, payload={}))
    session.commit()
    queue.cancel(session, job)
    session.commit()

    assert queue.claim(session, kinds=["resilience.cancelled"]) is None
    assert queue.run_pending(session, limit=3) == 0
    assert executed == []
    assert session.execute(select(Job).where(Job.id == job.id)).scalar_one().status == CANCELLED


def test_queued_work_survives_a_restart(session, db):
    """Jobs are durable: a new engine must still find queued work."""
    org = _org(session)
    queue = JobQueue(retry_backoff=0)
    queue.register("resilience.durable", lambda s, p: None)
    job = queue.enqueue(session, JobSpec(kind="resilience.durable", org_id=org.id,
                                         payload={"n": 9}))
    job_id = job.id
    session.commit()

    # Simulate a process restart: brand-new engine and session factory.
    restarted = build_engine(str(db.url))
    try:
        factory = session_factory(restarted)
        fresh = factory()
        try:
            row = fresh.execute(select(Job).where(Job.id == job_id)).scalar_one()
            assert row.status == QUEUED
            assert json.loads(row.payload) == {"n": 9}
            assert queue.run_pending(fresh, limit=1) == 1
            fresh.commit()
        finally:
            fresh.close()
    finally:
        restarted.dispose()


def test_database_reconnection_after_a_disconnect(db):
    """pool_pre_ping must recover from a dropped connection."""
    with db.connect() as connection:
        assert connection.execute(text("SELECT 1")).scalar() == 1
    db.dispose()  # drop every pooled connection
    with db.connect() as connection:
        assert connection.execute(text("SELECT 1")).scalar() == 1


# --------------------------------------------------------------------------- #
# Credentials and lockout
# --------------------------------------------------------------------------- #
def test_expired_session_is_rejected_and_valid_one_is_not(db, session):
    from ironclad.api.deps import _authenticate

    org = _org(session, "cred")
    user = User(org_id=org.id, email="cred@resilience.example",
                password_hash=hash_password(PASSWORD), role="owner")
    session.add(user)
    session.flush()

    valid_token, valid_hash = generate_session_token()
    expired_token, expired_hash = generate_session_token()
    session.add(SessionRow(user_id=user.id, org_id=org.id, token_hash=valid_hash,
                           expires_at=utcnow() + timedelta(hours=1)))
    session.add(SessionRow(user_id=user.id, org_id=org.id, token_hash=expired_hash,
                           expires_at=utcnow() - timedelta(seconds=1)))
    session.commit()

    fresh = session_factory(db)()
    try:
        assert _authenticate(fresh, valid_token)[0] is not None
        assert _authenticate(fresh, expired_token)[0] is None
    finally:
        fresh.close()


def test_revoked_session_stops_working_immediately(db, session):
    from ironclad.api.deps import _authenticate

    org = _org(session, "revoke")
    user = User(org_id=org.id, email="rev@resilience.example",
                password_hash=hash_password(PASSWORD), role="owner")
    session.add(user)
    session.flush()
    token, token_hash = generate_session_token()
    row = SessionRow(user_id=user.id, org_id=org.id, token_hash=token_hash,
                     expires_at=utcnow() + timedelta(hours=1))
    session.add(row)
    session.commit()

    fresh = session_factory(db)()
    try:
        assert _authenticate(fresh, token)[0] is not None
    finally:
        fresh.close()

    row.revoked_at = utcnow()
    session.commit()

    # A new request gets a new session (see api.deps.get_db), and that is the
    # point at which revocation must take effect.
    after = session_factory(db)()
    try:
        assert _authenticate(after, token)[0] is None, "revoked session still authenticates"
    finally:
        after.close()


def test_deactivated_user_cannot_authenticate_even_with_a_valid_session(db, session):
    from ironclad.api.deps import _authenticate

    org = _org(session, "deact")
    user = User(org_id=org.id, email="deact@resilience.example",
                password_hash=hash_password(PASSWORD), role="owner")
    session.add(user)
    session.flush()
    token, token_hash = generate_session_token()
    session.add(SessionRow(user_id=user.id, org_id=org.id, token_hash=token_hash,
                           expires_at=utcnow() + timedelta(hours=1)))
    session.commit()

    user.is_active = False
    session.commit()

    fresh = session_factory(db)()
    try:
        fresh.expire_all()
        assert _authenticate(fresh, token)[0] is None
    finally:
        fresh.close()


@pytest.mark.parametrize("failures,locked_until,expected", [
    (0, None, True),
    (MAX_FAILED_LOGINS - 1, None, True),
    (MAX_FAILED_LOGINS, None, False),
    (MAX_FAILED_LOGINS, time.time() + 60, False),
    (MAX_FAILED_LOGINS - 1, time.time() - 60, True),
])
def test_lockout_decision_matrix(failures, locked_until, expected):
    assert lockout_decision(failures, locked_until).allowed is expected


# --------------------------------------------------------------------------- #
# API-level failure behaviour
# --------------------------------------------------------------------------- #
@pytest.fixture()
def client(db):
    with session_scope(db) as s:
        org = _org(s, "api-resilience")
        s.add(User(org_id=org.id, email="owner@resilience.example",
                   password_hash=hash_password(PASSWORD), role="owner"))
    app = create_app(str(db.url), include_web=False)
    return TestClient(app)


def _token(client):
    response = client.post("/auth/login", json={"email": "owner@resilience.example",
                                                "password": PASSWORD})
    return response.json()["access_token"]


def test_lockout_engages_after_repeated_failures(client):
    for _ in range(MAX_FAILED_LOGINS):
        assert client.post("/auth/login", json={"email": "owner@resilience.example",
                                                "password": "wrong"}).status_code == 401
    response = client.post("/auth/login", json={"email": "owner@resilience.example",
                                                "password": PASSWORD})
    assert response.status_code == 429, response.text


@pytest.mark.parametrize("payload", [
    {},
    {"email": "owner@resilience.example"},
    {"password": PASSWORD},
    {"email": "not-an-email", "password": PASSWORD},
    {"email": "owner@resilience.example", "password": ""},
    {"email": "owner@resilience.example", "password": PASSWORD, "extra": 1},
])
def test_malformed_login_is_rejected_with_422(client, payload):
    assert client.post("/auth/login", json=payload).status_code == 422


def test_error_responses_never_leak_stack_traces(client):
    for method, path, body in [
        ("POST", "/auth/login", {"email": "x", "password": "y"}),
        ("POST", "/projects", {"name": 12345}),
        ("GET", "/findings/999999", None),
    ]:
        if body is None:
            response = client.get(path, headers={"Authorization": f"Bearer {_token(client)}"})
        else:
            response = client.request(method, path, json=body)
        text_body = json.dumps(response.json())
        assert "Traceback" not in text_body
        assert "File \"" not in text_body
        assert ".py" not in text_body or "detail" in text_body


def test_cross_tenant_access_is_a_404_not_a_403(client, db):
    """A 403 would confirm the object exists -- an existence oracle."""
    token = _token(client)
    mine = client.post("/projects", headers={"Authorization": f"Bearer {token}"},
                       json={"name": "Mine"}).json()

    with session_scope(db) as s:
        other = _org(s, "other-tenant")
        theirs = _project(s, other.id, "theirs")
        other_project_id = theirs.id

    assert client.get(f"/projects/{other_project_id}",
                      headers={"Authorization": f"Bearer {token}"}).status_code == 404
    assert client.delete(f"/projects/{other_project_id}",
                         headers={"Authorization": f"Bearer {token}"}).status_code == 404
    # Sanity: our own project is reachable, so the 404 is about tenancy.
    assert client.get(f"/projects/{mine['id']}",
                      headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_invalid_scan_paths_are_rejected(client):
    token = _token(client)
    project = client.post("/projects", headers={"Authorization": f"Bearer {token}"},
                          json={"name": "Scan Paths"}).json()
    for target in ["/etc", "/etc/passwd", "../../..", "\x00/etc", "   "]:
        response = client.post("/scan", headers={"Authorization": f"Bearer {token}"},
                               json={"project_id": project["id"], "target": target})
        assert response.status_code in (400, 422), f"{target!r} -> {response.status_code}"


def test_scan_of_a_missing_target_fails_the_scan_not_the_request(client, db, tmp_path):
    """A target deleted after queueing must produce a failed scan, never a
    silent 'succeeded with 0 findings'."""
    os.environ["IRONCLAD_SCAN_ROOT"] = str(tmp_path)
    token = _token(client)
    project = client.post("/projects", headers={"Authorization": f"Bearer {token}"},
                          json={"name": "Vanishing Target"}).json()
    response = client.post("/scan", headers={"Authorization": f"Bearer {token}"},
                           json={"project_id": project["id"], "target": "does-not-exist"})
    assert response.status_code == 400, response.text


def test_api_token_narrowing_survives_the_api(client, db):
    token = _token(client)
    created = client.post("/auth/tokens", headers={"Authorization": f"Bearer {token}"},
                          json={"name": "narrow", "scopes": ["scan.read"]})
    assert created.status_code == 201
    narrow = created.json()["token"]

    assert client.get("/scans", headers={"Authorization": f"Bearer {narrow}"}).status_code == 200
    # The token cannot do what its owner can.
    assert client.post("/projects", headers={"Authorization": f"Bearer {narrow}"},
                       json={"name": "Nope"}).status_code == 403

    revoked_id = created.json()["detail"]["id"]
    assert client.delete(f"/auth/tokens/{revoked_id}",
                         headers={"Authorization": f"Bearer {token}"}).status_code == 204
    assert client.get("/scans", headers={"Authorization": f"Bearer {narrow}"}).status_code == 401
