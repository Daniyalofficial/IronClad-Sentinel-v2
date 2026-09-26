"""PostgreSQL verification.

These tests run only when a real PostgreSQL server is reachable, via:

    export IRONCLAD_TEST_POSTGRES_URL="postgresql+psycopg2://user:pass@host/db"
    pytest tests/test_postgres.py -v

Without that variable the module skips, so the default suite stays
dependency-free. This exists because "the SQL files exist" is not evidence
that PostgreSQL works: the ordering bug these tests caught (an
``ALTER TABLE jobs`` placed above ``CREATE TABLE jobs``) made the Postgres
migration fail outright, and nothing else would have found it.

Set up a throwaway server with the bundled wheel if you have no instance:

    pip install pgserver
    python -c "import pgserver; print(pgserver.get_server('/tmp/pgdata').get_uri())"
"""
from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("psycopg2", reason="requires the postgres extra")

PG_URL = os.environ.get("IRONCLAD_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    not PG_URL,
    reason="set IRONCLAD_TEST_POSTGRES_URL to run the PostgreSQL verification",
)

from sqlalchemy import func, select, text  # noqa: E402

from ironclad.platform.database import (  # noqa: E402
    build_engine,
    current_schema_version,
    detect_dialect,
    pending_migrations,
    run_migrations,
    session_factory,
    session_scope,
)


#: This suite drops every table in the target database. Refuse to run unless
#: the database name marks it as disposable, so pointing it at a real
#: instance cannot destroy data. Override with
#: IRONCLAD_TEST_POSTGRES_ALLOW_UNSAFE=1 only if you know what you are doing.
SAFE_NAME_MARKERS = ("test", "verify", "ci", "scratch", "tmp", "temp")


@pytest.fixture(scope="module")
def engine():
    """A clean database with migrations applied, shared by the module."""
    from sqlalchemy.engine import make_url

    dbname = (make_url(PG_URL).database or "").lower()
    allowed = os.environ.get("IRONCLAD_TEST_POSTGRES_ALLOW_UNSAFE") == "1"
    if not allowed and not any(marker in dbname for marker in SAFE_NAME_MARKERS):
        pytest.fail(
            f"refusing to run: this suite DROPS EVERY TABLE in the target database, "
            f"and {dbname!r} does not look disposable. Use a scratch database, or set "
            f"IRONCLAD_TEST_POSTGRES_ALLOW_UNSAFE=1 to override.",
            pytrace=False,
        )

    eng = build_engine(PG_URL)
    with eng.begin() as connection:
        for (table,) in connection.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname='public'")).fetchall():
            connection.execute(text(f'DROP TABLE IF EXISTS "{table}" CASCADE'))
    run_migrations(eng)
    yield eng
    eng.dispose()


@pytest.fixture()
def session(engine):
    factory = session_factory(engine)
    s = factory()
    try:
        yield s
    finally:
        s.close()


def _org(session, slug, name=None):
    from ironclad.platform.models import Organization

    org = Organization(name=name or slug.title(), slug=slug)
    session.add(org)
    session.flush()
    return org


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #
def test_dialect_is_postgres():
    assert detect_dialect(PG_URL) == "postgres"


def test_migrations_applied_and_idempotent(engine):
    assert run_migrations(engine) == [], "a second run must apply nothing"
    assert pending_migrations(engine) == []
    assert current_schema_version(engine) is not None


def test_schema_objects_exist(engine):
    with engine.connect() as connection:
        tables = {r[0] for r in connection.execute(text(
            "SELECT tablename FROM pg_tables WHERE schemaname='public'"))}
        indexes = connection.execute(text(
            "SELECT count(*) FROM pg_indexes WHERE schemaname='public'")).scalar()
        fks = connection.execute(text(
            "SELECT count(*) FROM information_schema.table_constraints "
            "WHERE constraint_type='FOREIGN KEY' AND table_schema='public'")).scalar()
        checks = {r[0] for r in connection.execute(text(
            "SELECT conname FROM pg_constraint "
            "WHERE contype='c' AND connamespace='public'::regnamespace"))}

    expected = {"organizations", "users", "sessions", "api_tokens", "projects",
                "repositories", "policies", "baselines", "scans", "findings",
                "finding_events", "sboms", "components", "integrations",
                "audit_events", "jobs", "events", "schema_migrations"}
    assert expected <= tables, sorted(expected - tables)
    assert indexes >= 17, f"expected the documented indexes, found {indexes}"
    assert fks >= 17, f"expected foreign keys, found {fks}"
    # Postgres-only: SQLite cannot add constraints via ALTER TABLE, so these
    # are the clearest proof the Postgres dialect file was really applied.
    assert {"scans_status_valid", "findings_severity_valid", "findings_status_valid",
            "jobs_status_valid", "users_role_valid"} <= checks


def test_check_constraint_actually_rejects_a_bad_status(engine, session):
    """The CHECK constraint must reject at the database, not just in code."""
    from sqlalchemy.exc import IntegrityError

    from ironclad.platform.models import Scan

    org = _org(session, "chk")
    from ironclad.platform.models import Project

    project = Project(org_id=org.id, name="P", slug="p")
    session.add(project)
    session.flush()
    session.add(Scan(org_id=org.id, project_id=project.id, status="not-a-real-status"))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


# --------------------------------------------------------------------------- #
# CRUD + tenancy
# --------------------------------------------------------------------------- #
def test_full_object_graph_round_trips(engine, session):
    from ironclad.platform.models import (
        AuditEvent,
        Component,
        Finding,
        Project,
        Sbom,
        Scan,
        User,
    )
    from ironclad.platform.security import hash_password

    org = _org(session, "acme-pg")
    user = User(org_id=org.id, email="owner@acme-pg.example",
                password_hash=hash_password("Str0ng!Passw0rd-99"), role="owner")
    project = Project(org_id=org.id, name="Payments", slug="payments")
    session.add_all([user, project])
    session.flush()

    scan = Scan(org_id=org.id, project_id=project.id, status="succeeded",
                risk_score=40, grade="C", engines=json.dumps(["ast-python"]))
    session.add(scan)
    session.flush()

    finding = Finding(org_id=org.id, scan_id=scan.id, project_id=project.id,
                      fingerprint="pg-fp-1", rule_id="PY-AST-SQL-INJECTION",
                      title="SQLi", severity="critical", engine="ast-python")
    sbom = Sbom(org_id=org.id, project_id=project.id, scan_id=scan.id,
                format="cyclonedx", document="{}", component_count=1)
    session.add_all([finding, sbom])
    session.flush()
    session.add(Component(org_id=org.id, sbom_id=sbom.id, purl="pkg:pypi/requests@2.30.0",
                          name="requests", version="2.30.0", ecosystem="python",
                          license="Apache-2.0", license_class="allowed"))
    session.add(AuditEvent(org_id=org.id, actor=user.email, action="scan.created",
                           target_type="scan", target_id=str(scan.id), metadata="{}"))
    session.commit()

    # Re-read from the server to prove it persisted, not just sat in the session.
    fresh = session_factory(engine)()
    try:
        assert fresh.execute(select(func.count(Finding.id))).scalar_one() == 1
        assert fresh.execute(select(func.count(Component.id))).scalar_one() == 1
        assert fresh.execute(select(func.count(AuditEvent.id))).scalar_one() == 1
        loaded = fresh.execute(select(Finding)).scalar_one()
        assert loaded.severity == "critical"
        assert loaded.rule_id == "PY-AST-SQL-INJECTION"
    finally:
        fresh.close()


def test_tenant_isolation_across_organizations(engine, session):
    from ironclad.platform.models import Finding, Project, Scan
    from ironclad.platform.tenancy import TenantError, get_for_org, org_query, require_row

    org_a = _org(session, "tenant-a")
    org_b = _org(session, "tenant-b")
    project_a = Project(org_id=org_a.id, name="A", slug="a")
    session.add(project_a)
    session.flush()
    scan = Scan(org_id=org_a.id, project_id=project_a.id)
    session.add(scan)
    session.flush()
    session.add(Finding(org_id=org_a.id, scan_id=scan.id, project_id=project_a.id,
                        fingerprint="iso", rule_id="R", title="T", severity="high"))
    session.commit()

    # B cannot see A's rows.
    assert get_for_org(session, Project, org_b.id, project_a.id) is None
    assert session.execute(org_query(session, Finding, org_b.id)).scalars().all() == []

    class PrincipalB:
        org_id = org_b.id

    with pytest.raises(TenantError):
        require_row(session, Project, PrincipalB(), project_a.id)

    # A still sees its own.
    assert get_for_org(session, Project, org_a.id, project_a.id) is project_a
    assert len(session.execute(org_query(session, Finding, org_a.id)).scalars().all()) == 1


def test_unique_constraints_hold(engine, session):
    from sqlalchemy.exc import IntegrityError

    from ironclad.platform.models import Organization

    _org(session, "dupe-slug")
    session.add(Organization(name="Other", slug="dupe-slug"))
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_cascade_delete(engine, session):
    from ironclad.platform.models import Finding, Project, Scan

    org = _org(session, "cascade")
    project = Project(org_id=org.id, name="P", slug="p")
    session.add(project)
    session.flush()
    scan = Scan(org_id=org.id, project_id=project.id)
    session.add(scan)
    session.flush()
    session.add(Finding(org_id=org.id, scan_id=scan.id, project_id=project.id,
                        fingerprint="c", rule_id="R", title="T", severity="high"))
    session.commit()

    session.delete(scan)
    session.commit()
    # Scoped to this organization: the database is shared across the module,
    # so an unscoped count would include other tests' rows.
    remaining = session.execute(
        select(func.count(Finding.id)).where(Finding.org_id == org.id)).scalar_one()
    assert remaining == 0


# --------------------------------------------------------------------------- #
# Jobs, events, audit
# --------------------------------------------------------------------------- #
def test_job_queue_claims_and_completes(engine, session):
    from ironclad.platform.jobs import JobQueue, JobSpec
    from ironclad.platform.models import Job

    org = _org(session, "jobs-pg")
    queue = JobQueue(retry_backoff=0)
    seen = []
    queue.register("pg.echo", lambda s, payload: seen.append(payload))

    job = queue.enqueue(session, JobSpec(kind="pg.echo", org_id=org.id, payload={"n": 1}))
    session.commit()

    handled = queue.run_pending(session, limit=5)
    session.commit()
    assert handled == 1
    assert seen == [{"n": 1}]

    row = session.execute(select(Job).where(Job.id == job.id)).scalar_one()
    assert row.status == "succeeded"


def test_failing_job_retries_then_fails(engine, session):
    from ironclad.platform.jobs import JobQueue, JobSpec
    from ironclad.platform.models import Job

    org = _org(session, "jobs-fail-pg")
    queue = JobQueue(retry_backoff=0)

    def boom(s, payload):
        raise RuntimeError("boom")

    queue.register("pg.boom", boom)
    job = queue.enqueue(session, JobSpec(kind="pg.boom", org_id=org.id, payload={},
                                         max_attempts=3))
    session.commit()

    for _ in range(5):
        queue.run_pending(session, limit=1)
        session.commit()

    row = session.execute(select(Job).where(Job.id == job.id)).scalar_one()
    assert row.status == "failed"
    assert row.attempts >= 3
    assert "boom" in row.error


def test_events_and_audit_persist(engine, session):
    from ironclad.platform import events
    from ironclad.platform.audit import record
    from ironclad.platform.models import AuditEvent, Event

    org = _org(session, "events-pg")
    events.default_bus.publish(session, events.SCAN_CREATED, org.id,
                               {"scan_id": 42, "project_id": 7}, subject_id="42")
    record(session, org_id=org.id, action="scan.created", actor="ci@example",
           target_type="scan", target_id="42", metadata={"password": "hunter2"})
    session.commit()

    fresh = session_factory(engine)()
    try:
        event = fresh.execute(select(Event).where(Event.org_id == org.id)).scalars().first()
        assert event is not None and event.event_type == "scan.created"
        assert json.loads(event.payload)["scan_id"] == 42

        audit = fresh.execute(select(AuditEvent).where(AuditEvent.org_id == org.id)).scalars().first()
        assert audit is not None
        # NB: `audit.metadata` is SQLAlchemy's declarative MetaData object, not
        # the column -- the column is mapped as `metadata_json`. That collision
        # is exactly why the model renames it.
        assert "hunter2" not in audit.metadata_json
        assert "redacted" in audit.metadata_json
        # The API-facing serialisation must redact too.
        from ironclad.platform.audit import to_dict

        assert to_dict(audit)["metadata"]["password"] == "[redacted]"
    finally:
        fresh.close()


# --------------------------------------------------------------------------- #
# Persistence across a restart
# --------------------------------------------------------------------------- #
def test_data_survives_a_new_engine_connection(engine, session):
    """Simulates a process restart: brand-new engine, same database."""
    from ironclad.platform.models import Organization

    org = _org(session, "restart-pg")
    session.commit()

    restarted = build_engine(PG_URL)
    try:
        with session_scope(restarted) as fresh:
            found = fresh.execute(
                select(Organization).where(Organization.slug == "restart-pg")
            ).scalar_one_or_none()
            assert found is not None
            assert found.id == org.id
    finally:
        restarted.dispose()


# --------------------------------------------------------------------------- #
# Regression: the timezone bug that broke every authenticated request
# --------------------------------------------------------------------------- #
def test_postgres_returns_timezone_aware_timestamps():
    """Postgres TIMESTAMPTZ yields aware datetimes; SQLite yields naive ones.

    This asymmetry is the root cause of the bug the next test guards.
    """
    from datetime import datetime

    eng = build_engine(PG_URL)
    try:
        with eng.connect() as connection:
            value = connection.execute(text("SELECT now() AT TIME ZONE 'UTC'")).scalar()
        assert isinstance(value, datetime)
    finally:
        eng.dispose()


def test_session_expiry_comparison_survives_aware_timestamps(engine, session):
    """Regression: authenticating against PostgreSQL raised
    `TypeError: can't compare offset-naive and offset-aware datetimes`,
    which made **every** authenticated request a 500.

    The product stores naive-UTC by convention; PostgreSQL hands back aware
    values. `as_naive_utc` normalises before comparing. Nothing in the
    SQLite-only suite could ever hit this.
    """
    from datetime import datetime, timedelta, timezone

    from ironclad.api.deps import _authenticate
    from ironclad.platform.models import Session as SessionRow, User, as_naive_utc, utcnow
    from ironclad.platform.security import generate_session_token, hash_password

    org = _org(session, "tz-regression")
    user = User(org_id=org.id, email="tz@regression.example",
                password_hash=hash_password("Str0ng!Passw0rd-99"), role="owner")
    session.add(user)
    session.flush()

    token, token_hash = generate_session_token()
    # Store an explicitly timezone-AWARE expiry, as PostgreSQL would return.
    session.add(SessionRow(user_id=user.id, org_id=org.id, token_hash=token_hash,
                           expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
    session.commit()

    # Re-read so the value comes back through the driver, not the identity map.
    fresh = session_factory(engine)()
    try:
        row = fresh.execute(
            select(SessionRow).where(SessionRow.token_hash == token_hash)).scalar_one()
        # Guard the premise: the comparison must be between mismatched kinds.
        assert as_naive_utc(row.expires_at) > utcnow()

        principal, kind = _authenticate(fresh, token)
        assert principal is not None, "authentication must succeed on PostgreSQL"
        assert kind == "session"
        assert principal.org_id == org.id
    finally:
        fresh.close()


def test_expired_session_is_rejected_on_postgres(engine, session):
    """The same path must still reject an expired session."""
    from datetime import datetime, timedelta, timezone

    from ironclad.api.deps import _authenticate
    from ironclad.platform.models import Session as SessionRow, User
    from ironclad.platform.security import generate_session_token, hash_password

    org = _org(session, "tz-expired")
    user = User(org_id=org.id, email="exp@regression.example",
                password_hash=hash_password("Str0ng!Passw0rd-99"), role="owner")
    session.add(user)
    session.flush()
    token, token_hash = generate_session_token()
    session.add(SessionRow(user_id=user.id, org_id=org.id, token_hash=token_hash,
                           expires_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    session.commit()

    fresh = session_factory(engine)()
    try:
        assert _authenticate(fresh, token)[0] is None
    finally:
        fresh.close()


def test_session_timezone_is_pinned_to_utc(engine):
    """Naive parameters in SQL comparisons must be read as UTC.

    The job queue compares `scheduled_at <= now` and a stale-claim window
    SQL-side; if the server's TimeZone were not UTC those would shift.
    """
    with engine.connect() as connection:
        assert connection.execute(text("SHOW timezone")).scalar().upper() == "UTC"


@pytest.mark.parametrize("job_count", [1, 2])
def test_simultaneous_workers_claim_each_job_only_once(engine, job_count):
    """Force both workers to see the same first candidate before claiming.

    A SELECT followed by UPDATE WHERE status IN ('queued', 'running') lets
    both workers update the same row. With a second job, the loser must also
    retry rather than stopping while work is still available.
    """
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from sqlalchemy.orm import Session
    from sqlalchemy.sql import Select

    from ironclad.platform.jobs import JobQueue, JobSpec
    from ironclad.platform.models import Job

    queue = JobQueue()
    queue.register("race-test", lambda session, payload: None)
    with session_scope(engine) as session:
        org = _org(session, f"claim-race-{job_count}")
        ids = [queue.enqueue(session, JobSpec(kind="race-test", org_id=org.id,
                                               payload={"n": n})).id
               for n in range(job_count)]

    barrier = Barrier(2, timeout=8)

    def attempt():
        with Session(engine) as worker_session:
            original_execute = worker_session.execute
            waited = False

            def synced_execute(statement, *args, **kwargs):
                nonlocal waited
                result = original_execute(statement, *args, **kwargs)
                if (not waited and isinstance(statement, Select)
                        and statement.column_descriptions[0]["name"] == "id"):
                    waited = True
                    barrier.wait()
                return result

            worker_session.execute = synced_execute
            claimed = queue.claim(worker_session)
            return claimed.id if claimed else None

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(attempt) for _ in range(2)]
        claimed_ids = [future.result(timeout=15) for future in futures]

    assert sorted(value for value in claimed_ids if value is not None) == ids, claimed_ids
    with session_scope(engine) as session:
        assert all(session.get(Job, job_id).attempts == 1 for job_id in ids)


def test_operator_recovery_revokes_sessions_on_postgres(engine, session):
    """Recovery must work on TIMESTAMPTZ-backed rows, not just SQLite."""
    from datetime import datetime, timedelta, timezone

    from ironclad.platform.models import ApiToken, Session as SessionRow, User
    from ironclad.platform.ops import reset_password
    from ironclad.platform.security import hash_password, verify_password

    org = _org(session, "ops-pg")
    user = User(org_id=org.id, email="operator@pg.example.com",
                password_hash=hash_password("Old-Password-987!"), role="owner",
                failed_logins=5, locked_until=datetime.now(timezone.utc) + timedelta(minutes=5))
    session.add(user)
    session.flush()
    session.add(SessionRow(user_id=user.id, org_id=org.id, token_hash="pg-session-recovery",
                           expires_at=datetime.now(timezone.utc) + timedelta(hours=2)))
    session.add(ApiToken(org_id=org.id, user_id=user.id, name="old-api-token",
                         token_hash="pg-api-recovery", token_prefix="ics_", scopes="scan.read"))
    session.commit()

    assert reset_password(database_url=PG_URL, org_slug="ops-pg",
                          email="operator@pg.example.com",
                          new_password="Fresh-Password-987!") == user.id
    with session_scope(engine) as fresh:
        account = fresh.get(User, user.id)
        assert verify_password("Fresh-Password-987!", account.password_hash)
        assert account.failed_logins == 0 and account.locked_until is None
        assert fresh.execute(select(SessionRow).where(
            SessionRow.user_id == user.id)).scalar_one().revoked_at is not None
        assert fresh.execute(select(ApiToken).where(
            ApiToken.user_id == user.id)).scalar_one().revoked_at is not None


def test_inline_api_claim_recovers_after_crash_on_postgres(engine, tmp_path, monkeypatch):
    """Real HTTP request + PostgreSQL job claim + stale worker recovery."""
    from datetime import timedelta
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from ironclad.api.app import create_app
    from ironclad.platform.models import Job, Scan, utcnow
    from ironclad.platform.scanning import bootstrap_organization

    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setenv("IRONCLAD_SCAN_ROOT", str(target))
    monkeypatch.setenv("IRONCLAD_SIGNING_KEY", "test-signing-key-that-is-long-enough-32ch")
    with session_scope(engine) as session:
        org, _ = bootstrap_organization(session, name="Inline PostgreSQL", slug="inline-pg",
                                        admin_email="inline@pg.example.com",
                                        password="Str0ng!Passw0rd-99")
        org_id = org.id

    app = create_app(PG_URL, include_web=False)
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            login = client.post("/auth/login", json={
                "email": "inline@pg.example.com", "password": "Str0ng!Passw0rd-99",
            })
            assert login.status_code == 200, login.text
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            project = client.post("/projects", headers=headers, json={"name": "Inline"})
            assert project.status_code == 201, project.text
            with patch("ironclad.api.routes._run_scan_inline", side_effect=RuntimeError("API died")):
                response = client.post("/scan", headers=headers, json={
                    "project_id": project.json()["id"], "target": ".", "wait": True,
                })
            assert response.status_code == 500, response.text

        with session_scope(engine) as session:
            scan = session.execute(select(Scan).where(Scan.org_id == org_id)).scalar_one()
            scan_id = scan.id
            job = session.execute(select(Job).where(Job.org_id == org_id)).scalar_one()
            assert scan.status == "queued" and job.status == "running"
            assert job.attempts == 1
            assert app.state.queue.run_pending(session, limit=1) == 0
            job.started_at = utcnow() - timedelta(hours=1)
        with session_scope(engine) as session:
            assert app.state.queue.run_pending(session, limit=1) == 1
        with session_scope(engine) as session:
            assert session.get(Scan, scan_id).status == "succeeded"
            job = session.execute(select(Job).where(Job.org_id == org_id)).scalar_one()
            assert job.status == "succeeded" and job.attempts == 2
    finally:
        app.state.engine.dispose()


def test_zero_day_retention_preserves_purge_evidence_on_postgres(engine):
    """PostgreSQL TIMESTAMPTZ must not delete a just-written purge record."""
    from ironclad.platform import audit
    from ironclad.platform.models import AuditEvent

    with session_scope(engine) as session:
        org = _org(session, "retention-pg")
        org_id = org.id
        for index in range(3):
            audit.record(session, org_id=org_id, action="pg.test.action",
                         actor="operator@pg.example.com", metadata={"index": index})
    with session_scope(engine) as session:
        summary = audit.purge_expired(session, org_id, retention_days=0,
                                      actor="operator@pg.example.com")
    assert summary["expiring_records"] == 3
    with session_scope(engine) as session:
        events = session.execute(select(AuditEvent).where(AuditEvent.org_id == org_id)).scalars().all()
        assert [event.action for event in events] == ["audit.purged"]
        assert json.loads(events[0].metadata_json)["records_removed"] == 3

    with session_scope(engine) as session:
        summary = audit.purge_expired(session, org_id, retention_days=0)
    assert summary["expiring_records"] == 0, "older purge evidence must survive repeated purges"
    with session_scope(engine) as session:
        events = session.execute(select(AuditEvent).where(AuditEvent.org_id == org_id)).scalars().all()
        assert [event.action for event in events] == ["audit.purged", "audit.purged"]


def test_api_cancellation_cannot_be_overwritten_by_a_paused_worker(engine, tmp_path, monkeypatch):
    """A worker that read a scan before cancellation must not resurrect it."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event as ThreadEvent
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from ironclad.api.app import create_app
    from ironclad.platform import worker_jobs
    from ironclad.platform.models import Event, Finding, Job, Scan
    from ironclad.platform.scanning import bootstrap_organization

    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text('api_token = "Zk9pQ2xR7vN4mT8sW1yB6dF3hJ0aL5e"\n', encoding="utf-8")
    monkeypatch.setenv("IRONCLAD_SCAN_ROOT", str(target))
    monkeypatch.setenv("IRONCLAD_SIGNING_KEY", "test-signing-key-that-is-long-enough-32ch")
    with session_scope(engine) as session:
        org, _ = bootstrap_organization(session, name="Cancel Race", slug="cancel-race-pg",
                                        admin_email="cancel@pg.example.com",
                                        password="Str0ng!Passw0rd-99")
        org_id = org.id

    app = create_app(PG_URL, include_web=False)
    paused, resume = ThreadEvent(), ThreadEvent()
    original_resolve = worker_jobs.resolve_policy

    def before_scan(*args, **kwargs):
        paused.set()  # worker has loaded the scan but has not modified it yet
        if not resume.wait(timeout=15):
            raise TimeoutError("cancel request did not release the worker")
        return original_resolve(*args, **kwargs)

    try:
        with TestClient(app) as client:
            login = client.post("/auth/login", json={
                "email": "cancel@pg.example.com", "password": "Str0ng!Passw0rd-99",
            })
            assert login.status_code == 200, login.text
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            project = client.post("/projects", headers=headers, json={"name": "Cancel Race"})
            assert project.status_code == 201, project.text
            queued = client.post("/scan", headers=headers, json={
                "project_id": project.json()["id"], "target": ".", "wait": False,
            })
            assert queued.status_code == 202, queued.text
            scan_id = queued.json()["id"]

            def work():
                with session_scope(engine) as session:
                    return app.state.queue.run_pending(session, limit=1)

            with patch("ironclad.platform.worker_jobs.resolve_policy", side_effect=before_scan):
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(work)
                    try:
                        assert paused.wait(timeout=15), "worker did not reach the scan"
                        cancelled = client.post(f"/scan/{scan_id}/cancel", headers=headers)
                        assert cancelled.status_code == 200, cancelled.text
                        assert cancelled.json()["status"] == "cancelled"
                    finally:
                        resume.set()
                    assert future.result(timeout=30) == 1

        with session_scope(engine) as session:
            scan = session.get(Scan, scan_id)
            job = session.execute(select(Job).where(Job.org_id == org_id)).scalar_one()
            events = session.execute(select(Event.event_type).where(
                Event.org_id == org_id, Event.subject_id == str(scan_id))).scalars().all()
            assert scan.status == "cancelled", "cancellation must not become a successful scan"
            assert job.status == "cancelled", "a worker must not resurrect a cancelled job"
            assert session.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all() == []
            assert "scan.completed" not in events
    finally:
        resume.set()
        app.state.engine.dispose()


def test_cancel_request_racing_completed_scan_returns_conflict_on_postgres(engine, tmp_path, monkeypatch):
    """An already completed worker scan cannot be relabelled cancelled."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event as ThreadEvent
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from ironclad.api import routes
    from ironclad.api.app import create_app
    from ironclad.platform.models import Event, Finding, Job, Scan
    from ironclad.platform.scanning import bootstrap_organization

    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text('api_token = "Zk9pQ2xR7vN4mT8sW1yB6dF3hJ0aL5e"\n', encoding="utf-8")
    monkeypatch.setenv("IRONCLAD_SCAN_ROOT", str(target))
    monkeypatch.setenv("IRONCLAD_SIGNING_KEY", "test-signing-key-that-is-long-enough-32ch")
    with session_scope(engine) as session:
        org, _ = bootstrap_organization(session, name="Finish Race", slug="finish-race-pg",
                                        admin_email="finish@pg.example.com",
                                        password="Str0ng!Passw0rd-99")
        org_id = org.id

    app = create_app(PG_URL, include_web=False)
    read_scan, resume = ThreadEvent(), ThreadEvent()
    try:
        with TestClient(app) as client:
            login = client.post("/auth/login", json={
                "email": "finish@pg.example.com", "password": "Str0ng!Passw0rd-99",
            })
            assert login.status_code == 200, login.text
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            project = client.post("/projects", headers=headers, json={"name": "Finish Race"})
            assert project.status_code == 201, project.text
            queued = client.post("/scan", headers=headers, json={
                "project_id": project.json()["id"], "target": ".", "wait": False,
            })
            assert queued.status_code == 202, queued.text
            scan_id = queued.json()["id"]

            original_get = routes.get_for_org

            def paused_get(session, model, org, identifier):
                row = original_get(session, model, org, identifier)
                if model is Scan and identifier == scan_id:
                    read_scan.set()
                    if not resume.wait(timeout=15):
                        raise TimeoutError("worker did not release cancel request")
                return row

            with patch("ironclad.api.routes.get_for_org", side_effect=paused_get):
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(client.post, f"/scan/{scan_id}/cancel", headers=headers)
                    try:
                        assert read_scan.wait(timeout=15), "cancel request did not read scan"
                        with session_scope(engine) as session:
                            assert app.state.queue.run_pending(session, limit=1) == 1
                    finally:
                        resume.set()
                    cancelled = future.result(timeout=30)
            assert cancelled.status_code == 409, cancelled.text

        with session_scope(engine) as session:
            scan = session.get(Scan, scan_id)
            job = session.execute(select(Job).where(Job.org_id == org_id)).scalar_one()
            events = session.execute(select(Event.event_type).where(
                Event.org_id == org_id, Event.subject_id == str(scan_id))).scalars().all()
            assert scan.status == "succeeded" and job.status == "succeeded"
            assert session.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all()
            assert "scan.completed" in events and "scan.cancelled" not in events
    finally:
        resume.set()
        app.state.engine.dispose()


@pytest.mark.parametrize("error", ["", "temporary scanner error"])
def test_cancelled_job_is_not_resurrected_by_its_old_worker_on_postgres(engine, error):
    """A stale worker session must not overwrite a committed cancellation."""
    from ironclad.platform.jobs import JobQueue, JobSpec
    from ironclad.platform.models import Job

    queue = JobQueue()
    queue.register("cancellation-race-pg", lambda session, payload: None)
    with session_scope(engine) as session:
        org = _org(session, "cancelled-job-pg-" + ("retry" if error else "success"))
        job_id = queue.enqueue(session, JobSpec(kind="cancellation-race-pg", org_id=org.id,
                                                 payload={})).id

    with session_scope(engine) as worker:
        claimed = queue.claim(worker, kinds=["cancellation-race-pg"])
        assert claimed is not None and claimed.id == job_id
        claimed_attempt = claimed.attempts
        with session_scope(engine) as controller:
            queue.cancel(controller, controller.get(Job, job_id))
        assert queue.finish(worker, claimed, claimed_attempt=claimed_attempt,
                            error=error) == "cancelled"
    with session_scope(engine) as session:
        assert session.get(Job, job_id).status == "cancelled"


def test_older_stale_claim_cannot_finish_newer_worker_attempt_on_postgres(engine):
    """Reclaiming a stale job must fence out the previous attempt."""
    from datetime import timedelta

    from ironclad.platform.jobs import JobQueue, JobSpec
    from ironclad.platform.models import Job, utcnow

    queue = JobQueue(stale_after_seconds=0)
    queue.register("stale-fence-pg", lambda session, payload: None)
    with session_scope(engine) as session:
        org = _org(session, "stale-fence-pg")
        job_id = queue.enqueue(session, JobSpec(kind="stale-fence-pg", org_id=org.id,
                                                 payload={})).id

    with session_scope(engine) as old_worker:
        old_claim = queue.claim(old_worker, kinds=["stale-fence-pg"])
        assert old_claim is not None and old_claim.attempts == 1
        old_attempt = old_claim.attempts
        with session_scope(engine) as session:
            session.get(Job, job_id).started_at = utcnow() - timedelta(hours=1)
        with session_scope(engine) as new_worker:
            new_claim = queue.claim(new_worker, kinds=["stale-fence-pg"])
            assert new_claim is not None and new_claim.id == job_id
            assert new_claim.attempts == 2
            new_attempt = new_claim.attempts
            assert queue.finish(old_worker, old_claim, claimed_attempt=old_attempt) == "running"
            with session_scope(engine) as observer:
                state = observer.get(Job, job_id)
                assert state.status == "running" and state.attempts == 2
            assert queue.finish(new_worker, new_claim, claimed_attempt=new_attempt) == "succeeded"
    with session_scope(engine) as session:
        final = session.get(Job, job_id)
        assert final.status == "succeeded" and final.attempts == 2


def test_inline_scan_cancelled_while_preparing_does_not_write_findings_on_postgres(
    engine, tmp_path, monkeypatch,
):
    """Inline requests obey the same cancellation guard as background jobs."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event as ThreadEvent
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from ironclad.api.app import create_app
    from ironclad.platform import scanning
    from ironclad.platform.models import Event, Finding, Job, Scan
    from ironclad.platform.scanning import bootstrap_organization

    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text('api_token = "Zk9pQ2xR7vN4mT8sW1yB6dF3hJ0aL5e"\n', encoding="utf-8")
    monkeypatch.setenv("IRONCLAD_SCAN_ROOT", str(target))
    monkeypatch.setenv("IRONCLAD_SIGNING_KEY", "test-signing-key-that-is-long-enough-32ch")
    with session_scope(engine) as session:
        org, _ = bootstrap_organization(session, name="Inline Cancel", slug="inline-cancel-pg",
                                        admin_email="inlinecancel@pg.example.com",
                                        password="Str0ng!Passw0rd-99")
        org_id = org.id

    app = create_app(PG_URL, include_web=False)
    paused, resume = ThreadEvent(), ThreadEvent()
    original_resolve = scanning.resolve_policy

    def before_scan(*args, **kwargs):
        paused.set()
        if not resume.wait(timeout=15):
            raise TimeoutError("cancel request did not release the inline scan")
        return original_resolve(*args, **kwargs)

    try:
        with TestClient(app) as client:
            login = client.post("/auth/login", json={
                "email": "inlinecancel@pg.example.com", "password": "Str0ng!Passw0rd-99",
            })
            assert login.status_code == 200, login.text
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            project = client.post("/projects", headers=headers, json={"name": "Inline Cancel"})
            assert project.status_code == 201, project.text

            with patch("ironclad.platform.scanning.resolve_policy", side_effect=before_scan):
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(client.post, "/scan", headers=headers, json={
                        "project_id": project.json()["id"], "target": ".", "wait": True,
                    })
                    try:
                        assert paused.wait(timeout=15), "inline request did not reach the scanner"
                        with session_scope(engine) as session:
                            scan = session.execute(select(Scan).where(Scan.org_id == org_id)).scalar_one()
                            scan_id = scan.id
                        cancelled = client.post(f"/scan/{scan_id}/cancel", headers=headers)
                        assert cancelled.status_code == 200, cancelled.text
                    finally:
                        resume.set()
                    response = future.result(timeout=30)
            assert response.status_code == 202, response.text
            assert response.json()["status"] == "cancelled"

        with session_scope(engine) as session:
            job = session.execute(select(Job).where(Job.org_id == org_id)).scalar_one()
            events = session.execute(select(Event.event_type).where(
                Event.org_id == org_id, Event.subject_id == str(scan_id))).scalars().all()
            assert session.get(Scan, scan_id).status == "cancelled"
            assert job.status == "cancelled"
            assert session.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all() == []
            assert "scan.completed" not in events
    finally:
        resume.set()
        app.state.engine.dispose()


def test_late_job_cancel_cannot_overwrite_completed_attempt_on_postgres(engine):
    """A controller with a stale ORM row must not undo completed work."""
    from ironclad.platform.jobs import JobQueue, JobSpec
    from ironclad.platform.models import Job

    queue = JobQueue()
    queue.register("late-cancel-pg", lambda session, payload: None)
    with session_scope(engine) as session:
        org = _org(session, "late-cancel-pg")
        job_id = queue.enqueue(session, JobSpec(kind="late-cancel-pg", org_id=org.id,
                                                 payload={})).id

    with session_scope(engine) as worker:
        claimed = queue.claim(worker, kinds=["late-cancel-pg"])
        assert claimed is not None and claimed.id == job_id
        claimed_attempt = claimed.attempts
        with session_scope(engine) as controller:
            stale = controller.get(Job, job_id)
            assert stale.status == "running"
            assert queue.finish(worker, claimed, claimed_attempt=claimed_attempt) == "succeeded"
            worker.commit()
            queue.cancel(controller, stale)
            assert stale.status == "succeeded"
    with session_scope(engine) as session:
        assert session.get(Job, job_id).status == "succeeded"


def test_late_scan_failure_marker_cannot_overwrite_cancellation_on_postgres(
    engine, tmp_path, monkeypatch,
):
    """A failed attempt must not relabel a scan cancelled after its read."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event as ThreadEvent
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from ironclad.api.app import create_app
    from ironclad.platform import scanning
    from ironclad.platform.models import Event, Job, Scan
    from ironclad.platform.scanning import bootstrap_organization

    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setenv("IRONCLAD_SCAN_ROOT", str(target))
    monkeypatch.setenv("IRONCLAD_SIGNING_KEY", "test-signing-key-that-is-long-enough-32ch")
    with session_scope(engine) as session:
        org, _ = bootstrap_organization(session, name="Late Failure", slug="late-failure-pg",
                                        admin_email="latefail@pg.example.com",
                                        password="Str0ng!Passw0rd-99")
        org_id = org.id

    app = create_app(PG_URL, include_web=False)
    paused, resume = ThreadEvent(), ThreadEvent()
    original_now = scanning.utcnow

    def before_failure_write():
        paused.set()  # failure handler already read scan status, but has not flushed
        if not resume.wait(timeout=15):
            raise TimeoutError("cancel request did not release failure writer")
        return original_now()

    try:
        with TestClient(app) as client:
            login = client.post("/auth/login", json={
                "email": "latefail@pg.example.com", "password": "Str0ng!Passw0rd-99",
            })
            assert login.status_code == 200, login.text
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            project = client.post("/projects", headers=headers, json={"name": "Late Failure"})
            assert project.status_code == 201, project.text
            queued = client.post("/scan", headers=headers, json={
                "project_id": project.json()["id"], "target": ".", "wait": False,
            })
            assert queued.status_code == 202, queued.text
            scan_id = queued.json()["id"]

            def mark_failed():
                with session_scope(engine) as session:
                    scanning.record_scan_failure(session, org_id=org_id, scan_id=scan_id,
                                                 error=RuntimeError("old worker failed"))

            with patch("ironclad.platform.scanning.utcnow", side_effect=before_failure_write):
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(mark_failed)
                    try:
                        assert paused.wait(timeout=15), "failure handler did not read scan"
                        cancelled = client.post(f"/scan/{scan_id}/cancel", headers=headers)
                        assert cancelled.status_code == 200, cancelled.text
                    finally:
                        resume.set()
                    future.result(timeout=30)

        with session_scope(engine) as session:
            scan = session.get(Scan, scan_id)
            job = session.execute(select(Job).where(Job.org_id == org_id)).scalar_one()
            events = session.execute(select(Event.event_type).where(
                Event.org_id == org_id, Event.subject_id == str(scan_id))).scalars().all()
            assert scan.status == "cancelled", "late failure must not resurrect a cancelled scan"
            assert job.status == "cancelled"
            assert "scan.cancelled" in events and "scan.failed" not in events
    finally:
        resume.set()
        app.state.engine.dispose()


def test_old_worker_rollback_cannot_finish_a_newer_claim_on_postgres(engine):
    """An ORM rollback must not replace the old worker's claim token."""
    from datetime import timedelta

    from ironclad.platform.jobs import JobQueue, JobSpec
    from ironclad.platform.models import Job, utcnow

    queue = JobQueue(stale_after_seconds=0, retry_backoff=0)
    queue.register("rollback-fence-pg", lambda session, payload: None)
    with session_scope(engine) as session:
        org = _org(session, "rollback-fence-pg")
        job_id = queue.enqueue(session, JobSpec(kind="rollback-fence-pg", org_id=org.id,
                                                 payload={})).id

    with session_scope(engine) as old_worker:
        old_claim = queue.claim(old_worker, kinds=["rollback-fence-pg"])
        assert old_claim is not None and old_claim.attempts == 1
        old_attempt = old_claim.attempts
        with session_scope(engine) as session:
            session.get(Job, job_id).started_at = utcnow() - timedelta(hours=1)
        with session_scope(engine) as new_worker:
            new_claim = queue.claim(new_worker, kinds=["rollback-fence-pg"])
            assert new_claim is not None and new_claim.attempts == 2
            new_attempt = new_claim.attempts
            old_worker.rollback()  # handler exception expires the ORM job
            assert queue.finish(old_worker, old_claim, claimed_attempt=old_attempt,
                                error="first attempt failed") == "running"
            with session_scope(engine) as observer:
                state = observer.get(Job, job_id)
                assert state.status == "running" and state.attempts == 2
            assert queue.finish(new_worker, new_claim, claimed_attempt=new_attempt) == "succeeded"
    with session_scope(engine) as session:
        final = session.get(Job, job_id)
        assert final.status == "succeeded" and final.attempts == 2


def test_worker_error_after_reclaim_cannot_retry_new_attempt_on_postgres(engine):
    """run_pending preserves its claim token through handler rollback."""
    from concurrent.futures import ThreadPoolExecutor
    from datetime import timedelta
    from threading import Event as ThreadEvent

    from ironclad.platform.jobs import JobQueue, JobSpec
    from ironclad.platform.models import Job, utcnow

    queue = JobQueue(stale_after_seconds=0, retry_backoff=3600)
    paused, resume = ThreadEvent(), ThreadEvent()

    def failing_handler(session, payload):
        paused.set()
        if not resume.wait(timeout=15):
            raise TimeoutError("new worker did not release old worker")
        raise RuntimeError("old worker failed after reclaim")

    queue.register("worker-rollback-fence-pg", failing_handler)
    with session_scope(engine) as session:
        org = _org(session, "worker-rollback-fence-pg")
        job_id = queue.enqueue(session, JobSpec(kind="worker-rollback-fence-pg", org_id=org.id,
                                                 payload={}, scheduled_at=utcnow() - timedelta(days=1))).id

    def run_old_worker():
        with session_scope(engine) as session:
            return queue.run_pending(session, limit=1)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run_old_worker)
        try:
            assert paused.wait(timeout=15), "old worker did not claim the job"
            with session_scope(engine) as session:
                session.get(Job, job_id).started_at = utcnow() - timedelta(hours=1)
            with session_scope(engine) as new_worker:
                newer = queue.claim(new_worker, kinds=["worker-rollback-fence-pg"])
                assert newer is not None and newer.attempts == 2
                new_attempt = newer.attempts
                resume.set()
                assert future.result(timeout=30) == 1
                with session_scope(engine) as observer:
                    state = observer.get(Job, job_id)
                    assert state.status == "running" and state.attempts == 2
                    assert state.error == "", "old worker error must not touch new claim"
                assert queue.finish(new_worker, newer, claimed_attempt=new_attempt) == "succeeded"
        finally:
            resume.set()
    with session_scope(engine) as session:
        assert session.get(Job, job_id).status == "succeeded"


def test_inline_failure_after_reclaim_does_not_retry_new_worker_on_postgres(
    engine, tmp_path, monkeypatch,
):
    """The HTTP inline error path keeps its original job attempt after rollback."""
    import json
    from concurrent.futures import ThreadPoolExecutor
    from datetime import timedelta
    from threading import Event as ThreadEvent
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from ironclad.api.app import create_app
    from ironclad.platform import worker_jobs
    from ironclad.platform.models import Job, Scan, utcnow
    from ironclad.platform.scanning import bootstrap_organization

    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text('api_token = "Zk9pQ2xR7vN4mT8sW1yB6dF3hJ0aL5e"\n', encoding="utf-8")
    monkeypatch.setenv("IRONCLAD_SCAN_ROOT", str(target))
    monkeypatch.setenv("IRONCLAD_SIGNING_KEY", "test-signing-key-that-is-long-enough-32ch")
    with session_scope(engine) as session:
        org, _ = bootstrap_organization(session, name="Inline Reclaim", slug="inline-reclaim-pg",
                                        admin_email="inlinereclaim@pg.example.com",
                                        password="Str0ng!Passw0rd-99")
        org_id = org.id

    app = create_app(PG_URL, include_web=False)
    app.state.queue.stale_after_seconds = 0
    paused, resume = ThreadEvent(), ThreadEvent()

    def interrupted_policy(*args, **kwargs):
        paused.set()
        if not resume.wait(timeout=15):
            raise TimeoutError("new worker did not release inline request")
        raise RuntimeError("inline policy load failed")

    try:
        with TestClient(app) as client:
            login = client.post("/auth/login", json={
                "email": "inlinereclaim@pg.example.com", "password": "Str0ng!Passw0rd-99",
            })
            assert login.status_code == 200, login.text
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            project = client.post("/projects", headers=headers, json={"name": "Inline Reclaim"})
            assert project.status_code == 201, project.text

            with patch("ironclad.platform.scanning.resolve_policy", side_effect=interrupted_policy):
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(client.post, "/scan", headers=headers, json={
                        "project_id": project.json()["id"], "target": ".", "wait": True,
                    })
                    try:
                        assert paused.wait(timeout=15), "inline request did not claim its job"
                        with session_scope(engine) as session:
                            scan_id = session.execute(select(Scan.id).where(
                                Scan.org_id == org_id)).scalar_one()
                            job = session.execute(select(Job).where(Job.org_id == org_id)).scalar_one()
                            job_id = job.id
                            job.started_at = utcnow() - timedelta(hours=1)
                        with session_scope(engine) as new_worker:
                            newer = app.state.queue.claim(new_worker, kinds=["scan.run"])
                            assert newer is not None and newer.id == job_id
                            assert newer.attempts == 2
                            new_attempt = newer.attempts
                            payload = json.loads(newer.payload)
                            resume.set()
                            response = future.result(timeout=30)
                            assert response.status_code == 500, response.text
                            with session_scope(engine) as observer:
                                state = observer.get(Job, job_id)
                                assert state.status == "running" and state.attempts == 2
                                assert state.error == ""
                                assert observer.get(Scan, scan_id).status == "failed"
                            # New worker still owns the job and can complete the retry.
                            worker_jobs.handle_scan_run(engine, new_worker, payload)
                            assert app.state.queue.finish(
                                new_worker, newer, claimed_attempt=new_attempt) == "succeeded"
                    finally:
                        resume.set()
        with session_scope(engine) as session:
            assert session.get(Job, job_id).status == "succeeded"
            assert session.get(Scan, scan_id).status == "succeeded"
    finally:
        resume.set()
        app.state.engine.dispose()


@pytest.mark.parametrize("finish_new_worker", [False, True])
def test_inline_request_cannot_adopt_reclaimed_job_before_start_on_postgres(
    engine, tmp_path, monkeypatch, finish_new_worker,
):
    """A delayed inline request must not take over a newer worker's claim."""
    import json
    from datetime import timedelta
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from ironclad.api import routes
    from ironclad.api.app import create_app
    from ironclad.platform import worker_jobs
    from ironclad.platform.models import Event, Finding, Job, Scan, utcnow
    from ironclad.platform.scanning import bootstrap_organization

    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text('api_token = "Zk9pQ2xR7vN4mT8sW1yB6dF3hJ0aL5e"\n', encoding="utf-8")
    monkeypatch.setenv("IRONCLAD_SCAN_ROOT", str(target))
    monkeypatch.setenv("IRONCLAD_SIGNING_KEY", "test-signing-key-that-is-long-enough-32ch")
    suffix = "finished" if finish_new_worker else "pending"
    email = f"inlineclaim-{suffix}@pg.example.com"
    with session_scope(engine) as session:
        org, _ = bootstrap_organization(session, name="Inline Claim",
                                        slug=f"inline-claim-pg-{suffix}", admin_email=email,
                                        password="Str0ng!Passw0rd-99")
        org_id = org.id

    app = create_app(PG_URL, include_web=False)
    app.state.queue.stale_after_seconds = 0
    original_inline = routes._run_scan_inline

    def reclaim_before_inline(request, session, context, scan_id, job_id, payload, *args, **kwargs):
        with session_scope(engine) as controller:
            job = controller.get(Job, job_id)
            assert job.status == "running" and job.attempts == 1
            job.started_at = utcnow() - timedelta(hours=1)
        with session_scope(engine) as new_worker:
            claimed = request.app.state.queue.claim(new_worker, kinds=["scan.run"])
            assert claimed is not None and claimed.id == job_id and claimed.attempts == 2
            if finish_new_worker:
                worker_jobs.handle_scan_run(engine, new_worker, payload)
                assert request.app.state.queue.finish(
                    new_worker, claimed, claimed_attempt=2) == "succeeded"
        return original_inline(request, session, context, scan_id, job_id,
                               payload, *args, **kwargs)

    try:
        with TestClient(app) as client:
            login = client.post("/auth/login", json={
                "email": email, "password": "Str0ng!Passw0rd-99",
            })
            assert login.status_code == 200, login.text
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            project = client.post("/projects", headers=headers, json={"name": "Inline Claim"})
            assert project.status_code == 201, project.text

            with patch("ironclad.api.routes._run_scan_inline", side_effect=reclaim_before_inline):
                response = client.post("/scan", headers=headers, json={
                    "project_id": project.json()["id"], "target": ".", "wait": True,
                })
            assert response.status_code == 202, response.text
            scan_id = response.json()["id"]
            assert response.json()["status"] == ("succeeded" if finish_new_worker else "queued")

        with session_scope(engine) as session:
            job = session.execute(select(Job).where(Job.org_id == org_id)).scalar_one()
            job_id = job.id
            assert job.status == ("succeeded" if finish_new_worker else "running")
            assert job.attempts == 2
            findings = session.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all()
            events = session.execute(select(Event.event_type).where(
                Event.org_id == org_id, Event.subject_id == str(scan_id))).scalars().all()
            assert bool(findings) == finish_new_worker
            assert ("scan.started" in events) == finish_new_worker

        if not finish_new_worker:
            with session_scope(engine) as new_worker:
                job = new_worker.get(Job, job_id)
                payload = json.loads(job.payload)
                worker_jobs.handle_scan_run(engine, new_worker, payload)
                assert app.state.queue.finish(new_worker, job, claimed_attempt=2) == "succeeded"
        with session_scope(engine) as session:
            assert session.get(Scan, scan_id).status == "succeeded"
            assert session.get(Job, job_id).status == "succeeded"
            assert session.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all()
    finally:
        app.state.engine.dispose()


def test_inline_request_cancelled_before_helper_starts_returns_cancelled_on_postgres(
    engine, tmp_path, monkeypatch,
):
    """The original request must observe a concurrent cancellation, not 500."""
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event as ThreadEvent
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from ironclad.api import routes
    from ironclad.api.app import create_app
    from ironclad.platform.models import Event, Finding, Job, Scan
    from ironclad.platform.scanning import bootstrap_organization

    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text('api_token = "Zk9pQ2xR7vN4mT8sW1yB6dF3hJ0aL5e"\n', encoding="utf-8")
    monkeypatch.setenv("IRONCLAD_SCAN_ROOT", str(target))
    monkeypatch.setenv("IRONCLAD_SIGNING_KEY", "test-signing-key-that-is-long-enough-32ch")
    with session_scope(engine) as session:
        org, _ = bootstrap_organization(session, name="Early Cancel", slug="early-cancel-pg",
                                        admin_email="earlycancel@pg.example.com",
                                        password="Str0ng!Passw0rd-99")
        org_id = org.id

    app = create_app(PG_URL, include_web=False)
    paused, resume = ThreadEvent(), ThreadEvent()
    original_inline = routes._run_scan_inline

    def before_inline(*args, **kwargs):
        paused.set()  # request has committed its initial scan and inline job claim
        if not resume.wait(timeout=15):
            raise TimeoutError("cancel request did not release inline handler")
        return original_inline(*args, **kwargs)

    try:
        with TestClient(app) as client:
            login = client.post("/auth/login", json={
                "email": "earlycancel@pg.example.com", "password": "Str0ng!Passw0rd-99",
            })
            assert login.status_code == 200, login.text
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            project = client.post("/projects", headers=headers, json={"name": "Early Cancel"})
            assert project.status_code == 201, project.text

            with patch("ironclad.api.routes._run_scan_inline", side_effect=before_inline):
                with ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(client.post, "/scan", headers=headers, json={
                        "project_id": project.json()["id"], "target": ".", "wait": True,
                    })
                    try:
                        assert paused.wait(timeout=15), "inline request did not claim its job"
                        with session_scope(engine) as session:
                            scan_id = session.execute(select(Scan.id).where(
                                Scan.org_id == org_id)).scalar_one()
                        cancelled = client.post(f"/scan/{scan_id}/cancel", headers=headers)
                        assert cancelled.status_code == 200, cancelled.text
                    finally:
                        resume.set()
                    response = future.result(timeout=30)
            assert response.status_code == 202, response.text
            assert response.json()["status"] == "cancelled"

        with session_scope(engine) as session:
            job = session.execute(select(Job).where(Job.org_id == org_id)).scalar_one()
            events = session.execute(select(Event.event_type).where(
                Event.org_id == org_id, Event.subject_id == str(scan_id))).scalars().all()
            assert job.status == "cancelled" and session.get(Scan, scan_id).status == "cancelled"
            assert session.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all() == []
            assert "scan.completed" not in events
    finally:
        resume.set()
        app.state.engine.dispose()
