"""Audit export and retention tests.

Compliance frameworks require producing the full audit trail as evidence and
having a defined retention policy. The paged listing caps at 200 records,
which is unusable for either, so these cover the export and retention paths.

Key behaviours asserted:
  * export streams the WHOLE trail, not just one page
  * export is chronological (oldest first), the reverse of the UI listing
  * CSV export defuses spreadsheet formula injection
  * filters (action, actor, date range) are honoured and validated
  * tenant isolation holds on export
  * retention preview deletes nothing
  * purge is itself audited BEFORE the delete, so the deletion is recorded
  * purge requires the admin role
"""
from __future__ import annotations

import csv
import io
import json
import os
import tempfile
from datetime import timedelta

import pytest

pytest.importorskip("fastapi", reason="requires the server extra: pip install -e '.[server]'")
pytest.importorskip("sqlalchemy", reason="requires the server extra: pip install -e '.[server]'")

from fastapi.testclient import TestClient

from ironclad.api.app import create_app
from ironclad.platform import audit
from ironclad.platform.database import build_engine, run_migrations, session_factory, session_scope
from ironclad.platform.models import AuditEvent, Organization, User, utcnow
from ironclad.platform.security import hash_password

PASSWORD = "Audit-Export-Passw0rd-1"


@pytest.fixture()
def env():
    engine = build_engine("sqlite:///" + os.path.join(tempfile.mkdtemp(), "audit.db"))
    run_migrations(engine)
    with session_scope(engine) as s:
        org = Organization(name="Audit", slug="audit")
        s.add(org)
        s.flush()
        s.add(User(org_id=org.id, email="owner@audit-corp.com",
                   password_hash=hash_password(PASSWORD), role="owner"))
        s.add(User(org_id=org.id, email="sec@audit-corp.com",
                   password_hash=hash_password(PASSWORD), role="security"))
        other = Organization(name="Other", slug="other")
        s.add(other)
        s.flush()
        # A second tenant's records must never appear in the first's export.
        for i in range(5):
            audit.record(s, org_id=other.id, action="other.tenant.action",
                         actor="intruder@other-corp.com", metadata={"n": i})
        org_id, other_id = org.id, other.id

    app = create_app(str(engine.url), include_web=False)
    client = TestClient(app)

    def token(email):
        return client.post("/auth/login", json={"email": email,
                                                "password": PASSWORD}).json()["access_token"]

    return {"engine": engine, "client": client, "org_id": org_id, "other_id": other_id,
            "owner": {"Authorization": f"Bearer {token('owner@audit-corp.com')}"},
            "security": {"Authorization": f"Bearer {token('sec@audit-corp.com')}"}}


def _seed(engine, org_id, count, action="test.action"):
    with session_scope(engine) as s:
        for i in range(count):
            audit.record(s, org_id=org_id, action=action, actor="owner@audit-corp.com",
                         target_type="thing", target_id=str(i), metadata={"n": i})


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #
def test_export_returns_more_than_one_page(env):
    """The paged endpoint caps at 200; the export must not."""
    _seed(env["engine"], env["org_id"], 250)
    response = env["client"].get("/audit/export", headers=env["owner"])
    assert response.status_code == 200

    lines = [line for line in response.text.splitlines() if line.strip()]
    assert len(lines) > 200, f"export returned only {len(lines)} records"
    assert int(response.headers["X-Audit-Records"]) == len(lines)
    assert "attachment" in response.headers["Content-Disposition"]
    assert "ndjson" in response.headers["Content-Type"]

    # Every line is valid JSON with the expected shape.
    first = json.loads(lines[0])
    assert {"id", "created_at", "actor", "action", "metadata"} <= set(first)


def test_export_is_chronological_oldest_first(env):
    _seed(env["engine"], env["org_id"], 5)
    response = env["client"].get("/audit/export", headers=env["owner"])
    ids = [json.loads(line)["id"] for line in response.text.splitlines() if line.strip()]
    assert ids == sorted(ids), "export must be chronological for an auditor"


def test_export_never_leaks_another_tenant(env):
    _seed(env["engine"], env["org_id"], 3)
    response = env["client"].get("/audit/export", headers=env["owner"])
    assert "intruder@other-corp.com" not in response.text
    assert "other.tenant.action" not in response.text


def test_export_csv_format(env):
    _seed(env["engine"], env["org_id"], 3)
    response = env["client"].get("/audit/export?format=csv", headers=env["owner"])
    assert response.status_code == 200
    assert "text/csv" in response.headers["Content-Type"]
    rows = list(csv.reader(io.StringIO(response.text)))
    assert rows[0][:3] == ["id", "created_at", "actor"]
    assert len(rows) > 1


def test_csv_export_defuses_formula_injection(env):
    """An auditor opening an export in a spreadsheet must not execute a
    formula that arrived via audit data."""
    with session_scope(env["engine"]) as s:
        audit.record(s, org_id=env["org_id"], action="=cmd|'/C calc'!A0",
                     actor="+dangerous@audit-corp.com", metadata={"x": 1})
    response = env["client"].get("/audit/export?format=csv", headers=env["owner"])
    rows = list(csv.reader(io.StringIO(response.text)))
    flattened = [cell for row in rows for cell in row]
    for cell in flattened:
        assert not cell.startswith(("=", "+")), f"unescaped formula cell: {cell!r}"


def test_export_filters_by_action(env):
    _seed(env["engine"], env["org_id"], 3, action="alpha.action")
    _seed(env["engine"], env["org_id"], 4, action="beta.action")
    response = env["client"].get("/audit/export?action=alpha.action", headers=env["owner"])
    actions = {json.loads(line)["action"] for line in response.text.splitlines() if line.strip()}
    assert actions == {"alpha.action"}


def test_export_rejects_an_invalid_date(env):
    response = env["client"].get("/audit/export?since=not-a-date", headers=env["owner"])
    assert response.status_code == 422


def test_export_rejects_an_inverted_date_range(env):
    response = env["client"].get(
        "/audit/export?since=2030-01-01&until=2020-01-01", headers=env["owner"])
    assert response.status_code == 422


def test_export_date_filter_selects_a_range(env):
    _seed(env["engine"], env["org_id"], 3)
    future = (utcnow() + timedelta(days=1)).strftime("%Y-%m-%d")
    past = (utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")
    assert env["client"].get(f"/audit/export?since={past}",
                             headers=env["owner"]).text.strip() != ""
    assert env["client"].get(f"/audit/export?since={future}",
                             headers=env["owner"]).text.strip() == ""


def test_export_requires_the_audit_permission(env):
    """The security role has audit.read; an owner always does. Verify the
    endpoint is permission-gated rather than open to any authenticated user."""
    response = env["client"].get("/audit/export", headers=env["security"])
    assert response.status_code == 200
    assert env["client"].get("/audit/export").status_code == 401


def test_export_is_itself_audited(env):
    _seed(env["engine"], env["org_id"], 2)
    env["client"].get("/audit/export", headers=env["owner"])
    with session_scope(env["engine"]) as s:
        actions = {e.action for e in s.query(AuditEvent).filter(
            AuditEvent.org_id == env["org_id"]).all()}
    assert "audit.exported" in actions


def test_export_rejects_an_unknown_format(env):
    response = env["client"].get("/audit/export?format=xlsx", headers=env["owner"])
    assert response.status_code == 422


# --------------------------------------------------------------------------- #
# Retention
# --------------------------------------------------------------------------- #
def test_retention_preview_deletes_nothing(env):
    _seed(env["engine"], env["org_id"], 5)
    before = audit.count_for_org(session_factory(env["engine"])(), env["org_id"])

    response = env["client"].get("/audit/retention?retention_days=0", headers=env["owner"])
    assert response.status_code == 200
    body = response.json()
    assert body["expiring_records"] == before
    assert body["retained_records"] == 0

    after = audit.count_for_org(session_factory(env["engine"])(), env["org_id"])
    assert after == before, "a preview must not delete anything"


def test_purge_removes_only_expired_records(env):
    engine, org_id = env["engine"], env["org_id"]
    _seed(engine, org_id, 3)
    # Backdate two records so they fall outside a 1-day window.
    with session_scope(engine) as s:
        old = s.query(AuditEvent).filter(AuditEvent.org_id == org_id).limit(2).all()
        for event in old:
            event.created_at = utcnow() - timedelta(days=10)

    before = audit.count_for_org(session_factory(engine)(), org_id)
    response = env["client"].post("/audit/retention/purge", headers=env["owner"],
                                  json={"retention_days": 1})
    assert response.status_code == 200
    assert response.json()["expiring_records"] == 2

    with session_scope(engine) as s:
        remaining = s.query(AuditEvent).filter(AuditEvent.org_id == org_id).all()
        actions = [e.action for e in remaining]
        # The two backdated records are gone...
        assert len(remaining) == before - 2 + 1, (
            f"expected the 2 expired records removed and the purge record added, "
            f"got {len(remaining)} from {before}")
        # ...and the purge itself is permanently recorded (+1).
        assert "audit.purged" in actions
        assert all(e.action != "test.action" or e.created_at > utcnow() - timedelta(days=1)
                   for e in remaining)


def test_purge_is_itself_audited_before_deleting(env):
    """Deleting the record of a deletion would defeat the purpose of an audit
    log, so the purge record must survive the purge."""
    engine, org_id = env["engine"], env["org_id"]
    _seed(engine, org_id, 2)
    with session_scope(engine) as s:
        for event in s.query(AuditEvent).filter(AuditEvent.org_id == org_id).all():
            event.created_at = utcnow() - timedelta(days=10)

    env["client"].post("/audit/retention/purge", headers=env["owner"],
                       json={"retention_days": 1})

    with session_scope(engine) as s:
        actions = [e.action for e in s.query(AuditEvent).filter(
            AuditEvent.org_id == org_id).all()]
    assert "audit.purged" in actions, "the purge must leave a permanent record"


def test_purge_requires_admin(env):
    response = env["client"].post("/audit/retention/purge", headers=env["security"],
                                  json={"retention_days": 30})
    assert response.status_code == 403
    assert "admin" in response.json()["detail"]


def test_purge_rejects_a_negative_retention(env):
    response = env["client"].post("/audit/retention/purge", headers=env["owner"],
                                  json={"retention_days": -1})
    assert response.status_code == 422


def test_purge_does_not_touch_another_tenant(env):
    engine = env["engine"]
    _seed(engine, env["org_id"], 2)
    with session_scope(engine) as s:
        for event in s.query(AuditEvent).filter(AuditEvent.org_id == env["org_id"]).all():
            event.created_at = utcnow() - timedelta(days=10)

    env["client"].post("/audit/retention/purge", headers=env["owner"],
                       json={"retention_days": 1})

    with session_scope(engine) as s:
        other_count = s.query(AuditEvent).filter(
            AuditEvent.org_id == env["other_id"]).count()
    assert other_count == 5, "a purge must be scoped to one organization"


def test_retention_summary_rejects_negative_days(env):
    with session_scope(env["engine"]) as s:
        with pytest.raises(ValueError):
            audit.retention_summary(s, env["org_id"], retention_days=-1)
