"""Real API + worker regression cases for scan/job state transitions."""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

pytest.importorskip("fastapi", reason="requires the server extra")
pytest.importorskip("sqlalchemy", reason="requires the server extra")

from fastapi.testclient import TestClient
from sqlalchemy import select

from ironclad.api.app import create_app
from ironclad.platform.database import session_scope
from ironclad.platform.jobs import FAILED, QUEUED, SUCCEEDED, JobQueue
from ironclad.platform.models import Event, Finding, Job, Scan, utcnow
from ironclad.platform.scanning import bootstrap_organization
from ironclad.platform.worker_jobs import register_job_handlers


@pytest.fixture()
def stack(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setenv("IRONCLAD_SCAN_ROOT", str(target))
    monkeypatch.setenv("IRONCLAD_SIGNING_KEY", "test-signing-key-that-is-long-enough-32ch")
    app = create_app(f"sqlite:///{tmp_path / 'platform.db'}", include_web=False)
    with session_scope(app.state.engine) as session:
        bootstrap_organization(session, name="Pipeline", slug="pipeline",
                               admin_email="owner@pipeline.example.com",
                               password="Str0ng!Passw0rd-99")
    client = TestClient(app)
    login = client.post("/auth/login", json={
        "email": "owner@pipeline.example.com", "password": "Str0ng!Passw0rd-99",
    })
    assert login.status_code == 200, login.text
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    project = client.post("/projects", headers=headers, json={"name": "App"})
    assert project.status_code == 201, project.text
    yield app, client, headers, project.json()["id"], target
    app.state.engine.dispose()


def _scan(client, headers, project_id, *, wait):
    return client.post("/scan", headers=headers, json={
        "project_id": project_id, "target": ".", "wait": wait,
    })


def _job_for_scan(session, scan_id):
    matching = [job for job in session.execute(select(Job)).scalars()
                if json.loads(job.payload)["scan_id"] == scan_id]
    assert len(matching) == 1, matching
    return matching[0]


def test_wait_true_completes_job_once_without_a_worker_replay(stack):
    app, client, headers, project_id, _ = stack
    response = _scan(client, headers, project_id, wait=True)
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]
    assert response.json()["status"] == "succeeded"

    with session_scope(app.state.engine) as session:
        job = _job_for_scan(session, scan_id)
        assert job.status == SUCCEEDED, "a worker must not claim the already-executed inline scan"
        assert job.attempts == 1
        assert app.state.queue.run_pending(session, limit=1) == 0
        assert session.get(Scan, scan_id).status == "succeeded"


def test_inline_failure_persists_scan_and_retryable_job(stack, monkeypatch):
    app, client, headers, project_id, _ = stack
    # An operator-supplied bad source still fails; untrusted repo config is
    # intentionally ignored by server scans (tested separately below).
    monkeypatch.setenv("IRONCLAD_ADVISORY_SOURCE", "no-such-source")
    response = _scan(client, headers, project_id, wait=True)
    assert response.status_code == 500, response.text
    assert "no-such-source" not in response.text, "internal scanner details must not leak in HTTP 500"

    with session_scope(app.state.engine) as session:
        scan = session.execute(select(Scan)).scalar_one()
        assert scan.status == "failed", "an HTTP 500 must not strand the scan as queued"
        assert scan.finished_at is not None
        assert "advisory source" in scan.error
        assert session.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all() == []
        failures = session.execute(select(Event).where(
            Event.event_type == "scan.failed", Event.subject_id == str(scan.id))).scalars().all()
        assert len(failures) == 1, "persist exactly one failure event after rollback"
        scan_id = scan.id
        job = _job_for_scan(session, scan_id)
        assert job.status == QUEUED
        assert job.attempts == 1
        assert app.state.queue.run_pending(session, limit=1) == 0  # backoff
        job.scheduled_at = utcnow() - timedelta(seconds=1)

    monkeypatch.delenv("IRONCLAD_ADVISORY_SOURCE")  # operator fixes the source
    with session_scope(app.state.engine) as session:
        assert app.state.queue.run_pending(session, limit=1) == 1
    with session_scope(app.state.engine) as session:
        assert session.get(Scan, scan_id).status == "succeeded"
        job = _job_for_scan(session, scan_id)
        assert job.status == SUCCEEDED and job.attempts == 2


def test_exhausted_worker_failure_is_visible_on_the_scan(stack, monkeypatch):
    app, client, headers, project_id, _ = stack
    monkeypatch.setenv("IRONCLAD_ADVISORY_SOURCE", "no-such-source")
    response = _scan(client, headers, project_id, wait=False)
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]

    with session_scope(app.state.engine) as session:
        _job_for_scan(session, scan_id).max_attempts = 1
    with session_scope(app.state.engine) as session:
        assert app.state.queue.run_pending(session, limit=1) == 1
    with session_scope(app.state.engine) as session:
        job = _job_for_scan(session, scan_id)
        scan = session.get(Scan, scan_id)
        assert job.status == FAILED
        assert scan.status == "failed", "a dead-lettered job must not leave a queued scan"
        assert scan.finished_at is not None
        assert "advisory source" in scan.error
        assert session.execute(select(Finding).where(Finding.scan_id == scan.id)).scalars().all() == []
        failures = session.execute(select(Event).where(
            Event.event_type == "scan.failed", Event.subject_id == str(scan.id))).scalars().all()
        assert len(failures) == 1


def test_worker_retry_can_recover_a_failed_scan(stack, monkeypatch):
    app, client, headers, project_id, _ = stack
    monkeypatch.setenv("IRONCLAD_ADVISORY_SOURCE", "no-such-source")
    response = _scan(client, headers, project_id, wait=False)
    assert response.status_code == 202, response.text
    scan_id = response.json()["id"]

    queue = JobQueue(retry_backoff=0)
    register_job_handlers(queue, app.state.engine)
    with session_scope(app.state.engine) as session:
        assert queue.run_pending(session, limit=1) == 1
    with session_scope(app.state.engine) as session:
        assert _job_for_scan(session, scan_id).status == QUEUED
        assert session.get(Scan, scan_id).status == "failed"

    monkeypatch.delenv("IRONCLAD_ADVISORY_SOURCE")  # operator fixes the source
    with session_scope(app.state.engine) as session:
        assert queue.run_pending(session, limit=1) == 1
    with session_scope(app.state.engine) as session:
        assert _job_for_scan(session, scan_id).status == SUCCEEDED
        assert session.get(Scan, scan_id).status == "succeeded"


def test_crashed_inline_request_leaves_a_reclaimable_worker_job(stack):
    """A killed API process must not strand a scan with no runnable job."""
    from unittest.mock import patch

    app, _, headers, project_id, _ = stack
    crash_client = TestClient(app, raise_server_exceptions=False)
    with patch("ironclad.api.routes._run_scan_inline", side_effect=RuntimeError("simulated death")):
        response = _scan(crash_client, headers, project_id, wait=True)
    assert response.status_code == 500

    with session_scope(app.state.engine) as session:
        scan = session.execute(select(Scan)).scalar_one()
        scan_id = scan.id
        job = _job_for_scan(session, scan_id)
        assert scan.status == "queued"
        assert job.status == "running", "the job must remain reclaimable after an API crash"
        assert job.attempts == 1
        assert app.state.queue.run_pending(session, limit=1) == 0, "a live inline claim blocks workers"
        # Advance the stale clock without waiting 15 minutes in a test.
        job.started_at = utcnow() - timedelta(hours=1)
    with session_scope(app.state.engine) as session:
        assert app.state.queue.run_pending(session, limit=1) == 1
    with session_scope(app.state.engine) as session:
        assert session.get(Scan, scan_id).status == "succeeded"
        job = _job_for_scan(session, scan_id)
        assert job.status == SUCCEEDED and job.attempts == 2


def test_untrusted_repository_config_cannot_disable_server_detection(stack):
    app, client, headers, project_id, target = stack
    (target / "app.py").write_text(
        'api_token = "Zk9pQ2xR7vN4mT8sW1yB6dF3hJ0aL5e"\n', encoding="utf-8")
    (target / ".ironclad.yml").write_text(
        "enabled_engines: []\nmin_severity: critical\nignore_paths: [app.py]\n",
        encoding="utf-8",
    )
    response = _scan(client, headers, project_id, wait=True)
    assert response.status_code == 202, response.text
    assert response.json()["status"] == "succeeded"
    findings = client.get(f"/scan/{response.json()['id']}/findings", headers=headers)
    assert findings.status_code == 200
    assert any(f["rule_id"] == "SECRETS-HIGH-ENTROPY-ASSIGNMENT" for f in findings.json()), (
        "a repository must not suppress the server's scanning engines")


def test_untrusted_repository_config_cannot_force_server_network_egress(stack):
    from unittest.mock import patch

    from ironclad.core.config import IronCladConfig
    from ironclad.core.engine import run_scan

    _, client, headers, project_id, target = stack
    (target / "requirements.txt").write_text("requests==2.30.0\n", encoding="utf-8")
    (target / ".ironclad.yml").write_text(
        "advisory_source: remote\n"
        "advisory_endpoint: https://attacker.example.invalid/lookup\n",
        encoding="utf-8",
    )
    with patch("urllib.request.urlopen", side_effect=OSError("outbound attempt blocked")) as outgoing:
        response = _scan(client, headers, project_id, wait=True)
        assert response.status_code == 202, response.text
        assert response.json()["status"] == "succeeded"
        assert outgoing.call_count == 0, "server must ignore repo-requested outbound requests"

        # A local CLI user may explicitly opt in via a project config. The
        # server-only boundary must not silently disable that capability.
        local = IronCladConfig.load(str(target))
        assert local.advisory_source == "remote"
        run_scan(local)
        assert outgoing.call_count >= 1


def test_failed_scan_with_queued_retry_can_be_cancelled(stack, monkeypatch):
    """A failed attempt is not terminal when its job is queued to retry."""
    app, client, headers, project_id, _ = stack
    monkeypatch.setenv("IRONCLAD_ADVISORY_SOURCE", "no-such-source")
    created = _scan(client, headers, project_id, wait=False)
    assert created.status_code == 202, created.text
    scan_id = created.json()["id"]

    with session_scope(app.state.engine) as session:
        assert app.state.queue.run_pending(session, limit=1) == 1
    with session_scope(app.state.engine) as session:
        scan = session.get(Scan, scan_id)
        job = _job_for_scan(session, scan_id)
        assert scan.status == "failed" and job.status == QUEUED
        assert job.attempts == 1

    cancelled = client.post(f"/scan/{scan_id}/cancel", headers=headers)
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["status"] == "cancelled"
    monkeypatch.delenv("IRONCLAD_ADVISORY_SOURCE")
    with session_scope(app.state.engine) as session:
        scan = session.get(Scan, scan_id)
        job = _job_for_scan(session, scan_id)
        assert scan.status == "cancelled" and job.status == "cancelled"
        assert scan.error, "retain the reason for the failed attempt"
        job.scheduled_at = utcnow() - timedelta(hours=1)
        assert app.state.queue.run_pending(session, limit=1) == 0
        event_types = session.execute(select(Event.event_type).where(
            Event.subject_id == str(scan_id))).scalars().all()
        assert event_types.count("scan.failed") == 1
        assert event_types.count("scan.cancelled") == 1
        assert "scan.completed" not in event_types
        assert session.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all() == []
    again = client.post(f"/scan/{scan_id}/cancel", headers=headers)
    assert again.status_code == 409


def test_terminal_failed_scan_cannot_be_relabeled_cancelled(stack, monkeypatch):
    """When retry attempts are exhausted, a failed scan really is final."""
    app, client, headers, project_id, _ = stack
    monkeypatch.setenv("IRONCLAD_ADVISORY_SOURCE", "no-such-source")
    created = _scan(client, headers, project_id, wait=False)
    assert created.status_code == 202, created.text
    scan_id = created.json()["id"]
    with session_scope(app.state.engine) as session:
        _job_for_scan(session, scan_id).max_attempts = 1
    with session_scope(app.state.engine) as session:
        assert app.state.queue.run_pending(session, limit=1) == 1
    cancelled = client.post(f"/scan/{scan_id}/cancel", headers=headers)
    assert cancelled.status_code == 409, cancelled.text
    with session_scope(app.state.engine) as session:
        assert session.get(Scan, scan_id).status == "failed"
        assert _job_for_scan(session, scan_id).status == FAILED
        events = session.execute(select(Event.event_type).where(
            Event.subject_id == str(scan_id))).scalars().all()
        assert "scan.cancelled" not in events
