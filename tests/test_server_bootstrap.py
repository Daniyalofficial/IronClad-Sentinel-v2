"""A database connection alone must not pass readiness before first setup."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi", reason="requires the server extra")
pytest.importorskip("sqlalchemy", reason="requires the server extra")

from fastapi.testclient import TestClient

from ironclad.api.app import create_app
from ironclad.platform.database import session_scope
from ironclad.platform.scanning import bootstrap_organization


def test_migrated_but_uninitialized_database_is_not_ready(tmp_path):
    app = create_app(f"sqlite:///{tmp_path / 'unexpected.db'}", include_web=False)
    client = TestClient(app)
    health = client.get("/health")
    assert health.status_code == 200  # liveness must remain reachable
    assert health.json()["checks"]["database"] == "ok"
    assert health.json()["checks"]["bootstrap"] == "uninitialized"
    assert health.json()["status"] == "degraded"
    ready = client.get("/ready")
    assert ready.status_code == 503
    assert ready.json()["ready"] is False
    assert "server init" in ready.json()["reason"]

    with session_scope(app.state.engine) as session:
        bootstrap_organization(session, name="Ready", slug="ready",
                               admin_email="owner@ready.example.com",
                               password="Str0ng!Passw0rd-99")
    assert client.get("/health").json()["status"] == "ok"
    assert client.get("/ready").json()["ready"] is True
    app.state.engine.dispose()
