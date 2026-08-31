"""Rate limiting tests.

These set tight limits explicitly rather than relying on the production
defaults, so they assert real throttling behaviour. `tests/conftest.py`
raises the limits for the rest of the suite; this module overrides them per
test with monkeypatch, which takes effect because limits are resolved from
the environment on every check.

Covers:
  * the sliding-window store itself (window expiry, retry_after, reset)
  * the pluggable database store, including cross-"process" sharing
  * fail-open behaviour when the store errors
  * the API returning 429 with Retry-After and standard headers
  * per-IP and per-account login limits being independent
  * a successful login clearing the per-account counter
  * X-Forwarded-For only being trusted when explicitly enabled
"""
from __future__ import annotations

import os
import tempfile

import pytest

pytest.importorskip("fastapi", reason="requires the server extra: pip install -e '.[server]'")
pytest.importorskip("sqlalchemy", reason="requires the server extra: pip install -e '.[server]'")

from fastapi.testclient import TestClient
from sqlalchemy import text

from ironclad.api.app import create_app
from ironclad.platform.database import build_engine, run_migrations, session_scope
from ironclad.platform.models import Organization, User
from ironclad.platform.ratelimit import (
    DatabaseStore,
    InMemoryStore,
    RateLimiter,
    client_ip,
    limits,
)
from ironclad.platform.security import hash_password

PASSWORD = "Ratelimit-Passw0rd-1"


# --------------------------------------------------------------------------- #
# The sliding-window store
# --------------------------------------------------------------------------- #
def test_in_memory_store_allows_up_to_the_limit():
    store = InMemoryStore()
    now = 1000.0
    for i in range(5):
        assert store.record_and_count("k", now + i * 0.1, 60) == i + 1


def test_in_memory_store_expires_old_hits():
    store = InMemoryStore()
    assert store.record_and_count("k", 1000.0, 60) == 1
    assert store.record_and_count("k", 1010.0, 60) == 2
    # 61s later the first hit has aged out of the window.
    assert store.record_and_count("k", 1061.0, 60) == 2


def test_in_memory_store_reset_clears_history():
    store = InMemoryStore()
    store.record_and_count("k", 1000.0, 60)
    store.record_and_count("k", 1001.0, 60)
    store.reset("k")
    assert store.record_and_count("k", 1002.0, 60) == 1


def test_retry_after_shrinks_as_the_window_ages():
    limiter = RateLimiter(store=InMemoryStore(), _now=1000.0)
    for _ in range(3):
        decision = limiter.check("k", limit=3, window=60)
    assert decision.allowed
    blocked = limiter.check("k", limit=3, window=60)
    assert not blocked.allowed
    assert 0 < blocked.retry_after <= 61

    # Advance past the window: allowed again.
    limiter._now = 1062.0
    assert limiter.check("k", limit=3, window=60).allowed


def test_limit_zero_disables_the_check():
    limiter = RateLimiter(store=InMemoryStore())
    for _ in range(50):
        assert limiter.check("k", limit=0, window=60).allowed


def test_limiter_is_disabled_globally_when_configured():
    limiter = RateLimiter(store=InMemoryStore(), enabled=False)
    for _ in range(100):
        assert limiter.check("k", limit=1, window=60).allowed


def test_store_failure_fails_open_but_is_counted():
    class BrokenStore:
        def record_and_count(self, key, now, window):
            raise RuntimeError("store unavailable")

        def reset(self, key):
            raise RuntimeError("store unavailable")

        def retry_after(self, key, now, window, limit):
            raise RuntimeError("store unavailable")

    limiter = RateLimiter(store=BrokenStore())
    decision = limiter.check("k", limit=1, window=60)
    assert decision.allowed, "a limiter outage must not take the API down"
    assert limiter.errors == 1
    limiter.reset("k")
    assert limiter.errors == 2


def test_limit_without_an_explicit_window_uses_the_default(monkeypatch):
    from ironclad.platform.ratelimit import DEFAULT_LOGIN_LIMIT, _read_limit

    monkeypatch.setenv("IRONCLAD_RATELIMIT_LOGIN", "7")
    assert _read_limit("login") == (7, DEFAULT_LOGIN_LIMIT[1])


def test_limits_are_resolved_from_the_environment(monkeypatch):
    monkeypatch.setenv("IRONCLAD_RATELIMIT_LOGIN", "3:30")
    monkeypatch.setenv("IRONCLAD_RATELIMIT_GENERAL", "0:60")
    resolved = limits()
    assert resolved["login"] == (3, 30)
    assert resolved["general"] == (0, 60)
    # Untouched keys keep their defaults.
    assert resolved["token_create"][0] > 0


@pytest.mark.parametrize("bad", ["nonsense", "-1:60", "10:0", "abc:def", "10:-5"])
def test_malformed_limit_configuration_is_rejected(monkeypatch, bad):
    from ironclad.platform.ratelimit import _read_limit

    monkeypatch.setenv("IRONCLAD_RATELIMIT_LOGIN", bad)
    with pytest.raises(ValueError):
        _read_limit("login")


# --------------------------------------------------------------------------- #
# The database store
# --------------------------------------------------------------------------- #
def test_database_store_shares_state_between_limiter_instances():
    """Two limiters over one store must see each other's hits -- that is the
    entire point of the database backend in a multi-process deployment."""
    engine = build_engine("sqlite:///" + os.path.join(tempfile.mkdtemp(), "rl.db"))
    run_migrations(engine)
    store = DatabaseStore(engine)

    first = RateLimiter(store=store, _now=1000.0)
    second = RateLimiter(store=store, _now=1000.0)

    assert first.check("shared", limit=2, window=60).allowed
    assert second.check("shared", limit=2, window=60).allowed
    assert not second.check("shared", limit=2, window=60).allowed


def test_database_store_reset_clears():
    engine = build_engine("sqlite:///" + os.path.join(tempfile.mkdtemp(), "rl2.db"))
    run_migrations(engine)
    limiter = RateLimiter(store=DatabaseStore(engine), _now=1000.0)
    assert limiter.check("k", limit=1, window=60).allowed
    assert not limiter.check("k", limit=1, window=60).allowed
    limiter.reset("k")
    assert limiter.check("k", limit=1, window=60).allowed


def test_database_store_expires_old_hits():
    engine = build_engine("sqlite:///" + os.path.join(tempfile.mkdtemp(), "rl3.db"))
    run_migrations(engine)
    limiter = RateLimiter(store=DatabaseStore(engine), _now=1000.0)
    assert limiter.check("k", limit=1, window=60).allowed
    assert not limiter.check("k", limit=1, window=60).allowed
    limiter._now = 1061.0
    assert limiter.check("k", limit=1, window=60).allowed


def test_database_store_creates_its_own_table():
    engine = build_engine("sqlite:///" + os.path.join(tempfile.mkdtemp(), "rl4.db"))
    run_migrations(engine)
    DatabaseStore(engine)
    with engine.connect() as connection:
        tables = {r[0] for r in connection.execute(
            text("SELECT name FROM sqlite_master WHERE type='table'"))}
    assert "rate_limit_hits" in tables


# --------------------------------------------------------------------------- #
# X-Forwarded-For handling
# --------------------------------------------------------------------------- #
class _FakeRequest:
    def __init__(self, headers=None, host="1.2.3.4"):
        self.headers = headers or {}

        class _Client:
            pass

        self.client = _Client()
        self.client.host = host


def test_forwarded_for_is_ignored_by_default(monkeypatch):
    monkeypatch.delenv("IRONCLAD_TRUST_PROXY", raising=False)
    request = _FakeRequest({"x-forwarded-for": "9.9.9.9"})
    assert client_ip(request) == "1.2.3.4"


def test_forwarded_for_is_honoured_when_trusted(monkeypatch):
    monkeypatch.setenv("IRONCLAD_TRUST_PROXY", "1")
    request = _FakeRequest({"x-forwarded-for": "9.9.9.9, 10.0.0.1"})
    # The left-most entry is the original client.
    assert client_ip(request) == "9.9.9.9"


# --------------------------------------------------------------------------- #
# API behaviour
# --------------------------------------------------------------------------- #
@pytest.fixture()
def app_url():
    engine = build_engine("sqlite:///" + os.path.join(tempfile.mkdtemp(), "api.db"))
    run_migrations(engine)
    with session_scope(engine) as s:
        org = Organization(name="RL", slug="rl")
        s.add(org)
        s.flush()
        s.add(User(org_id=org.id, email="owner@rl-corp.com",
                   password_hash=hash_password(PASSWORD), role="owner"))
    return str(engine.url)


def test_login_is_rate_limited_per_ip(monkeypatch, app_url):
    monkeypatch.setenv("IRONCLAD_RATELIMIT_LOGIN", "3:60")
    client = TestClient(create_app(app_url, include_web=False))

    statuses = [
        client.post("/auth/login", json={"email": "owner@rl-corp.com",
                                         "password": "wrong"}).status_code
        for _ in range(5)
    ]
    assert statuses[:3] == [401, 401, 401], statuses
    assert statuses[3] == 429, f"fourth attempt should be throttled: {statuses}"
    assert statuses[4] == 429


def test_throttled_response_carries_retry_after_and_limit_headers(monkeypatch, app_url):
    monkeypatch.setenv("IRONCLAD_RATELIMIT_LOGIN", "1:60")
    client = TestClient(create_app(app_url, include_web=False))

    client.post("/auth/login", json={"email": "owner@rl-corp.com", "password": "wrong"})
    response = client.post("/auth/login", json={"email": "owner@rl-corp.com",
                                                "password": "wrong"})
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) > 0
    assert response.headers["X-RateLimit-Limit"] == "1"
    assert response.headers["X-RateLimit-Remaining"] == "0"
    assert "retry in" in response.json()["detail"]


def test_per_account_limit_is_independent_of_per_ip(monkeypatch, app_url):
    """A per-IP limit must not be the only defence: an attacker should not get
    the full per-IP budget against a single account."""
    monkeypatch.setenv("IRONCLAD_RATELIMIT_LOGIN", "100:60")
    monkeypatch.setenv("IRONCLAD_RATELIMIT_LOGIN_ACCOUNT", "2:300")
    client = TestClient(create_app(app_url, include_web=False))

    statuses = [
        client.post("/auth/login", json={"email": "owner@rl-corp.com",
                                         "password": "wrong"}).status_code
        for _ in range(4)
    ]
    assert statuses[:2] == [401, 401]
    assert statuses[2] == 429, f"account limit should engage: {statuses}"


def test_successful_login_clears_the_account_counter(monkeypatch, app_url):
    monkeypatch.setenv("IRONCLAD_RATELIMIT_LOGIN", "100:60")
    monkeypatch.setenv("IRONCLAD_RATELIMIT_LOGIN_ACCOUNT", "3:300")
    client = TestClient(create_app(app_url, include_web=False))

    # Two failures, then a success, then two more failures must still work.
    for _ in range(2):
        assert client.post("/auth/login", json={"email": "owner@rl-corp.com",
                                                "password": "wrong"}).status_code == 401
    ok = client.post("/auth/login", json={"email": "owner@rl-corp.com", "password": PASSWORD})
    assert ok.status_code == 200

    after = [
        client.post("/auth/login", json={"email": "owner@rl-corp.com",
                                         "password": "wrong"}).status_code
        for _ in range(2)
    ]
    assert after == [401, 401], f"counter should have been reset: {after}"


def test_token_creation_is_rate_limited(monkeypatch, app_url):
    monkeypatch.setenv("IRONCLAD_RATELIMIT_TOKEN_CREATE", "2:300")
    client = TestClient(create_app(app_url, include_web=False))
    token = client.post("/auth/login", json={"email": "owner@rl-corp.com",
                                             "password": PASSWORD}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    codes = [
        client.post("/auth/tokens", headers=headers,
                    json={"name": f"t{i}"}).status_code
        for i in range(4)
    ]
    assert codes[:2] == [201, 201], codes
    assert codes[2] == 429, f"third token should be throttled: {codes}"


def test_password_change_is_rate_limited(monkeypatch, app_url):
    monkeypatch.setenv("IRONCLAD_RATELIMIT_PASSWORD_CHANGE", "2:300")
    client = TestClient(create_app(app_url, include_web=False))
    token = client.post("/auth/login", json={"email": "owner@rl-corp.com",
                                             "password": PASSWORD}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    codes = [
        client.post("/auth/password", headers=headers,
                    json={"current_password": "not-the-password",
                          "new_password": "Another-Strong-Passw0rd"}).status_code
        for _ in range(4)
    ]
    assert codes[2] == 429, f"third attempt should be throttled: {codes}"


def test_disabling_the_limiter_allows_everything(monkeypatch, app_url):
    """With the limiter off, no *rate-limit* 429 is returned.

    Note the distinction this test has to make: the pre-existing per-account
    lockout also answers 429 after MAX_FAILED_LOGINS failures, and that is a
    separate mechanism which disabling rate limiting must not affect. A
    rate-limit 429 is identifiable by its X-RateLimit-Limit header.
    """
    monkeypatch.setenv("IRONCLAD_RATELIMIT_ENABLED", "0")
    monkeypatch.setenv("IRONCLAD_RATELIMIT_LOGIN", "1:60")
    client = TestClient(create_app(app_url, include_web=False))
    responses = [
        client.post("/auth/login", json={"email": "owner@rl-corp.com", "password": "wrong"})
        for _ in range(6)
    ]
    rate_limited = [r for r in responses if "X-RateLimit-Limit" in r.headers]
    assert not rate_limited, [r.headers for r in rate_limited]
    # The account lockout still engages -- that is correct and independent.
    assert any(r.status_code == 429 for r in responses)


def test_database_backend_can_be_selected(monkeypatch, app_url):
    monkeypatch.setenv("IRONCLAD_RATELIMIT_BACKEND", "database")
    monkeypatch.setenv("IRONCLAD_RATELIMIT_LOGIN", "2:60")
    client = TestClient(create_app(app_url, include_web=False))
    codes = [
        client.post("/auth/login", json={"email": "owner@rl-corp.com",
                                         "password": "wrong"}).status_code
        for _ in range(4)
    ]
    assert codes[2] == 429, f"database backend should enforce the limit: {codes}"


def test_unknown_backend_does_not_prevent_startup(monkeypatch, app_url):
    monkeypatch.setenv("IRONCLAD_RATELIMIT_BACKEND", "carrier-pigeon")
    client = TestClient(create_app(app_url, include_web=False))
    assert client.get("/health").status_code == 200
