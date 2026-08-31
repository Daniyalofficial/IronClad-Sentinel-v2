"""Request rate limiting.

Account lockout alone is not brute-force protection: it is *per account*, so
an attacker who wants to guess across an organization gets
``MAX_FAILED_LOGINS`` attempts against **every** address, and nothing limits
how fast they can go. Measured on this codebase before this module existed:
25 credential guesses across 5 accounts in 1.9s (~13/sec) with no 429 ever
returned.

Design
------
Sliding-window log: each hit records a timestamp, and a request is allowed
only if fewer than ``limit`` hits fall inside the trailing ``window``
seconds. This is more accurate than a fixed window (which allows up to 2x
the limit across a boundary) and cheaper to reason about than a token
bucket.

Storage is pluggable behind :class:`RateLimiterStore`:

``InMemoryStore``
    The default. Correct and dependency-free, but **per process**: with
    multiple uvicorn workers or multiple API replicas each process keeps its
    own counters, so the effective limit is ``limit x processes``. That is
    stated in the docs rather than hidden -- it is the honest trade for not
    requiring Redis.

``DatabaseStore``
    Shares state across processes using the existing database. Costs a write
    per checked request, so it is opt-in via ``IRONCLAD_RATELIMIT_BACKEND=database``.

A Redis-backed store can be added by implementing the same three methods;
nothing else in the product needs to change.

Fail-open on error
------------------
If the store raises, the request is **allowed** and the failure is counted.
A rate limiter that takes the API down when its own backend hiccups is worse
than no rate limiter; the error is observable via ``errors`` and the metrics
counter rather than silently swallowed.
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Protocol

ENV_BACKEND = "IRONCLAD_RATELIMIT_BACKEND"
ENV_ENABLED = "IRONCLAD_RATELIMIT_ENABLED"

#: Default limits as (max requests, window seconds). Conservative on the
#: credential endpoints, generous elsewhere so normal CI and dashboard use is
#: never throttled.
#:
#: Every limit is operator-tunable through the environment, because the right
#: value depends on how many humans and CI runners sit behind one IP. Set a
#: limit to 0 to disable that specific check.
DEFAULT_LOGIN_LIMIT = (10, 60)              # per client IP
DEFAULT_LOGIN_PER_ACCOUNT_LIMIT = (5, 300)  # per account
DEFAULT_TOKEN_CREATE_LIMIT = (10, 300)      # per user
DEFAULT_PASSWORD_CHANGE_LIMIT = (5, 300)    # per user
DEFAULT_GENERAL_LIMIT = (600, 60)           # per client IP, other API traffic
DEFAULT_PASSWORD_RESET_REQUEST_LIMIT = (5, 300)   # per client IP
DEFAULT_PASSWORD_RESET_REDEEM_LIMIT = (10, 300)   # per client IP

_LIMIT_ENV = {
    "login": ("IRONCLAD_RATELIMIT_LOGIN", DEFAULT_LOGIN_LIMIT),
    "login_account": ("IRONCLAD_RATELIMIT_LOGIN_ACCOUNT", DEFAULT_LOGIN_PER_ACCOUNT_LIMIT),
    "token_create": ("IRONCLAD_RATELIMIT_TOKEN_CREATE", DEFAULT_TOKEN_CREATE_LIMIT),
    "password_change": ("IRONCLAD_RATELIMIT_PASSWORD_CHANGE", DEFAULT_PASSWORD_CHANGE_LIMIT),
    "general": ("IRONCLAD_RATELIMIT_GENERAL", DEFAULT_GENERAL_LIMIT),
    "password_reset_request": ("IRONCLAD_RATELIMIT_PASSWORD_RESET_REQUEST",
                               DEFAULT_PASSWORD_RESET_REQUEST_LIMIT),
    "password_reset_redeem": ("IRONCLAD_RATELIMIT_PASSWORD_RESET_REDEEM",
                              DEFAULT_PASSWORD_RESET_REDEEM_LIMIT),
}


def _read_limit(name: str) -> tuple:
    env_var, default = _LIMIT_ENV[name]
    raw = os.environ.get(env_var)
    if raw is None or not raw.strip():
        return default
    try:
        limit_str, _, window_str = raw.partition(":")
        limit = int(limit_str)
        window = int(window_str) if window_str else default[1]
    except ValueError:
        raise ValueError(f"{env_var} must look like LIMIT:WINDOW_SECONDS, got {raw!r}")
    if limit < 0 or window <= 0:
        raise ValueError(f"{env_var} must be non-negative limit and positive window, got {raw!r}")
    return (limit, window)


def limits() -> Dict[str, tuple]:
    """Currently configured limits, resolved from the environment."""
    return {name: _read_limit(name) for name in _LIMIT_ENV}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    remaining: int
    retry_after: int
    limit: int

    def headers(self) -> Dict[str, str]:
        headers = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
        }
        if not self.allowed:
            headers["Retry-After"] = str(self.retry_after)
        return headers


class RateLimiterStore(Protocol):
    """Storage interface. Implement these three methods to add a backend."""

    def record_and_count(self, key: str, now: float, window: float) -> int:
        """Record a hit at ``now`` and return hits within ``window`` seconds."""

    def reset(self, key: str) -> None:
        """Drop all recorded hits for ``key`` (e.g. after a successful login)."""

    def retry_after(self, key: str, now: float, window: float, limit: int) -> int:
        """Seconds until the oldest relevant hit leaves the window."""


class InMemoryStore:
    """Thread-safe sliding-window log kept in process memory."""

    def __init__(self) -> None:
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, bucket: Deque[float], now: float, window: float) -> None:
        cutoff = now - window
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

    def record_and_count(self, key: str, now: float, window: float) -> int:
        with self._lock:
            bucket = self._hits[key]
            self._prune(bucket, now, window)
            bucket.append(now)
            return len(bucket)

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def retry_after(self, key: str, now: float, window: float, limit: int) -> int:
        with self._lock:
            bucket = self._hits.get(key)
            if not bucket:
                return 0
            self._prune(bucket, now, window)
            if not bucket:
                return 0
            # The request is allowed again once the oldest of the `limit`
            # most recent hits ages out of the window.
            index = max(0, len(bucket) - limit)
            oldest = bucket[index]
            return max(1, int(oldest + window - now) + 1)

    def size(self) -> int:
        with self._lock:
            return len(self._hits)


class DatabaseStore:
    """Shares counters across processes via the database.

    Uses a single table created on first use so it needs no migration. A
    write per checked request is the cost of cross-process correctness; that
    is why it is opt-in.
    """

    TABLE = "rate_limit_hits"

    def __init__(self, engine) -> None:
        self._engine = engine
        self._lock = threading.Lock()
        self._ensure_table()

    def _ensure_table(self) -> None:
        from sqlalchemy import text

        with self._lock, self._engine.begin() as connection:
            connection.execute(text(
                f"CREATE TABLE IF NOT EXISTS {self.TABLE} ("
                "  key VARCHAR(255) NOT NULL,"
                "  hit_at DOUBLE PRECISION NOT NULL"
                ")"
            ))
            connection.execute(text(
                f"CREATE INDEX IF NOT EXISTS idx_{self.TABLE}_key ON {self.TABLE} (key, hit_at)"
            ))

    def record_and_count(self, key: str, now: float, window: float) -> int:
        from sqlalchemy import text

        cutoff = now - window
        with self._engine.begin() as connection:
            connection.execute(
                text(f"DELETE FROM {self.TABLE} WHERE key = :key AND hit_at <= :cutoff"),
                {"key": key, "cutoff": cutoff},
            )
            connection.execute(
                text(f"INSERT INTO {self.TABLE} (key, hit_at) VALUES (:key, :hit_at)"),
                {"key": key, "hit_at": now},
            )
            count = connection.execute(
                text(f"SELECT COUNT(*) FROM {self.TABLE} WHERE key = :key AND hit_at > :cutoff"),
                {"key": key, "cutoff": cutoff},
            ).scalar_one()
        return int(count)

    def reset(self, key: str) -> None:
        from sqlalchemy import text

        with self._engine.begin() as connection:
            connection.execute(text(f"DELETE FROM {self.TABLE} WHERE key = :key"), {"key": key})

    def retry_after(self, key: str, now: float, window: float, limit: int) -> int:
        from sqlalchemy import text

        cutoff = now - window
        with self._engine.connect() as connection:
            rows = connection.execute(
                text(f"SELECT hit_at FROM {self.TABLE} WHERE key = :key AND hit_at > :cutoff "
                     f"ORDER BY hit_at"),
                {"key": key, "cutoff": cutoff},
            ).fetchall()
        if not rows:
            return 0
        index = max(0, len(rows) - limit)
        return max(1, int(rows[index][0] + window - now) + 1)


@dataclass
class RateLimiter:
    """Applies named limits over a pluggable store."""

    store: RateLimiterStore
    enabled: bool = True
    errors: int = 0
    blocked: int = 0
    _now: Optional[float] = field(default=None, repr=False)

    def _clock(self) -> float:
        return self._now if self._now is not None else time.time()

    def check(self, key: str, limit: int, window: int) -> Decision:
        """Record a hit and decide whether it is allowed."""
        if not self.enabled or limit <= 0:
            return Decision(True, limit, 0, limit)
        now = self._clock()
        try:
            count = self.store.record_and_count(key, now, window)
        except Exception:  # noqa: BLE001 - fail open, but make it observable
            self.errors += 1
            return Decision(True, limit, 0, limit)
        if count <= limit:
            return Decision(True, limit - count, 0, limit)
        self.blocked += 1
        try:
            retry_after = self.store.retry_after(key, now, window, limit)
        except Exception:  # noqa: BLE001
            self.errors += 1
            retry_after = window
        return Decision(False, 0, max(1, retry_after), limit)

    def reset(self, key: str) -> None:
        """Clear a key's history -- used after a successful login."""
        if not self.enabled:
            return
        try:
            self.store.reset(key)
        except Exception:  # noqa: BLE001
            self.errors += 1

    def check_login(self, client_ip: str) -> Decision:
        return self.check(f"login:ip:{client_ip}", *_read_limit("login"))

    def check_login_account(self, account: str) -> Decision:
        return self.check(f"login:acct:{account.lower()}", *_read_limit("login_account"))

    def check_token_create(self, user_id: int) -> Decision:
        return self.check(f"token:user:{user_id}", *_read_limit("token_create"))

    def check_password_change(self, user_id: int) -> Decision:
        return self.check(f"pwchange:user:{user_id}", *_read_limit("password_change"))

    def check_general(self, client_ip: str) -> Decision:
        return self.check(f"api:ip:{client_ip}", *_read_limit("general"))

    def check_password_reset_request(self, client_ip: str) -> Decision:
        return self.check(f"pwreset:req:ip:{client_ip}", *_read_limit("password_reset_request"))

    def check_password_reset_redeem(self, client_ip: str) -> Decision:
        return self.check(f"pwreset:use:ip:{client_ip}", *_read_limit("password_reset_redeem"))

    def reset_login_account(self, account: str) -> None:
        self.reset(f"login:acct:{account.lower()}")

    def stats(self) -> Dict[str, int]:
        return {"blocked": self.blocked, "errors": self.errors}


# Backward-compatible module-level names (resolved at import time).
LOGIN_LIMIT = DEFAULT_LOGIN_LIMIT
LOGIN_PER_ACCOUNT_LIMIT = DEFAULT_LOGIN_PER_ACCOUNT_LIMIT
TOKEN_CREATE_LIMIT = DEFAULT_TOKEN_CREATE_LIMIT
PASSWORD_CHANGE_LIMIT = DEFAULT_PASSWORD_CHANGE_LIMIT
GENERAL_LIMIT = DEFAULT_GENERAL_LIMIT
PASSWORD_RESET_REQUEST_LIMIT = DEFAULT_PASSWORD_RESET_REQUEST_LIMIT
PASSWORD_RESET_REDEEM_LIMIT = DEFAULT_PASSWORD_RESET_REDEEM_LIMIT


def limiter_enabled() -> bool:
    return os.environ.get(ENV_ENABLED, "1").strip().lower() not in {"0", "false", "no", "off"}


def build_store(engine=None) -> RateLimiterStore:
    backend = (os.environ.get(ENV_BACKEND) or "memory").strip().lower()
    if backend == "database":
        if engine is None:
            raise ValueError(f"{ENV_BACKEND}=database requires an engine")
        return DatabaseStore(engine)
    if backend not in {"", "memory", "in-memory"}:
        raise ValueError(f"unknown {ENV_BACKEND}: {backend!r} (expected memory|database)")
    return InMemoryStore()


def build_limiter(engine=None) -> RateLimiter:
    return RateLimiter(store=build_store(engine), enabled=limiter_enabled())


def client_ip(request) -> str:
    """Best-effort client address.

    ``X-Forwarded-For`` is trusted only when ``IRONCLAD_TRUST_PROXY=1``; behind
    an untrusted proxy an attacker could otherwise set the header and get a
    fresh limit per request.
    """
    if os.environ.get("IRONCLAD_TRUST_PROXY", "").strip().lower() in {"1", "true", "yes"}:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            first = forwarded.split(",")[0].strip()
            if first:
                return first
    return request.client.host if request.client else "unknown"
