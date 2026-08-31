"""FastAPI application factory.

Run it with::

    uvicorn ironclad.api.app:create_app --factory --host 0.0.0.0 --port 8000

or ``ironclad serve``.

Middleware responsibilities, in order:

1. **Request id** -- generated per request, put on the response as
   ``X-Request-Id``, and bound into the logging context so every log line
   from that request carries it.
2. **Metrics** -- request counter and latency histogram per route.
3. **CORS** -- explicit allowlist from ``IRONCLAD_CORS_ORIGINS``; an
   unlisted origin gets no CORS headers at all (never a reflected ``*``
   with credentials).
4. **Security headers** -- the dashboard is server-rendered HTML, so it
   ships a restrictive CSP, ``X-Content-Type-Options: nosniff``,
   ``X-Frame-Options: DENY`` and ``Referrer-Policy: no-referrer``.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from sqlalchemy import exc as sqlalchemy_exc
from sqlalchemy import text

from ironclad import __version__
from ironclad.api import routes, schemas
from ironclad.api.deps import cors_allowed_origins
from ironclad.platform.database import build_engine, run_migrations, session_scope, session_factory, session_scope
from ironclad.platform.events import default_bus
from ironclad.platform.jobs import JobQueue
from ironclad.platform.mail import build_transport_from_env
from ironclad.platform.ratelimit import InMemoryStore, RateLimiter, build_limiter, limiter_enabled
from ironclad.platform.observability import (
    API_LATENCY,
    API_REQUESTS,
    QUEUE_DEPTH,
    configure_logging,
    get_logger,
    new_request_id,
    registry,
    request_scope,
)
from ironclad.platform.worker_jobs import register_job_handlers

logger = get_logger("api")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
    ),
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


def create_app(database_url: Optional[str] = None, *, run_migrations_on_start: bool = True,
               include_web: bool = True) -> FastAPI:
    """Build a configured application instance."""
    configure_logging(os.environ.get("IRONCLAD_LOG_LEVEL", "INFO"))

    app = FastAPI(
        title="IronClad Sentinel API",
        version=__version__,
        description="Self-hosted application security platform API. No telemetry, no external calls.",
        # Secure by default: the interactive docs and /openapi.json enumerate
        # the entire API surface, which is useful while developing and useful
        # to an attacker in production. Opt in with IRONCLAD_ENABLE_DOCS=1.
        docs_url="/docs" if os.environ.get("IRONCLAD_ENABLE_DOCS", "0") == "1" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if os.environ.get("IRONCLAD_ENABLE_DOCS", "0") == "1" else None,
    )

    engine = build_engine(database_url)
    if run_migrations_on_start:
        run_migrations(engine)
    app.state.engine = engine
    app.state.session_factory = session_factory(engine)

    queue = JobQueue()
    register_job_handlers(queue, engine)
    app.state.queue = queue

    # Bind the per-organization egress provider so the outbound delivery path
    # enforces the organization policy, not just the process-global allowlist.
    # The provider reads through the shared engine and fails closed.
    from ironclad.platform import egress as egress_policy
    from ironclad.platform.integrations import set_org_allowlist_provider

    def _org_allowlist():
        org_id = egress_policy.current_org_id()
        if org_id is None:
            return None
        from ironclad.platform.models import Organization

        with session_scope(engine) as lookup:
            org = lookup.get(Organization, org_id)
            if org is None:
                return None
            return egress_policy.policy_from_settings(org.id, org.settings).as_allowlist()

    set_org_allowlist_provider(_org_allowlist)
    app.state.org_allowlist_provider = _org_allowlist

    # Mail transport for password resets. Defaults to in-memory so a fresh
    # install never attempts a network connection; set IRONCLAD_MAIL_TRANSPORT
    # to smtp for real delivery.
    app.state.mail = build_transport_from_env()

    # Rate limiting. The store is per-process by default; opt into the shared
    # database backend with IRONCLAD_RATELIMIT_BACKEND=database when running
    # more than one worker or replica.
    try:
        app.state.limiter = build_limiter(engine)
    except ValueError as exc:
        # An unrecognised backend must not stop the API from starting. Fall
        # back to the in-memory store explicitly -- re-calling build_limiter()
        # would just re-read the same bad environment value and raise again.
        app.state.limiter = RateLimiter(store=InMemoryStore(), enabled=limiter_enabled())
        configure_logging(os.environ.get("IRONCLAD_LOG_LEVEL", "INFO"))
        get_logger("api").warning("rate limit backend unavailable, using in-memory",
                                  extra={"fields": {"error": str(exc)}})
    app.state.event_bus = default_bus

    origins = cors_allowed_origins()
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type", "X-Request-Id"],
        )

    @app.middleware("http")
    async def request_context_middleware(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or new_request_id()
        started = time.perf_counter()
        with request_scope(request_id):
            request.state.request_id = request_id
            try:
                response = await call_next(request)
            except Exception:
                registry.inc(API_REQUESTS, 1, "API requests")
                registry.observe(API_LATENCY, time.perf_counter() - started, "API latency")
                logger.exception("unhandled error", extra={"fields": {"path": request.url.path}})
                raise
        registry.inc(API_REQUESTS, 1, "API requests")
        registry.observe(API_LATENCY, time.perf_counter() - started, "API latency")
        response.headers["X-Request-Id"] = request_id
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response

    @app.exception_handler(OverflowError)
    @app.exception_handler(sqlalchemy_exc.DataError)
    async def _numeric_out_of_range(request: Request, exc: Exception):
        """A client-supplied number too wide for the column type.

        Bounded path parameters (``EntityId``) reject the common case with a
        422 before it reaches the database. This is the backstop for any
        integer that still does -- SQLite raises ``OverflowError`` and
        PostgreSQL raises ``DataError`` -- so an attacker cannot turn an
        oversized identifier into a 500.
        """
        logger.warning("numeric value out of range",
                       extra={"fields": {"path": request.url.path}})
        return JSONResponse({"detail": "numeric value out of range"},
                            status_code=422, headers=SECURITY_HEADERS)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):  # pragma: no cover - defensive
        # A stack trace in a response body leaks paths and internals; the
        # detail goes to the structured log, the client gets a bare 500.
        logger.exception("unhandled error", extra={"fields": {"path": request.url.path}})
        return JSONResponse({"detail": "internal error"}, status_code=500, headers=SECURITY_HEADERS)

    # ---- health / version / metrics -------------------------------------
    @app.get("/health", response_model=schemas.HealthOut, tags=["health"])
    def health() -> schemas.HealthOut:
        checks: Dict[str, str] = {}
        try:
            with app.state.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            checks["database"] = f"error: {type(exc).__name__}"
        checks["migrations"] = "ok"
        healthy = all(value == "ok" for value in checks.values())
        return schemas.HealthOut(status="ok" if healthy else "degraded", version=__version__, checks=checks)

    @app.get("/ready", tags=["health"])
    def ready() -> JSONResponse:
        """Readiness: can this replica serve traffic right now?"""
        try:
            with app.state.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception as exc:  # noqa: BLE001
            return JSONResponse({"ready": False, "reason": f"database: {type(exc).__name__}"},
                                status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
        return JSONResponse({"ready": True, "version": __version__})

    @app.get("/version", tags=["health"])
    def version() -> Dict[str, Any]:
        import sys

        return {"product": "IronClad Sentinel", "version": __version__,
                "python": sys.version.split()[0], "api": "v1"}

    @app.get("/metrics", response_class=PlainTextResponse, tags=["health"])
    def metrics() -> str:
        """Prometheus text exposition, including live queue depth."""
        try:
            with session_scope(app.state.engine) as session:
                depth = app.state.queue.depth(session)
            for name, value in depth.items():
                registry.gauge(f"{QUEUE_DEPTH}{{status=\"{name}\"}}", "Queued jobs by status").set(value)
        except Exception as exc:  # noqa: BLE001 - metrics must not 500
            logger.warning("queue depth unavailable", extra={"fields": {"error": str(exc)}})
        return registry.render()

    for router in routes.ALL_ROUTERS:
        app.include_router(router)

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/ui/")

    if include_web:
        from ironclad.web.app import mount_dashboard

        mount_dashboard(app)

    @app.on_event("startup")
    async def _startup() -> None:  # pragma: no cover - trivial
        logger.info("api started", extra={"fields": {"version": __version__,
                                                     "cors_origins": origins}})

    return app
