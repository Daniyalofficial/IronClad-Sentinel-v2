"""Persistent storage layer.

Design rules this module enforces:

* **Schema lives in migrations, never in application code.** Tables are
  created by numbered SQL files under ``ironclad/platform/migrations/<dialect>/``
  and applied by :func:`run_migrations`. ``Base.metadata.create_all()`` is
  deliberately not used anywhere in the product.
* **Two dialects, explicit DDL.** SQLite for development and single-node
  installs, PostgreSQL for production. Each has its own migration folder so
  neither dialect is served by "portable" SQL that quietly drops
  constraints or index types.
* **Every migration is checksummed.** A file that changed after it was
  applied raises instead of silently diverging between environments.
* **Sessions are scoped by the caller**, never global, so tests can run
  against a temporary database without leaking state.
"""
from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import make_url
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

MIGRATION_DIR = os.path.join(os.path.dirname(__file__), "migrations")

SQLITE_URL_ENV = "IRONCLAD_DATABASE_URL"
DEFAULT_SQLITE_URL = "sqlite:///./.ironclad/ironclad.db"

# SQLite needs these to be usable as a concurrent-read store behind a worker.
SQLITE_CONNECT_ARGS = {"timeout": 30, "check_same_thread": False}


@dataclass(frozen=True)
class MigrationRecord:
    version: str
    filename: str
    checksum: str


class MigrationError(RuntimeError):
    """Raised when migrations cannot be applied safely."""


def detect_dialect(url: str) -> str:
    """Map a SQLAlchemy URL onto one of the supported dialects.

    Parsed with SQLAlchemy's own URL parser rather than a string prefix, so
    every driver spelling works: ``postgresql://``, ``postgres://`` and
    ``postgresql+psycopg2://`` are all PostgreSQL. A prefix check would
    reject the driver-qualified form, which is exactly what a production
    deployment is told to use.
    """
    try:
        # get_backend_name() -- not get_driver_name(): the latter resolves to
        # the DBAPI ("pysqlite", "psycopg2"), the former to the database
        # ("sqlite", "postgresql"), which is what selects a migration folder.
        backend = make_url(url).get_backend_name()
    except Exception as exc:  # noqa: BLE001 - surfaced as a config error
        raise MigrationError(f"unparseable database URL: {exc}") from exc
    if backend in {"postgresql", "postgres"}:
        return "postgres"
    if backend == "sqlite":
        return "sqlite"
    raise MigrationError(f"unsupported database backend: {backend!r}")


def database_url(override: Optional[str] = None) -> str:
    """Resolve the database URL: explicit > env > default (local SQLite).

    For a file-backed SQLite URL the parent directory is created first, so a
    fresh checkout does not fail with "unable to open database file".
    """
    url = override or os.environ.get(SQLITE_URL_ENV) or DEFAULT_SQLITE_URL
    if detect_dialect(url) == "sqlite":
        # Three slashes = relative path, four = absolute. Taking everything
        # after "sqlite:///" preserves that distinction; stripping the
        # leading slash would silently turn an absolute path into a relative
        # one and create the directory in the wrong place.
        database = make_url(url).database
        if database and database != ":memory:":
            directory = os.path.dirname(os.path.abspath(database))
            if directory:
                os.makedirs(directory, exist_ok=True)
    return url


def build_engine(url: Optional[str] = None, **kwargs) -> Engine:
    resolved = database_url(url)
    if resolved.startswith("sqlite"):
        kwargs.setdefault("connect_args", SQLITE_CONNECT_ARGS)
        engine = create_engine(resolved, future=True, **kwargs)
        with engine.begin() as connection:
            # WAL lets the API read while a worker writes; foreign keys are
            # what make tenant-scoped deletes safe.
            connection.execute(text("PRAGMA journal_mode=WAL"))
            connection.execute(text("PRAGMA foreign_keys=ON"))
        return engine
    kwargs.setdefault("pool_pre_ping", True)
    engine = create_engine(resolved, future=True, **kwargs)

    @event.listens_for(engine, "connect")
    def _force_utc(dbapi_connection, _record):  # noqa: ANN001 - driver-supplied types
        """Pin the session timezone to UTC.

        The product stores naive-UTC timestamps by convention (SQLite cannot
        carry an offset). PostgreSQL resolves a naive parameter against the
        *session* TimeZone, so a server configured for anything other than
        UTC would silently shift every timestamp comparison -- the job
        queue's stale-claim window and its `scheduled_at <= now` claim query
        are both SQL-side comparisons. Pinning UTC makes the convention hold
        regardless of how the server was configured.
        """
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("SET TIME ZONE 'UTC'")
        finally:
            cursor.close()

    return engine


def session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope(engine: Engine) -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on any exception."""
    session = session_factory(engine)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# --------------------------------------------------------------------------- #
# Migrations
# --------------------------------------------------------------------------- #
def _checksum(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _migration_files(dialect: str) -> List[str]:
    directory = os.path.join(MIGRATION_DIR, dialect)
    if not os.path.isdir(directory):
        raise MigrationError(f"no migrations directory for dialect {dialect!r} at {directory}")
    return sorted(
        name for name in os.listdir(directory) if name.endswith(".sql")
    )


def applied_migrations(connection) -> Dict[str, str]:
    connection.execute(text(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "  version VARCHAR(64) PRIMARY KEY,"
        "  filename VARCHAR(255) NOT NULL,"
        "  checksum VARCHAR(64) NOT NULL,"
        "  applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")"
    ))
    rows = connection.execute(text("SELECT version, filename, checksum FROM schema_migrations")).fetchall()
    return {row[0]: row[2] for row in rows}


def pending_migrations(engine: Engine) -> List[str]:
    dialect = detect_dialect(str(engine.url))
    with engine.begin() as connection:
        applied = applied_migrations(connection)
    return [name for name in _migration_files(dialect) if name.split("_", 1)[0] not in applied]


def run_migrations(engine: Engine, verbose: bool = False) -> List[str]:
    """Apply every outstanding migration in filename order.

    Each file runs in its own transaction. An already-applied file whose
    contents changed raises :class:`MigrationError` -- editing history is
    how environments drift apart silently.
    """
    dialect = detect_dialect(str(engine.url))
    applied_now: List[str] = []
    for filename in _migration_files(dialect):
        version = filename.split("_", 1)[0]
        path = os.path.join(MIGRATION_DIR, dialect, filename)
        with open(path, "r", encoding="utf-8") as fh:
            sql = fh.read()
        checksum = _checksum(sql)
        with engine.begin() as connection:
            applied = applied_migrations(connection)
            if version in applied:
                if applied[version] != checksum:
                    raise MigrationError(
                        f"migration {filename} changed after being applied "
                        f"(applied checksum {applied[version][:12]}, on-disk {checksum[:12]}). "
                        f"Add a new migration instead of editing history."
                    )
                continue
            for statement in _split_statements(sql):
                connection.execute(text(statement))
            connection.execute(
                text("INSERT INTO schema_migrations (version, filename, checksum) "
                     "VALUES (:version, :filename, :checksum)"),
                {"version": version, "filename": filename, "checksum": checksum},
            )
        applied_now.append(filename)
        if verbose:
            print(f"applied migration {filename}")
    return applied_now


def _split_statements(sql: str) -> List[str]:
    """Split a migration file into statements.

    ``--`` comments are stripped first so a semicolon inside a comment
    cannot split a statement in half.
    """
    lines = []
    for line in sql.splitlines():
        stripped = line.strip()
        if stripped.startswith("--") or not stripped:
            continue
        lines.append(line)
    body = "\n".join(lines)
    return [statement.strip() for statement in body.split(";") if statement.strip()]


def current_schema_version(engine: Engine) -> Optional[str]:
    with engine.begin() as connection:
        applied = applied_migrations(connection)
    return max(applied) if applied else None
