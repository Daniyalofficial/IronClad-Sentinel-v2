"""SQLAlchemy models.

These classes *map* the schema created by the migrations in
``ironclad/platform/migrations/``; they never create it. If a column exists
here but not in a migration, the mapping fails loudly at query time rather
than silently diverging.

Multi-tenancy
-------------
Every tenant-owned table has ``org_id``. The application never issues a
query without it -- see ``ironclad.platform.tenancy.org_query`` which is
the only supported way to start a tenant-scoped select.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Naive UTC timestamp.

    Naive-by-convention (always UTC) is deliberate: SQLite cannot store a
    UTC offset, so storing tz-aware values would silently lose it on one
    dialect and keep it on the other. Every timestamp in this product is
    UTC and this function is the only way to produce one.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def as_naive_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Normalise a database-loaded timestamp to naive UTC.

    PostgreSQL `TIMESTAMPTZ` hands back **timezone-aware** datetimes, while
    SQLite hands back naive ones. Comparing an aware value against
    :func:`utcnow` raises `TypeError: can't compare offset-naive and
    offset-aware datetimes` -- which on PostgreSQL meant *every authenticated
    request failed with a 500*, because session expiry is checked on each one.

    Every timestamp in this product is UTC, so converting to UTC and dropping
    the offset makes both dialects behave identically without changing the
    stored representation.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


Timestamp = DateTime


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    slug: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    settings: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)

    users: Mapped[list["User"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    projects: Mapped[list["Project"]] = relationship(back_populates="organization", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("org_id", "email", name="uq_users_org_email"),
                      Index("idx_users_org", "org_id"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    email: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    full_name: Mapped[str] = mapped_column(Text, nullable=False, default="")
    role: Mapped[str] = mapped_column(Text, nullable=False, default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean().with_variant(Integer, "sqlite"), nullable=False, default=True)
    failed_logins: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(Timestamp)
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(Timestamp)

    organization: Mapped[Organization] = relationship(back_populates="users")


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = (Index("idx_sessions_user", "user_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(Timestamp)
    user_agent: Mapped[str] = mapped_column(Text, nullable=False, default="")


class ApiToken(Base):
    __tablename__ = "api_tokens"
    __table_args__ = (Index("idx_api_tokens_org", "org_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    token_prefix: Mapped[str] = mapped_column(Text, nullable=False)
    scopes: Mapped[str] = mapped_column(Text, nullable=False, default="scan:read,scan:create,finding:read")
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(Timestamp)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(Timestamp)


class Project(Base):
    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("org_id", "slug", name="uq_projects_org_slug"),
                      Index("idx_projects_org", "org_id"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    slug: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    default_branch: Mapped[str] = mapped_column(Text, nullable=False, default="main")
    archived_at: Mapped[Optional[datetime]] = mapped_column(Timestamp)
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)

    organization: Mapped[Organization] = relationship(back_populates="projects")
    scans: Mapped[list["Scan"]] = relationship(back_populates="project")


class Repository(Base):
    __tablename__ = "repositories"
    __table_args__ = (Index("idx_repositories_project", "org_id", "project_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False, default="filesystem")
    clone_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    default_branch: Mapped[str] = mapped_column(Text, nullable=False, default="main")
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_policies_org_name"),
                      Index("idx_policies_org", "org_id"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    document: Mapped[str] = mapped_column(Text, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean().with_variant(Integer, "sqlite"), nullable=False, default=False)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)


class Baseline(Base):
    __tablename__ = "baselines"
    __table_args__ = (UniqueConstraint("org_id", "project_id", "name", name="uq_baselines_org_project_name"),
                      Index("idx_baselines_project", "org_id", "project_id"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False, default="default")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_by: Mapped[str] = mapped_column(Text, nullable=False, default="")
    entries: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)
    expires_at: Mapped[Optional[datetime]] = mapped_column(Timestamp)


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (UniqueConstraint("org_id", "idempotency_key", name="uq_scans_org_idempotency"),
                      Index("idx_scans_project", "org_id", "project_id", "created_at"),
                      Index("idx_scans_status", "org_id", "status"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    repository_id: Mapped[Optional[int]] = mapped_column(ForeignKey("repositories.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(Text, nullable=False, default="queued")
    target_path: Mapped[str] = mapped_column(Text, nullable=False, default="")
    revision: Mapped[str] = mapped_column(Text, nullable=False, default="")
    requested_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    idempotency_key: Mapped[Optional[str]] = mapped_column(Text)
    policy_id: Mapped[Optional[int]] = mapped_column(ForeignKey("policies.id", ondelete="SET NULL"))
    #: The exact policy document applied, so the decision can be recomputed
    #: later even when the policy was supplied inline and has no row.
    policy_document: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(Timestamp)
    finished_at: Mapped[Optional[datetime]] = mapped_column(Timestamp)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float)
    files_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    lines_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    engines: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    grade: Mapped[str] = mapped_column(Text, nullable=False, default="")
    policy_passed: Mapped[Optional[bool]] = mapped_column(Boolean().with_variant(Integer, "sqlite"))
    baseline_suppressed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    baseline_expired: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")

    project: Mapped[Project] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("scan_id", "fingerprint", name="uq_findings_scan_fingerprint"),
                      Index("idx_findings_project", "org_id", "project_id", "status", "severity"),
                      Index("idx_findings_fingerprint", "org_id", "fingerprint"),
                      Index("idx_findings_scan", "scan_id"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    rule_id: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    engine: Mapped[str] = mapped_column(Text, nullable=False, default="")
    category: Mapped[str] = mapped_column(Text, nullable=False, default="general")
    cwe: Mapped[str] = mapped_column(Text, nullable=False, default="")
    owasp: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confidence: Mapped[str] = mapped_column(Text, nullable=False, default="medium")
    remediation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    file_path: Mapped[str] = mapped_column(Text, nullable=False, default="")
    start_line: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    end_line: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    snippet: Mapped[str] = mapped_column(Text, nullable=False, default="")
    extra: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    status: Mapped[str] = mapped_column(Text, nullable=False, default="open")
    baselined: Mapped[bool] = mapped_column(Boolean().with_variant(Integer, "sqlite"),
                                            nullable=False, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(Timestamp)
    suppressed_by: Mapped[str] = mapped_column(Text, nullable=False, default="")
    suppressed_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")

    scan: Mapped[Scan] = relationship(back_populates="findings")
    events: Mapped[list["FindingEvent"]] = relationship(back_populates="finding", cascade="all, delete-orphan")

    def extra_dict(self) -> Dict[str, Any]:
        import json

        try:
            return json.loads(self.extra or "{}")
        except ValueError:
            return {}


class FindingEvent(Base):
    __tablename__ = "finding_events"
    __table_args__ = (Index("idx_finding_events", "org_id", "finding_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)

    finding: Mapped[Finding] = relationship(back_populates="events")


class Sbom(Base):
    __tablename__ = "sboms"
    __table_args__ = (Index("idx_sboms_project", "org_id", "project_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    format: Mapped[str] = mapped_column(Text, nullable=False, default="cyclonedx")
    document: Mapped[str] = mapped_column(Text, nullable=False)
    component_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)

    components: Mapped[list["Component"]] = relationship(back_populates="sbom", cascade="all, delete-orphan")


class Component(Base):
    __tablename__ = "components"
    __table_args__ = (UniqueConstraint("sbom_id", "purl", name="uq_components_sbom_purl"),
                      Index("idx_components_org", "org_id", "license_class"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    sbom_id: Mapped[int] = mapped_column(ForeignKey("sboms.id", ondelete="CASCADE"), nullable=False)
    purl: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[str] = mapped_column(Text, nullable=False, default="")
    ecosystem: Mapped[str] = mapped_column(Text, nullable=False, default="")
    license: Mapped[str] = mapped_column(Text, nullable=False, default="UNKNOWN")
    license_class: Mapped[str] = mapped_column(Text, nullable=False, default="unknown")
    bom_ref: Mapped[str] = mapped_column(Text, nullable=False, default="")

    sbom: Mapped[Sbom] = relationship(back_populates="components")


class Integration(Base):
    __tablename__ = "integrations"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_integrations_org_name"),
                      Index("idx_integrations_org", "org_id"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    config: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    secret: Mapped[str] = mapped_column(Text, nullable=False, default="")
    enabled: Mapped[bool] = mapped_column(Boolean().with_variant(Integer, "sqlite"), nullable=False, default=True)
    last_status: Mapped[str] = mapped_column(Text, nullable=False, default="never-run")
    last_run_at: Mapped[Optional[datetime]] = mapped_column(Timestamp)
    last_error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)


class AuditEvent(Base):
    """Append-only audit record.

    Nothing in the product updates or deletes these rows; the API exposes
    read-only listing. The migration grants no update path and the
    application has no code path that writes to an existing row.
    """

    __tablename__ = "audit_events"
    __table_args__ = (Index("idx_audit_org_time", "org_id", "created_at"),
                      Index("idx_audit_action", "org_id", "action"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    actor: Mapped[str] = mapped_column(Text, nullable=False, default="anonymous")
    actor_id: Mapped[Optional[int]] = mapped_column(BigInteger().with_variant(Integer, "sqlite"))
    action: Mapped[str] = mapped_column(Text, nullable=False)
    target_type: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_id: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Mapped to the `metadata` column but named metadata_json on the Python
    # side: `metadata` is reserved by SQLAlchemy's Declarative API.
    metadata_json: Mapped[str] = mapped_column("metadata", Text, nullable=False, default="{}")
    request_id: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (Index("idx_jobs_pending", "status", "scheduled_at"),
                      Index("idx_jobs_org", "org_id", "status"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    status: Mapped[str] = mapped_column(Text, nullable=False, default="queued")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    scheduled_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)
    started_at: Mapped[Optional[datetime]] = mapped_column(Timestamp)
    finished_at: Mapped[Optional[datetime]] = mapped_column(Timestamp)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (Index("idx_events_org", "org_id", "event_type", "created_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    subject_id: Mapped[str] = mapped_column(Text, nullable=False, default="")
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    correlation_id: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(Timestamp, nullable=False, default=utcnow)
