"""Pydantic request/response schemas for the HTTP API.

Every input is validated here: bounded string lengths, constrained
integers, enumerated choices. Nothing from a request body reaches the
scanner, the database or a filesystem path without passing through one of
these models first.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

SEVERITIES = ("critical", "high", "medium", "low", "info")
ROLES = ("owner", "admin", "security", "developer", "viewer")
FINDING_STATUSES = ("open", "resolved", "suppressed")
INTEGRATION_KINDS = ("webhook", "github", "gitlab", "slack", "teams", "jira")

# Hard bounds. A request that exceeds them is a 422 before any work happens.
MAX_NAME = 120
MAX_SLUG = 80
MAX_TEXT = 2000
MAX_PAGE_SIZE = 200


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
class LoginRequest(StrictModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=512)


class TokenResponse(StrictModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: "UserOut"


class PasswordChangeRequest(StrictModel):
    current_password: str = Field(min_length=1, max_length=512)
    new_password: str = Field(min_length=12, max_length=512)


class ApiTokenCreate(StrictModel):
    name: str = Field(min_length=1, max_length=MAX_NAME)
    scopes: List[str] = Field(default_factory=list, max_length=32)


class ApiTokenOut(StrictModel):
    id: int
    name: str
    token_prefix: str
    scopes: List[str]
    created_at: Optional[str] = None
    last_used_at: Optional[str] = None
    revoked_at: Optional[str] = None


class ApiTokenSecret(StrictModel):
    """Returned exactly once, at creation time."""

    token: str
    detail: ApiTokenOut


# --------------------------------------------------------------------------- #
# Users / organizations
# --------------------------------------------------------------------------- #
class UserOut(StrictModel):
    id: int
    email: EmailStr
    full_name: str
    role: str
    is_active: bool
    org_id: int
    created_at: Optional[str] = None
    last_login_at: Optional[str] = None


class UserCreate(StrictModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=512)
    full_name: str = Field(default="", max_length=MAX_NAME)
    role: str = "viewer"

    @field_validator("role")
    @classmethod
    def _valid_role(cls, value: str) -> str:
        if value not in ROLES:
            raise ValueError(f"role must be one of {list(ROLES)}")
        return value


class RoleUpdate(StrictModel):
    role: str

    @field_validator("role")
    @classmethod
    def _valid_role(cls, value: str) -> str:
        if value not in ROLES:
            raise ValueError(f"role must be one of {list(ROLES)}")
        return value


class OrganizationOut(StrictModel):
    id: int
    name: str
    slug: str
    created_at: Optional[str] = None


# --------------------------------------------------------------------------- #
# Projects
# --------------------------------------------------------------------------- #
class ProjectCreate(StrictModel):
    name: str = Field(min_length=1, max_length=MAX_NAME)
    description: str = Field(default="", max_length=MAX_TEXT)
    default_branch: str = Field(default="main", max_length=MAX_SLUG)


class ProjectOut(StrictModel):
    id: int
    name: str
    slug: str
    description: str
    default_branch: str
    archived_at: Optional[str] = None
    created_at: Optional[str] = None


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #
class ScanRequest(StrictModel):
    project_id: int = Field(gt=0)
    target: str = Field(min_length=1, max_length=1024)
    revision: str = Field(default="", max_length=MAX_SLUG)
    policy_id: Optional[int] = None
    policy: Optional[Dict[str, Any]] = None
    idempotency_key: Optional[str] = Field(default=None, max_length=MAX_SLUG)
    wait: bool = False

    @field_validator("target")
    @classmethod
    def _no_nulls(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("target must not contain NUL bytes")
        return value


class ScanOut(StrictModel):
    id: int
    org_id: int
    project_id: int
    status: str
    target_path: str
    revision: str
    created_at: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    files_scanned: int
    lines_scanned: int
    engines: List[str]
    risk_score: int
    grade: str
    policy_passed: Optional[bool] = None
    baseline_suppressed: int
    baseline_expired: int
    finding_count: int = 0
    error: str = ""


class PolicyViolationOut(StrictModel):
    kind: str
    message: str
    rule_id: str = ""
    file_path: str = ""
    line: int = 0
    severity: str = ""


class PolicyDecisionOut(StrictModel):
    passed: bool
    policy: str
    violation_count: int
    violations: List[PolicyViolationOut]
    summary: Dict[str, Any]


class ScanResultOut(StrictModel):
    scan: ScanOut
    decision: Optional[PolicyDecisionOut] = None


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
class FindingOut(StrictModel):
    id: int
    scan_id: int
    project_id: int
    fingerprint: str
    rule_id: str
    title: str
    description: str
    severity: str
    engine: str
    category: str
    cwe: str
    owasp: str
    confidence: str
    remediation: str
    file_path: str
    start_line: int
    end_line: int
    snippet: str
    status: str
    baselined: bool
    extra: Dict[str, Any] = Field(default_factory=dict)
    first_seen_at: Optional[str] = None
    last_seen_at: Optional[str] = None
    resolved_at: Optional[str] = None


class FindingUpdate(StrictModel):
    status: str
    reason: str = Field(default="", max_length=MAX_TEXT)

    @field_validator("status")
    @classmethod
    def _valid_status(cls, value: str) -> str:
        if value not in ("open", "resolved", "suppressed"):
            raise ValueError(f"status must be one of {list(FINDING_STATUSES)}")
        return value


class FindingEventOut(StrictModel):
    id: int
    event_type: str
    actor: str
    detail: Dict[str, Any]
    created_at: Optional[str] = None


# --------------------------------------------------------------------------- #
# Policies / baselines
# --------------------------------------------------------------------------- #
class PolicyUpsert(StrictModel):
    name: str = Field(min_length=1, max_length=MAX_NAME)
    document: Dict[str, Any]
    is_default: bool = False


class PolicyOut(StrictModel):
    id: int
    name: str
    version: int
    is_default: bool
    document: Dict[str, Any]
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class BaselineOut(StrictModel):
    id: int
    project_id: int
    name: str
    reason: str
    created_by: str
    count: int
    created_at: Optional[str] = None
    expires_at: Optional[str] = None


# --------------------------------------------------------------------------- #
# SBOM / licenses
# --------------------------------------------------------------------------- #
class SbomOut(StrictModel):
    id: int
    project_id: int
    scan_id: Optional[int] = None
    format: str
    component_count: int
    created_at: Optional[str] = None


class ComponentOut(StrictModel):
    id: int
    purl: str
    name: str
    version: str
    ecosystem: str
    license: str
    license_class: str


class LicenseSummaryOut(StrictModel):
    project_id: int
    counts: Dict[str, int]
    blocked: List[ComponentOut]
    unknown: List[ComponentOut]


# --------------------------------------------------------------------------- #
# Integrations / audit / jobs
# --------------------------------------------------------------------------- #
class IntegrationCreate(StrictModel):
    kind: str
    name: str = Field(min_length=1, max_length=MAX_NAME)
    config: Dict[str, Any] = Field(default_factory=dict)
    secret: str = Field(default="", max_length=512)
    enabled: bool = True

    @field_validator("kind")
    @classmethod
    def _valid_kind(cls, value: str) -> str:
        if value not in INTEGRATION_KINDS:
            raise ValueError(f"kind must be one of {list(INTEGRATION_KINDS)}")
        return value


class IntegrationOut(StrictModel):
    id: int
    kind: str
    name: str
    config: Dict[str, Any]
    enabled: bool
    last_status: str
    last_run_at: Optional[str] = None
    last_error: str
    has_secret: bool = False


class AuditOut(StrictModel):
    id: int
    actor: str
    actor_id: Optional[int] = None
    action: str
    target_type: str
    target_id: str
    metadata: Dict[str, Any]
    request_id: str
    created_at: Optional[str] = None


class HealthOut(StrictModel):
    status: str
    version: str
    checks: Dict[str, str]


class JobOut(StrictModel):
    id: int
    kind: str
    status: str
    attempts: int
    max_attempts: int
    scheduled_at: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error: str


class DashboardOut(StrictModel):
    summary: Dict[str, Any]
    trend: List[Dict[str, Any]]
    license_counts: Dict[str, int]


TokenResponse.model_rebuild()
