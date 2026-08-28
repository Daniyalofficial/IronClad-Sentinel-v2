-- IronClad Sentinel initial schema (PostgreSQL dialect).
--
-- Every tenant-owned table carries org_id and every cross-tenant query in
-- the application is filtered on it; the foreign keys below make
-- organization-scoped deletes safe, and the composite indexes lead with
-- org_id because that is always the first predicate.
--
-- PostgreSQL uses BIGSERIAL identities, TIMESTAMPTZ timestamps, native
-- BOOLEAN, and CHECK constraints that SQLite cannot enforce.

CREATE TABLE organizations (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    settings    TEXT NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id             BIGSERIAL PRIMARY KEY,
    org_id         BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email          TEXT NOT NULL,
    password_hash  TEXT NOT NULL,
    full_name      TEXT NOT NULL DEFAULT '',
    role           TEXT NOT NULL DEFAULT 'viewer',
    is_active      BOOLEAN NOT NULL DEFAULT TRUE,
    failed_logins  INTEGER NOT NULL DEFAULT 0,
    locked_until   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at  TIMESTAMPTZ,
    UNIQUE (org_id, email)
);
CREATE INDEX idx_users_org ON users (org_id);

CREATE TABLE sessions (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    user_agent  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_sessions_user ON sessions (user_id);

CREATE TABLE api_tokens (
    id           BIGSERIAL PRIMARY KEY,
    org_id       BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    scopes       TEXT NOT NULL DEFAULT 'scan:read,scan:create,finding:read',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX idx_api_tokens_org ON api_tokens (org_id);

CREATE TABLE projects (
    id             BIGSERIAL PRIMARY KEY,
    org_id         BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    slug           TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    default_branch TEXT NOT NULL DEFAULT 'main',
    archived_at    TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, slug)
);
CREATE INDEX idx_projects_org ON projects (org_id);

CREATE TABLE repositories (
    id             BIGSERIAL PRIMARY KEY,
    org_id         BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id     BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    provider       TEXT NOT NULL DEFAULT 'filesystem',
    clone_url      TEXT NOT NULL DEFAULT '',
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_repositories_project ON repositories (org_id, project_id);

CREATE TABLE policies (
    id             BIGSERIAL PRIMARY KEY,
    org_id         BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    version        INTEGER NOT NULL DEFAULT 1,
    document       TEXT NOT NULL,
    is_default     BOOLEAN NOT NULL DEFAULT FALSE,
    created_by     BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
CREATE INDEX idx_policies_org ON policies (org_id);

CREATE TABLE baselines (
    id           BIGSERIAL PRIMARY KEY,
    org_id       BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id   BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT 'default',
    reason       TEXT NOT NULL DEFAULT '',
    created_by   TEXT NOT NULL DEFAULT '',
    entries      TEXT NOT NULL DEFAULT '[]',
    count        INTEGER NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    UNIQUE (org_id, project_id, name)
);
CREATE INDEX idx_baselines_project ON baselines (org_id, project_id);

CREATE TABLE scans (
    id                 BIGSERIAL PRIMARY KEY,
    org_id             BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id         BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    repository_id      BIGINT REFERENCES repositories(id) ON DELETE SET NULL,
    status             TEXT NOT NULL DEFAULT 'queued',
    target_path        TEXT NOT NULL DEFAULT '',
    revision           TEXT NOT NULL DEFAULT '',
    requested_by       BIGINT REFERENCES users(id) ON DELETE SET NULL,
    idempotency_key    TEXT,
    policy_id          BIGINT REFERENCES policies(id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at         TIMESTAMPTZ,
    finished_at        TIMESTAMPTZ,
    duration_seconds   DOUBLE PRECISION,
    files_scanned      INTEGER NOT NULL DEFAULT 0,
    lines_scanned      INTEGER NOT NULL DEFAULT 0,
    engines            TEXT NOT NULL DEFAULT '[]',
    risk_score         INTEGER NOT NULL DEFAULT 0,
    grade              TEXT NOT NULL DEFAULT '',
    policy_passed      BOOLEAN,
    baseline_suppressed INTEGER NOT NULL DEFAULT 0,
    baseline_expired   INTEGER NOT NULL DEFAULT 0,
    error              TEXT NOT NULL DEFAULT '',
    UNIQUE (org_id, idempotency_key)
);
CREATE INDEX idx_scans_project ON scans (org_id, project_id, created_at);
CREATE INDEX idx_scans_status ON scans (org_id, status);

CREATE TABLE findings (
    id             BIGSERIAL PRIMARY KEY,
    org_id         BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_id        BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    project_id     BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint    TEXT NOT NULL,
    rule_id        TEXT NOT NULL,
    title          TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    severity       TEXT NOT NULL,
    engine         TEXT NOT NULL DEFAULT '',
    category       TEXT NOT NULL DEFAULT 'general',
    cwe            TEXT NOT NULL DEFAULT '',
    owasp          TEXT NOT NULL DEFAULT '',
    confidence     TEXT NOT NULL DEFAULT 'medium',
    remediation    TEXT NOT NULL DEFAULT '',
    file_path      TEXT NOT NULL DEFAULT '',
    start_line     INTEGER NOT NULL DEFAULT 0,
    end_line       INTEGER NOT NULL DEFAULT 0,
    snippet        TEXT NOT NULL DEFAULT '',
    extra          TEXT NOT NULL DEFAULT '{}',
    status         TEXT NOT NULL DEFAULT 'open',
    baselined      BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at    TIMESTAMPTZ,
    suppressed_by  TEXT NOT NULL DEFAULT '',
    suppressed_reason TEXT NOT NULL DEFAULT '',
    UNIQUE (scan_id, fingerprint)
);
CREATE INDEX idx_findings_project ON findings (org_id, project_id, status, severity);
CREATE INDEX idx_findings_fingerprint ON findings (org_id, fingerprint);
CREATE INDEX idx_findings_scan ON findings (scan_id);

CREATE TABLE finding_events (
    id          BIGSERIAL PRIMARY KEY,
    org_id      BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    finding_id  BIGINT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    event_type  TEXT NOT NULL,
    actor       TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_finding_events ON finding_events (org_id, finding_id);

CREATE TABLE sboms (
    id              BIGSERIAL PRIMARY KEY,
    org_id          BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id      BIGINT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scan_id         BIGINT REFERENCES scans(id) ON DELETE SET NULL,
    format          TEXT NOT NULL DEFAULT 'cyclonedx',
    document        TEXT NOT NULL,
    component_count INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sboms_project ON sboms (org_id, project_id);

CREATE TABLE components (
    id         BIGSERIAL PRIMARY KEY,
    org_id     BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    sbom_id    BIGINT NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    purl       TEXT NOT NULL,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL DEFAULT '',
    ecosystem  TEXT NOT NULL DEFAULT '',
    license    TEXT NOT NULL DEFAULT 'UNKNOWN',
    license_class TEXT NOT NULL DEFAULT 'unknown',
    bom_ref    TEXT NOT NULL DEFAULT '',
    UNIQUE (sbom_id, purl)
);
CREATE INDEX idx_components_org ON components (org_id, license_class);

CREATE TABLE integrations (
    id           BIGSERIAL PRIMARY KEY,
    org_id       BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    name         TEXT NOT NULL,
    config       TEXT NOT NULL DEFAULT '{}',
    secret       TEXT NOT NULL DEFAULT '',
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    last_status  TEXT NOT NULL DEFAULT 'never-run',
    last_run_at  TIMESTAMPTZ,
    last_error   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
CREATE INDEX idx_integrations_org ON integrations (org_id);

CREATE TABLE audit_events (
    id          BIGSERIAL PRIMARY KEY,
    org_id      BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor       TEXT NOT NULL DEFAULT 'anonymous',
    actor_id    INTEGER,
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    metadata    TEXT NOT NULL DEFAULT '{}',
    request_id  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_org_time ON audit_events (org_id, created_at);
CREATE INDEX idx_audit_action ON audit_events (org_id, action);

CREATE TABLE jobs (
    id           BIGSERIAL PRIMARY KEY,
    org_id       BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    payload      TEXT NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'queued',
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    error        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_jobs_pending ON jobs (status, scheduled_at);
CREATE INDEX idx_jobs_org ON jobs (org_id, status);

CREATE TABLE events (
    id          BIGSERIAL PRIMARY KEY,
    org_id      BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_type  TEXT NOT NULL,
    subject_id  TEXT NOT NULL DEFAULT '',
    payload     TEXT NOT NULL DEFAULT '{}',
    correlation_id TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_events_org ON events (org_id, event_type, created_at);

-- CHECK constraints must come last: `jobs` and `events` are defined below
-- `audit_events`, so an ALTER TABLE placed earlier in the file fails with
-- "relation does not exist". Found by running this migration against a real
-- PostgreSQL 16 server -- it had never been executed before.
ALTER TABLE scans ADD CONSTRAINT scans_status_valid
    CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled'));
ALTER TABLE findings ADD CONSTRAINT findings_severity_valid
    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'));
ALTER TABLE findings ADD CONSTRAINT findings_status_valid
    CHECK (status IN ('open', 'resolved', 'suppressed'));
ALTER TABLE jobs ADD CONSTRAINT jobs_status_valid
    CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled'));
ALTER TABLE users ADD CONSTRAINT users_role_valid
    CHECK (role IN ('owner', 'admin', 'security', 'developer', 'viewer'));
