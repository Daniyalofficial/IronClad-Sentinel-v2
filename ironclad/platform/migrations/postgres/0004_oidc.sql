-- OIDC browser flows are single-use and shared across API replicas.
-- State is stored as a digest; subjects are bound to already-provisioned users.
CREATE TABLE oidc_states (
    state_hash    TEXT PRIMARY KEY,
    org_id        BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    nonce         TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_oidc_states_expiry ON oidc_states (expires_at);

CREATE TABLE oidc_identities (
    id         BIGSERIAL PRIMARY KEY,
    org_id     BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer     TEXT NOT NULL,
    subject    TEXT NOT NULL,
    bound_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (issuer, subject),
    UNIQUE (user_id, issuer)
);
CREATE INDEX idx_oidc_identities_org ON oidc_identities (org_id, user_id);
