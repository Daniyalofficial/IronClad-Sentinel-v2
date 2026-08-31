-- Password reset tokens.
--
-- Only the SHA-256 digest of a token is stored, never the token itself, so a
-- database leak does not hand over usable reset links. `used_at` makes the
-- token single-use: it is set the moment the token is redeemed, and a token
-- that has already been used is rejected rather than silently reused.
CREATE TABLE password_reset_tokens (
    id            BIGSERIAL PRIMARY KEY,
    org_id        BIGINT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash    TEXT NOT NULL UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    used_at       TIMESTAMPTZ,
    request_ip    TEXT NOT NULL DEFAULT '',
    redeemed_ip   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_password_reset_user ON password_reset_tokens (user_id, used_at);
CREATE INDEX idx_password_reset_expiry ON password_reset_tokens (expires_at);
