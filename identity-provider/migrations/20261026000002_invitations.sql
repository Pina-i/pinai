-- Invitations: single-use links an admin creates, which let someone in without a mailed code, and
-- who vouched for each account let in so (identity-provider/specs/auth.md § 5).
CREATE TABLE invitations (
    id         UUID PRIMARY KEY,
    -- SHA-256 of the token the link carries: the token itself is never kept.
    token_hash BYTEA NOT NULL UNIQUE,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    used_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    revoked_at TIMESTAMPTZ
);

ALTER TABLE users ADD COLUMN invited_by UUID REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX users_invited_by ON users (invited_by) WHERE invited_by IS NOT NULL;
