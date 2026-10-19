-- Refresh tokens, and the sessions a native client opens for itself
-- (identity-provider/specs/auth.md § 1, "Sessions" and "Tokens").
ALTER TABLE sessions
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'browser' CHECK (kind IN ('browser', 'app')),
    -- An app session's client; a browser session serves any app its account signed in to.
    ADD COLUMN client_id TEXT,
    ADD CONSTRAINT sessions_app_client CHECK ((kind = 'app') = (client_id IS NOT NULL)),
    DROP CONSTRAINT sessions_revoked_reason_check,
    ADD CONSTRAINT sessions_revoked_reason_check
        CHECK (revoked_reason IN ('sign_out', 'replaced', 'reuse'));
ALTER TABLE sessions ALTER COLUMN kind DROP DEFAULT;

-- Each use rotates a token to its successor; a session's chain has one unrotated token, its head.
-- The rotated ones stay while the session lives, so a copy presented late is caught.
CREATE TABLE refresh_tokens (
    -- SHA-256 of the token: the token itself is never kept.
    token_hash     BYTEA PRIMARY KEY,
    session_id     UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    client_id      TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL,
    rotated_at     TIMESTAMPTZ,
    -- What it was rotated to. A rotated token without one had its successor replaced.
    successor_hash BYTEA
);
CREATE INDEX refresh_tokens_session_id ON refresh_tokens (session_id);
