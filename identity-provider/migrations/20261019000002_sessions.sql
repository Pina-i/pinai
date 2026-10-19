-- The browser sessions: what the idp_session cookie names, each a row so each can end on its own,
-- and what every access token belongs to (identity-provider/specs/auth.md § 1, "Sessions").
CREATE TABLE sessions (
    id             UUID PRIMARY KEY,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at     TIMESTAMPTZ NOT NULL,
    -- The last sign-in that used it; 90 days past it, the session is over.
    last_used_at   TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ,
    revoked_reason TEXT CHECK (revoked_reason IN ('sign_out', 'replaced')),
    CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
);
CREATE INDEX sessions_user_id ON sessions (user_id);

-- A code belongs to the session it was issued under. The ten-minute codes issued before had none.
DELETE FROM authorization_codes;
ALTER TABLE authorization_codes
    ADD COLUMN session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE;
