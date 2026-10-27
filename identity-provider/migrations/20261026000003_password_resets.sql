-- Password reset links: single-use links an admin gives a member to set a new password, and the
-- reason they end the member's sessions (identity-provider/specs/auth.md § 7).
CREATE TABLE password_resets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- SHA-256 of the token the link carries: the token itself is never kept.
    token_hash  BYTEA NOT NULL UNIQUE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- A link answers for the admin who made it, as an invitation does: it goes with them.
    created_by  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    -- A newer link for the same account took its place.
    replaced_at TIMESTAMPTZ
);
-- One link per account neither used nor replaced: a new one replaces it.
CREATE UNIQUE INDEX password_resets_one_open ON password_resets (user_id)
    WHERE used_at IS NULL AND replaced_at IS NULL;

ALTER TABLE sessions
    DROP CONSTRAINT sessions_revoked_reason_check,
    ADD CONSTRAINT sessions_revoked_reason_check CHECK (revoked_reason IN (
        'sign_out', 'replaced', 'reuse', 'device_revoked', 'signed_out_elsewhere', 'password_reset'
    ));
