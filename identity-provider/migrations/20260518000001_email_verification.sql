-- Email verification: per-user verified timestamp + short-lived OTP table.
-- Grandfathers existing dev users so they keep working after deploy.

ALTER TABLE users
    ADD COLUMN email_verified_at TIMESTAMPTZ;

UPDATE users
   SET email_verified_at = created_at
 WHERE email_verified_at IS NULL;

CREATE TABLE email_verification_codes (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash    BYTEA       NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ,
    attempts     INTEGER     NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The handler only ever queries the *current* unconsumed code per user, so the
-- index stays tight as historical rows pile up before the reaper sweeps them.
CREATE INDEX idx_evc_user_unconsumed
    ON email_verification_codes(user_id)
 WHERE consumed_at IS NULL;
