-- TOTP 2FA: per-user secret + recovery codes + short-lived enrollment / login tickets.

ALTER TABLE users
    ADD COLUMN totp_secret  BYTEA,
    ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Enrollment scratchpad. One row per in-flight enrollment; replaced on retry.
-- The secret is committed to `users.totp_secret` once verify succeeds.
CREATE TABLE pending_totp_enrollments (
    user_id     UUID        PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret      BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- "You passed the password, now enter your TOTP" tickets. OIDC params live
-- here so the URL only has to carry an opaque id. 5-minute expiry.
CREATE TABLE pending_totp_logins (
    id                     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id              TEXT        NOT NULL,
    redirect_uri           TEXT        NOT NULL,
    scope                  TEXT        NOT NULL,
    oauth_state            TEXT        NOT NULL,
    code_challenge         TEXT        NOT NULL,
    code_challenge_method  TEXT        NOT NULL,
    nonce                  TEXT,
    expires_at             TIMESTAMPTZ NOT NULL,
    consumed_at            TIMESTAMPTZ,
    attempts               INTEGER     NOT NULL DEFAULT 0,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ptl_unconsumed
    ON pending_totp_logins(user_id)
 WHERE consumed_at IS NULL;

-- Single-use recovery codes (10 per user). Hash uses HMAC-SHA256 under the
-- same EMAIL_OTP_PEPPER as signup OTPs — one secret to manage.
CREATE TABLE recovery_codes (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   BYTEA       NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_recovery_codes_user_unconsumed
    ON recovery_codes(user_id)
 WHERE consumed_at IS NULL;
