CREATE TABLE authorization_codes (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    code                  TEXT        UNIQUE NOT NULL,
    client_id             TEXT        NOT NULL,
    user_id               UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    redirect_uri          TEXT        NOT NULL,
    code_challenge        TEXT        NOT NULL,
    -- Enforce S256 at the DB level — defense in depth against plain method bugs
    code_challenge_method TEXT        NOT NULL CHECK (code_challenge_method = 'S256'),
    scope                 TEXT        NOT NULL,
    nonce                 TEXT,
    expires_at            TIMESTAMPTZ NOT NULL,
    used                  BOOL        NOT NULL DEFAULT false,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Fast lookup by code during token exchange
CREATE UNIQUE INDEX idx_auth_codes_code ON authorization_codes (code);

-- Efficient expiry cleanup (only index live codes)
CREATE INDEX idx_auth_codes_expires ON authorization_codes (expires_at)
    WHERE used = false;
