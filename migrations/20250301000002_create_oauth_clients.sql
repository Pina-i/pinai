CREATE TABLE oauth_clients (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id      TEXT        UNIQUE NOT NULL,
    redirect_uris  TEXT[]      NOT NULL,
    grant_types    TEXT[]      NOT NULL,
    response_types TEXT[]      NOT NULL,
    is_public      BOOL        NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Pre-seed the web-client as a trusted public PKCE client.
-- No client_secret because is_public = true (PKCE replaces the secret).
INSERT INTO oauth_clients (id, client_id, redirect_uris, grant_types, response_types, is_public)
VALUES (
    gen_random_uuid(),
    'web-client',
    ARRAY[
        'http://localhost:5173/callback',
        'http://localhost:3000/callback'
    ],
    ARRAY['authorization_code'],
    ARRAY['code'],
    true
);
