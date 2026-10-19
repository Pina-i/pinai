-- The apps each account signed in to with its password. A live session signs in again to these
-- only, so a site that just sends a browser to /authorize never gets a code silently
-- (identity-provider/specs/auth.md § 1, "The session cookie").
CREATE TABLE client_sign_ins (
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id      TEXT NOT NULL,
    -- It asked to stay signed in on its device; once given, kept.
    offline_access BOOLEAN NOT NULL DEFAULT FALSE,
    signed_in_at   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, client_id)
);
