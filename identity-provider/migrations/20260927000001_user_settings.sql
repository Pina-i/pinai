-- The account's settings: one JSON document per user, owned by the client.
-- Each top-level key is a section (`appearance`, …) the server stores without
-- interpreting; `PATCH /api/settings` replaces the sections it names and keeps
-- the rest. Settings that belong to one device never reach this table.
-- See identity-provider/specs/01-identity-federation.md § 1.6.
CREATE TABLE user_settings (
    user_id    UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    settings   JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(settings) = 'object')
        CHECK (octet_length(settings::text) <= 16384),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
