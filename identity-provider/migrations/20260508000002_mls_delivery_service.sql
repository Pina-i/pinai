-- MLS Delivery Service: per-conversation commit log + offline welcome dispatch.
-- Both blobs are opaque to the server — it just orders, persists, and routes.
-- See identity-provider/specs/e2ee.md § 4.

-- Strict per-group total order of commits, enforced by UNIQUE(conversation_id, epoch).
-- The DS hands one back at a time to clients catching up, and rejects any
-- second commit at the same epoch with `409 Conflict`.
CREATE TABLE mls_commits (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id     UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    epoch               BIGINT NOT NULL,
    commit_blob         BYTEA NOT NULL,            -- TLS-encoded MLS Commit message
    proposer_actor_uri  TEXT  NOT NULL,            -- whose device proposed it
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (conversation_id, epoch)
);

-- Catch-up query: `WHERE conversation_id = $1 AND epoch > $2 ORDER BY epoch ASC`.
-- The UNIQUE index on (conversation_id, epoch) already serves this — keep it
-- as the only index to avoid double-write cost on every commit.

-- Welcome bundles for offline device add events. Consumed (server-side) when
-- the recipient device fetches them via GET /api/mls/welcomes.
CREATE TABLE mls_welcomes (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient_user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_device_id  UUID NOT NULL,             -- targeted leaf
    conversation_id      UUID NOT NULL,             -- redundant; helps routing on fetch
    welcome_blob         BYTEA NOT NULL,            -- TLS-encoded MLS Welcome message
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    consumed_at          TIMESTAMPTZ
);

-- Used by `GET /api/mls/welcomes` to find unconsumed rows for any of the
-- caller's devices in one round-trip.
CREATE INDEX idx_mls_welcomes_pending
    ON mls_welcomes (recipient_user_id, created_at)
    WHERE consumed_at IS NULL;
