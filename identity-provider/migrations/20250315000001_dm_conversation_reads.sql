-- Tracks the last time a user "read" a DM conversation.
-- Used to compute per-conversation unread counts on login.
CREATE TABLE dm_conversation_reads (
    user_id          UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    other_actor_uri  TEXT        NOT NULL,
    last_read_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, other_actor_uri)
);
