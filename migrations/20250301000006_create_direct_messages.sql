-- Stores direct messages between users.
-- ap_id holds the ActivityPub Note ID for federated messages.
CREATE TABLE direct_messages (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content      TEXT        NOT NULL,
    ap_id        TEXT,                    -- ActivityPub Note ID (for federated messages)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX dm_sender_idx    ON direct_messages (sender_id);
CREATE INDEX dm_recipient_idx ON direct_messages (recipient_id);
-- Quickly fetch a conversation between two users
CREATE INDEX dm_conversation_idx ON direct_messages (
    LEAST(sender_id, recipient_id),
    GREATEST(sender_id, recipient_id),
    created_at
);
