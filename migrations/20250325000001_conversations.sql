-- Migrate from sender/recipient DM pairs to a conversation-based model.
-- Creates conversations + conversation_members tables, migrates direct_messages
-- to reference conversation_id, and renames dm_conversation_reads to conversation_reads.

-- 1. Create the conversations table
CREATE TABLE conversations (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind       TEXT NOT NULL DEFAULT 'dm'
                 CHECK (kind IN ('dm', 'group')),
    name       TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Create the conversation_members table
CREATE TABLE conversation_members (
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    actor_uri       TEXT NOT NULL,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    left_at         TIMESTAMPTZ,
    PRIMARY KEY (conversation_id, actor_uri)
);

CREATE INDEX idx_conv_members_actor
    ON conversation_members (actor_uri) WHERE left_at IS NULL;

-- 3. Add conversation_id column to direct_messages (nullable for backfill)
ALTER TABLE direct_messages ADD COLUMN conversation_id UUID;

-- 4. Backfill: create one conversation per unique DM pair and link messages
DO $$
DECLARE
    rec RECORD;
    conv_id UUID;
    min_ts TIMESTAMPTZ;
BEGIN
    -- Find all unique DM pairs (normalised so actor_a < actor_b)
    FOR rec IN
        SELECT DISTINCT
            LEAST(sender_actor_uri, recipient_actor_uri)    AS actor_a,
            GREATEST(sender_actor_uri, recipient_actor_uri) AS actor_b
        FROM direct_messages
    LOOP
        -- Get the earliest message timestamp for this pair
        SELECT MIN(created_at) INTO min_ts
        FROM direct_messages
        WHERE LEAST(sender_actor_uri, recipient_actor_uri) = rec.actor_a
          AND GREATEST(sender_actor_uri, recipient_actor_uri) = rec.actor_b;

        -- Create a conversation
        INSERT INTO conversations (kind, created_at)
        VALUES ('dm', COALESCE(min_ts, now()))
        RETURNING id INTO conv_id;

        -- Add both actors as members
        INSERT INTO conversation_members (conversation_id, actor_uri, joined_at)
        VALUES (conv_id, rec.actor_a, COALESCE(min_ts, now())),
               (conv_id, rec.actor_b, COALESCE(min_ts, now()));

        -- Link all messages in this pair to the conversation
        UPDATE direct_messages
        SET conversation_id = conv_id
        WHERE LEAST(sender_actor_uri, recipient_actor_uri) = rec.actor_a
          AND GREATEST(sender_actor_uri, recipient_actor_uri) = rec.actor_b;
    END LOOP;
END $$;

-- 5. Make conversation_id NOT NULL and add FK
ALTER TABLE direct_messages
    ALTER COLUMN conversation_id SET NOT NULL;

ALTER TABLE direct_messages
    ADD CONSTRAINT fk_dm_conversation
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE;

-- 6. Drop the recipient_actor_uri column and old indexes
DROP INDEX IF EXISTS idx_dm_conversation_cursor;
DROP INDEX IF EXISTS idx_dm_conversation_cursor_reverse;

ALTER TABLE direct_messages DROP COLUMN recipient_actor_uri;

-- 7. Create new keyset pagination index
CREATE INDEX idx_dm_conversation_cursor
    ON direct_messages (conversation_id, created_at DESC, id DESC);

-- 8. Create conversation_reads from dm_conversation_reads
-- We need to map (user_id, other_actor_uri) → (user_id, conversation_id)
CREATE TABLE conversation_reads (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    last_read_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, conversation_id)
);

-- Backfill conversation_reads from dm_conversation_reads
INSERT INTO conversation_reads (user_id, conversation_id, last_read_at)
SELECT
    dcr.user_id,
    cm.conversation_id,
    dcr.last_read_at
FROM dm_conversation_reads dcr
JOIN users u ON u.id = dcr.user_id
JOIN conversation_members cm
    ON cm.actor_uri = dcr.other_actor_uri
JOIN conversation_members cm_self
    ON cm_self.conversation_id = cm.conversation_id
   AND cm_self.actor_uri = u.actor_uri
ON CONFLICT DO NOTHING;

-- 9. Drop the old table
DROP TABLE dm_conversation_reads;
