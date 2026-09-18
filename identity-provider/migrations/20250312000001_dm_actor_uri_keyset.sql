-- Migrate direct_messages from UUID foreign keys to actor_uri text columns,
-- add federation fields, and create keyset pagination indexes (tech-specs §5).

-- Drop old indexes
DROP INDEX IF EXISTS dm_sender_idx;
DROP INDEX IF EXISTS dm_recipient_idx;
DROP INDEX IF EXISTS dm_conversation_idx;

-- Add new columns (nullable first so existing rows survive the migration)
ALTER TABLE direct_messages
    ADD COLUMN sender_actor_uri    TEXT,
    ADD COLUMN recipient_actor_uri TEXT,
    ADD COLUMN activity_uri        TEXT,
    ADD COLUMN federation_status   TEXT NOT NULL DEFAULT 'pending'
        CHECK (federation_status IN ('pending', 'delivered', 'failed')),
    ADD COLUMN edited_at           TIMESTAMPTZ,
    ADD COLUMN deleted_at          TIMESTAMPTZ;

-- Back-fill actor URIs from the users table for any existing rows
UPDATE direct_messages dm
SET sender_actor_uri = u.actor_uri
FROM users u
WHERE u.id = dm.sender_id;

UPDATE direct_messages dm
SET recipient_actor_uri = u.actor_uri
FROM users u
WHERE u.id = dm.recipient_id;

-- Back-fill activity_uri from the old ap_id column (or generate a placeholder)
UPDATE direct_messages
SET activity_uri = COALESCE(ap_id, 'urn:uuid:' || id::text);

-- Now make the new columns NOT NULL
ALTER TABLE direct_messages
    ALTER COLUMN sender_actor_uri SET NOT NULL,
    ALTER COLUMN recipient_actor_uri SET NOT NULL,
    ALTER COLUMN activity_uri SET NOT NULL;

-- Unique constraint on activity_uri (canonical ActivityPub object ID)
ALTER TABLE direct_messages
    ADD CONSTRAINT dm_activity_uri_unique UNIQUE (activity_uri);

-- Drop old columns
ALTER TABLE direct_messages
    DROP COLUMN sender_id,
    DROP COLUMN recipient_id,
    DROP COLUMN ap_id;

-- Keyset pagination indexes (tech-specs §5)
CREATE INDEX idx_dm_conversation_cursor
    ON direct_messages (sender_actor_uri, recipient_actor_uri, created_at DESC, id DESC);

CREATE INDEX idx_dm_conversation_cursor_reverse
    ON direct_messages (recipient_actor_uri, sender_actor_uri, created_at DESC, id DESC);
