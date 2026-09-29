-- One DM per pair of actors (identity-provider/specs/03-direct-messages.md § Conversation IDs).
-- Opening a DM looked for the pair's conversation, then created one: two concurrent first
-- messages or accepts each created their own. A DM now carries its pair, normalised (the
-- smaller actor URI first), and the pair is unique among DMs.
ALTER TABLE conversations
    ADD COLUMN dm_low  TEXT,
    ADD COLUMN dm_high TEXT,
    ADD CONSTRAINT conversations_dm_pair_only_on_dms
        CHECK ((dm_low IS NULL AND dm_high IS NULL) OR (kind = 'dm' AND dm_low < dm_high));

-- A DM's pair is its two members. Of duplicate DMs, the oldest keeps the pair; the others stay
-- readable but are no longer where the pair's new messages go.
WITH pairs AS (
    SELECT c.id, c.created_at,
           MIN(m.actor_uri) AS low, MAX(m.actor_uri) AS high, COUNT(*) AS members
    FROM conversations c
    JOIN conversation_members m ON m.conversation_id = c.id
    WHERE c.kind = 'dm'
    GROUP BY c.id, c.created_at
), ranked AS (
    SELECT id, low, high,
           ROW_NUMBER() OVER (PARTITION BY low, high ORDER BY created_at, id) AS rank
    FROM pairs
    WHERE members = 2
)
UPDATE conversations c
SET dm_low = r.low, dm_high = r.high
FROM ranked r
WHERE c.id = r.id AND r.rank = 1;

CREATE UNIQUE INDEX conversations_dm_pair ON conversations (dm_low, dm_high)
    WHERE dm_low IS NOT NULL;
