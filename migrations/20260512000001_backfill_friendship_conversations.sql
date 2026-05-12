-- Backfill DM conversations for existing accepted friendships.
--
-- After the "friendship creates the conversation" refactor every new
-- accepted friendship creates a DM conversation row in the same
-- transaction as `set_status('accepted')`. This migration retroactively
-- creates one for every already-accepted friendship that doesn't yet
-- have a corresponding 2-member DM. Idempotent — re-running is a no-op
-- because `find_dm_between` returns the existing row.
--
-- We do it in two passes so we can reuse the freshly-inserted
-- conversation ids in the second pass (membership). The first pass
-- builds a list of (owner_actor_uri, friend_actor_uri, new_conv_id)
-- tuples for pairs that lack a DM today; the second inserts both
-- members for each new conversation.

WITH pairs_without_dm AS (
    -- One row per accepted friendship whose owner/friend pair has no DM.
    -- We deduplicate by ordering the pair lexicographically so the two
    -- friendship rows (one per direction) don't each get their own
    -- conversation.
    SELECT DISTINCT ON (LEAST(owner.actor_uri, f.friend_actor_uri), GREATEST(owner.actor_uri, f.friend_actor_uri))
        owner.actor_uri AS owner_actor_uri,
        f.friend_actor_uri AS friend_actor_uri
    FROM friendships f
    JOIN users owner ON owner.id = f.owner_user_id
    WHERE f.status = 'accepted'
      AND owner.actor_uri IS NOT NULL
      AND NOT EXISTS (
          SELECT 1
          FROM conversation_members cm1
          JOIN conversation_members cm2
              ON cm2.conversation_id = cm1.conversation_id
             AND cm2.actor_uri = f.friend_actor_uri
             AND cm2.left_at IS NULL
          JOIN conversations c
              ON c.id = cm1.conversation_id
             AND c.kind = 'dm'
          WHERE cm1.actor_uri = owner.actor_uri
            AND cm1.left_at IS NULL
      )
),
created_convs AS (
    INSERT INTO conversations (id, kind, name)
    SELECT gen_random_uuid(), 'dm', NULL
    FROM pairs_without_dm
    RETURNING id
),
-- Pair each fresh conversation id with the actor pair that needed it.
-- ROW_NUMBER ties them in insertion order.
paired AS (
    SELECT
        c.id AS conversation_id,
        p.owner_actor_uri,
        p.friend_actor_uri
    FROM (
        SELECT id, ROW_NUMBER() OVER () AS rn FROM created_convs
    ) c
    JOIN (
        SELECT owner_actor_uri, friend_actor_uri, ROW_NUMBER() OVER () AS rn
        FROM pairs_without_dm
    ) p ON p.rn = c.rn
)
INSERT INTO conversation_members (conversation_id, actor_uri)
SELECT conversation_id, owner_actor_uri  FROM paired
UNION ALL
SELECT conversation_id, friend_actor_uri FROM paired
ON CONFLICT (conversation_id, actor_uri) DO NOTHING;
