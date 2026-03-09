-- Friendship system refactor:
-- 1. Users: add display_name, actor_uri, inbox_url, outbox_url, updated_at; drop handle_suffix
-- 2. New remote_actors table for caching federated user profiles
-- 3. Replace follows table with friendships (actor_uri-keyed)

-- ── 1. Users table changes ──────────────────────────────────────────────────────

ALTER TABLE users ADD COLUMN display_name TEXT;
ALTER TABLE users ADD COLUMN actor_uri TEXT UNIQUE;
ALTER TABLE users ADD COLUMN inbox_url TEXT;
ALTER TABLE users ADD COLUMN outbox_url TEXT;
ALTER TABLE users ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Drop handle_suffix column and its unique index
DROP INDEX IF EXISTS users_username_handle_suffix_idx;
ALTER TABLE users DROP COLUMN IF EXISTS handle_suffix;

-- ── 2. Remote actors cache ──────────────────────────────────────────────────────

CREATE TABLE remote_actors (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_uri     TEXT NOT NULL UNIQUE,
  username      TEXT NOT NULL,
  instance      TEXT NOT NULL,
  display_name  TEXT,
  avatar_url    TEXT,
  fetched_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── 3. Replace follows with friendships ─────────────────────────────────────────

DROP TABLE IF EXISTS follows;

CREATE TABLE friendships (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  friend_actor_uri  TEXT NOT NULL,
  friend_avatar_url TEXT,
  status            TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'accepted')),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE (owner_user_id, friend_actor_uri)
);

CREATE INDEX idx_friendships_owner ON friendships (owner_user_id);
CREATE INDEX idx_friendships_friend_uri ON friendships (friend_actor_uri);
