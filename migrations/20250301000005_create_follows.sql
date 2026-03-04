-- Tracks follow relationships between users.
-- state: 'pending' (requested), 'accepted', 'rejected'
CREATE TABLE follows (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    follower_id  UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    following_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    state        TEXT        NOT NULL DEFAULT 'pending'
                             CHECK (state IN ('pending', 'accepted', 'rejected')),
    -- ActivityPub activity ID for the originating Follow activity (for federation)
    ap_activity_id TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (follower_id, following_id)
);

CREATE INDEX follows_follower_idx  ON follows (follower_id);
CREATE INDEX follows_following_idx ON follows (following_id);
