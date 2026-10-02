-- A group's changes as its conversation shows them, between the messages — see
-- identity-provider/specs/groups.md § 6. `created_at` is the change's stamp.
CREATE TABLE conversation_events (
    id               UUID PRIMARY KEY,
    conversation_id  UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    kind             TEXT NOT NULL
        CHECK (kind IN ('created', 'added', 'removed', 'left', 'renamed', 'role_changed')),
    actor_uri        TEXT NOT NULL,            -- who made the change
    subject_uri      TEXT,                     -- whom it is about: added, removed, role_changed
    detail           TEXT,                     -- the new name, or the new role
    created_at       TIMESTAMPTZ NOT NULL
);

CREATE INDEX conversation_events_timeline
    ON conversation_events (conversation_id, created_at DESC, id DESC);
