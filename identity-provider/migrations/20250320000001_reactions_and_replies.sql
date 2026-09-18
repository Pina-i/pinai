-- Add reply support to direct messages (self-referential FK, ON DELETE SET NULL
-- so replies become standalone if the parent is deleted).
ALTER TABLE direct_messages
  ADD COLUMN reply_to_id UUID REFERENCES direct_messages(id) ON DELETE SET NULL;

-- Reactions on messages. One user can only react once with the same emoji on the
-- same message, enforced by the UNIQUE constraint.
CREATE TABLE message_reactions (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id        UUID NOT NULL REFERENCES direct_messages(id) ON DELETE CASCADE,
  reactor_actor_uri TEXT NOT NULL,
  emoji             TEXT NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE (message_id, reactor_actor_uri, emoji)
);
