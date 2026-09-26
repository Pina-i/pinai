-- Which side of a friendship sent the request. Without it a pending row reads
-- the same to both parties, so the requester could accept their own request
-- (locally, or by a peer IdP answering a request it sent) and a friendship
-- would form without the recipient consenting.
--
--   outgoing — the owner sent the request
--   incoming — the owner received it; only this side may accept or decline
--
-- Kept on accepted rows too: it records who asked, and costs nothing.

ALTER TABLE friendships
    ADD COLUMN direction TEXT CHECK (direction IN ('outgoing', 'incoming'));

-- Local pairs: both rows live in this database, and every request path
-- inserts the requester's row first.
UPDATE friendships f
SET direction = CASE WHEN f.created_at < r.created_at THEN 'outgoing' ELSE 'incoming' END
FROM users owner, users peer, friendships r
WHERE owner.id = f.owner_user_id
  AND peer.actor_uri = f.friend_actor_uri
  AND r.owner_user_id = peer.id
  AND r.friend_actor_uri = owner.actor_uri
  AND f.created_at <> r.created_at;

-- A cross-IdP row, or a local pair written in the same instant, carries no
-- trace of who asked. Treat it as received: a legacy request stays
-- answerable, and the peer IdP, which checks its own side, still refuses an
-- Accept for a request it did not send.
UPDATE friendships SET direction = 'incoming' WHERE direction IS NULL;

ALTER TABLE friendships ALTER COLUMN direction SET NOT NULL;
