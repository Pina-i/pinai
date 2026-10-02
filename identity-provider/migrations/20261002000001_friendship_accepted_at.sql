-- When each side of a friendship was accepted: stamped there once and never moved, so a friend
-- made again starts a new date — see identity-provider/specs/social.md. A side accepted earlier
-- takes its acceptance where it is known: both sides of a local pair, whose `updated_at` nothing
-- but the acceptance writes once accepted. A remote friend's moves with each of their profile
-- changes, so theirs takes the request's time instead, never later than the acceptance.
ALTER TABLE friendships ADD COLUMN accepted_at TIMESTAMPTZ;
UPDATE friendships f
   SET accepted_at = CASE
       WHEN EXISTS (SELECT 1 FROM users u WHERE u.actor_uri = f.friend_actor_uri) THEN f.updated_at
       ELSE f.created_at
   END
 WHERE f.status = 'accepted';
ALTER TABLE friendships ADD CONSTRAINT friendships_accepted_when_accepted
    CHECK ((status = 'accepted') = (accepted_at IS NOT NULL));
