-- The actors a local account blocked, local or remote, by actor URI: private to the blocker and
-- never federated — see identity-provider/specs/social.md § 2.
CREATE TABLE user_blocks (
    owner_user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_actor_uri TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (owner_user_id, blocked_actor_uri)
);
