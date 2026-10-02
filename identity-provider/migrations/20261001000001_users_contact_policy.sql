-- Who may message an account or add it to a group, as its owner chose — see
-- identity-provider/specs/social.md § 2.
ALTER TABLE users
    ADD COLUMN contact_policy TEXT NOT NULL DEFAULT 'friends_and_groups'
        CHECK (contact_policy IN ('everyone', 'friends_and_groups', 'friends'));
