-- How a member came to be out of a group, for one an admin removed: who removed them, the group as
-- it stood then — what their list keeps showing —, and whether they cleared it. Each departure
-- sets all three anew — see identity-provider/specs/03-direct-messages.md § 10.
ALTER TABLE conversation_members
    ADD COLUMN removed_by     TEXT,
    ADD COLUMN departure_view JSONB,
    ADD COLUMN dismissed_at   TIMESTAMPTZ;
