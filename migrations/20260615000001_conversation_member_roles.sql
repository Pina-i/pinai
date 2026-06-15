-- Group-conversation member roles. Adds an admin/member distinction so group
-- management (add/remove members, rename, promote) can be permission-gated.
-- DMs ignore the column entirely — both members are implicitly equal.

ALTER TABLE conversation_members
    ADD COLUMN role TEXT NOT NULL DEFAULT 'member'
        CHECK (role IN ('member', 'admin'));
