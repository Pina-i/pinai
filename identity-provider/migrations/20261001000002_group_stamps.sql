-- When a group's name and each member's role were last set, wherever that was: a copy of a group
-- takes a change only if it is newer than what it holds — see
-- identity-provider/specs/groups.md § 7.
ALTER TABLE conversations ADD COLUMN name_at TIMESTAMPTZ;
UPDATE conversations SET name_at = created_at;
ALTER TABLE conversations
    ALTER COLUMN name_at SET NOT NULL,
    ALTER COLUMN name_at SET DEFAULT now();

ALTER TABLE conversation_members ADD COLUMN role_at TIMESTAMPTZ;
UPDATE conversation_members SET role_at = joined_at;
ALTER TABLE conversation_members
    ALTER COLUMN role_at SET NOT NULL,
    ALTER COLUMN role_at SET DEFAULT now();
