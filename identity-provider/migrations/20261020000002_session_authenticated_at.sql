-- When the account's password was last typed on each session: what a sensitive action asks to be
-- recent (identity-provider/specs/auth.md § 1, "Sensitive actions").
ALTER TABLE sessions ADD COLUMN authenticated_at TIMESTAMPTZ;
UPDATE sessions SET authenticated_at = created_at;
ALTER TABLE sessions ALTER COLUMN authenticated_at SET NOT NULL;
