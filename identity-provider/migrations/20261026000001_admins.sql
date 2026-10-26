-- The instance's admins, and the accounts let in without confirming their address — the first
-- admin among them (identity-provider/specs/auth.md § 4).
ALTER TABLE users
    ADD COLUMN is_admin    BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN admitted_at TIMESTAMPTZ;
