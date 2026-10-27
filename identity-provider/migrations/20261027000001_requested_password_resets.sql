-- Reset links an account asks for by mail, "Forgot your password?" on an open instance: no admin
-- made them (identity-provider/specs/auth.md § 7).
ALTER TABLE password_resets ALTER COLUMN created_by DROP NOT NULL;
-- The link that replaced this one, which gives it back when its own mail fails. No foreign key:
-- that link is deleted first, and the reference is only read to find this one.
ALTER TABLE password_resets ADD COLUMN replaced_by UUID;
-- The links an account asked for in the last hour are counted at each request.
CREATE INDEX password_resets_by_account ON password_resets (user_id, created_at);
