-- The last time step whose TOTP code an account used: a code is accepted once, and only for a
-- later step than the last (RFC 6238 § 5.2).
ALTER TABLE users ADD COLUMN totp_last_step BIGINT;
