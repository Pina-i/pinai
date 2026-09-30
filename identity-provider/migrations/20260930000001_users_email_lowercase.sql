-- An address is one account whatever its case: kept lowercase, and unique as such.
-- Two accounts whose addresses differ only in case stop this migration: merge them first.
UPDATE users SET email = lower(email) WHERE email <> lower(email);

CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));
