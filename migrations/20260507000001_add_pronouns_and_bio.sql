-- Adds optional self-declared profile fields to users.
--
-- pronouns is constrained at the DB level to a closed enum (CHECK rather than
-- a Postgres ENUM type so adding a new value later is a single ALTER … CHECK
-- instead of `ALTER TYPE`).
-- bio is freeform short text; the server enforces the ≤ 190 char ceiling.

ALTER TABLE users
    ADD COLUMN pronouns TEXT,
    ADD COLUMN bio      TEXT;

ALTER TABLE users
    ADD CONSTRAINT users_pronouns_check
    CHECK (pronouns IS NULL OR pronouns IN ('he', 'she', 'non-binary'));
