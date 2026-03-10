-- Add a short discriminator suffix to usernames (e.g. "alex-7G4K")
-- Generates a 4-char base36 (0-9 A-Z) suffix from the user's UUID bytes.
ALTER TABLE users
    ADD COLUMN handle_suffix TEXT NOT NULL DEFAULT '';

-- Backfill: derive a 4-char base36 suffix from the UUID's first 4 bytes.
-- We use bitwise ops on the UUID integer representation available in Postgres.
DO $$
DECLARE
    rec RECORD;
    n   BIGINT;
    suffix TEXT;
    chars TEXT := '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    i INT;
BEGIN
    FOR rec IN SELECT id FROM users LOOP
        -- Extract first 4 bytes of UUID as unsigned 32-bit integer
        n := ('x' || encode(substring(uuid_send(rec.id), 1, 4), 'hex'))::bit(32)::bigint & 4294967295;
        n := n % 1679616; -- mod 36^4 → range 0..1679615
        suffix := '';
        FOR i IN 1..4 LOOP
            suffix := substring(chars, (n % 36)::int + 1, 1) || suffix;
            n := n / 36;
        END LOOP;
        UPDATE users SET handle_suffix = suffix WHERE id = rec.id;
    END LOOP;
END $$;

-- Remove the default (new users must supply a suffix via app code)
ALTER TABLE users ALTER COLUMN handle_suffix DROP DEFAULT;

-- Enforce uniqueness: two users may share a display name only if suffixes differ
CREATE UNIQUE INDEX users_username_handle_suffix_idx
    ON users (username, handle_suffix);
