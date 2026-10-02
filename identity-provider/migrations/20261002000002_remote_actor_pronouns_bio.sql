-- The pronouns and bio another instance's account shows, as this instance last heard them: like
-- its name and avatar, they are public.
ALTER TABLE remote_actors
    ADD COLUMN pronouns TEXT CHECK (pronouns IN ('he', 'she', 'non-binary')),
    ADD COLUMN bio      TEXT;
