-- How the instance introduces itself, as an admin saved it in Settings → Instance: in force over
-- INSTANCE_NAME and INSTANCE_DESCRIPTION (identity-provider/specs/identity.md § 6). No row until
-- an admin first saves; NULL is the default (the domain, no description).
CREATE TABLE instance_intro (
    only_row    BOOLEAN PRIMARY KEY DEFAULT true CHECK (only_row),
    name        TEXT,
    description TEXT,
    updated_by  UUID REFERENCES users (id) ON DELETE SET NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);
