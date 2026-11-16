-- Each conversation's newest MLS GroupInfo (identity-provider/specs/e2ee.md § 5): what a device of a
-- member's with none of its devices left in the group joins it by, with an external commit. One
-- row a conversation, replaced only by a later epoch's, from a commit stored here. Opaque, as the
-- commits are.
CREATE TABLE mls_group_infos (
    conversation_id UUID PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
    epoch           BIGINT NOT NULL CHECK (epoch >= 0),
    group_info      BYTEA NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
