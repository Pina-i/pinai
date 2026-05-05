-- File attachments on direct messages.
--
-- A row exists in two phases:
--   1. orphan (message_id IS NULL) — uploaded but not yet attached to a message.
--      Reaped by a background sweep after `attachment_orphan_ttl`.
--   2. linked (message_id IS NOT NULL) — attached to a message.
--      Hard-deleted (along with the storage object) when the parent message is
--      soft-deleted.
--
-- For remote attachments received via federation, `remote_origin_url` points at
-- the origin IdP's HTTP-Signature-protected `/api/attachments/{id}/content`
-- endpoint; bytes never live in this IdP's bucket. `storage_key` is still set
-- (= id::text) for schema uniformity but no object exists in our bucket.
CREATE TABLE message_attachments (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id            UUID REFERENCES direct_messages(id),
    uploaded_by_actor_uri TEXT NOT NULL,
    storage_key           TEXT NOT NULL UNIQUE,
    mime_type             TEXT NOT NULL,
    byte_size             BIGINT NOT NULL CHECK (byte_size > 0),
    original_filename     TEXT NOT NULL,
    remote_origin_url     TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Used by the orphan-sweep background task (5-min cadence).
CREATE INDEX idx_message_attachments_orphan
    ON message_attachments (created_at)
    WHERE message_id IS NULL;

-- Used by GET /api/dm/{conv_id} response enrichment to load all attachments
-- for a page of messages.
CREATE INDEX idx_message_attachments_message_id
    ON message_attachments (message_id)
    WHERE message_id IS NOT NULL;
