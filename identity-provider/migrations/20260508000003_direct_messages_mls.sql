-- Phase 3 of MLS rollout: rip plaintext message content out of the schema.
-- Pre-deployment treatment — no backfill, no compatibility shim, no DEFAULT.
-- See specs/05-e2ee.md § 5 and docs/plans/2026-05-08-mls-e2ee-implementation.md.

-- 1) Drop the plaintext column. The MLS body lives in `mls_ciphertext` from
--    here on; reply previews and reaction state move into the encrypted
--    application stream.
ALTER TABLE direct_messages DROP COLUMN content;

-- 2) Add the opaque ciphertext column. NOT NULL with no DEFAULT — an empty
--    DB is the precondition (the user explicitly opted into "treat it as
--    if there's no data"). The server never inspects these bytes.
ALTER TABLE direct_messages ADD COLUMN mls_ciphertext BYTEA NOT NULL;

-- 3) Reactions are now MLS application messages (kind = "reaction") inside
--    the encrypted stream. Server-side reaction state is removed entirely;
--    each client replays its decrypted stream to compute reaction counts.
DROP TABLE message_reactions;
