-- Per-device identity attestation + history archive key derivation.
--
-- Drops deprecated user-level identity + recovery tables (user_identity_keys,
-- recovery_blobs) — these are pre-1.0 dev tables and contain no production data.
--
-- Extends user_devices with IdP-attested DRK (Device Root Key) columns so each
-- device carries a public key signed by the IdP that proves device ownership.
--
-- Adds history_archive_salt to users and history_messages table for server-side
-- encrypted-at-rest backup of DMs indexed by per-user, per-conversation. Ciphertexts
-- are opaque to the server — clients derive the History Archive Key via Argon2id
-- using the per-user salt.

-- 1. Drop deprecated user-level identity tables
DROP TABLE IF EXISTS user_identity_keys CASCADE;
DROP TABLE IF EXISTS recovery_blobs CASCADE;

-- 2. Extend user_devices with IdP attestation columns
--
--    drk_public_key:        raw DRK public key (Ed25519, 32 bytes)
--    attestation_signature: IdP signature over (device_id || drk_public_key)
--    attestation_kid:       Key ID of the IdP's signing key (for key rotation)
--    attestation_issued_at: when the signature was minted (device pairing time)
--    attestation_expires_at: when the attestation expires (optional, allows IdP to
--                           rotate/revoke device identities server-side)
ALTER TABLE user_devices
    ADD COLUMN drk_public_key         BYTEA,
    ADD COLUMN attestation_signature  BYTEA,
    ADD COLUMN attestation_kid        TEXT,
    ADD COLUMN attestation_issued_at  TIMESTAMPTZ,
    ADD COLUMN attestation_expires_at TIMESTAMPTZ;

-- 3. Per-user salt for History Archive Key derivation via Argon2id.
--    Each user's History Archive Key = Argon2id(passphrase, salt) where
--    passphrase is the 24-word BIP-39 mnemonic generated client-side on first
--    sign-in. The salt is not secret — its job is to slow offline brute-force
--    against a stolen archive. Set once (the POST /api/history/salt endpoint
--    is idempotent), so all of a user's devices derive the same HAK.
ALTER TABLE users
    ADD COLUMN history_archive_salt BYTEA;

-- 4. History backup archive — opaque ciphertexts, server can never decrypt.
--    Each device of the user, on decrypting an MLS application message, also
--    encrypts the plaintext under the HAK (AES-256-GCM, 12-byte nonce) and
--    uploads it here. Primary key (user_id, id) makes the batch upsert
--    idempotent — first decryptor of a given message wins; subsequent uploads
--    from the user's other devices no-op via ON CONFLICT DO NOTHING.
CREATE TABLE history_messages (
    id                UUID NOT NULL,
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    conversation_id   UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    ciphertext        BYTEA NOT NULL,
    nonce             BYTEA NOT NULL,
    client_message_id TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, id)
);

-- 5. Index for efficient history scans: (user_id, created_at DESC, id DESC)
--    allows keyset pagination without full table scans.
CREATE INDEX idx_history_messages_user_created
    ON history_messages(user_id, created_at DESC, id DESC);
