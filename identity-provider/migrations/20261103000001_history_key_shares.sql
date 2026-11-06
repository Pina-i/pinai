-- Key shares (identity-provider/specs/e2ee.md § 3.11): the account's history passphrase sealed by a
-- device holding it for a device of the account it approved with the code — HPKE to the
-- recipient's key, signed by the sender's root key, opaque here. One per recipient and generation: the first stored
-- stays. Deleted by a new generation, the recipient's report that it holds it, a revoke of either
-- device, a new root key of either, and a new HPKE key of the recipient.
CREATE TABLE history_key_shares (
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_device_id UUID NOT NULL REFERENCES user_devices(device_id) ON DELETE CASCADE,
    generation          INTEGER NOT NULL CHECK (generation > 0),
    sender_device_id    UUID NOT NULL REFERENCES user_devices(device_id) ON DELETE CASCADE,
    enc                 BYTEA NOT NULL CHECK (length(enc) = 32),
    ciphertext          BYTEA NOT NULL CHECK (length(ciphertext) BETWEEN 1 AND 1024),
    signature           BYTEA NOT NULL CHECK (length(signature) = 64),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (recipient_device_id, generation),
    CHECK (sender_device_id <> recipient_device_id)
);
CREATE INDEX history_key_shares_by_account ON history_key_shares (user_id);
CREATE INDEX history_key_shares_by_sender ON history_key_shares (sender_device_id);
