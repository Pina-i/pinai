-- The account's history passphrase in generations (identity-provider/specs/e2ee.md § 3.6–3.8):
-- one row per account, none until its first device sets generation 1. Each generation has its
-- own salt, and two values the client derives from its HAK — the server only keeps them: the
-- check value, HMAC-SHA256(key = HAK, message = "pinai/history-archive/check-v1"), and the
-- approval public key, the Ed25519 public key whose 32-byte seed is
-- HKDF-SHA256(ikm = HAK, info = "pinai/device-approval/v1"), with no salt (§ 3.7). set_by_device
-- is the device the setting session named.
CREATE TABLE history_keys (
    user_id             UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    generation          INTEGER NOT NULL CHECK (generation > 0),
    salt                BYTEA NOT NULL CHECK (length(salt) = 16),
    check_value         BYTEA NOT NULL CHECK (length(check_value) = 32),
    approval_public_key BYTEA NOT NULL CHECK (length(approval_public_key) = 32),
    set_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    set_by_device       UUID REFERENCES user_devices(device_id) ON DELETE SET NULL
);

-- The generation each device says it holds.
ALTER TABLE user_devices
    ADD COLUMN history_generation INTEGER CHECK (history_generation > 0);

-- The archive holds the current generation's entries only, and the existing ones have none: no
-- generation, no check value — which only a device can compute. Their salts go with them.
DELETE FROM history_messages;
ALTER TABLE users DROP COLUMN history_archive_salt;
