-- Each device's HPKE public key, which the account's other devices encrypt to, and its root key's
-- signature over it (identity-provider/specs/e2ee.md § 3.3). Signed by the root key, so never
-- without one.
ALTER TABLE user_devices
    ADD COLUMN hpke_public_key    BYTEA,
    ADD COLUMN hpke_key_signature BYTEA,
    ADD CONSTRAINT user_devices_hpke_key_signed CHECK (
        (hpke_public_key IS NULL) = (hpke_key_signature IS NULL)
        AND (hpke_public_key IS NULL OR drk_public_key IS NOT NULL)
    );
