-- A device's two names (identity-provider/specs/e2ee.md § 4): display_name stays the automatic
-- one, its client's or its User-Agent's; chosen_name is the one its user gave it, NULL until then,
-- and shown over the other. client tells the Pīna'i app from a browser.
ALTER TABLE user_devices
    ADD COLUMN chosen_name TEXT,
    ADD COLUMN client      TEXT NOT NULL DEFAULT 'unknown'
        CHECK (client IN ('app', 'browser', 'unknown'));
