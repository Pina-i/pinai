-- The E2EE device each session signed in, and the reasons tied to devices
-- (identity-provider/specs/auth.md § 1, "Sessions and devices").
ALTER TABLE sessions
    ADD COLUMN device_id UUID REFERENCES user_devices(device_id) ON DELETE SET NULL,
    DROP CONSTRAINT sessions_revoked_reason_check,
    ADD CONSTRAINT sessions_revoked_reason_check CHECK (revoked_reason IN (
        'sign_out', 'replaced', 'reuse', 'device_revoked', 'signed_out_elsewhere'
    ));
CREATE INDEX sessions_device_id ON sessions (device_id) WHERE device_id IS NOT NULL;
