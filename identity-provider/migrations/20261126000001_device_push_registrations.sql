-- Where each device's push notices go: the relay its app names and the token the relay gave it
-- (identity-provider/specs/push.md). Set and removed by the device's own session; a revoke deletes
-- it in the same write.
CREATE TABLE device_push_registrations (
    device_id  UUID PRIMARY KEY REFERENCES user_devices(device_id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    relay      TEXT NOT NULL CHECK (octet_length(relay) BETWEEN 1 AND 512),
    token      TEXT NOT NULL CHECK (octet_length(token) BETWEEN 1 AND 512),
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_device_push_registrations_user ON device_push_registrations(user_id);
