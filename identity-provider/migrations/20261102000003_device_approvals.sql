-- Approvals (identity-provider/specs/e2ee.md § 3.9): a signature over PINAI-DEVICE-APPROVAL-v1
-- bytes binding a device to its root key, by another device's root key or by a generation's
-- approval key — exactly one of approver_device_id and generation. One per approved device and
-- approver. drk_public_key is the root key the approval binds: a new root key drops the device's
-- approvals, and those it signed, in the same write.
CREATE TABLE device_approvals (
    device_id          UUID NOT NULL REFERENCES user_devices(device_id) ON DELETE CASCADE,
    drk_public_key     BYTEA NOT NULL CHECK (length(drk_public_key) = 32),
    approver_device_id UUID REFERENCES user_devices(device_id) ON DELETE CASCADE,
    generation         INTEGER CHECK (generation > 0),
    signature          BYTEA NOT NULL CHECK (length(signature) = 64),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((approver_device_id IS NULL) <> (generation IS NULL)),
    CHECK (approver_device_id IS DISTINCT FROM device_id)
);
CREATE UNIQUE INDEX device_approvals_by_device
    ON device_approvals (device_id, approver_device_id) WHERE approver_device_id IS NOT NULL;
CREATE UNIQUE INDEX device_approvals_by_passphrase
    ON device_approvals (device_id, generation) WHERE generation IS NOT NULL;
CREATE INDEX device_approvals_of_device ON device_approvals (device_id);
CREATE INDEX device_approvals_signed_by
    ON device_approvals (approver_device_id) WHERE approver_device_id IS NOT NULL;

-- The approval handshake's relay (§ 3.10): a device asks to be approved, the first other device
-- to post answers it. Kept an hour after it opened, so the account's hourly count holds.
CREATE TABLE approval_requests (
    id                 UUID PRIMARY KEY,
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id          UUID NOT NULL REFERENCES user_devices(device_id) ON DELETE CASCADE,
    approver_device_id UUID REFERENCES user_devices(device_id) ON DELETE CASCADE,
    created_at         TIMESTAMPTZ NOT NULL,
    expires_at         TIMESTAMPTZ NOT NULL,
    closed_at          TIMESTAMPTZ,
    CHECK (approver_device_id IS DISTINCT FROM device_id)
);
-- One request a device not closed yet: a new one closes the one before.
CREATE UNIQUE INDEX approval_requests_one_per_device
    ON approval_requests (device_id) WHERE closed_at IS NULL;
CREATE INDEX approval_requests_by_account ON approval_requests (user_id, created_at);

-- The messages relayed over a request, opaque here.
CREATE TABLE approval_messages (
    request_id UUID NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
    seq        INTEGER NOT NULL CHECK (seq > 0),
    device_id  UUID NOT NULL REFERENCES user_devices(device_id) ON DELETE CASCADE,
    body       BYTEA NOT NULL CHECK (length(body) BETWEEN 1 AND 4096),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (request_id, seq)
);
