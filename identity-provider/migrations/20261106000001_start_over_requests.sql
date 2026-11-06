-- Start over requests (identity-provider/specs/e2ee.md § 3.12): a device not approved under the
-- account's generation asks to set the next one. When it may is computed at each read from the
-- approved devices' sessions, never stored. One open an account; ended_reason says how it ended.
-- Kept a week after it ended, so its device reads how, and the account's daily count holds.
CREATE TABLE start_over_requests (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id    UUID NOT NULL REFERENCES user_devices(device_id) ON DELETE CASCADE,
    generation   INTEGER NOT NULL CHECK (generation > 0),
    created_at   TIMESTAMPTZ NOT NULL,
    ended_at     TIMESTAMPTZ,
    ended_reason TEXT CHECK (ended_reason IN
        ('cancelled', 'withdrawn', 'used', 'superseded', 'revoked', 'approved')),
    CHECK ((ended_at IS NULL) = (ended_reason IS NULL))
);
CREATE UNIQUE INDEX start_over_requests_one_open
    ON start_over_requests (user_id) WHERE ended_at IS NULL;
CREATE INDEX start_over_requests_by_account ON start_over_requests (user_id, created_at);
CREATE INDEX start_over_requests_by_device ON start_over_requests (device_id, created_at);
CREATE INDEX start_over_requests_ended ON start_over_requests (ended_at) WHERE ended_at IS NOT NULL;
