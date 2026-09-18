-- Per-device metadata for the Settings → Devices view (Phase 6b).
--
-- The client already publishes a `device_id` UUID on every KeyPackage. Until
-- now the server only used it as an opaque key for stash bookkeeping. This
-- table adds the human-readable bits (name, kind), pairing/last-seen
-- timestamps, and an explicit revoked flag so the UI can render a device
-- list, surface "last seen X min ago", and let users sign out forgotten
-- devices.
--
-- The display name + kind are auto-detected from the User-Agent header at
-- first publish; the user-editable rename UX is a future follow-up.

CREATE TABLE user_devices (
    device_id      UUID PRIMARY KEY,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    display_name   TEXT NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('laptop','phone','tablet','unknown')),
    paired_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at     TIMESTAMPTZ
);

CREATE INDEX idx_user_devices_user ON user_devices(user_id);

-- Backfill from existing `key_packages` rows so accounts that registered
-- before this migration still show up in their own Devices view. The
-- earliest KeyPackage's `created_at` stands in for `paired_at`. Display
-- name / kind default to "Web client" / "unknown" since the original UA
-- isn't recorded — once these devices publish a new KP after the upgrade
-- the upsert path in `POST /api/keys/packages` will refresh `last_seen_at`
-- (but won't overwrite the legacy name, by design).
INSERT INTO user_devices (device_id, user_id, display_name, kind, paired_at, last_seen_at)
SELECT
    device_id,
    user_id,
    'Web client'                  AS display_name,
    'unknown'                     AS kind,
    MIN(created_at)               AS paired_at,
    MAX(created_at)               AS last_seen_at
FROM key_packages
GROUP BY device_id, user_id
ON CONFLICT (device_id) DO NOTHING;
