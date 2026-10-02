-- MLS key directory: per-user identity keys, KeyPackage stash, optional
-- passphrase-wrapped Recovery Key. See identity-provider/specs/e2ee.md.
--
-- The IdP holds public material only — every private key (MSK, SSK, USK,
-- per-device leaf) lives exclusively on user devices. The Recovery Key
-- ciphertext is opaque to the server; the Argon2id-derived KEK never leaves
-- the user's device.

-- Long-term per-user identity keys.
-- One row per user. Replaced atomically on rotation.
CREATE TABLE user_identity_keys (
    user_id        UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    msk_public     BYTEA NOT NULL,            -- Ed25519 public key, root of the user's chain
    ssk_public     BYTEA NOT NULL,            -- Ed25519, signs device-leaf credentials
    ssk_signature  BYTEA NOT NULL,            -- SSK signed by MSK
    usk_public     BYTEA NOT NULL,            -- Ed25519, signs other users' MSKs after verification
    usk_signature  BYTEA NOT NULL,            -- USK signed by MSK
    published_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Single-use KeyPackages. Each device maintains a stash; the server hands
-- one out per incoming "add to group" request and marks it consumed.
-- Cap, refill threshold, and lifetime are enforced at the handler layer
-- (see config: E2EE_KEYPACKAGE_*).
CREATE TABLE key_packages (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id    UUID NOT NULL,                  -- client-generated, opaque to server
    key_package  BYTEA NOT NULL,                 -- TLS-encoded MLS KeyPackage
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ,                    -- NULL = available; set when claimed
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Used by `POST /api/keys/packages/claim` (FOR UPDATE SKIP LOCKED) to find
-- one available unexpired KeyPackage; also by `GET /api/keys/packages/status`
-- for the per-device count.
CREATE INDEX idx_key_packages_available
    ON key_packages (user_id, device_id, expires_at)
    WHERE consumed_at IS NULL;

-- Used by the background sweep to delete expired rows. Plain (non-partial)
-- because Postgres requires partial-index predicates to be IMMUTABLE, and
-- `now()` is only STABLE — the sweep's secondary `consumed_at < now() - 1 day`
-- branch falls back to a seq scan, which is fine on this low-cardinality table.
CREATE INDEX idx_key_packages_gc
    ON key_packages (expires_at);

-- Wrapped MSK for opt-in account recovery. The IdP cannot decrypt without
-- the user's passphrase: the KEK is derived client-side via Argon2id.
CREATE TABLE recovery_blobs (
    user_id        UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    wrapped_msk    BYTEA NOT NULL,             -- XChaCha20-Poly1305 ciphertext of the MSK
    salt           BYTEA NOT NULL,             -- 32 bytes, unique per user
    argon2_params  JSONB NOT NULL,             -- { m_kib, t, p } — params at wrap time
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
