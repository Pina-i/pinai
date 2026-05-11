# MLS E2EE — Implementation Plan

Sequencing the work for the design in
[`specs/05-e2ee.md`](../../specs/05-e2ee.md). Six phases. Each phase is
independently mergeable: it leaves the system in a working state, even if
the user-facing E2EE story isn't complete until the last phase lands.

## Phase summary

| # | Phase | Scope | Effort | Mergeable on its own? |
|---|---|---|---|---|
| 1 | Key directory backend | Tables + REST endpoints for identity keys, KeyPackages, Recovery Key | M | Yes (no clients use it yet) |
| 2 | MLS Delivery Service backend | Tables + endpoints for commits / welcomes; AP envelope routing | M | Yes |
| 3 | Wire-format migration | `direct_messages.mls_ciphertext`; thread through REST/WS/AP | S | Yes (server can carry opaque bodies even if no client speaks MLS) |
| 4 | Web-client crypto core | MLS library integration, MSK/SSK/USK generation, IndexedDB storage, pairing flow, Recovery Key wrap/unwrap | **L** (the hard one) | Behind a feature flag; nothing in the UI calls it yet |
| 5 | Encrypted message + attachment paths | Replace plaintext send/receive/edit/react/attach paths with their MLS-encrypted equivalents | M | Yes — flips the app from no-E2EE to E2EE |
| 6 | UI surface | Onboarding, fingerprint verification, devices screen, identity-change warnings, Recovery Key onboarding, encrypted badges | M | Yes |

Total estimated effort: roughly 3–4× the message-attachments feature's
scope. Phase 4 is the dominant cost and the dominant risk.

---

## Phase 1 — Key directory backend

### Goal

Stand up the IdP-side surfaces for publishing and serving identity keys,
KeyPackages, and the optional Recovery Key blob. Nothing crypto-heavy on
the server side — just opaque storage + auth + rate limits.

### Tasks

1. **Migration** `20260508000001_mls_key_directory.sql`:
   - `user_identity_keys` (PK = user_id, public-only material).
   - `key_packages` (one row per single-use bundle, indexed for "available unexpired by user").
   - `recovery_blobs` (PK = user_id, opt-in passphrase-wrapped MSK).
2. **New crate** `crates/e2ee/`:
   - `e2ee::repos` — three repos mirroring the new tables.
   - `e2ee::keys` — endpoint handlers + DTOs.
   - Cargo deps: `axum`, `sqlx`, `serde`, `idp-state`, `idp-federation` (for HTTP-Sig), `idp-db`. No MLS library at this stage.
3. **Endpoints** wired into `crates/server/src/router.rs`:
   - `POST /api/keys/identity` (Bearer)
   - `GET /api/keys/identity/:actor_uri` (Bearer for local user, HTTP-Sig for peer IdP — reuse `verify_http_signature`)
   - `POST /api/keys/packages` (Bearer)
   - `POST /api/keys/packages/claim` (Bearer **or** HTTP-Sig)
   - `GET /api/keys/packages/status` (Bearer)
   - `PUT /api/keys/recovery` (Bearer)
   - `GET /api/keys/recovery` (Bearer)
   - `DELETE /api/keys/recovery` (Bearer)
4. **Rate limits** on `claim`: 60 / minute per requester (Bearer or HTTP-Sig peer). Implementation: in-memory token bucket keyed by requester id. Excessive bursts → `429`.
5. **Stash sizing** — config + handler enforcement:
   - `E2EE_KEYPACKAGE_CAP_PER_DEVICE = 100` — `POST /api/keys/packages` rejects any upload that would push the device's unconsumed count above this.
   - `E2EE_KEYPACKAGE_REFILL_THRESHOLD = 20` — `GET /api/keys/packages/status` returns a `needs_refill` flag per device when the count drops to this or below; clients use it to top up.
   - `E2EE_KEYPACKAGE_LIFETIME_DAYS = 30` — server validates that `expires_at - created_at ≤ 30 days` on upload.
   - All three loaded via `idp_config::Config` so operators can tune.
6. **Atomic claim**: `UPDATE … SET consumed_at = now() WHERE id = (SELECT id FROM key_packages WHERE user_id = $1 AND device_id = $2 AND consumed_at IS NULL AND expires_at > now() ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING *` — single round-trip, race-free.
7. **Background sweep**: extend the existing orphan-sweep task to also delete `key_packages` rows with `expires_at < now() - interval '1 day'`. Garbage-collection only.
8. **Tests**: integration tests for happy paths + race on `claim` + HTTP-Sig peer fetch + cap-enforcement (101st upload rejected). Use the existing fixture pattern.
9. **CLAUDE.md endpoint table**: add the eight new rows.

### Deliverables

- One PR adding the migration, the crate, the routes, and the tests.

### Exit criteria

- Bearer-authenticated user can publish identity keys + a stash of KeyPackages.
- A peer IdP can fetch identity keys + claim a KeyPackage via HTTP Signatures.
- Recovery Key roundtrips (PUT → GET → DELETE).
- Concurrent `claim` requests on the same user/device never return the same row twice (proven by a stress test).
- Server rejects an upload that would exceed `E2EE_KEYPACKAGE_CAP_PER_DEVICE`; rejects a KeyPackage whose lifetime exceeds `E2EE_KEYPACKAGE_LIFETIME_DAYS`.

### Risks / decisions still open

- **KeyPackage size cap on upload.** Need a sane upper bound to prevent storage abuse. ~16 KiB per blob is generous.

---

## Phase 2 — MLS Delivery Service backend

### Goal

Stand up the commit log + welcome dispatch. Server is opaque to the contents — it just orders, persists, and routes blobs.

### Tasks

1. **Migration** `20260508000002_mls_delivery_service.sql`:
   - `mls_commits` with `UNIQUE(conversation_id, epoch)`.
   - `mls_welcomes` with `consumed_at` so the server stops handing one out twice.
   - Indexes for the catch-up query.
2. **New module** `crates/e2ee/src/ds.rs`:
   - Repos.
   - Endpoint handlers.
3. **Endpoints**:
   - `POST /api/mls/groups/:conversation_id/commits` (Bearer): atomically insert at `epoch = max(epoch) + 1`. If a row at that epoch already exists, return `409 Conflict` with the winning commit body in the response.
   - `GET /api/mls/groups/:conversation_id/commits?since=:epoch` (Bearer): keyset pagination by epoch, returns the gap.
   - `GET /api/mls/welcomes` (Bearer): fetch all unconsumed welcomes targeted at any of the caller's devices, mark `consumed_at = now()` in the same transaction.
4. **AP envelope routing**: extend `crates/federation/src/inbox.rs` to dispatch on `Note.mediaType`:
   - `application/mls` + commit/welcome/application discriminator → forward to the e2ee crate's inbound handler.
   - The handler:
     - If commit → insert into `mls_commits` (409 on conflict; reply with conflict body).
     - If welcome → insert into `mls_welcomes` for the targeted user/device.
     - If application message → write through to the existing DM-write path (shared with Phase 3).
5. **Outbound AP** for cross-IdP commits and welcomes: same `tokio::spawn` best-effort pattern as DMs. Live alongside `propagate_profile_update` in `federation::profile` or a new `federation::mls`.
6. **WS push**: when a commit / welcome / application message lands, push to local recipients via the existing `WsHub`. New `WsEvent` variants:
   - `MlsCommit { conversation_id, epoch, blob }`
   - `MlsWelcome { conversation_id, blob }`
   - (Application messages reuse `NewDm` per Phase 3.)
7. **Tests**: concurrent-commit race, cross-IdP delivery via the inbox handler, welcome dispatch + consume.
8. **CLAUDE.md** endpoint table updates.

### Deliverables

- One PR. Migration + new module + AP inbox routing.

### Exit criteria

- Two simulated clients on the same IdP can exchange a Commit + Welcome via the new endpoints.
- Two clients on different IdPs (in test) can exchange via AP.
- 409 is returned (with body) when two commits race for the same epoch.

### Risks / decisions still open

- **AP wire format ambiguity.** Should commits travel as `mediaType: application/mls; type=commit` or via the discriminator inside the MLSMessage struct? Going with the latter (RFC 9420's `wire_format` field) to keep the AP envelope shape stable.
- **Welcome size**. KeyPackages can be a few KB; welcomes carry epoch state. Cap the wire size at, say, 256 KiB to prevent abuse.

---

## Phase 3 — Wire-format migration (aggressive — pre-deployment)

### Goal

Make the server *only* speak MLS-ciphertext for messages. No plaintext fallback, no compatibility shim. Pre-deployment treatment: assume the database is empty and the API can break clients between phases.

After this phase, the messaging API rejects any send that doesn't carry `mls_ciphertext`. The web client can't produce one yet — that lands in Phase 4 — so messaging is effectively offline between Phase 3 and Phase 4 shipping. Acceptable in pre-deployment.

### Tasks

1. **Migration** `20260508000003_direct_messages_mls.sql`:
   - `ALTER TABLE direct_messages DROP COLUMN content;`
   - `ALTER TABLE direct_messages ADD COLUMN mls_ciphertext BYTEA NOT NULL;` (no DEFAULT — DB is empty, so it just works).
   - `DROP TABLE message_reactions;` — reactions move into the MLS application stream from day one; no server-side reaction state remains.
2. **Schema/DTO updates**:
   - `idp_db::models::DirectMessage`: drop `content: String`, add `mls_ciphertext: Vec<u8>`.
   - `messaging::MessageResponse` and `realtime::DmPayload`: same swap. Wire format is base64 over JSON for `mls_ciphertext`.
   - `idp_db::models::DirectMessageWithReply` likewise. Reply preview is no longer fetched server-side — `reply_to_id` stays plaintext (server uses it for routing) but `reply_to_content` / `reply_to_sender` columns are removed from the JOIN; clients reconstruct previews from their decrypted MLS stream.
3. **REST send path** (`POST /api/dm`): require `mls_ciphertext` in the body; reject with `400` if absent.
4. **WS send path** (`send_dm`): require `mls_ciphertext` in `SendDmPayload`; the `content: String` field is removed from the type.
5. **REST edit path** (`PATCH /api/dm/:message_id/edit`): replaces row's `mls_ciphertext` and stamps `edited_at`. The new content lives inside the new ciphertext.
6. **REST reactions paths**: delete the endpoints `POST /api/dm/:message_id/reactions` and `DELETE /api/dm/:message_id/reactions` and their handlers / repos. Reactions are now MLS application messages of `kind = "reaction"`, indistinguishable from text messages on the wire.
7. **Federation outbound**: when serializing a `Create{Note}` activity, set `mediaType: application/mls` and put the base64'd `mls_ciphertext` in `content` (Note.content is a string field — fine for base64).
8. **Federation inbound** (`federation::inbox::handle_create_note`): require `mediaType: application/mls`; reject any incoming Note without it (peer must run an MLS-capable build). Write `mls_ciphertext` into the new column.
9. **WS event payload type** in `web-client/src/domain/models/ws.ts`: drop `content`, replace with `mls_ciphertext: string` (base64).
10. **Spec 03 update**: rewrite the relevant sections of `specs/03-direct-messages.md` to reflect the schema change (no more `content` column, no more `message_reactions` table). Keep replies/edits/attachments sections — only their plaintext details move into the MLS body.
11. **Tests**: round-trip an opaque blob via REST + WS + AP and verify it lands in the `mls_ciphertext` column. Verify rejected sends without `mls_ciphertext` return `400`.

### Deliverables

- One PR. Backend only — but it breaks messaging until Phase 4 ships the client. Land Phase 3 and Phase 4 close together to minimise the offline window.

### Exit criteria

- `direct_messages.content` and `message_reactions` are gone from the schema.
- Server stores and federates opaque blobs only.
- Any plaintext send is rejected with `400`.

### Risks / decisions still open

None — the simplification eliminated the previous open question about timing the drop.

---

## Phase 4 — Web-client crypto core

### Goal

Build the **client-side** MLS engine and the supporting plumbing (key generation, IndexedDB persistence, pairing, Recovery Key wrap/unwrap), but don't yet wire it to the message UI. This phase ends with a green `e2ee.test.ts` suite and a hidden settings panel for inspection.

This is the hardest phase. Budget accordingly.

### Tasks

1. **Build the `openmls` WASM bundle** in a new repo-internal package `web-client/crypto/openmls-wasm/`:
   - Cargo project depending on `openmls` + `wasm-bindgen` + `serde-wasm-bindgen`.
   - Expose the minimal MLS surface we use: `MlsGroup` operations (create, add, remove, update, application encrypt/decrypt), `KeyPackage` build/parse, `Welcome` handling.
   - Build script: `wasm-pack build --release --target web --out-dir ../openmls-pkg`.
   - The `openmls-pkg/` directory is published as a workspace package consumed by the web-client via `import * as openmls from "@local/openmls-pkg"`.
   - One-time investment; subsequent phases just import the package.
2. **New module** `web-client/src/adapters/e2ee/`:
   - `mls.adapter.ts` — wraps the WASM bundle; exposes `init`, `createKeyPackage`, `processCommit`, `processWelcome`, `encryptApplication`, `decryptApplication`, `addMember`, `removeMember`, `update`, `exportSecret`.
   - `identity.adapter.ts` — MSK/SSK/USK generation, signing, fingerprint computation. Uses `@noble/curves` (Ed25519) for the user-controlled keys; MLS leaf keys come from `openmls`.
   - `storage.adapter.ts` — IndexedDB persistence of MLS group state + identity keys, encrypted at rest by a device-bound non-extractable key (Web Crypto `subtle.generateKey` + `wrapKey`).
3. **Domain ports** under `web-client/src/domain/ports/`:
   - `IE2eePort` — high-level operations: `register()`, `pair(qr_payload)`, `addContactToGroup(actor_uri, conversation_id)`, `encryptOutbound(conversation_id, ApplicationMessage)`, `decryptInbound(conversation_id, ciphertext)`, `revokeDevice(device_id)`.
4. **Domain use cases** under `domain/usecases/e2ee/`:
   - `register-identity.usecase.ts` (first-time MSK generation + publish via `POST /api/keys/identity` + initial KeyPackage stash via `POST /api/keys/packages`).
   - `pair-device.usecase.ts` (QR + SPAKE2 flow).
   - `setup-recovery-key.usecase.ts`.
   - `recover-from-passphrase.usecase.ts`.
   - `revoke-device.usecase.ts`.
   - `replenish-keypackages.usecase.ts` — background task; polls `GET /api/keys/packages/status`, refills when `needs_refill` is `true`, capping uploads to keep the server's count at the configured maximum.
5. **PAKE for pairing**: SPAKE2 implemented as a thin wrapper over `@noble/curves` (Ed25519 / X25519 group operations). Roughly 200 lines + tests against the spec test vectors.
6. **Argon2id for Recovery Key**: `argon2-browser` (npm). Recommended params from spec § 9: `m = 64 MiB, t = 3, p = 4`.
7. **Identity verification utility**: compute the 60-character base32 fingerprint over the MSK public key. Expose as a `useFingerprint(actor_uri)` hook backed by a `Map<actor_uri, fingerprint>` in the auth slice.
8. **Tests**:
   - WASM unit tests in the `openmls-wasm` Cargo project (group create/add/remove/update/encrypt/decrypt happy paths).
   - JS integration tests in `web-client/test/e2ee.spec.ts` simulating Alice + Bob in two browser contexts (Vitest with `@vitest/web-worker`); exchange a 2-member group commit + welcome + application message; assert decryption matches.
9. **Hidden debug panel** at `/settings/e2ee-debug` (gated on `import.meta.env.DEV`) showing: MSK fingerprint, paired devices, KeyPackage stash counts, last commit epoch per group. Useful for debugging, not for end users.

### Deliverables

- Two PRs:
  - **4a**: the `openmls-wasm` Cargo project + build pipeline + WASM unit tests. ✅ **Landed.** `web-client/crypto/openmls-wasm/` (Cargo project, pinned `openmls 0.8.1` + matching deps, single ciphersuite `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`). Wrapper exposes `Provider`, `Identity`, `KeyPackage`, `Group` (`create_new` / `join` / `add_member` / `remove_member` / `update` / `merge_pending_commit` / `encrypt_application` / `process_message` / `export_secret` / `export_ratchet_tree` / `epoch`). 5 native unit tests cover the happy paths (two-member round trip, three-member fanout, remove advances epoch, self-update advances epoch, exported secrets match). `wasm-pack build --release` produces a 1.5 MiB bundle at `web-client/crypto/openmls-pkg/`.
  - **4b foundation**: the JS adapters wired into `IE2eePort`, plus the two non-recovery non-pairing use cases. ✅ **Landed.**
    - `web-client/src/adapters/e2ee/`: `mls.adapter.ts` (façade over `openmls-wasm`), `identity.adapter.ts` (`NobleIdentityAdapter` — Ed25519 MSK/SSK/USK via `@noble/curves`, SHA-512-based 60-char base32 fingerprint), `storage.adapter.ts` (`IndexedDbStorageAdapter` — encrypted at rest by a non-extractable AES-256-GCM CryptoKey), `key-directory.adapter.ts` (REST client for the eight `/api/keys/*` and three `/api/mls/*` endpoints), `e2ee.adapter.ts` (top-level `IE2eePort` impl).
    - `web-client/src/domain/{models,ports}/e2ee.{ts,port.ts}` + `usecases/e2ee/{register-identity,replenish-keypackages}.usecase.ts`.
    - IoC wiring in `src/ioc/index.ts` (`getE2eePort()`).
    - `vitest.config.ts` + `test/e2ee.spec.ts` — Vitest under jsdom, loads the real `openmls-wasm` bundle, drives identity + a two-member MLS round trip end-to-end. 6 tests green; type-check clean for every E2EE file.
  - **4b — Recovery Key**: ✅ **Landed.** `recovery.adapter.ts` (Argon2id via `@noble/hashes/argon2.js`, XChaCha20-Poly1305 via `@noble/ciphers`, AAD-tagged), `setup-recovery-key.usecase.ts`, `recover-from-passphrase.usecase.ts`. Recovery PUT/GET/DELETE on `key-directory.adapter.ts`. `IdentityAdapter.recoverFromMsk` rebuilds the keypair from a decrypted MSK + fresh SSK/USK.
  - **4b — Pairing**: ✅ **Landed.** `spake2.ts` (SPAKE2 over Ristretto255 via `@noble/curves`; M/N derived from labels via `ristretto255_hasher.hashToCurve`), `pairing.adapter.ts` (`PairingInitiator` + `PairingResponder` classes, AEAD-sealed `IdentityKeypair` bundle), `pair-device.usecase.ts` with a transport-agnostic `PairDeviceTransport` port, `revoke-device.usecase.ts` (calls into the still-deferred port method). 11 tests across `spake2.spec.ts` + `pairing.spec.ts`. The peer-facing key-package status endpoint is deferred to Phase 5 (the question of "calling IdP picks the device vs. server picks any device" belongs with the messaging integration).
  - **4b — UI surface**: ✅ **Landed.** `useFingerprint(actorUri)` hook + `e2ee.slice.ts` (cleared on `clearSession`), debug panel at `/_authenticated/settings/e2ee-debug` gated on `import.meta.env.DEV`. `getPeerFingerprint` on `IE2eePort` for the hook's peer path (validates SSK+USK chain before fingerprinting).
- **`revokeDevice`** still throws — its per-group MLS Update commits need the Phase 5 messaging integration to enumerate the user's active conversations.

### Exit criteria

- The WASM bundle builds in CI on Linux + macOS.
- Two clients (in tests) can establish a 2-member group, exchange messages, decrypt them.
- A new device pairing via QR completes in under 2 s on dev hardware.
- Recovery Key roundtrips (set passphrase → wrap → upload → erase → fetch → unwrap → restore).
- Device revocation propagates a Commit excluding the revoked leaf, and subsequent messages encrypted in the new epoch fail to decrypt on the revoked leaf.

### Risks / decisions still open

- **`openmls` API surface stability.** The crate is on a 0.x release line; minor bumps may break the wrapper. Pin a specific version in `Cargo.toml` and treat upgrades as a tracked task.
- **WASM bundle size.** `openmls` + dependencies likely produce a 1–3 MiB WASM artefact. Acceptable; lazy-load behind a route boundary so the public landing page doesn't pay the cost.
- **IndexedDB security**. Browser sandboxing protects against most threats but not against XSS in our own code. Mitigation: strict CSP, no inline scripts, audit any third-party JS we pull in.
- **SPAKE2 implementation correctness**. Test against the IETF test vectors (RFC 9382 appendix). If we miss something subtle, pairing handshakes silently produce mismatching keys — symptom is "pairing fails with wrong-fingerprint" rather than a security hole, but bothersome.

---

## Phase 5 — Wire client crypto into the messaging paths

### Goal

Connect the crypto layer built in Phase 4 to the existing `ConversationPage`, `MessageItem`, attachment pipeline, etc. No rip-and-replace dance — Phase 3 already removed the plaintext server paths, and Phase 4 already built the crypto adapters. This phase just calls the new adapters at the right moments in the existing UI plumbing.

### Tasks

1. **Send a text message**:
   - `ConversationPage.viewmodel.ts::sendMessage` — encode `ApplicationMessage{kind:"text", body}`, encrypt via `IE2eePort.encryptOutbound(conversation_id, msg)`, send `mls_ciphertext` over REST or WS.
   - Optimistic local insert keeps the plaintext locally so the optimistic UI path is unchanged.
2. **Receive a text message**:
   - `useIdpWebSocket.ts::new_dm` — decrypt `mls_ciphertext` via `IE2eePort.decryptInbound`, fold the recovered plaintext into the existing `Message` model.
   - `mapApiMessage` — decrypt history entries when fetched from REST.
   - Decryption failures (out-of-order MLS state, missing commit) trigger a one-shot fetch of missing commits via `GET /api/mls/groups/:id/commits?since=:epoch`, then retry.
3. **Reactions**: send/receive via `ApplicationMessage{kind:"reaction"}` in the MLS stream. Client maintains reaction state in its local store by replaying the stream — no server-side reaction rows (the table was removed in Phase 3).
4. **Edits**: send via `ApplicationMessage{kind:"edit"}` plus the existing `PATCH /api/dm/:message_id/edit` endpoint to stamp `edited_at`. Receive via the MLS stream; the latest `edit` for a `target_message_id` wins.
5. **Replies**: `reply_to_id` stays plaintext on the row (already the case after Phase 3); the preview travels as `ApplicationMessage{kind:"reply_meta"}` piggy-backed on the reply.
6. **Attachments**:
   - Composer: AES-256-GCM encrypt before upload. Existing upload pipeline doesn't change.
   - Display: decrypt on the client after `useAttachmentBlobUrl` returns the ciphertext.
   - `original_filename` and `mime_type` sent as `"encrypted"` / `application/octet-stream` to the API; real values travel inside the MLS body.
7. **Group create / add / remove flows**: hooked via the new `IE2eePort` operations, surfacing pending commits to the UI ("Adding Bob…").
8. **Tests**: full-loop integration test (browser + headless second client) sending an encrypted message, an encrypted attachment, and an edit, with full decryption verification.

### Deliverables

- One PR — wiring only, no protocol changes.

### Sub-turn status

- **5a foundation rewiring**: ✅ **Landed.** Domain models + DM port + WS payloads carry `mls_ciphertext` (base64); `dm-api.adapter.ts` reaction methods removed; `ConversationPage.viewmodel::sendMessage` encrypts via `encryptOutbound`; `useIdpWebSocket::new_dm` / `message_edited` decrypt with `[encrypted]` fallback; reactions / edits temporarily local-only pending 5c. Pre-existing `DmConversation.name` cleanup also done.
- **5b group bootstrap**: ✅ **Landed.** Backend: `claim` accepts `device_id = null` ("server picks"), new `claim_one_any_device` repo helper, new `POST /api/mls/welcomes` (Bearer-auth) for local welcome insert, `POST /api/dm` accepts optional client-pinned `conversation_id`. Client: `e2ee.adapter::addContactToGroup` is now real (claim + commit + welcome dispatch via `postLocalWelcome`); `ensureGroupExists` is idempotent and called by the viewmodel before encrypt; `consumePendingWelcomes` polls on login via the new `useConsumeMlsWelcomes` hook; first-message UUID pinning so client and server agree on `conversations.id`.
- **5b cleanup**: ✅ **Landed.** All four deferred items finished:
  - Zustand `persist` middleware for the message-plaintext cache (`dmMessages` + `dmUnread`), backed by a new `pinai-zustand-store` IndexedDB database, AES-256-GCM-encrypted at rest using the same non-extractable device key the E2EE storage adapter manages. Survives reloads — MLS forward secrecy no longer blanks conversation history on refresh.
  - `decryptInbound` accepts `{ idpUrl, accessToken }` and on failure pulls `GET /api/mls/groups/:id/commits?since=:epoch`, replays each commit, retries the decrypt once. Wired in WS `new_dm` / `message_edited` and the REST history load.
  - WS `mls_welcome_ready` event variant + `useIdpWebSocket` handler that fires `consumePendingWelcomes` on receipt — welcomes land within seconds instead of waiting for the next login poll.
  - `POST /api/mls/welcomes` routes remote recipients via AP: resolve the inbox (cache-first, WebFinger fallback), dispatch through `federation::mls::deliver_welcome_to_remote`. Same-IdP path unchanged.
- **5c reactions + edits + replies**: ✅ **Landed.** Reactions ride as `kind:"reaction"` rows on `direct_messages`; receivers project them via `applyReaction` (idempotent, dedup'd by reaction message id, persisted alongside `dmMessages`). Sender side encrypts + REST-sends the reaction message; optimistic toggle rolls back on failure. Edits use `kind:"edit"` MLS application messages over the existing `PATCH /api/dm/:id/edit` endpoint (replaces row's `mls_ciphertext`, server pushes `message_edited` WS event). Replies inline `reply_meta` on the text body — preview text + sender display name travel inside the encrypted body, only `reply_to_id` is server-visible. WS `new_dm` handler dispatches on decrypted `kind` to route text/reply vs. reaction. REST history `mapApiMessage` returns a discriminated `MappedRow` so the consumer can seed text and replay reactions in two passes.
- **5c.4 attachments**: ✅ **Landed.** Backend: `POST /api/attachments` accepts an optional `attachment_id` multipart form field (client-supplied UUID, paired with the single file part). Client: `attachment-crypto.ts` (`encryptForUpload` / `decryptDownloaded`), `upload-encrypted-attachment.usecase.ts` (encrypt, upload as `encrypted` + `application/octet-stream`, return AttachmentBlobKey), `Message.attachmentKeys?: Record<id, AttachmentBlobKey>` carries decryption material, `useAttachmentBlobUrl(id, key)` fetches ciphertext → decrypts → blob URL, `AttachmentFilmstrip` / `SingleImageAttachment` / `ImageLightboxDialog` consume the real filename + MIME from `attachmentKey` with placeholder fallback. AAD = attachment UUID per spec.
- **5d follow-ups**: ✅ **Landed.**
  - **`revokeDevice`**: leaf credentials embed `(actor_uri, device_id)` JSON in the BasicCredential; `Group.list_members()` exposed by the WASM wrapper; `MlsAdapter.findLeafByDeviceId` walks credentials; `e2ee.adapter::revokeDevice(idpUrl, token, actorUri, deviceId, conversationIds, opts?)` iterates the caller-supplied conversation list, posts one Remove commit per group, optionally clears the wrapped Recovery Key. Per-group failures logged + swallowed so one bad group doesn't block the rest.
  - **MLS group-state persistence**: WASM wrapper gains `Provider.serialize_storage()` / `Provider.deserialize_storage(bytes)` (length-prefixed `(key, value)` pairs over the openmls `MemoryStorage` HashMap) and `Group.load_from_provider(provider, group_id)` for rebuilding handles. New Rust test `provider_storage_round_trip_restores_group` proves a fresh provider can decrypt after restoring a snapshot. `IndexedDbStorageAdapter` adds an `mls_snapshot` store (DB v2), AES-256-GCM-encrypted under the same device key. `E2eeAdapter.ensureInitialized` restores once per session; every state-changing op (`createKeyPackage`, `encryptApplication`, `decryptInbound`, `addContactToGroup`, `consumePendingWelcomes`, `revokeDevice`) calls `persistMlsState()` afterwards.

  - **5d.1 Cross-IdP claim proxy**: ✅ **Landed.** New `idp_federation::delivery::signed_post_json<R>()` — generic HTTP-Sig signed JSON POST that mirrors the Cavage-spec signing path used by AP `deliver_activity`. `crates/e2ee/src/packages.rs::post_packages_claim` now dispatches on local-vs-remote: Bearer + remote → proxy via `proxy_claim_to_remote` (signs as the local user, hits the target IdP's `/api/keys/packages/claim`); Peer + remote → reject (no proxy chains); either + local → unchanged. Browser can no longer claim a remote KeyPackage from its own IdP — it always wins because the IdP federates server-side.
  - **5d.2 Full-loop integration test**: ✅ **Landed.** New `web-client/test/e2ee-integration.spec.ts` drives two `E2eeAdapter` instances (Alice + Bob) against an in-memory `IKeyDirectoryAdapter` + `E2eeStorage` stub. One test exercises register → `addContactToGroup` → `consumePendingWelcomes` → text send/receive → reaction → edit → encrypted attachment upload + receiver download/decrypt. Caught + fixed a real bug along the way: `JSON.stringify` turns the per-attachment `Uint8Array` key/nonce into indexed objects that Web Crypto rejects on decrypt. Fixed in `e2ee.adapter.ts` by adding a `Uint8Array` ↔ `@u8:<base64>` replacer/reviver pair around the `ApplicationMessage` serialise/deserialise boundary.

  - **5d.3 Client-side cross-IdP welcome dispatch**: ✅ **Landed.** The server already routed local-vs-remote on `POST /api/mls/welcomes` since 5b cleanup, but the client adapter still named the call `postLocalWelcome` and the `addContactToGroup` comment claimed "same-IdP DMs are the supported path" — both misleading. Renamed `IKeyDirectoryAdapter::postLocalWelcome` → `postWelcome` (interface + impl + in-memory test stub), refreshed the comment in `e2ee.adapter::addContactToGroup` to describe the IdP-side routing, and extended `test/e2ee-integration.spec.ts` to assert the welcome is tagged `remote` when Alice and Bob live on different issuers (plus a second `it` that asserts the `local` path when they share an issuer).

  Remaining 5d items (still open, lower priority):
  - **A second IdP running this build can interop** — needs a multi-instance smoke run + a few minor message-edited / reaction edge cases under federation.

### Exit criteria

- Sending a text message round-trips encrypted (server only sees ciphertext). ✅ (same-IdP, 5b)
- Reactions and edits round-trip encrypted. ✅ (5c)
- Attachments round-trip encrypted (filename + MIME hidden). ✅ (5c.4)
- Old plaintext code paths are gone (or behind a deprecated feature flag). ✅ (5a)
- A second IdP running this build can interop. (cross-IdP welcome wiring — 5d)

### Risks / decisions still open

- **What to do with conversations that lack an MLS group state at the moment Phase 5 ships.** Pre-deployment, none should exist. If any test data does, drop it.
- **Concurrent commit storms when groups grow large**. Worth a load test at this point.
- **Forward-secrecy makes REST history un-decryptable on reload.** 5b deferral: persist the in-memory plaintext cache to IndexedDB. Until then, `[encrypted]` placeholders show after page refresh.

---

## Phase 6 — UI surface

### Goal

Make E2EE legible and usable. Implements the UI requirements from `specs/05-e2ee.md § 11`.

### Tasks

1. **Onboarding flow** — modal at first login post-deployment:
   - "Generate identity" (default, single device).
   - "Pair with another device" (QR scan).
   - "Restore from Recovery Key" (passphrase entry).
   - "Set up Recovery Key" — passphrase + strength meter + literal "if you lose this passphrase, your account is unrecoverable" copy that the user must check a box to confirm understanding.
2. **Devices screen** under Settings → Devices:
   - List paired devices with leaf fingerprint (last 8 chars), last-seen, "this device" badge, "Revoke" button (only on others).
   - "Pair a new device" button → shows QR.
3. **Fingerprint verification UI** (per-contact):
   - In the conversation header → "Verify fingerprint" → modal showing 60-char base32 + a 12-block emoji visualisation + "Show as QR".
   - On confirm → USK signs contact's MSK; conversation header shows a small ✓ badge.
4. **Identity-change warning**:
   - When a contact's MSK fingerprint differs from the pinned one, show a non-dismissible modal blocking sends until acknowledged. Wording: "X's identity changed. This could be a routine new device — or someone impersonating them. Verify before continuing."
   - On acknowledge → re-pin.
5. **Encrypted badge** on every conversation in the sidebar + header. Subtle, not in-your-face.
6. **Pairing scanner** — camera-based QR scanner. Library: `@zxing/browser` or similar.
7. **Recovery Key change** flow under Settings → Security → "Change passphrase".
8. **Multi-device echo-decrypt rework**. Today `useIdpWebSocket::new_dm` skips the decrypt whenever `senderAddress === user.address` to suppress the "secret deleted to preserve forward secrecy" panic when a tab receives back its own ciphertext (MLS wipes the per-generation send-side key on `encrypt_application`). That gate is a single-device shortcut: once a user can pair a second device, the laptop must decrypt the phone's ciphertexts (different MLS leaf → different ratchet → recv-side key still present), and the current `isOwn` skip silently hides them. Replace with: always attempt decrypt; on success render; on failure if `isOwn` drop silently (same-leaf forward-secrecy wipe — there's nothing to recover); on failure if `!isOwn` push placeholder + warn. Suppress the catch-up retry log inside `decryptInbound` for the expected-fail case via either an `expectOwnFail?: boolean` caller flag (lighter-touch) or a wasm-bindgen "peek the framed-content sender" method that lets the adapter detect own-leaf ciphertext before attempting decrypt (more principled). Also revisit `client_id` propagation: only the WS-shortcut send path threads it today; `POST /api/dm` should accept + echo it too so the sender's tab can reconcile its optimistic via `isOwnEcho` regardless of transport.
9. **Tests**: viewmodel-level tests for each modal's state machine; manual QA checklist for the scanner + camera permissions.

### Deliverables

- One PR. Mostly presentation work.

### Exit criteria

- A new user can complete onboarding without reading any docs.
- A user can pair a second device end-to-end via QR.
- An identity-change warning is impossible to dismiss without explicit acknowledge.
- The "Devices" screen accurately reflects paired devices including revocation.

### Risks / decisions still open

- **Recovery Key UX copy**. This is where users hurt themselves; the wording matters more than the tech. Consider running it past someone outside the project before shipping.
- **Camera permission flow** on Safari (iOS PWA): notoriously finicky. May require a fallback "type the pairing code manually" path.

---

## Library decisions

### MLS — Rust (server)

**Not needed for Phase 1/2/3.** The server is opaque to MLS payloads — no validation, no parsing. We just store and route bytes. Postpone any MLS Rust dep until / unless we want server-side commit validation in the future (which would be a genuine feature flip).

### MLS — JavaScript / WASM (client) — **LOCKED**

Build our own WASM bundle from `openmls` (Apache-2.0 / MIT). Lives in
`web-client/crypto/openmls-wasm/` as a Cargo project; built via `wasm-pack`
into a workspace package consumed by the web client.

Rationale: the alternative (`@wireapp/core-crypto`) is GPL-3 in its npm
distribution, which we'd rather avoid for the web client. Building our own
bundle is a one-time investment; subsequent phases just import the package.
We pin a specific `openmls` minor and treat upgrades as deliberate work.

### Argon2id — JavaScript — **LOCKED**

`argon2-browser` (npm). WASM bundle of the reference implementation.
Recommended params from spec § 9: `m = 64 MiB, t = 3, p = 4`.

### PAKE — JavaScript — **LOCKED**

Hand-rolled SPAKE2 over `@noble/curves` (~200 lines + tests against
RFC 9382 appendix vectors). No vetted single-purpose JS lib exists; the
`openmls` route doesn't ship PAKE.

### Encryption-at-rest for IndexedDB

- Web Crypto `subtle.wrapKey` with a non-extractable AES-GCM key derived from a device-bound source. Browser wraps it; the wrapped form is what hits IndexedDB.

### QR code

- Generation: `qrcode` (npm).
- Scanning: `@zxing/browser` for the camera path.

---

## Cross-cutting concerns

### Migration ordering

Phases 1, 2, 3 ship migrations. Order matters:

1. Phase 1's tables are independent — can land first.
2. Phase 2's tables reference `conversations(id)` — already exists; safe to land after 1.
3. Phase 3's `direct_messages.mls_ciphertext` is additive — safe to land after 2.

All three can ship independently. Phase 5's deletion of plaintext columns ships only after Phase 5's client changes are deployed everywhere.

### Federation requirement

After Phase 5, peer IdPs must run an MLS-capable build to interop. Document this in `CLAUDE.md` as a deployment requirement. Pre-Phase-5 builds should error gracefully on unrecognised mediaType (already the inbox behaviour).

### Backwards compatibility within the dev cycle

During Phase 4–5, the plaintext path still works. Once Phase 5 lands and removes it, devs need to re-pair their dev devices and start fresh. Document.

### Observability

Each phase adds new failure modes. Plan dashboards / log queries for:
- KeyPackage stash low alerts (per device).
- 409 commit-conflict rate per group (storm detection).
- Welcome-pending count per recipient device.
- Encryption / decryption errors per conversation.

---

## Definition of done (for the whole feature)

- Every conversation in the app is end-to-end encrypted from creation; there is no plaintext path.
- A user can register on a fresh device, pair a second device via QR, opt into a Recovery Key, lose a device and revoke it, and recover after losing all devices via the Recovery Key.
- The IdP database, including a hostile DBA's view of every table and every Redis stream, contains no plaintext message content, reactions, edits, attachment filenames, or attachment MIME types.
- Cross-IdP conversations work between two Pina'i instances running this build.
- A user-visible identity-change warning appears within seconds of a contact's MSK rotation.

---

## What this plan deliberately does **not** include

- Sealed sender / metadata-privacy improvements (deferred per spec § 12).
- Mobile clients (no design surface yet).
- Search over message content (lost when going E2EE; out of scope to add back).
- Server-side commit validation (deferred until a use case demands it).
- Cross-DS group migration (a group changing DS as members move; deferred).

---

## What to do next session

Start Phase 1: write the migration SQL, scaffold the `e2ee` crate, and stub the eight endpoints. We can iterate on the request/response shapes once we have the skeleton.
