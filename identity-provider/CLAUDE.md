# CLAUDE.md — identity-provider

## What is Pina'i?

Pina'i is a self-hostable, federated, open-source Discord alternative built on ActivityPub,
developed under the GitHub organisation `Pina-i`.

This repo is **Layer 2** of a three-layer architecture:

| Layer | Repo | Role |
|---|---|---|
| 1 | `pina-i/web-client`, `pina-i/desktop-client` | React + Vite, Electron |
| **2** | **`pina-i/identity-provider` ← this repo** | OIDC, DMs, friends, ActivityPub federation |
| 3 | `pina-i/chat-server` | Community servers, JWT validation only |

Shared crates (JWT utils, HTTP Signatures, ActivityPub types, federation transport) live in
`crates/` at the monorepo root.

---

## What this service does

A single self-hostable Rust service that bundles:

1. **OIDC Provider** — user registration, authentication, JWT issuance
2. **Messaging Backbone** — friend graph, private DMs over WebSocket
3. **ActivityPub Federation** — federation with other identity-provider instances

A user's permanent identity is expressed as `alice@idp.alice.com`. This identity is portable
across all chat servers in the network.

---

## Tech stack

| Layer | Technology |
|---|---|
| Language | Rust (stable) |
| Web framework | Axum + Tokio |
| Database | PostgreSQL via SQLx |
| Auth protocol | OIDC / OAuth2 (Authorization Code + PKCE) |
| Token format | JWT (RS256, Ed25519) |
| Federation protocol | ActivityPub (W3C standard) |
| Inter-server auth | HTTP Signatures |
| Real-time | WebSockets + Redis (Streams + pub-sub) |
| Object storage | RustFS (S3-compatible) |
| Containerization | Docker / Docker Compose |

---

## Workspace structure (Cargo)

**Migration in progress.** The service is moving, one bounded context at a time, to hexagonal
layer crates — `domain`, `application`, `infrastructure`, `api` — following
`.claude/skills/rust-backend-architecture`, which applies to every Rust change. New code goes in
the layer crates; legacy crates only shrink. A legacy handler may call a new use case; a layer crate
reaches a legacy crate only from an `infrastructure` adapter wrapping a component not migrated yet.
Migrated so far: **account settings** (`PATCH /api/settings`, and the `settings` that `/userinfo`
and `PATCH /api/profile` return); **identity & addressing** — `domain::identity` (`Handle`,
`FederatedAddress`, `ActorUri`, `InstanceOrigin`, `Recipient`) is the only parser of addresses and
actor URIs, and legacy code reaches it through `AppState::origin` / `AppState::is_local_actor`;
**social graph** — the `/api/friends` routes (`api::social`) and the inbox's
`Follow` / `Accept` / `Reject` / `Undo{Follow}`, which call the `Receive*` use cases through
`AppState`; **messages** — `/api/dm*` and `POST /api/groups/:id/messages` (`api::messaging`), the
WebSocket `send_dm`, and the inbox's MLS application messages, edits and group rosters, which call
`application::messaging` use cases through `AppState`; **group management** —
`/api/groups*` (`api::groups`); **attachments** — `/api/attachments*` (`api::attachments`), the
peer-facing `/content` endpoint, which calls `ServePeerContent` through `AppState`, and the orphan
sweep (`api::background`); **E2EE** — the key directory `/api/keys/*` (`api::key_directory`),
with a `Caller` extractor that takes a bearer token or else a peer's HTTP Signature; the MLS
Delivery Service `/api/mls/*` (`api::mls`) and the inbox's commits and Welcomes
(`ReceiveCommit`, `ReceiveWelcome` through `AppState`); the history archive `/api/history/*`
(`api::history`); and the KeyPackage and Welcome sweeps; **local realtime** — the `/ws` upgrade
and read loop (`api::ws`: heartbeats, `set_presence`, typing, `send_dm`, watching a conversation),
`GET /api/presence` (`api::presence`), the presence bus relayed to the sessions and the idle
sweep (`api::background`); **cross-instance presence** — the peer endpoints
`POST /api/presence/batch` and `GET /api/presence/stream` (`api::presence`, behind a `SignedPeer`
extractor), the polls of the remote friends' instances and the relay of the peers' streams
(`api::background`). The new `api::router` is merged into the legacy router in `server`.

```
identity-provider/
├── Cargo.toml              # workspace root
├── crates/
│   ├── domain/             # idp-domain — entities, value objects, port traits, domain errors
│   ├── application/        # idp-application — use cases over the ports
│   ├── infrastructure/     # idp-infrastructure — port adapters: SQLx, AP delivery + WebFinger,
│   │                       #   signed downloads and claims, object storage, blob tokens, JWT and
│   │                       #   HTTP Signature verification, device attestation, WS hub, the
│   │                       #   presence bus and the peers' presence polls and streams; `MIGRATOR`
│   ├── api/                # idp-api — Axum routes, the `/ws` upgrade and read loop, DTOs,
│   │                       #   `ApiError`, background sweeps, the presence bus relay and polls
│   ├── server/             # main Axum application: entrypoint + router (wires every crate)
│   ├── auth/               # OIDC/OAuth2 flows, JWT issuance, JWKS, registration, cookies,
│   │                       #   avatar profile, login/logout, signup OTP + reaper.
│   ├── email/              # Outbound SMTP (lettre). `EmailSender` trait + LettreSmtpSender +
│   │                       #   InMemoryEmailSender (test-utils). One method per template kind.
│   ├── totp/               # Pure TOTP + recovery-code primitives (RFC 6238, no DB / no HTTP).
│   │                       #   Used by auth's enrollment + login challenge (Phase 3).
│   ├── federation/         # ActivityPub: WebFinger, actor, inbox, outbox, delivery,
│   │                       #   HTTP Signatures, Bearer-auth helper, actor-name lookup.
│   ├── social/             # User search (`GET /api/users/search`); the friend graph is in the
│   │                       #   layer crates.
│   ├── realtime/           # WS connection registry (WsHub), typed WsEvent / WsClientMessage.
│   │                       #   Pure transport — knows no domain logic.
│   ├── state/              # Shared AppState + OidcError (integration seam consumed by
│   │                       #   every domain crate; constructed in `server`).
│   ├── broker/             # Redis pub-sub + Streams abstraction (EventBroker trait).
│   ├── db/                 # SQLx models, repositories (migrations run by `infrastructure::MIGRATOR`)
│   │   └── repos/          # auth_codes, clients, conversations, email_verification_codes,
│   │                       #   friendships, history_messages, history_salt,
│   │                       #   pending_totp_enrollments, pending_totp_logins,
│   │                       #   recovery_codes, remote_actors, users
│   │                       #   (reactions repo dropped in Phase 3; user_identity_keys
│   │                       #   + recovery_blobs dropped in Phase 7)
│   ├── storage/            # S3-compatible (RustFS) object storage client
│   └── config/             # Configuration loading, env vars
├── migrations/             # SQLx migrations (numbered, applied on startup)
├── specs/                  # Feature specifications (see routing table below)
├── docs/adr/               # Architecture Decision Records (ADR-0001: bounded contexts)
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── keys/                   # JWT signing keys (gitignored)
└── .env.example
```

### Dependency direction (no cycles)

```
domain  ──► (no internal deps)
application ──► domain
infrastructure ──► domain (+ realtime, broker, storage: wrapped until they migrate)
api     ──► application, domain, realtime (the connection registry, a transport)
server  ──► every crate (composition root)
auth    ──► application, domain, state, federation, db, storage, config, email, totp
social     ──► state, federation, db
federation ──► application, domain, state, db, broker, config, realtime
realtime   ──► (no internal deps)
state      ──► application, domain, realtime, db, broker, email, storage, config
db, broker, storage, config ──► (leaves)
```

> The inbox dispatches friendship activities to `application::social`, MLS application
> messages to `application::messaging`, and MLS commits and Welcomes to `application::e2ee`.
> ADR-0001 plans to route this dispatch through the broker (Federation publishes
> typed events; messaging/social subscribe).

---

## API endpoints

| Endpoint | Description |
|---|---|
| `GET /.well-known/openid-configuration` | OIDC Discovery document |
| `GET /.well-known/jwks.json` | Public keys for JWT validation |
| `GET /.well-known/webfinger` | ActivityPub actor discovery |
| `GET /authorize` | Authorization endpoint (PKCE flow) |
| `POST /token` | Token exchange |
| `GET /userinfo` | UserInfo endpoint — also carries the account `settings` document |
| `PATCH /api/profile` | Update display_name / pronouns / bio (Bearer-auth); fans out via `propagate_profile_update` |
| `PATCH /api/settings` | Bearer-auth. Replace the account-settings sections the body names (`{ appearance: {…} }`), keep the others; returns the merged document and pushes it to the user's sessions as `settings_updated`. Read back on `GET /userinfo` (`settings`). Device-scoped settings never reach the IdP — see `identity-provider/specs/01-identity-federation.md § 1.6` |
| `PUT /api/avatar` | Replace the user's avatar (raw image bytes; ≤2 MiB; jpeg/png/webp/gif). URL is cache-busted with `?v=<unix_secs>` |
| `DELETE /api/avatar` | Clear the user's avatar |
| `POST /register` | User self-registration — dispatches signup OTP, no session |
| `POST /register-and-login` | Form submit from web client; same as `/register` plus carries OIDC params through to the verify page |
| `POST /verify-email-and-login` | Consume signup OTP, mark `email_verified_at`, issue auth code + session, redirect to OIDC `redirect_uri` |
| `POST /verify-email/resend` | Re-issue a signup OTP for an unverified user (rate-limited: 5 per 10 min) |
| `POST /login/totp` | Consume TOTP-challenge ticket (or recovery code), issue auth code + session, redirect to `redirect_uri`. Failures redirect back with `?error=...`. |
| `POST /api/totp/enroll` | Bearer auth. Start TOTP enrollment — returns `{ secret_base32, provisioning_url }` |
| `POST /api/totp/enroll/verify` | Bearer auth. Verify first code, commit secret, return 10 one-time recovery codes |
| `POST /api/totp/disable` | Bearer auth + current TOTP code. Clears secret + recovery codes |
| `POST /api/totp/recovery-codes/regenerate` | Bearer auth + current TOTP code. Replaces the user's 10 recovery codes |
| `GET /api/users/search?q=` | Search local users by username (Bearer) |
| `POST /api/friends/request` | Send a friend request. Body: `{ address }` — local, or `Follow` to a remote IdP (sent in the background: an unreachable peer never fails the request). Both sides start `pending` |
| `GET /api/friends/incoming` | Pending friend requests |
| `POST /api/friends/:id/accept` | Accept a request; mints the DM conversation and sends `friend_accepted` (local) or `Accept{Follow}` with `conversationId` (remote) |
| `DELETE /api/friends/:id/reject` | Decline a pending request, silently. Clears the requester's side: their row (local) or `Reject{Follow}` (remote) |
| `DELETE /api/friends/:actor_uri` | Unfriend (`actor_uri` percent-encoded; 404 when not a friend). Deletes both sides — the friend's row plus a refresh-only `friend_removed` (local) or `Undo{Follow}` (remote). The DM conversation is kept |
| `GET /api/friends` | Accepted friends, local and remote |
| `POST /users/:handle/inbox` | ActivityPub inbox (Follow/Accept/Reject/Undo{Follow}/Create{Note,MLS}/Update{Note,MLS}/MLS commits+welcomes) |
| `GET /users/:handle` | ActivityPub actor profile (JSON-LD) |
| `GET /ws?token=<jwt>&last_event_id=` | WebSocket upgrade (DMs + presence + events); 401 plain text for a bad token. Replays the durable events after `last_event_id` first. Frames: `heartbeat` (→ `heartbeat_ack`), `set_presence`, `typing_start` (active members only, 1/s), `send_dm`, `watch_conversation` / `unwatch_conversation` |
| `POST /api/dm` | Send a DM. Body carries `mls_ciphertext` (base64, mandatory after Phase 3); creates conversation if first message; supports `attachment_ids` (orphans, or ids linked to the caller's own `federation_status = 'failed'` message, which move over), `reply_to_id` and `client_id` (echoed on the sender's `new_dm`). A remote DM's delivery outcome lands in `federation_status`; a failure is pushed to the sender as `dm_delivery_failed` |
| `GET /api/dm` | List conversations (`kind`, `name`, `members[]` with `avatarUrl`, `unread_count`, `last_message_at`, `last_message_sender`). No plaintext preview — clients compute it from the decrypted MLS stream |
| `GET /api/dm/:conversation_id` | Conversation history, newest first (keyset cursor `cursor_created_at` — RFC 3339, as `created_at` is returned — plus `cursor_id`; `limit` ≤ 100, default 50) — every row carries `mls_ciphertext`; marks as read on initial load |
| `PATCH /api/dm/:message_id/edit` | Replace the row's `mls_ciphertext` and stamp `edited_at`; sender-only |
| `POST /api/groups` | Create a group conversation (Bearer). Body: `{ name?, member_actor_uris[] }`, created in one step. Every `/api/groups/:id…` route answers 404 for a DM. Caller becomes admin; members join as `member`. Returns the group view; emits `group_created` WS to local members — remote members get theirs from their own IdP when it materialises the group off the Welcome's `mlsGroup` snapshot. Client bootstraps MLS afterwards. |
| `POST /api/groups/:conversation_id/messages` | Send a message to a group (Bearer; member-gated). Body: `{ mls_ciphertext, reply_to_id?, attachment_ids? }`. Persists one row, then fans the ciphertext out to every other member — local via WS, remote via signed AP `Create{Note}` (`mlsKind: application`) carrying the `mlsGroup` roster, so a member whose Welcome was lost still gets the conversation. |
| `GET /api/groups/:conversation_id/members` | List members with `role` (`admin`/`member`) + `displayName`/`avatarUrl` (Bearer; member-gated). |
| `POST /api/groups/:conversation_id/members` | Add a member (Bearer; **admin-gated**). Body: `{ actor_uri }`; 409 when already a member. Emits `member_added`. MLS key delivery happens separately via the welcome the client posts. |
| `DELETE /api/groups/:conversation_id/members/:actor_uri` | Remove a member (**admin-gated**) or leave (caller == target); the last admin cannot leave while others remain (409). `actor_uri` percent-encoded. Sets `left_at`; emits `member_removed`. |
| `PATCH /api/groups/:conversation_id` | Rename a group (Bearer; **admin-gated**). Body: `{ name }` (1–100 characters). Emits `group_renamed`. |
| `POST /api/groups/:conversation_id/members/:actor_uri/role` | Promote/demote a member (**admin-gated**). Body: `{ role: "admin" \| "member" }`; never the last admin (409). Emits `member_role_changed`. |
| `POST /api/attachments` | Upload up to 5 multipart files; returns orphan attachment IDs. A client-chosen `attachment_id` already taken answers 409 — an id is never written over |
| `GET /api/attachments/:id` | Returns a token-protected blob URL + metadata (Bearer auth) |
| `GET /api/attachments/:id/blob` | The actual byte fetch — token-authed; streams bytes through the IdP from the private object store, or for a remote attachment from the origin via a screened, signed download that follows no redirect and stops at the `byte_size` the origin announced |
| `GET /api/attachments/:id/content` | Inter-IdP source of truth for attachment bytes (HTTP-Signature auth); streams through the IdP after a membership check |
| `GET /api/presence?actors[]=` | Current presence snapshot: real for the caller, its friends and its conversations' members; anyone else reads `offline` |
| `GET /api/presence/stream?actors[]=` | Inter-IdP SSE stream for open conversations (HTTP Signature; 400 without `actors[]`): replays the last known states, then presence and typing — only of this instance's accounts the peer's accounts know, typing only in conversations with a member on the peer's instance |
| `POST /api/presence/batch` | Inter-IdP batch poll behind the friends lists (HTTP Signature). Body `{ actors[] }`; every actor answered in order — `offline` for whoever none of the peer's accounts knows and for other instances' actors |
| `POST /api/keys/devices` | Register/renew/rotate this device's IdP-attested DRK (Bearer-auth). Idempotent on `(device_id, drk_public_key)`. New row → first-time mint + `DeviceJoined` WS event; same DRK → fresh `expires_at`; new DRK → rotation. Returns the signature, kid, expiries, and the canonical bytes the IdP signed so the client can re-verify locally. A device id another account holds → 409; a revoked device → 403. |
| `POST /api/keys/packages` | Upload a batch of KeyPackages for one of the caller's devices (cap + lifetime enforced; the same 409 / 403 as registration) |
| `POST /api/keys/packages/claim` | Atomically reserve one KeyPackage for `actor_uri` — of `device_id`, or of any unrevoked device with some left, named in the answer. Bearer requests for a remote `actor_uri` are sent to the target's IdP signed as the user; its 404 / 409 / 429 come back as they are, and a peer that fails to answer is 502. Bearer or HTTP-Sig; 60 claims then one a second per requester (429); peer requests for remote targets are refused (400). No KeyPackage left → 409. |
| `GET /api/keys/packages/status` | Per-device available KeyPackage counts + `needs_refill` flag |
| `GET /api/keys/devices` | List the caller's devices (Bearer-auth) — `device_id`, `display_name`, `kind`, `paired_at`, `last_seen_at`, `revoked_at`, `attestation_expires_at` (when the device's DRK attestation expires, for renewal scheduling). |
| `POST /api/keys/devices/:device_id/revoke` | Mark the caller's device revoked (Bearer-auth) — directory-level flag complementing MLS Remove commits: its KeyPackages are never claimed again. 404 for another account's device. |
| `POST /api/history/messages` | Batch upload of encrypted plaintext archive entries (1–50). Only for conversations the caller is or was a member of (403); idempotent upsert on `(user_id, id)`, answering how many were new. |
| `GET /api/history/messages?after_id=&after_created_at=&limit=` | Keyset-paginated download of the user's encrypted archive `(created_at DESC, id DESC)`, 100 a page by default, at most 500; `next_cursor` is null only on an empty page. |
| `DELETE /api/history/messages` | Wipe the user's archive (Settings → Clear). |
| `GET /api/history/salt` | Return the per-user salt for Argon2id HAK derivation, or 404 when unset. |
| `POST /api/history/salt` | Idempotent set-once. Multi-device race-safe via `COALESCE` — loser receives the winning device's salt. |
| `POST /api/mls/groups/:conversation_id/commits` | Append an MLS Commit at the next epoch (Bearer; active members only, 403). Returns `409` with the winning commit on epoch race; an unknown conversation is 404 at any epoch — a conversation exists before its MLS group. Pushed to every local member, sent to the remote ones. |
| `GET /api/mls/groups/:conversation_id/commits?since=:epoch` | Catch-up: every commit `> since` in epoch order, 256 a page with `has_more` (Bearer; member-gated) |
| `GET /api/mls/welcomes?device_id=:uuid` | Atomically claim every pending Welcome targeted at the calling device (Bearer; per-device to keep multi-device users from racing each other) |
| `POST /api/mls/welcomes` | Hand a Welcome bundle to the sender's IdP for delivery (Bearer-auth as the sender). Body: `{ recipient_actor_uri, recipient_device_id, conversation_id, welcome_blob }`. Sender and recipient must both be active members (403) — a Welcome never changes membership. Server routes off `recipient_actor_uri`: **local** → insert into `mls_welcomes` + `MlsWelcomeReady` WS push; **remote** → signed AP `Create{Note}` (`mlsKind: welcome`) to the recipient IdP's inbox, answering a nil `id`. For a **group**, the outbound Note carries an `mlsGroup` roster snapshot so the recipient's IdP materialises the conversation and emits `group_created`. The client never branches on local-vs-remote — it always hands the welcome to its own IdP. |

---

## Spec files **IMPORTANT**

This service's specifications live in `identity-provider/specs/`. Platform-wide specs —
the architecture diagram and federation authentication — live in `specs/` at the repo
root; the root `CLAUDE.md` lists them. **Read only the file(s) relevant to your task.**

Spec paths are written from the repo root throughout, so a reference means the same
file wherever it is read from.

| File | Contents | Read when working on… |
|---|---|---|
| `identity-provider/specs/01-identity-federation.md` | `users`, `remote_actors`, `friendships` schema, real-time profile propagation, Redis broker strategy, federation delivery semantics | Auth, user accounts, friend requests, profile updates, WebFinger, ActivityPub inbox/outbox |
| `identity-provider/specs/03-direct-messages.md` | `conversations`, `conversation_members`, `direct_messages` schema, DM delivery (local + federated), unread tracking, reactions, replies, message editing | Anything touching DMs, conversations, messages, reactions, replies, unread counts |
| `identity-provider/specs/04-presence.md` | Presence states (online/away/offline/dnd), typing indicators, Redis pub-sub channels, heartbeat, the presence board, cross-instance presence (batch poll, SSE stream, what a peer is told and what is taken from it) | Online status, typing indicators, presence propagation, inter-IdP SSE |
| `identity-provider/specs/05-e2ee.md` | MLS-based E2EE: trust model (user-controlled MSK / SSK / USK / Recovery Key), key directory tables + endpoints, group lifecycle on top of `conversation_members`, MLSCiphertext wire format, encrypted attachments, multi-device pairing, account recovery | Anything touching message content, identity keys, KeyPackages, group commits/welcomes, encrypted attachments, device pairing |

## Spec file modifications **IMPORTANT**

If specs file needs to be updated or created due to code modifications, feature implementation or deletion, ect... make the change accordingly taking care of explaining the globals principles and the different elements, then explain the different usecase scenarios. Use mermaid graph when possible.
Don't mention any "phase" development or what is currently being worked on. The specs should always reflect the final, stable state of the feature.

---

## Cross-cutting rules (always apply)

### Identity & addressing
- **`username`** = user input + NanoID suffix (e.g. `alice_xK9mP`). Used for federation and `actor_uri`. **Never shown in the UI.**
- **`display_name`** = user input only (e.g. `alice`). Freeform, not unique. **Only name shown client-side.**
- **Federated address format**: `username@domain` — **no** leading `@`. Produced by `User::federated_address(&self, domain)`. Clients receive raw actor URIs in some WS events and normalise to this format via `actorUriToAddress()`.
- **`actor_uri`** is the universal federation key (e.g. `https://idp.alice.com/users/alice_xK9mP`).
- **Parsing** an address or an actor URI, or deciding whether one is local, goes through
  `domain::identity` — never `split('@')`, `starts_with("{issuer}/users/")` or path slicing. A bare
  name means a local account; our own domain matches in any case. The handle rules
  (`Handle`, `UsernameChoice`: 2–32 of `a–z0–9_.` + `_` + 5 of `a–z0–9`) are enforced at
  registration once the auth context migrates.

### Conversations
- Every conversation (DM or group) has a stable **`conversation_id UUID`** that never changes regardless of participant count.
- Never derive a conversation key from actor URIs.
- For **DMs**, the UUID is minted at **friendship-accept time** on the accepter's IdP (`SocialGraph::accept` flips both rows and opens the DM in one transaction). It's propagated to the requester's IdP via the WS `friend_accepted` payload (`FriendshipPayload.conversation_id`) for local accepts, or via a non-standard `conversationId` field on the AP `Accept{Follow}` activity for cross-IdP accepts (the peer's `ReceiveAccept` opens its DM under the same id). The first-message-sender path is gone; the WS `dm-conversations` query is invalidated on `friend_accepted` so clients see the row immediately. Group conversations still mint the UUID at creation time.
- **One DM per pair**: the pair is a unique key. An id a client pins or a peer advertises is used only when the pair has no DM yet, and only if it names no conversation or a DM none but the pair ever belonged to (`domain::messaging::may_hold_dm`) — never a group, never another pair's DM.
- `kind = 'dm'` | `'group'`. DM titles are derived client-side from `members[0].display_name`. Group titles use the stored `name` column (defaults to comma-joined member display names at creation, editable via `PATCH`).
- **Cross-IdP row-id bridging**: `direct_messages.id` and `message_attachments.id` are NOT freshly generated — they're derived from the trailing UUID of the message's `activity_uri` (`<issuer>/users/<username>/activities/<uuid>`) and the attachment's URL (`<issuer>/api/attachments/<uuid>/content`) respectively. Both IdPs in a cross-server DM see the same activity URLs, so both compute the same row ids. Without this, anything that references a message or attachment by id from inside the encrypted MLS body (reactions' `target_message_id`, `AttachmentBlobKey.id`, edits, replies) silently fails on the receiver. The rule lives in `domain::messaging` (`MessageId::of_activity`, `AttachmentId::of_content_url`) and every writer goes through it; a URI without a trailing UUID gets a fresh id. An inbound attachment URL is kept only when it is the sender's own instance's `/content` endpoint (`AttachmentLimits::admit`), since this IdP later fetches it as itself.

### Redis
- **pub-sub** → ephemeral events (presence states, typing indicators). Loss is acceptable.
- **Streams** → durable events (DMs, profile updates, friend requests). Must survive disconnect.

### Federation
- **Outbound AP delivery** is best-effort, inline `tokio::spawn` per remote inbox — no persistent outbox queue. A delivery never fails the request that caused it: friendship activities go through the fire-and-forget `SocialFederation` port. Each activity owns its own reconciliation story (TTL re-fetch, idempotent retry, a failed 1:1 DM reported to its sender). See `identity-provider/specs/01-identity-federation.md § Federation delivery semantics`.
- **`remote_actors.inbox_url`** is cached on first WebFinger resolution. Every writer (`remote_actors::upsert()`, `FederatedRemoteActors`) uses `COALESCE(EXCLUDED.inbox_url, remote_actors.inbox_url)` — never overwrite a cached value with `None`.
- **HTTP Signatures** are mandatory on all incoming ActivityPub activities and on the inter-IdP presence endpoints. Reuses the instance's key pair — no separate key material.

### Database
- **Soft deletes**: messages use `deleted_at TIMESTAMPTZ` — never hard-delete.
- **Keyset pagination**: always `(created_at DESC, id DESC)` — never `LIMIT/OFFSET`.

---

## Database schema — quick reference

```
users                    — local accounts (actor_uri, inbox_url, display_name, username+NanoID,
                            avatar_url, pronouns ∈ {he, she, non-binary}, bio, email_verified_at,
                            totp_secret, totp_enabled)
email_verification_codes — signup OTPs (peppered HMAC, 10-min expiry, 5-attempt limit)
pending_totp_enrollments — in-flight 2FA secret awaiting first-code verify
pending_totp_logins      — short-lived "passed password, need TOTP" tickets carrying OIDC params
recovery_codes           — 10 per user, single-use, peppered HMAC
remote_actors            — cache of federated users (inbox_url, avatar_url, fetched_at TTL)
user_settings            — account settings, one client-owned JSONB document per user
                            (sections replaced whole by PATCH /api/settings; ≤ 16 KiB)
friendships              — friend graph (friend_actor_uri, friend_avatar_url, status,
                            direction: outgoing|incoming — only the incoming side may answer)
conversations            — anchor for every conversation (kind: dm|group, name; dm_low/dm_high:
                            a DM's actor pair, unique — one DM per pair)
conversation_members     — participants (actor_uri, joined_at, left_at, role: member|admin —
                            role is meaningful only for groups; DMs leave both at 'member')
direct_messages          — messages (conversation_id, sender_actor_uri, mls_ciphertext, activity_uri,
                            reply_to_id) — body is opaque MLS ciphertext after Phase 3
conversation_reads       — last_read_at per user per conversation (unread tracking)
message_attachments      — file attachments (message_id, storage_key, mime_type, byte_size,
                            original_filename, remote_origin_url)
                            Reactions table was dropped in Phase 3 — reactions are MLS
                            application messages of `kind = "reaction"` inside the encrypted
                            body, computed client-side from the decrypted stream
key_packages             — single-use MLS KeyPackages (per-device stash, expires_at, consumed_at)
user_devices             — per-device metadata + Phase 7 IdP-attested DRK columns:
                            base fields (display_name, kind, paired_at, last_seen_at, revoked_at)
                            attestation fields (drk_public_key, attestation_signature,
                            attestation_kid, attestation_issued_at, attestation_expires_at).
                            Upserted on every `POST /api/keys/packages` (display_name + kind
                            parsed from User-Agent on first publish); attestation columns set
                            by `POST /api/keys/devices` (Phase 7).
users.history_archive_salt
                            — Phase 7 per-user random salt for Argon2id HAK derivation.
                            Set once via idempotent `POST /api/history/salt`; never
                            overwritten.
history_messages         — Phase 7 server-side encrypted plaintext archive
                            (user_id, id, conversation_id, ciphertext, nonce, client_message_id,
                            created_at). Primary key `(user_id, id)` for idempotent upserts.
                            Server stores opaque ciphertexts; clients derive HAK from the
                            user's passphrase + salt and encrypt every decrypted plaintext.
mls_commits              — per-conversation MLS commit log (UNIQUE(conversation_id, epoch))
mls_welcomes             — outbound queue for offline device adds (recipient_user_id + device_id)

Dropped in Phase 7: `user_identity_keys` (user-level MSK/SSK/USK trust → per-device
IdP-attested DRK) and `recovery_blobs` (passphrase-wrapped MSK → encrypted plaintext
archive under HAK). See `docs/plans/2026-05-14-per-device-identity-design.md`.
```

---

## Key design decisions

- **JWT algorithm**: Ed25519 preferred, RS256 for compatibility
- **PKCE**: Mandatory for all clients (S256 only — `plain` is rejected)
- **Password hashing**: Argon2id
- **No client-side password storage on chat servers** — they only validate JWTs via JWKS
- **JWKS**: Must return an array of keys to support key rotation. Chat servers cache JWKS with a TTL and refetch on validation failure — keep the old key in JWKS for at least one full JWT lifetime (default: 1h) before removing it after rotation.
- **ActivityPub actor == OIDC subject**: the same PostgreSQL row backs both identities — no sync overhead.

---

## Security constraints (never violate)

- Never log raw passwords, tokens, or private keys
- JWT `iss` claim must always match `DOMAIN`
- Always validate `redirect_uri` against pre-registered clients
- Reject PKCE `plain` challenge method
- HTTP Signature verification is mandatory on all incoming ActivityPub activities
- Private keys must never be stored in the database — use filesystem or secrets manager

---

## Environment variables

```env
DATABASE_URL=postgres://user:pass@localhost/identity_provider
DOMAIN=idp.alice.com
JWT_PRIVATE_KEY_PATH=./keys/ed25519.pem
JWT_KEY_ID=key-2024-01
PORT=8080
REDIS_URL=redis://localhost:6379
COOKIE_SECRET=<64-byte-hex-or-random-string>
```

---

## Deployment notes

- TLS must be terminated by a reverse proxy (Caddy or Nginx) in production
- JWT private keys are mounted as a file secret — never stored in env vars or the database
- Generate keys locally: `openssl genpkey -algorithm ed25519`
- The `keys/` directory is gitignored

---

## Workflow for cross-cutting tasks

The general rule for changes spanning several specs is in the root `CLAUDE.md` and applies
here — it is not repeated, so that it cannot drift. On top of it, a change inside this
service also means:

- Check the quick-reference schema above for any table that needs updating.
- If the workspace structure changed, or API endpoints were added, modified or deleted,
  update the corresponding sections of this file to match.
