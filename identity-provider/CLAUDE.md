# CLAUDE.md — identity-provider

## What is Pina'i?

Pina'i is a self-hostable, federated, open-source Discord alternative built on ActivityPub,
developed under the GitHub organisation `Pina-i`.

This service is **Layer 2** of a three-layer architecture:

| Layer | Where | Role |
|---|---|---|
| 1 | `pina-i/web-client`, `pina-i/desktop-client` | React + Vite, Electron |
| **2** | **`identity-provider/` ← this service** | OIDC, DMs, friends, ActivityPub federation |
| 3 | `chat-server/` | Community servers, JWT validation only |

Layers 2 and 3 are subtrees of the `pina-i/pinai` monorepo; the clients are repositories of their
own.

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

The service is hexagonal, as `.claude/skills/rust-backend-architecture` describes, which applies to
every Rust change: layers as crates, each organised by bounded context (`auth`, `identity`,
`profile`, `settings`, `social`, `messaging`, `e2ee`, `presence`).

- **`domain`** — entities, value objects, the rules, the port traits, typed errors; the in-memory
  fakes and each port's contract suite behind `test-utils`.
- **`application`** — one use case per flow, holding `Arc<dyn Port>`s.
- **`infrastructure`** — the outbound adapters: SQL, other instances, mail, object storage,
  WebSocket push, the presence bus.
- **`api`** — the inbound ones: every route, the inbox (`api::inbox`: the three inbound checks,
  then each activity to its use case), the WebSocket's upgrade and read loop (`api::ws`), the
  background timers and relays (`api::background`).
- **`app`** — the composition root: `Config`, `Application::build(config, listener)`, which wires
  everything by hand and starts the background tasks, and `run_until_stopped`; the binary
  `idp-server`. Its `tests/api` are the end-to-end journeys.

One crate sits beside the layers: `connections`, the registry of the accounts' live connections.
The WebSocket's two adapters share it — `api::ws` registers a connection and writes its frames out,
`infrastructure::realtime` pushes to an account's connections — so it lies below both, and carries
frames without knowing what they say: the pushed events are `infrastructure::realtime::events`,
what a client sends `api::ws::frames`.

```
identity-provider/          # the Cargo workspace is the monorepo's, at the repo root
├── crates/
│   ├── domain/             # idp-domain — entities, value objects, port traits, domain errors
│   ├── application/        # idp-application — use cases over the ports
│   ├── infrastructure/     # idp-infrastructure — port adapters: SQLx, Redis (`broker`: the
│   │                       #   event streams and the presence bus), S3 (`storage`), AP delivery +
│   │                       #   WebFinger, signed downloads and claims, blob tokens, JWT and HTTP
│   │                       #   Signature verification, device attestation, WebSocket pushes and
│   │                       #   their wire format, the peers' presence polls and streams, the
│   │                       #   sign-in, sign-up and second-factor stores, Argon2, TOTP, token
│   │                       #   signing, SMTP mail; `MIGRATOR`
│   ├── api/                # idp-api — Axum routes (the inbox, the actor documents and
│   │                       #   WebFinger included), the `/ws` upgrade and read loop, DTOs,
│   │                       #   `ApiError`, the CORS and trace layers, background sweeps, the
│   │                       #   presence bus relay and polls
│   ├── app/                # idp-app — `Config`, `Application` (the composition root), the
│   │                       #   session keys, the `idp-server` binary; `tests/api`: the journeys
│   ├── connections/        # idp-connections — the live connections by account, each a queue
│   │                       #   of frames; knows neither the wire format nor any rule
│   └── dev-inject-data/    # seeds a development instance with accounts (`make alice-seed`)
├── migrations/             # SQLx migrations (numbered, applied on startup)
├── specs/                  # Feature specifications (see routing table below)
├── docker/
│   ├── Dockerfile
│   └── Dockerfile.dev
└── keys/                   # JWT signing keys (gitignored)
```

`compose.yaml` and `.env.example` live at the repo root, as the root `CLAUDE.md` explains.

### Dependency direction (no cycles)

```
domain  ──► (no internal deps)
application ──► domain
infrastructure ──► domain, connections
api     ──► application, domain, connections
app     ──► every crate (composition root)
connections ──► (no internal deps)
```

> The inbox dispatches friendship activities to `application::social`, MLS application
> messages to `application::messaging`, MLS commits and Welcomes to `application::e2ee`, and
> `Update{Person}` to `application::profile`.

---

## API endpoints

| Endpoint | Description |
|---|---|
| `GET /.well-known/openid-configuration` | OIDC Discovery document |
| `GET /.well-known/jwks.json` | Public keys for JWT validation |
| `GET /.well-known/webfinger` | ActivityPub actor discovery — an account of this instance only |
| `GET /users/:handle` · `GET /actor` | The account's `Person` (name, inbox, `icon`, the instance key) · the instance's `Application` actor, whose key signs inter-instance requests |
| `POST /users/:handle/inbox` | Peers' activities: signature, `Digest` and actor binding checked first; `Follow`/`Accept`/`Reject`/`Undo{Follow}`, MLS `Create`/`Update{Note}`, `Update{Person}`, and a group's changes — `Add`, `Remove`, `Leave`, `Update{Group}`, `Update{Membership}` — taken only from an entitled maker, through a member's inbox, when newer than this copy's stamps; otherwise 202 and ignored, 400 when malformed. A 1:1 `Create`/`Update{Note}` from an actor the owner doesn't admit is 403 `Message could not be delivered`; a `Follow` from an actor the owner blocked is 202 and dropped. A Welcome from someone the owner doesn't admit is 403 (a 1:1's, or a group's when the owner isn't a member yet); a group Note that would bring the owner into a group from such a sender, or with someone they blocked in it, is 202 and dropped, as is one for an owner no longer in the group. A group Note's `mlsGroup` changes this instance's copy only where its stamps are newer; one listing more than 50 members is 400 |
| `GET /users/:handle/outbox` · `/followers` · `/following` | Always empty collections: nothing is published, and friend lists are not public |
| `GET /authorize` | Authorization endpoint (code + PKCE `S256`). An unknown client or unregistered `redirect_uri` is answered here (401 / 400); a bad flow goes back to the client with `error` and `state`. A live session cookie gets a code at once, else the web client's `/login` page |
| `POST /login` | The login form: the request checked again (401 / 400), 10 guesses per email then 1/min, an unknown email costs a decoy hash check. A code + session cookie, or on to `/verify-email` (a code is mailed) or `/login/totp?ticket=` |
| `POST /token` | Code exchange (single use, spent even when refused): access + ID token, 1 h, `Cache-Control: no-store`. `unsupported_grant_type`, `invalid_client`, `invalid_grant` |
| `GET /logout` | Drops the session cookie; `post_logout_redirect_uri` only to the origin of a registered redirect URI, else `/` |
| `GET /userinfo` | The account (handle, `address`, `actor_uri`, name, avatar, pronouns, bio, `email_verified`, `totp_enabled`), its `settings` document, and `privacy: { contact_policy }`. A token outliving its account is `401 invalid_token` |
| `PATCH /api/profile` | Bearer-auth. Every field on every save: `display_name` trimmed 1–50, `pronouns` ∈ {he, she, non-binary} or empty, `bio` ≤ 190 or empty; `400` names the rule broken. Answers the new userinfo; the friends are told (`friend_profile_updated` here, `Update{Person}` elsewhere) |
| `PATCH /api/settings` | Bearer-auth. Replace the account-settings sections the body names (`{ appearance: {…} }`), keep the others; returns the merged document and pushes it to the user's sessions as `settings_updated`. Read back on `GET /userinfo` (`settings`). Device-scoped settings never reach the IdP — see `identity-provider/specs/01-identity-federation.md § 1.6` |
| `PUT /api/avatar` | Replace the avatar (raw image bytes; 1 byte–2 MiB; jpeg/png/webp/gif): stored, shown, then the other types removed; URL cache-busted with `?v=<unix_secs>`; the friends are told |
| `DELETE /api/avatar` | Clear the avatar, then remove its images; the friends are told |
| `POST /register` | JSON self-registration: `201` with the account, a code mailed, no session. `400` names the rule broken (the handle rules, an address, 8-byte passwords) or `Email already registered` — whatever its case, races included |
| `POST /register-and-login` | The web client's sign-up form: the same, carrying the OIDC request on to `/verify-email`; a broken rule goes back to `/login?tab=register&error=` |
| `POST /verify-email-and-login` | The mailed code: 5 guesses a code, counted under a row lock; the right one confirms the address, issues an auth code + session, redirects to `redirect_uri` |
| `POST /verify-email/resend` | Another code: `204`, `410` once confirmed, `429` past 5 codes in 10 min — a sign-in on the unconfirmed address counts too |
| `POST /dev/send-test-email` | Development instances only: a signup mail with a fixed code, to check SMTP |
| `POST /login/totp` | The code page: the authenticator's code — good once, for a step later than the last used — or a recovery code, against the ticket the password step opened (5 attempts, reserved atomically). An auth code + session, or back with `?error=...` |
| `POST /api/totp/enroll` | Bearer auth. Start TOTP enrollment — returns `{ secret_base32, provisioning_url }` |
| `POST /api/totp/enroll/verify` | Bearer auth. The first code: in one transaction the secret committed, its step recorded, the enrollment forgotten and 10 one-time recovery codes minted and returned |
| `POST /api/totp/disable` | Bearer auth + a current, unused TOTP code. Clears the secret, its last step, the recovery codes and any enrollment in one transaction |
| `POST /api/totp/recovery-codes/regenerate` | Bearer auth + a current, unused TOTP code. Replaces the user's 10 recovery codes |
| `GET /api/users/search?q=&limit=` | Accounts whose handle holds `q`, taken literally (`%`, `_` are no wildcards); `q` of 2+ characters, else `400`; at most 50 (Bearer) |
| `POST /api/friends/request` | Send a friend request. Body: `{ address }` — local, or `Follow` to a remote IdP (sent in the background: an unreachable peer never fails the request). Both sides start `pending`. 502 when the target's instance fails to answer the WebFinger resolution. 400 `Unblock this user first` to someone the caller blocked; a target who blocked the caller never hears of it, while the caller's side stays `pending` as for any unanswered request |
| `GET /api/friends/incoming` | Pending friend requests |
| `POST /api/friends/:id/accept` | Accept a request; mints the DM conversation and sends `friend_accepted` (local) or `Accept{Follow}` with `conversationId` (remote) |
| `DELETE /api/friends/:id/reject` | Decline a pending request, silently. Clears the requester's side: their row (local) or `Reject{Follow}` (remote) |
| `DELETE /api/friends/:actor_uri` | Unfriend (`actor_uri` percent-encoded; 404 when not a friend). Deletes both sides — the friend's row plus a refresh-only `friend_removed` (local) or `Undo{Follow}` (remote). The DM conversation is kept |
| `GET /api/friends` | Accepted friends, local and remote |
| `PATCH /api/privacy` | Bearer-auth. Body `{ contact_policy }`: `everyone` \| `friends_and_groups` (default) \| `friends` — who may message the account; 400 otherwise. Enforced with the blocks by one rule, one refusal (`identity-provider/specs/01-identity-federation.md § 1.7`) |
| `GET /api/blocks` | The caller's blocked actors, newest first (`actor_uri`, `display_name`, `avatar_url`, `blocked_at`). Private to the blocker, never federated |
| `POST /api/blocks` | Block an actor. Body: `{ actor_uri }`; idempotent, 204. Ends the friendship as an unfriend — or a decline, for a request they sent — would. 400 for one's own URI, an invalid one, or past 1000 blocks. `blocks_updated` to the caller's sessions |
| `DELETE /api/blocks/:actor_uri` | Unblock (`actor_uri` percent-encoded); 404 when not blocked. Restores nothing. `blocks_updated` to the caller's sessions |
| `POST /users/:handle/inbox` | ActivityPub inbox (Follow/Accept/Reject/Undo{Follow}/Create{Note,MLS}/Update{Note,MLS}/MLS commits+welcomes) |
| `GET /users/:handle` | ActivityPub actor profile (JSON-LD) |
| `GET /ws?token=<jwt>&last_event_id=` | WebSocket upgrade (DMs + presence + events); 401 plain text for a bad token. Replays the durable events after `last_event_id` first. Frames: `heartbeat` (→ `heartbeat_ack`), `set_presence`, `typing_start` (active members only, 1/s), `send_dm`, `watch_conversation` / `unwatch_conversation` |
| `POST /api/dm` | Send a DM. Body carries `mls_ciphertext` (base64, mandatory after Phase 3); creates conversation if first message; supports `attachment_ids` (orphans, or ids linked to the caller's own `federation_status = 'failed'` message, which move over), `reply_to_id` and `client_id` (echoed on the sender's `new_dm`). 403 `You blocked this user`, or `Message could not be delivered` for a local recipient who doesn't admit the sender — checked before the DM is opened. 502 when an address not cached here can't be resolved on its instance. A remote DM's delivery outcome lands in `federation_status`; a failure (a remote refusal included) is pushed to the sender as `dm_delivery_failed` |
| `GET /api/dm` | List conversations (`kind`, `name`, `members[]` with `avatarUrl`, `unread_count` — blocked senders left out —, `last_message_at`, `last_message_sender`, `removed_at`). A group the caller was removed from and hasn't cleared is listed as it stood then, with `removed_at` set and nothing unread. No plaintext preview — clients compute it from the decrypted MLS stream |
| `GET /api/dm/:conversation_id` | Conversation history, newest first — up to their removal for a member removed from a group, until they clear it. Items tagged `kind: message`; with `include=events`, a group's changes too (`kind: event`), those its reader saw happen; also pushed live as `group_event` (keyset cursor `cursor_created_at` — RFC 3339, as `created_at` is returned — plus `cursor_id`; `limit` ≤ 100, default 50) — every row carries `mls_ciphertext`; marks as read on initial load |
| `POST /api/dm/:conversation_id/read` | Mark the conversation read (Bearer): `204`, or `404` for a conversation the caller is not a member of |
| `PATCH /api/dm/:message_id/edit` | Replace the row's `mls_ciphertext` and stamp `edited_at`; sender-only. In a 1:1, the same two 403s as `POST /api/dm` |
| `POST /api/groups` | Create a group conversation (Bearer). Body: `{ name?, member_actor_uris[] }`, created in one step. Every `/api/groups/:id…` route answers 404 for a DM. Caller becomes admin; members join as `member`. Returns the group view; emits `group_created` WS to local members — remote members get theirs from their own IdP when it materialises the group off the Welcome's `mlsGroup` snapshot. Client bootstraps MLS afterwards. At most 50 members, the creator included: 400 `A group holds at most 50 members`, before any invitee is looked up. Each invitee is resolved anew (local, or WebFinger on its own IdP — never the cache): 404 `User not found` with its `actor_uri` otherwise, 502 with it when that IdP fails to answer. 403 with the invitee's `actor_uri` — `You blocked this user`, or `Can't add this person` for a local invitee who doesn't admit the caller. Nothing written on any refusal |
| `POST /api/groups/:conversation_id/messages` | Send a message to a group (Bearer; member-gated). Body: `{ mls_ciphertext, reply_to_id?, attachment_ids? }`. Persists one row, then fans the ciphertext out to every other member — local via WS, remote via signed AP `Create{Note}` (`mlsKind: application`) carrying the `mlsGroup` roster, so a member whose Welcome was lost still gets the conversation. |
| `GET /api/groups/:conversation_id/members` | List members with `role` (`admin`/`member`) + `displayName`/`avatarUrl` (Bearer; member-gated). |
| `POST /api/groups/:conversation_id/members` | Add a member (Bearer; **admin-gated**). Body: `{ actor_uri }`; 409 when already a member, or `The group is full: it holds at most 50 members`; the same 404 and two 403s as `POST /api/groups`. Emits `member_added`. MLS key delivery happens separately via the welcome the client posts. |
| `DELETE /api/groups/:conversation_id/members/:actor_uri` | Remove a member (**admin-gated**) or leave (caller == target); the last admin cannot leave while others remain (409). `actor_uri` percent-encoded. Sets `left_at`; emits `member_removed`. A removed member keeps the group in their list as it stood, with its history up to then; one who leaves keeps nothing |
| `DELETE /api/groups/:conversation_id` | Clear a group the caller was removed from from their list: 204; 409 `Leave the group first` for an active member; 404 otherwise |
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
| `POST /api/keys/packages/claim` | Atomically reserve one KeyPackage for `actor_uri` — of `device_id`, or of any unrevoked device with some left, named in the answer. Bearer requests for a remote `actor_uri` are sent to the target's IdP signed as the user; its 404 / 409 / 429 come back as they are, and a peer that fails to answer is 502. Bearer or HTTP-Sig; 60 claims then one a second per requester (429); peer requests for remote targets are refused (400). No KeyPackage left → 409. A claimer the account doesn't admit → 403 `Can't add this person`, before a package is taken (one's own packages always) |
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
| `POST /api/mls/welcomes` | Hand a Welcome bundle to the sender's IdP for delivery (Bearer-auth as the sender). Body: `{ recipient_actor_uri, recipient_device_id, conversation_id, welcome_blob }`. Sender and recipient must both be active members (403) — a Welcome never changes membership. A 1:1's to a local recipient who doesn't admit the sender → 403 `Can't add this person`. Server routes off `recipient_actor_uri`: **local** → insert into `mls_welcomes` + `MlsWelcomeReady` WS push; **remote** → signed AP `Create{Note}` (`mlsKind: welcome`) to the recipient IdP's inbox, answering a nil `id`. For a **group**, the outbound Note carries an `mlsGroup` roster snapshot so the recipient's IdP materialises the conversation and emits `group_created`. The client never branches on local-vs-remote — it always hands the welcome to its own IdP. |

---

## Spec files **IMPORTANT**

This service's specifications live in `identity-provider/specs/`. Platform-wide specs —
the architecture diagram and federation authentication — live in `specs/` at the repo
root; the root `CLAUDE.md` lists them. **Read only the file(s) relevant to your task.**

Spec paths are written from the repo root throughout, so a reference means the same
file wherever it is read from.

| File | Contents | Read when working on… |
|---|---|---|
| `identity-provider/specs/01-identity-federation.md` | `users`, `remote_actors`, `friendships`, `user_blocks` schema, who can reach a user (the contact setting, blocks, the rule and where it is enforced), real-time profile propagation, Redis broker strategy, federation delivery semantics | Auth, user accounts, friend requests, blocking, the contact setting, profile updates, WebFinger, ActivityPub inbox/outbox |
| `identity-provider/specs/03-direct-messages.md` | `conversations`, `conversation_members`, `direct_messages` schema, DM delivery (local + federated), unread tracking, reactions, replies, message editing | Anything touching DMs, conversations, messages, reactions, replies, unread counts |
| `identity-provider/specs/04-presence.md` | Presence states (online/away/offline/dnd), typing indicators, Redis pub-sub channels, heartbeat, the presence board, cross-instance presence (batch poll, SSE stream, what a peer is told and what is taken from it) | Online status, typing indicators, presence propagation, inter-IdP SSE |
| `identity-provider/specs/05-e2ee.md` | MLS-based E2EE: trust model (user-controlled MSK / SSK / USK / Recovery Key), key directory tables + endpoints, group lifecycle on top of `conversation_members`, MLSCiphertext wire format, encrypted attachments, multi-device pairing, account recovery | Anything touching message content, identity keys, KeyPackages, group commits/welcomes, encrypted attachments, device pairing |

## Spec file modifications **IMPORTANT**

If specs file needs to be updated or created due to code modifications, feature implementation or deletion, ect... make the change accordingly taking care of explaining the globals principles and the different elements, then explain the different usecase scenarios. Use mermaid graph when possible.
Don't mention any "phase" development or what is currently being worked on. The specs should always reflect the final, stable state of the feature.

---

## Cross-cutting rules (always apply)

### Identity & addressing
- **`username`** = the handle: the chosen name + `_` + 5 of `a–z0–9` (e.g. `alice_xk9mp`). Used for federation and `actor_uri`. **Never shown in the UI.**
- **`display_name`** = user input only (e.g. `alice`): trimmed, 1–50 characters (`DisplayName`), not unique. **Only name shown client-side.** A peer's is taken within the same rules, or not at all.
- **Federated address format**: `username@domain` — **no** leading `@`; `/userinfo` answers it as `address`. Clients receive raw actor URIs in some WS events and normalise to this format via `actorUriToAddress()`.
- **`actor_uri`** is the universal federation key (e.g. `https://idp.alice.com/users/alice_xk9mp`).
- **Parsing** an address or an actor URI, or deciding whether one is local, goes through
  `domain::identity` — never `split('@')`, `starts_with("{issuer}/users/")` or path slicing. A bare
  name means a local account; our own domain matches in any case. An `ActorUri` is 2 KiB at most
  once normalised: every writer stores what it is handed. The handle rules
  (`Handle`, `UsernameChoice`: 2–32 of `a–z0–9_.` + `_` + 5 of `a–z0–9`) are enforced at
  registration.

### Profile
- An inbound `Update{Person}` changes only its signer's own account, never one of this instance
  (`ReceiveProfileUpdate`), and keeps only a name and an `http(s)` avatar URL within
  `PublicProfile::within_limits` — every friend's client loads that URL.
- An avatar is replaced upload → `users.avatar_url` → removal of the other types, and cleared
  `users.avatar_url` → removal: the account never points at a removed object.

### Reaching a user
- Whether one account may message another goes through `domain::social::Relation`, read by the
  `Reachability` port in one query — never an ad-hoc check. A block and the contact setting give
  the same refusal, so nobody can tell one from the other
  (`identity-provider/specs/01-identity-federation.md § 1.7`).

### Conversations
- Every conversation (DM or group) has a stable **`conversation_id UUID`** that never changes regardless of participant count.
- Never derive a conversation key from actor URIs.
- For **DMs**, the UUID is minted at **friendship-accept time** on the accepter's IdP (`SocialGraph::accept` flips both rows and opens the DM in one transaction). It's propagated to the requester's IdP via the WS `friend_accepted` payload (`FriendshipPayload.conversation_id`) for local accepts, or via a non-standard `conversationId` field on the AP `Accept{Follow}` activity for cross-IdP accepts (the peer's `ReceiveAccept` opens its DM under the same id). The first-message-sender path is gone; the WS `dm-conversations` query is invalidated on `friend_accepted` so clients see the row immediately. Group conversations still mint the UUID at creation time.
- **One DM per pair**: the pair is a unique key. An id a client pins or a peer advertises is used only when the pair has no DM yet, and only if it names no conversation or a DM none but the pair ever belonged to (`domain::messaging::may_hold_dm`) — never a group, never another pair's DM.
- **A group's copies converge by stamps**: each instance holding a member keeps its own copy, and
  takes a name, a role, a join or a rejoin from a snapshot only when its stamp is newer than the
  one held (`domain::messaging::GroupSnapshot::changes`) — so a stale snapshot never undoes a
  departure, a rename or a role change (`identity-provider/specs/03-direct-messages.md § 10`).
- `kind = 'dm'` | `'group'`. DM titles are derived client-side from `members[0].display_name`. Group titles use the stored `name` column (defaults to comma-joined member display names at creation, editable via `PATCH`).
- **Cross-IdP row-id bridging**: `direct_messages.id` and `message_attachments.id` are NOT freshly generated — they're derived from the trailing UUID of the message's `activity_uri` (`<issuer>/users/<username>/activities/<uuid>`) and the attachment's URL (`<issuer>/api/attachments/<uuid>/content`) respectively. Both IdPs in a cross-server DM see the same activity URLs, so both compute the same row ids. Without this, anything that references a message or attachment by id from inside the encrypted MLS body (reactions' `target_message_id`, `AttachmentBlobKey.id`, edits, replies) silently fails on the receiver. The rule lives in `domain::messaging` (`MessageId::of_activity`, `AttachmentId::of_content_url`) and every writer goes through it; a URI without a trailing UUID gets a fresh id. An inbound attachment URL is kept only when it is the sender's own instance's `/content` endpoint (`AttachmentLimits::admit`), since this IdP later fetches it as itself.

### Redis
- **pub-sub** → ephemeral events (presence states, typing indicators). Loss is acceptable.
- **Streams** → durable events (DMs). Must survive disconnect. Profile and friendship events go
  to the live sessions only.

### Federation
- **Outbound AP delivery** is best-effort, inline `tokio::spawn` per remote inbox — no persistent outbox queue. A delivery never fails the request that caused it: friendship activities go through the fire-and-forget `SocialFederation` port. Each activity owns its own reconciliation story (the next profile change, idempotent retry, a failed 1:1 DM reported to its sender). See `identity-provider/specs/01-identity-federation.md § Federation delivery semantics`.
- **`remote_actors.inbox_url`** is cached on first WebFinger resolution. Every writer (`remote_actors::upsert()`, `FederatedRemoteActors`) uses `COALESCE(EXCLUDED.inbox_url, remote_actors.inbox_url)` — never overwrite a cached value with `None`.
- **A group's changes travel on their own**: an add, removal, leave, rename or role change made
  here is sent to the group's remote members as `Add`, `Remove`, `Leave` or `Update`, stamped
  (`GroupFederation`, `ReceiveGroupChange`; `identity-provider/specs/03-direct-messages.md § 10`).
- **A fan-out reaches every remote member, met here or not**: use cases hand the federation actor URIs, and `infrastructure::federation::Inboxes` finds each inbox in the background — the cache, else WebFinger, 10 lookups a send, an unresolved actor left alone for 10 minutes. Never filter recipients on the cache in a use case.
- **HTTP Signatures** are mandatory on all incoming ActivityPub activities and on the inter-IdP endpoints. Reuses the instance's key pair — no separate key material. A signed request with a body goes through `SignedBody` / `SignedJson` / `CallerJson`, which check its `Digest` before the body is read; `SignedPeer` is for bodyless requests only.

### Database
- **Soft deletes**: messages use `deleted_at TIMESTAMPTZ` — never hard-delete.
- **Keyset pagination**: always `(created_at DESC, id DESC)` — never `LIMIT/OFFSET`.

---

## Database schema — quick reference

```
users                    — local accounts (actor_uri, inbox_url, display_name, username (the handle),
                            email lowercase and unique whatever its case,
                                                        avatar_url, pronouns ∈ {he, she, non-binary}, bio, email_verified_at,
                            totp_secret, totp_enabled, totp_last_step — a code is good once,
                            contact_policy: everyone | friends_and_groups (default) | friends)
email_verification_codes — signup codes (peppered HMAC, 10-min expiry, 5 attempts, 5 codes / 10 min)
pending_totp_enrollments — in-flight 2FA secret awaiting first-code verify
pending_totp_logins      — short-lived "passed password, need TOTP" tickets carrying OIDC params
                            (5 attempts)
recovery_codes           — 10 per user, single-use, peppered HMAC
remote_actors            — cache of federated users (inbox_url, display_name, avatar_url — as the
                            actor's own `Update{Person}` last said, within the profile limits)
user_settings            — account settings, one client-owned JSONB document per user
                            (sections replaced whole by PATCH /api/settings; ≤ 16 KiB)
friendships              — friend graph (friend_actor_uri, status, direction: outgoing|incoming —
                            only the incoming side may answer; friend_avatar_url, read for a
                            remote friend only — a local one is shown from `users`)
user_blocks              — actors a local user blocked (owner_user_id, blocked_actor_uri, created_at;
                            1000 per owner) — never federated
conversations            — anchor for every conversation (kind: dm|group, name, name_at;
                            dm_low/dm_high: a DM's actor pair, unique — one DM per pair)
conversation_members     — participants (actor_uri, joined_at, left_at, role: member|admin,
                            role_at — role is meaningful only for groups; DMs leave both at
                            'member'). joined_at/left_at/role_at and name_at are stamped where
                            the change is made and copied as received; removed_by,
                            departure_view (the group as a removed member last saw it) and
                            dismissed_at, set anew by each departure
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
conversation_events      — a group's changes as its conversation shows them (kind, actor_uri,
                            subject_uri, detail, created_at = the change's stamp)
mls_commits              — per-conversation MLS commit log (UNIQUE(conversation_id, epoch))
mls_welcomes             — outbound queue for offline device adds (recipient_user_id + device_id)

Dropped in Phase 7: `user_identity_keys` (user-level MSK/SSK/USK trust → per-device
IdP-attested DRK) and `recovery_blobs` (passphrase-wrapped MSK → encrypted plaintext
archive under HAK).
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
- `SESSION_SECRET` is never a key itself: `app::keys::SessionKeys` derives one per purpose from
  all of it (HKDF-SHA256) — the session cookie's, the attachment links'. A new purpose takes a
  new label, never an existing key

## Running and stopping

`Application::build` connects to Postgres, Redis and the object store, runs the migrations and
starts the background tasks; `run_until_stopped` serves until its stop token is cancelled — by
`SIGTERM` or Ctrl-C in the binary. It then takes no new connection, answers the requests under
way, closes each WebSocket with `1001` and ends the peers' presence streams, lets every background
task finish its run under way, and drops what is still open ten seconds on
(`identity-provider/specs/04-presence.md` § When the instance stops).

---

## Environment variables

`.env.example` at the repo root documents every variable the service reads, and the root
`README.md` groups them; `app::configuration` is where they are read.

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
