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
│   │                       #   WebFinger included), the sign-in pages (`templates/`,
│   │                       #   `assets/`), the `/ws` upgrade and read loop, DTOs,
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
| `GET /authorize` | Authorization endpoint (code + PKCE `S256`). The client is the URL of its document, fetched and kept (`identity-provider/specs/auth.md § 1` "Clients"). A client whose document can't be had or breaks a rule, or a `redirect_uri` it doesn't list, is answered here, on the "This app couldn't be verified" page (401 / 400); a bad flow goes back to the client with `error` and `state`. A live session cookie — a browser session used in the last 90 days, its cookie then set again — gets a code at once for an app its account signed in to with the password (`client_sign_ins`), else the instance's own `/login` page, naming the app, carrying the request and the optional `theme` / `motif` the client is painted in. `prompt=login` always shows the login page (the desktop app sends it at each sign-in; any client before a sensitive action) |
| `GET /login` · `GET /verify-email` · `GET /login/totp` · `GET /signed-out` | The sign-in pages, rendered here (askama, no inline script, a strict CSP, `no-store`): the instance's name, description and facts beside the form; errors arrive as codes and only known codes have words; "← Another home" goes back to the client with `error=access_denied`. A link with no request left, or a gone ticket, says the sign-in expired (`identity-provider/specs/auth.md § 1` "The sign-in pages") |
| `GET /assets/{path}` | The pages' stylesheet, script, fonts, motifs and grain, built into the binary, kept a day |
| `GET /i/{token}` | An invitation's doorway, rendered here like the sign-in pages (strict CSP, `no-store`, `Referrer-Policy: no-referrer` — its URL holds the token): "You've been invited by {inviter's display name} to join {instance}.", the description, "This link lets one person create an account and expires in {N days / hours}", **Continue** to `/i/{token}/sign-up`, "Only the admins of {domain} make invitations". Anything but an open invitation — unknown, used, revoked, expired — is one `404` page, "This invitation can no longer be used. Ask the person who sent it for a new one." (`identity-provider/specs/auth.md § 5`) |
| `GET /i/{token}/sign-up` · `POST /i/{token}/sign-up` | The invitation's sign-up form (display name, email, password; the same headers but the sign-in pages' `Referrer-Policy: same-origin`, so the form posts its `Origin`; the POST refused 403 from another site). The account is created admitted, `invited_by` the invitation's admin, the invitation spent — one transaction, so two sign-ups racing on one link create one account — and no code is mailed. With the official web app known (`WEB_APP_ORIGIN` overrides its address): a browser session and the web app remembered in `client_sign_ins`, then `303` to `{web app}/?instance={domain}` (`no-referrer`), whose `/authorize` then gets a code at once. Without one — or should that sign-in fail —: the "Your account on {instance} is ready" page (`no-referrer`). A broken rule or a taken address shows the form again (`400`); an invitation spent meanwhile, the `404` page |
| `GET /.well-known/nodeinfo` · `GET /nodeinfo/2.1` | NodeInfo 2.1: `software.name` `pinai`, `openRegistrations`, `usage.users.total` (counted at most a minute ago), `metadata.nodeName` / `nodeDescription` from `INSTANCE_NAME` / `INSTANCE_DESCRIPTION` (`identity-provider/specs/identity.md § 6`) |
| `POST /login` | The login form, refused 403 when posted from another site: the request checked again (401 / 400), 10 guesses per email then 1/min, an unknown email costs a decoy hash check. A code + session cookie, or on to `/verify-email` (a code is mailed — an address neither confirmed nor admitted, `SignInAccount::needs_code`) or `/login/totp?ticket=`, or back to `/login` with `error=<code>` |
| `POST /token` | `authorization_code`: code exchange (single use, spent even when refused) for access + refresh + ID token, 1 h; a code whose session ended is `invalid_grant`; a native client staying signed in (`offline_access`) gets an app session of its own. `refresh_token`: rotates the token — access + the next refresh token, no ID token; a rotated one presented again past its 60 s grace ends the session (`reuse`). `Cache-Control: no-store`. The access token's `aud` is this instance, its `client_id` the client (RFC 9068), its `sid` its session, its `auth_time` the password last typed on that session. `unsupported_grant_type`, `invalid_client`, `invalid_grant` |
| `POST /revoke` | RFC 7009: `client_id`, `token` (a refresh token). Ends the token's session (`sign_out`) — how the desktop app signs out; the browser session its window signed in through is left alone. `200` for an unknown or another client's token too; `400` without a token, `401` for a malformed `client_id` |
| `GET /logout` | Ends the browser session — its tokens refused at once, its WebSockets closed with `1008` — and drops the cookie; back to `post_logout_redirect_uri` only when the named `client_id`'s document lists it exactly, else `/signed-out` |
| `GET /clients/desktop.json` | The official desktop app's client document, as every instance describes it (`io.github.pina-i:/callback`, native, `offline_access`) |
| `GET /userinfo` | The account (handle, `address`, `actor_uri`, name, avatar, pronouns, bio, `email_verified` — `false` for an admitted account too —, `totp_enabled`, `admin`), its `settings` document, and `privacy: { contact_policy }`. A token outliving its account is `401 invalid_token` |
| `PATCH /api/profile` | Bearer-auth. Every field on every save: `display_name` trimmed 1–50, `pronouns` ∈ {he, she, non-binary} or empty, `bio` ≤ 190 or empty; `400` names the rule broken. Answers the new userinfo; the friends are told (`friend_profile_updated` here, `Update{Person}` elsewhere) |
| `PATCH /api/settings` | Bearer-auth. Replace the account-settings sections the body names (`{ appearance: {…} }`), keep the others; returns the merged document and pushes it to the user's sessions as `settings_updated`. Read back on `GET /userinfo` (`settings`). Device-scoped settings never reach the IdP — see `identity-provider/specs/profile-and-settings.md § 2` |
| `PUT /api/avatar` | Replace the avatar (raw image bytes; 1 byte–2 MiB; jpeg/png/webp/gif): stored, shown, then the other types removed; URL cache-busted with `?v=<unix_secs>`; the friends are told |
| `DELETE /api/avatar` | Clear the avatar, then remove its images; the friends are told |
| `GET /api/profiles?actor=<actor URI>` | Bearer-auth. The profile card: `actor_uri`, `display_name`, `avatar_url`, `pronouns`, `bio`, `friends_since` (RFC 3339 or null). An account here for anyone here; one elsewhere, from `remote_actors`, only for an accepted friend or an active co-member — any other is `404 User not found`, cached or not. A cache over 24 h old is answered and rediscovered in the background |
| `POST /register` | JSON self-registration `{ display_name, email, password }`: `201` with the account, its handle derived from the display name, a code mailed, no session. `400` names the rule broken (a 1–50 character name, an address, 8-byte passwords) or `Email already registered` — whatever its case, races included |
| `POST /register-and-login` | The register tab's form (403 from another site): the same, carrying the OIDC request on to `/verify-email`; a broken rule goes back to `/login?tab=register&error=<code>` |
| `POST /verify-email-and-login` | The mailed code: 5 guesses a code, counted under a row lock; the right one confirms the address, issues an auth code + session, redirects to `redirect_uri`. An admitted account (`SignInAccount::needs_code` false) is never signed in by a code: no code tried, no session, on to `/login?notice=no_code_needed` |
| `POST /verify-email/resend` | The code page's "Send a new code" form: another code, then the page again with `notice=code_resent`, or `error=too_many_codes` past 5 codes in 10 min — a sign-in on the unconfirmed address counts too; on to `/login` once confirmed, or, mailing nothing, for an admitted account (`notice=no_code_needed`) |
| `POST /dev/send-test-email` | Development instances only: a signup mail with a fixed code, to check SMTP |
| `POST /login/totp` | The code page's form: the authenticator's code — good once, for a step later than the last used — or a recovery code, against the ticket the password step opened (5 attempts, reserved atomically). An auth code + session, or back with `error=<code>`, or `/login?error=ticket_expired` / `ticket_exhausted` |
| `POST /api/admin/invitations` | An admin's bearer (`401` without one, `403` for a member). No body. `201 { id, link, expires_at }`: `link` = `{issuer}/i/{token}`, open 7 days, the token in this answer only |
| `GET /api/admin/invitations` | An admin's bearer. The open invitations, newest first: `id`, `created_at`, `expires_at`, `created_by: { display_name }`; used, expired and revoked ones are not listed |
| `DELETE /api/admin/invitations/{id}` | An admin's bearer — a member is `403` whatever the id. Revokes an open invitation: `204`; anything else `404` |
| `POST /api/totp/enroll` | Bearer auth, a recent password. Start TOTP enrollment — returns `{ secret_base32, provisioning_url }` |
| `POST /api/totp/enroll/verify` | Bearer auth. The first code: in one transaction the secret committed, its step recorded, the enrollment forgotten and 10 one-time recovery codes minted and returned |
| `POST /api/totp/disable` | Bearer auth + a current, unused TOTP code. Clears the secret, its last step, the recovery codes and any enrollment in one transaction |
| `POST /api/totp/recovery-codes/regenerate` | Bearer auth + a current, unused TOTP code. Replaces the user's 10 recovery codes |
| `GET /api/users/search?q=&limit=` | Accounts whose handle holds `q`, taken literally (`%`, `_` are no wildcards); `q` of 2+ characters, else `400`; at most 50 (Bearer) |
| `POST /api/friends/request` | Send a friend request. Body: `{ address }` — local, or `Follow` to a remote IdP (sent in the background: an unreachable peer never fails the request). Both sides start `pending`. 502 when the target's instance fails to answer the WebFinger resolution. 400 `Unblock this user first` to someone the caller blocked; a target who blocked the caller never hears of it, while the caller's side stays `pending` as for any unanswered request |
| `GET /api/friends/incoming` | Pending friend requests |
| `POST /api/friends/:id/accept` | Accept a request; mints the DM conversation and sends `friend_accepted` (local) or `Accept{Follow}` with `conversationId` (remote) |
| `DELETE /api/friends/:id/reject` | Decline a pending request, silently. Clears the requester's side: their row (local) or `Reject{Follow}` (remote) |
| `DELETE /api/friends/:actor_uri` | Unfriend (`actor_uri` percent-encoded; 404 when not a friend). Deletes both sides — the friend's row plus a refresh-only `friend_removed` (local) or `Undo{Follow}` (remote). The DM conversation is kept |
| `GET /api/friends` | Accepted friends, local and remote, each with `since`: when the friendship was accepted on this side |
| `PATCH /api/privacy` | Bearer-auth. Body `{ contact_policy }`: `everyone` \| `friends_and_groups` (default) \| `friends` — who may message the account; 400 otherwise. Enforced with the blocks by one rule, one refusal (`identity-provider/specs/social.md § 2`) |
| `GET /api/blocks` | The caller's blocked actors, newest first (`actor_uri`, `display_name`, `avatar_url`, `blocked_at`). Private to the blocker, never federated |
| `POST /api/blocks` | Block an actor. Body: `{ actor_uri }`; idempotent, 204. Ends the friendship as an unfriend — or a decline, for a request they sent — would. 400 for one's own URI, an invalid one, or past 1000 blocks. `blocks_updated` to the caller's sessions |
| `DELETE /api/blocks/:actor_uri` | Unblock (`actor_uri` percent-encoded); 404 when not blocked. Restores nothing. `blocks_updated` to the caller's sessions |
| `POST /users/:handle/inbox` | ActivityPub inbox (Follow/Accept/Reject/Undo{Follow}/Create{Note,MLS}/Update{Note,MLS}/MLS commits+welcomes) |
| `GET /users/:handle` | ActivityPub actor profile (JSON-LD) |
| `GET /ws?token=<jwt>&last_event_id=` | WebSocket upgrade (DMs + presence + events); 401 plain text for a bad token or an ended session. Closed with `1008` when the session it was opened under ends. Replays the durable events after `last_event_id` first. Frames: `heartbeat` (→ `heartbeat_ack`), `set_presence`, `typing_start` (active members only, 1/s), `send_dm`, `watch_conversation` / `unwatch_conversation` |
| `POST /api/dm` | Send a DM. Body carries `mls_ciphertext` (base64, mandatory after Phase 3); creates conversation if first message; supports `attachment_ids` (orphans, or ids linked to the caller's own `federation_status = 'failed'` message, which move over), `reply_to_id` and `client_id` (echoed on the sender's `new_dm`). 403 `You blocked this user`, or `Message could not be delivered` for a local recipient who doesn't admit the sender — checked before the DM is opened. 502 when an address not cached here can't be resolved on its instance. A remote DM's delivery outcome lands in `federation_status`; a failure (a remote refusal included) is pushed to the sender as `dm_delivery_failed` |
| `GET /api/dm` | List conversations (`kind`, `name`, `members[]` with `avatarUrl`, `unread_count` — blocked senders left out —, `last_message_at`, `last_message_sender`, `removed_at`). A group the caller was removed from and hasn't cleared is listed as it stood then, with `removed_at` set and nothing unread. No plaintext preview — clients compute it from the decrypted MLS stream |
| `GET /api/dm/:conversation_id` | Conversation history, newest first — up to their removal for a member removed from a group, until they clear it. Items tagged `kind: message`; with `include=events`, a group's changes too (`kind: event`), those its reader saw happen; also pushed live as `group_event` (keyset cursor `cursor_created_at` — RFC 3339, as `created_at` is returned — plus `cursor_id`; `limit` ≤ 100, default 50) — every row carries `mls_ciphertext`; marks as read on initial load |
| `POST /api/dm/:conversation_id/read` | Mark the conversation read (Bearer): `204`, or `404` for a conversation the caller is not a member of |
| `PATCH /api/dm/:message_id/edit` | Replace the row's `mls_ciphertext` and stamp `edited_at`; sender-only. In a 1:1, the same two 403s as `POST /api/dm` |
| `POST /api/groups` | Create a group conversation (Bearer). Body: `{ name?, member_actor_uris[] }`, created in one step. Every `/api/groups/:id…` route answers 404 for a DM. Caller becomes admin; members join as `member`. Returns the group view; emits `group_created` WS to local members — remote members get theirs from their own IdP when it materialises the group off the `mlsGroup` snapshot of the first commit or Welcome to arrive. Client bootstraps MLS afterwards. At most 50 members, the creator included: 400 `A group holds at most 50 members`, before any invitee is looked up. Each invitee is resolved anew (local, or WebFinger on its own IdP — never the cache): 404 `User not found` with its `actor_uri` otherwise, 502 with it when that IdP fails to answer. 403 with the invitee's `actor_uri` — `You blocked this user`, or `Can't add this person` for a local invitee who doesn't admit the caller. Nothing written on any refusal |
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
| `POST /api/keys/packages/claim/devices` | One KeyPackage of each of `actor_uri`'s unrevoked devices that has any, as `{ claims: [...] }`, so a contact's first add brings every device of theirs in. Asked, proxied, rate-limited, admitted and notified as `/claim` is; none at all → 409 |
| `POST /api/keys/packages/claim` | Atomically reserve one KeyPackage for `actor_uri` — of `device_id`, or of any unrevoked device with some left, named in the answer. Bearer requests for a remote `actor_uri` are sent to the target's IdP signed as the user; its 404 / 409 / 429 come back as they are, and a peer that fails to answer is 502. Bearer or HTTP-Sig; 60 claims then one a second per requester (429); peer requests for remote targets are refused (400). No KeyPackage left → 409. A claimer the account doesn't admit → 403 `Can't add this person`, before a package is taken (one's own packages always). A claim that leaves a device at the refill threshold, or finds none, pushes `key_packages_low` to the owner's live sessions, which top their own device up |
| `GET /api/keys/packages/status` | Per-device available KeyPackage counts + `needs_refill` flag |
| `GET /api/keys/devices` | List the caller's devices (Bearer-auth) — `device_id`, `display_name`, `kind`, `paired_at`, `last_seen_at`, `revoked_at`, `signed_in` and `last_active_at` (a live session of it, and its last use), `attestation_expires_at` (when the device's DRK attestation expires, for renewal scheduling). |
| `POST /api/keys/devices/:device_id/revoke` | Revoke the caller's device (Bearer-auth, a recent password): its sessions end first (`device_revoked` — tokens, refresh tokens, sockets with `1008`), then the directory flag complementing MLS Remove commits: its KeyPackages are never claimed again. 404 for another account's device. |
| `PUT /api/sessions/current/device` | Bearer-auth. `{ device_id }`: the session names the E2EE device it signed in, ending that device's other session (`replaced`). 403 for a device not the caller's, or revoked |
| `DELETE /api/sessions?keep=current` | Bearer-auth, a recent password. Ends every session of the account but the caller's (`signed_out_elsewhere`); 400 without `keep=current` |
| `POST /api/history/messages` | Batch upload of encrypted plaintext archive entries (1–50). Only for conversations the caller is or was a member of (403); idempotent upsert on `(user_id, id)`, answering how many were new. |
| `GET /api/history/messages?after_id=&after_created_at=&limit=` | Keyset-paginated download of the user's encrypted archive `(created_at DESC, id DESC)`, 100 a page by default, at most 500; `next_cursor` is null only on an empty page. |
| `DELETE /api/history/messages` | Wipe the user's archive (Settings → Clear). Bearer-auth, a recent password. |
| `GET /api/history/salt` | Return the per-user salt for Argon2id HAK derivation, or 404 when unset. |
| `POST /api/history/salt` | Idempotent set-once. Multi-device race-safe via `COALESCE` — loser receives the winning device's salt. |
| `POST /api/mls/groups/:conversation_id/commits` | Append an MLS Commit at the next epoch (Bearer; active members only, 403). Returns `409` with the winning commit on epoch race; an unknown conversation is 404 at any epoch — a conversation exists before its MLS group. Pushed to every local member, sent to the remote ones — a group's with its `mlsGroup` roster, so it lands even ahead of the Welcome that would bring the group there. |
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
| `identity-provider/specs/identity.md` | `users` and `remote_actors` schema, the remote actor cache and how a group's remote members are reached, what peers read of an account (WebFinger, the actor documents), the address and name formats | Accounts, handles and display names, actor URIs and addresses, WebFinger, the actor documents |
| `identity-provider/specs/auth.md` | OpenID Connect sign-in (clients, `/authorize`, `/login`, the session cookie, `/token`, tokens, logout, discovery), sign-up email verification, TOTP two-factor and recovery codes, admins and admitted accounts (the first admin from `ADMIN_EMAIL` / `ADMIN_PASSWORD`), invitations (the admin API, the `/i/{token}` pages, joining into the official web app) | Signing in, sessions, tokens, sign-up, email codes, the second factor, admins, invitations |
| `identity-provider/specs/social.md` | `friendships` and `user_blocks` schema, a friendship's life (request, accept opening the DM, decline, unfriend), who can reach a user (the contact setting, blocks, the rule and where it is enforced) | Friend requests, the friends list, blocking, the contact setting |
| `identity-provider/specs/profile-and-settings.md` | Profile editing and avatar storage, the profile card (`GET /api/profiles`), `user_settings`, real-time profile propagation (`friend_profile_updated`, `Update{Person}`) | Profile fields, avatars, the profile card, account settings, profile federation |
| `identity-provider/specs/event-delivery.md` | Redis Streams vs pub-sub, federation delivery semantics (best-effort, each activity's recovery), reconnect and catch-up | The broker, the WebSocket replay, outbound ActivityPub delivery |
| `identity-provider/specs/direct-messages.md` | `conversations`, `conversation_members`, `direct_messages` schema, DM delivery (local + federated) and delivery failure, pagination, unread tracking, replies and reactions, editing | Anything touching DMs, conversations, messages, reactions, replies, unread counts |
| `identity-provider/specs/attachments.md` | `message_attachments`, the upload and download routes, the federation wire format, validation and limits | Attachments |
| `identity-provider/specs/groups.md` | Roles, the group routes, a member removed from a group, fan-out, a group's changes in its conversation (`conversation_events`), federated groups and their changes | Group conversations, membership and roles, group federation |
| `identity-provider/specs/presence.md` | Presence states (online/away/offline/dnd), typing indicators, Redis pub-sub channels, heartbeat, the presence board, cross-instance presence (batch poll, SSE stream, what a peer is told and what is taken from it) | Online status, typing indicators, presence propagation, inter-IdP SSE |
| `identity-provider/specs/e2ee.md` | MLS-based E2EE: trust model (user-controlled MSK / SSK / USK / Recovery Key), key directory tables + endpoints, group lifecycle on top of `conversation_members`, MLSCiphertext wire format, encrypted attachments, multi-device pairing, account recovery | Anything touching message content, identity keys, KeyPackages, group commits/welcomes, encrypted attachments, device pairing |

## Spec file modifications **IMPORTANT**

If specs file needs to be updated or created due to code modifications, feature implementation or deletion, ect... make the change accordingly taking care of explaining the globals principles and the different elements, then explain the different usecase scenarios. Use mermaid graph when possible.
Don't mention any "phase" development or what is currently being worked on. The specs should always reflect the final, stable state of the feature.

---

## Cross-cutting rules (always apply)

### Identity & addressing
- **`username`** = the handle: the display name in ASCII, lowercase, `_` between words (`UsernameChoice::derived_from`) + `_` + 5 of `a–z0–9` (e.g. "Hōkū" → `hoku_xk9mp`). Used for federation and `actor_uri`. **Never shown in the UI.**
- **`display_name`** = user input only, typed at sign-up (e.g. `Hōkū`): trimmed, 1–50 characters (`DisplayName`), not unique. **Only name shown client-side.** A peer's is taken within the same rules, or not at all.
- **Federated address format**: `username@domain` — **no** leading `@`; `/userinfo` answers it as `address`. Clients receive raw actor URIs in some WS events and normalise to this format via `actorUriToAddress()`.
- **`actor_uri`** is the universal federation key (e.g. `https://idp.alice.com/users/alice_xk9mp`).
- **Parsing** an address or an actor URI, or deciding whether one is local, goes through
  `domain::identity` — never `split('@')`, `starts_with("{issuer}/users/")` or path slicing. A bare
  name means a local account; our own domain matches in any case. An `ActorUri` is 2 KiB at most
  once normalised: every writer stores what it is handed. A handle (`Handle`: 2–32 of
  `a–z0–9_.` + `_` + 5 of `a–z0–9`) is derived from the display name at registration, never
  typed.

### Profile
- An inbound `Update{Person}` changes only its signer's own account, never one of this instance
  (`ReceiveProfileUpdate`), and keeps only a name, an `http(s)` avatar URL, pronouns and a bio
  within `PublicProfile::within_limits` — every friend's client loads that URL. The `summary`
  is HTML both ways (`activitypub::summary_html` / `summary_text`).
- Accepting a friend elsewhere sends them an `Update{Person}`, on both sides
  (`application::profile::introduce`): each instance read the other's `Person` at request time.
- Whether a viewer may read a card is `CardFacts::card` (domain); the facts come in one query
  (`PgProfileCards`).
- An avatar is replaced upload → `users.avatar_url` → removal of the other types, and cleared
  `users.avatar_url` → removal: the account never points at a removed object.

### Reaching a user
- Whether one account may message another goes through `domain::social::Relation`, read by the
  `Reachability` port in one query — never an ad-hoc check. A block and the contact setting give
  the same refusal, so nobody can tell one from the other
  (`identity-provider/specs/social.md § 2`).

### Conversations
- Every conversation (DM or group) has a stable **`conversation_id UUID`** that never changes regardless of participant count.
- Never derive a conversation key from actor URIs.
- For **DMs**, the UUID is minted at **friendship-accept time** on the accepter's IdP (`SocialGraph::accept` flips both rows and opens the DM in one transaction). It's propagated to the requester's IdP via the WS `friend_accepted` payload (`FriendshipPayload.conversation_id`) for local accepts, or via a non-standard `conversationId` field on the AP `Accept{Follow}` activity for cross-IdP accepts (the peer's `ReceiveAccept` opens its DM under the same id). The first-message-sender path is gone; the WS `dm-conversations` query is invalidated on `friend_accepted` so clients see the row immediately. Group conversations still mint the UUID at creation time.
- **One DM per pair**: the pair is a unique key. An id a client pins or a peer advertises is used only when the pair has no DM yet, and only if it names no conversation or a DM none but the pair ever belonged to (`domain::messaging::may_hold_dm`) — never a group, never another pair's DM.
- **A group's copies converge by stamps**: each instance holding a member keeps its own copy, and
  takes a name, a role, a join or a rejoin from a snapshot only when its stamp is newer than the
  one held (`domain::messaging::GroupSnapshot::changes`) — so a stale snapshot never undoes a
  departure, a rename or a role change (`identity-provider/specs/groups.md § 7`).
- **One Note per member, one copy per instance**: a group activity reaches each member's inbox on
  its own, so an instance holding several members gets it several times, at once or not. What it
  writes once acts for every member there: a stored message is pushed to each
  (`ReceiveMessage`); a roster brings in, checks and announces each account it lists
  (`messaging::shared::Roster`), and only whom `Conversations::mirror_group` says its write
  brought in is told and given a line — never decide "new here" from a read taken before it.
- `kind = 'dm'` | `'group'`. DM titles are derived client-side from `members[0].display_name`. Group titles use the stored `name` column (defaults to comma-joined member display names at creation, editable via `PATCH`).
- **Cross-IdP row-id bridging**: `direct_messages.id` and `message_attachments.id` are NOT freshly generated — they're derived from the trailing UUID of the message's `activity_uri` (`<issuer>/users/<username>/activities/<uuid>`) and the attachment's URL (`<issuer>/api/attachments/<uuid>/content`) respectively. Both IdPs in a cross-server DM see the same activity URLs, so both compute the same row ids. Without this, anything that references a message or attachment by id from inside the encrypted MLS body (reactions' `target_message_id`, `AttachmentBlobKey.id`, edits, replies) silently fails on the receiver. The rule lives in `domain::messaging` (`MessageId::of_activity`, `AttachmentId::of_content_url`) and every writer goes through it; a URI without a trailing UUID gets a fresh id. An inbound attachment URL is kept only when it is the sender's own instance's `/content` endpoint (`AttachmentLimits::admit`), since this IdP later fetches it as itself.

### Redis
- **pub-sub** → ephemeral events (presence states, typing indicators). Loss is acceptable.
- **Streams** → durable events (DMs). Must survive disconnect. Profile and friendship events go
  to the live sessions only.

### Federation
- **Outbound AP delivery** is best-effort, inline `tokio::spawn` per remote inbox — no persistent outbox queue. A delivery never fails the request that caused it: friendship activities go through the fire-and-forget `SocialFederation` port. Each activity owns its own reconciliation story (the next profile change, idempotent retry, a failed 1:1 DM reported to its sender). See `identity-provider/specs/event-delivery.md § 2`.
- **`remote_actors.inbox_url`** is cached on first WebFinger resolution. Every writer (`remote_actors::upsert()`, `FederatedRemoteActors`) uses `COALESCE(EXCLUDED.inbox_url, remote_actors.inbox_url)` — never overwrite a cached value with `None`.
- **A group's changes travel on their own**: an add, removal, leave, rename or role change made
  here is sent to the group's remote members as `Add`, `Remove`, `Leave` or `Update`, stamped
  (`GroupFederation`, `ReceiveGroupChange`; `identity-provider/specs/groups.md § 8`).
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
                            admitted_at: let in without confirming the address — signs in without a
                            code, is never mailed one, never swept; is_admin: an admin of the
                            instance; invited_by: the admin whose invitation let it in,
                            totp_secret, totp_enabled, totp_last_step — a code is good once,
                            contact_policy: everyone | friends_and_groups (default) | friends)
email_verification_codes — signup codes (peppered HMAC, 10-min expiry, 5 attempts, 5 codes / 10 min)
pending_totp_enrollments — in-flight 2FA secret awaiting first-code verify
pending_totp_logins      — short-lived "passed password, need TOTP" tickets carrying OIDC params
                            (5 attempts)
sessions                 — browser and app sessions (user_id, kind: browser | app, client_id for an
                            app's, device_id: the E2EE device it signed in — one live session a
                            device, created_at, last_used_at, authenticated_at: the password last
                            typed on it, revoked_at, revoked_reason: sign_out |
                            replaced | reuse | device_revoked | signed_out_elsewhere): live until
                            revoked or 90 days unused; the cookie names a browser one, every code
                            (authorization_codes.session_id), access token (`sid`) and refresh
                            token belongs to one
refresh_tokens           — chains of refresh tokens, kept as SHA-256 (session_id, client_id,
                            rotated_at, successor_hash): each use rotates the head; a rotated one
                            presented again ends its session
client_sign_ins          — the apps each account signed in to with its password (offline_access
                            once asked, kept): a session signs in silently to these only
recovery_codes           — 10 per user, single-use, peppered HMAC
invitations              — an admin's single-use links (token_hash: SHA-256 only, created_by,
                            created_at, expires_at = 7 days on, used_at + used_by, revoked_at):
                            open while unused, unrevoked, unexpired; swept 30 days after it ended
remote_actors            — cache of federated users (inbox_url, display_name, avatar_url, pronouns,
                            bio — as the actor's own `Update{Person}` or document last said, within
                            the profile limits; fetched_at dates the last resolution)
user_settings            — account settings, one client-owned JSONB document per user
                            (sections replaced whole by PATCH /api/settings; ≤ 16 KiB)
friendships              — friend graph (friend_actor_uri, status, direction: outgoing|incoming —
                            only the incoming side may answer; friend_avatar_url, read for a
                            remote friend only — a local one is shown from `users`;
                            accepted_at, set once when the side is accepted, and only then)
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
- Always validate `redirect_uri` against the client's own document (its `client_id` URL), exactly
- A bearer token is good only while its session lives: every authenticated route and the `/ws`
  upgrade go through `application::auth::Authenticate`, never `TokenVerifier` alone
- A sensitive action — revoking a device, signing out the others, turning TOTP on, clearing the
  history backup — takes the `RecentlySignedIn` extractor: the token's `auth_time` within
  `RECENT_SIGN_IN` (10 min), else `401 insufficient_user_authentication` (RFC 9470)
  (`identity-provider/specs/auth.md § 1` "Sensitive actions")
- A refresh token is never stored, only its SHA-256; nor is an invitation's token, whose path
  (`/i/{token}`) the request log writes as `/i/…`
- Only admins create, list and revoke invitations: the use cases refuse anyone else
  (`AuthError::NotAdmin`, `403`)
- The password is typed on this instance's own pages only: never a form on a client. The pages run
  no script but their own file (`/assets/sign-in.js`), their forms take same-origin POSTs only, and an error reaches them as a code —
  never as words a link chooses
- Reject PKCE `plain` challenge method
- HTTP Signature verification is mandatory on all incoming ActivityPub activities
- Private keys must never be stored in the database — use filesystem or secrets manager
- `SESSION_SECRET` is never a key itself: `app::keys::SessionKeys` derives one per purpose from
  all of it (HKDF-SHA256) — the session cookie's, the attachment links'. A new purpose takes a
  new label, never an existing key

## Running and stopping

`Application::build` connects to Postgres, Redis and the object store, runs the migrations, creates
the first admin from `ADMIN_EMAIL` / `ADMIN_PASSWORD` when no account has that address — or
refuses to start, saying why (`identity-provider/specs/auth.md § 4`) — and starts the background
tasks; `run_until_stopped` serves until its stop token is cancelled — by
`SIGTERM` or Ctrl-C in the binary. It then takes no new connection, answers the requests under
way, closes each WebSocket with `1001` and ends the peers' presence streams, lets every background
task finish its run under way, and drops what is still open ten seconds on
(`identity-provider/specs/presence.md` § When the instance stops).

---

## Environment variables

`.env.example` at the repo root documents every variable the service reads, and the root
`README.md` groups them; `app::configuration` is where they are read. `ADMIN_PASSWORD` is only
ever read to create the first admin, never logged and never written over the account's password.
`WEB_APP_ORIGIN` overrides the built-in official web app's address
(`domain::auth::OFFICIAL_WEB_APP_ORIGIN`) in any environment; development defaults it to
`http://localhost:5173`.

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
