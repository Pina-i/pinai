# Pīna'i — Identity Provider

OIDC identity provider and ActivityPub federation server for the Pīna'i platform.

Built with Rust · Axum · SQLx · PostgreSQL · Redis · Ed25519

---

## What it does

- **OIDC / OAuth 2.0** — authorization code flow with mandatory PKCE (`S256`) for the web client
- **Session SSO** — a signed `HttpOnly` cookie skips the login form on repeat visits
- **Sign-up and second factor** — emailed verification codes, TOTP with one-time recovery codes
- **ActivityPub federation** — WebFinger discovery, actor documents, friend requests, DMs and
  profile updates between instances, every inbound activity HTTP-signed
- **Messaging backbone** — DMs and groups over WebSocket, with opaque MLS ciphertext as the body
- **E2EE key directory** — IdP-attested devices, KeyPackages, MLS commits and Welcomes, the
  encrypted history archive
- **Presence** — online/away/dnd and typing, shared with peer instances by poll and SSE stream
- **User handles** — the chosen name, `_`, and 5 random characters of `a–z0–9` (e.g. `alice_xk9mp`)

---

## Project structure

The Cargo workspace is the monorepo's: its manifest, `compose.yaml`, `.env.example` and the
`Makefile` sit at the repo root, one level up.

```
identity-provider/
├── crates/
│   ├── domain/          # entities, rules, port traits, typed errors
│   ├── application/     # the use cases
│   ├── infrastructure/  # outbound adapters: Postgres, Redis, other instances, SMTP, S3
│   ├── api/             # inbound adapters: every route, the inbox, the WebSocket
│   ├── app/             # the composition root and the `idp-server` binary
│   ├── connections/     # the live connections, shared by `api` and `infrastructure`
│   └── dev-inject-data/ # seeds a development instance
├── migrations/          # SQLx migrations (applied on startup)
├── specs/               # this service's specifications
├── docker/
│   ├── Dockerfile
│   └── Dockerfile.dev
└── keys/                # instance signing keys (git-ignored)
```

`CLAUDE.md` describes the architecture, the rules every change follows, and each endpoint in
detail.

---

## Running

Setup, the instance secrets and signing key, both ways of running (Docker or `cargo run`), the
dev users and the configuration reference are in the root [`README.md`](../README.md). In short,
from the repo root:

```bash
make alice   # an instance on :8080
make bob     # a second one on :8081, to exercise federation
```

```bash
curl http://localhost:8080/health   # → {"ok":true}
```

---

## API reference

Paths only — the rules, bodies and status codes of each route are in `CLAUDE.md` § API endpoints.

### OIDC and sign-in

| Method | Path | Description |
|---|---|---|
| `GET` | `/.well-known/openid-configuration` | OIDC discovery document |
| `GET` | `/.well-known/jwks.json` | Public key set (Ed25519 JWK) |
| `GET` | `/authorize` | Start the flow — a code at once for a live session cookie, else the web client's login page |
| `POST` | `/login` | Login form — a code and session cookie, or on to email verification or the TOTP step |
| `POST` | `/login/totp` | The second step: an authenticator or recovery code |
| `POST` | `/token` | Code exchange → `access_token` + `id_token` |
| `GET` | `/userinfo` | Bearer token → the account, its settings and privacy |
| `GET` | `/logout` | Clears the session cookie, redirects to `post_logout_redirect_uri` |
| `POST` | `/register` | JSON self-registration; a verification code is mailed |
| `POST` | `/register-and-login` | The web client's sign-up form, carrying the OIDC request on |
| `POST` | `/verify-email-and-login` | The mailed code — confirms the address, continues the flow |
| `POST` | `/verify-email/resend` | Another code |
| `GET` | `/i/{token}` | An invitation's doorway |
| `GET` · `POST` | `/i/{token}/sign-up` | Its sign-up form — an admitted account, then into the web app signed in |
| `POST` | `/dev/send-test-email` | Development instances only — checks SMTP |

### Account (Bearer)

| Method | Path | Description |
|---|---|---|
| `PATCH` | `/api/profile` | Display name, pronouns, bio |
| `PUT` · `DELETE` | `/api/avatar` | Replace or clear the avatar |
| `PATCH` | `/api/settings` | Replace account-settings sections |
| `PATCH` | `/api/privacy` | Who may message the account |
| `POST` | `/api/totp/enroll` · `/api/totp/enroll/verify` | Enroll an authenticator |
| `POST` | `/api/totp/disable` · `/api/totp/recovery-codes/regenerate` | Turn it off, or new recovery codes |
| `GET` | `/api/users/search?q=` | Accounts by handle |
| `POST` · `GET` | `/api/admin/invitations` | An admin's: create an invitation, list the open ones |
| `DELETE` | `/api/admin/invitations/{id}` | An admin's: revoke an open invitation |

### Friends and blocks (Bearer)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/friends` | Accepted friends, local and remote |
| `POST` | `/api/friends/request` | `{ address }` — a local account or a remote one |
| `GET` | `/api/friends/incoming` | Pending requests aimed at me |
| `POST` | `/api/friends/{friendship_id}/accept` | Accept — opens the DM |
| `DELETE` | `/api/friends/{friendship_id}/reject` | Decline, silently |
| `DELETE` | `/api/friends/{actor_uri}` | Unfriend |
| `GET` · `POST` | `/api/blocks` | List blocked actors · block one |
| `DELETE` | `/api/blocks/{actor_uri}` | Unblock |

### Conversations and attachments (Bearer)

| Method | Path | Description |
|---|---|---|
| `POST` · `GET` | `/api/dm` | Send a 1:1 message · list conversations |
| `GET` | `/api/dm/{conversation_id}` | History, newest first |
| `POST` | `/api/dm/{conversation_id}/read` | Mark the conversation read |
| `PATCH` | `/api/dm/{message_id}/edit` | Edit one's own message |
| `POST` | `/api/groups` | Create a group |
| `PATCH` | `/api/groups/{conversation_id}` | Rename it |
| `POST` | `/api/groups/{conversation_id}/messages` | Send to a group |
| `GET` · `POST` | `/api/groups/{conversation_id}/members` | List · add a member |
| `DELETE` | `/api/groups/{conversation_id}/members/{actor_uri}` | Remove a member, or leave |
| `POST` | `/api/groups/{conversation_id}/members/{actor_uri}/role` | Promote or demote |
| `POST` | `/api/attachments` | Upload files |
| `GET` | `/api/attachments/{id}` | A token-protected blob URL and metadata |
| `GET` | `/api/attachments/{id}/blob` | The bytes (token-authed) |

### E2EE (Bearer)

| Method | Path | Description |
|---|---|---|
| `GET` · `POST` | `/api/keys/devices` | List devices · register or renew one |
| `POST` | `/api/keys/devices/{device_id}/revoke` | Revoke a device |
| `POST` | `/api/keys/packages` | Upload KeyPackages |
| `POST` | `/api/keys/packages/claim` | Claim one (Bearer or HTTP Signature) |
| `GET` | `/api/keys/packages/status` | KeyPackages left per device |
| `POST` · `GET` | `/api/mls/groups/{conversation_id}/commits` | Append a commit · catch up |
| `GET` · `POST` | `/api/mls/welcomes` | Claim this device's Welcomes · send one |
| `POST` · `GET` · `DELETE` | `/api/history/messages` | The encrypted history archive |
| `GET` · `POST` | `/api/history/salt` | Its per-user salt |

### Realtime and presence

| Method | Path | Description |
|---|---|---|
| `GET` | `/ws?token=` | WebSocket — DMs, presence, events |
| `GET` | `/api/presence?actors[]=` | Presence snapshot (Bearer) |
| `POST` | `/api/presence/batch` | Peer batch poll (HTTP Signature) |
| `GET` | `/api/presence/stream?actors[]=` | Peer SSE stream (HTTP Signature) |

### Federation

| Method | Path | Description |
|---|---|---|
| `GET` | `/.well-known/webfinger` | Discovery (`?resource=acct:alice_xk9mp@domain`) |
| `GET` | `/actor` | The instance's own actor, whose key signs inter-instance requests |
| `GET` | `/users/{handle}` | Actor profile (`Person`, `application/activity+json`) |
| `POST` | `/users/{handle}/inbox` | Peers' activities (HTTP Signature) |
| `GET` | `/users/{handle}/outbox` · `/followers` · `/following` | Always-empty collections |
| `GET` | `/api/attachments/{id}/content` | Attachment bytes for a peer (HTTP Signature) |
| `GET` | `/health` | `{"ok": true}` |
