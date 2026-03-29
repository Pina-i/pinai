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

Shared crates (JWT utils, HTTP Signatures, ActivityPub types) live in `pina-i/core-libs`.

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

```
identity-provider/
├── Cargo.toml              # workspace root (crates: config, db, oidc, server)
├── crates/
│   ├── server/             # main Axum application, entrypoint + router
│   ├── oidc/               # OIDC/OAuth2 flows, JWT issuance, JWKS
│   │   └── src/
│   │       ├── federation/ # ActivityPub, WebFinger, inbox, friends, DMs (REST), delivery
│   │       └── ws/         # WebSocket upgrade handler + hub + events + broker
│   ├── db/                 # SQLx models, migrations, repositories
│   │   └── repos/          # auth_codes, clients, conversations, friendships,
│   │                       # messages, reactions, remote_actors, users
│   └── config/             # Configuration loading, env vars
├── migrations/             # SQLx migrations (numbered, applied on startup)
├── specs/                  # Feature specifications (see routing table below)
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── keys/                   # JWT signing keys (gitignored)
└── .env.example
```

> There is no separate `federation/` or `messaging/` crate. All ActivityPub logic, WebSocket
> handling, DMs, and friend graph live as modules inside the `oidc` crate.

---

## API endpoints

| Endpoint | Description |
|---|---|
| `GET /.well-known/openid-configuration` | OIDC Discovery document |
| `GET /.well-known/jwks.json` | Public keys for JWT validation |
| `GET /.well-known/webfinger` | ActivityPub actor discovery |
| `GET /authorize` | Authorization endpoint (PKCE flow) |
| `POST /token` | Token exchange |
| `GET /userinfo` | UserInfo endpoint |
| `POST /register` | User self-registration |
| `POST /users/:handle/inbox` | ActivityPub inbox (Follow/Accept/Create/Update/Like…) |
| `GET /users/:handle` | ActivityPub actor profile (JSON-LD) |
| `GET /ws?token=<jwt>` | WebSocket upgrade (DMs + presence + events) |
| `POST /api/dm` | Send a DM (creates conversation if first message) |
| `GET /api/dm` | List conversations (`kind`, `name`, `members[]`, `unread_count`, last message preview) |
| `GET /api/dm/:conversation_id` | Conversation history (keyset cursor); marks as read on initial load |
| `PATCH /api/dm/:conversation_id` | Edit a message / rename a group conversation |
| `GET /api/presence` | Current presence snapshot for a set of actors |
| `GET /api/presence/stream` | Inter-IdP SSE stream for active conversations (authenticated via HTTP Signatures) |
| `POST /api/presence/batch` | Inter-IdP batch presence poll for sidebar (authenticated via HTTP Signatures) |

---

## Spec files

All detailed specifications live in `specs/`. **Read only the file(s) relevant to your task.**

| File | Contents | Read when working on… |
|---|---|---|
| `specs/01-identity-federation.md` | `users`, `remote_actors`, `friendships` schema, real-time profile propagation, Redis broker strategy, `federation_queue` | Auth, user accounts, friend requests, profile updates, WebFinger, ActivityPub inbox/outbox, federation queue worker |
| `specs/02-architecture-diagram.md` | Mermaid flowchart of the full system (C4-style) | Understanding the global picture, updating the diagram |
| `specs/03-direct-messages.md` | `conversations`, `conversation_members`, `direct_messages` schema, DM delivery (local + federated), unread tracking, reactions, replies, message editing | Anything touching DMs, conversations, messages, reactions, replies, unread counts |
| `specs/04-presence.md` | Presence states (online/away/offline), typing indicators, Redis pub-sub channels, inter-IdP SSE stream, heartbeat, `PresenceStore` | Online status, typing indicators, presence propagation, inter-IdP SSE |

---

## Cross-cutting rules (always apply)

### Identity & addressing
- **`username`** = user input + NanoID suffix (e.g. `alice_xK9mP`). Used for federation and `actor_uri`. **Never shown in the UI.**
- **`display_name`** = user input only (e.g. `alice`). Freeform, not unique. **Only name shown client-side.**
- **Federated address format**: `username@domain` — **no** leading `@`. Produced by `User::federated_address(&self, domain)`. Clients receive raw actor URIs in some WS events and normalise to this format via `actorUriToAddress()`.
- **`actor_uri`** is the universal federation key (e.g. `https://idp.alice.com/users/alice_xK9mP`).

### Conversations
- Every conversation (DM or group) has a stable **`conversation_id UUID`** that never changes regardless of participant count.
- Never derive a conversation key from actor URIs.
- The UUID is generated by the first-message sender and shared via the ActivityPub `context` field.
- `kind = 'dm'` | `'group'`. DM titles are derived client-side from `members[0].display_name`. Group titles use the stored `name` column (defaults to comma-joined member display names at creation, editable via `PATCH`).

### Redis
- **pub-sub** → ephemeral events (presence states, typing indicators). Loss is acceptable.
- **Streams** → durable events (DMs, profile updates, friend requests). Must survive disconnect.

### Federation
- **`federation_queue`** handles profile updates and non-time-critical AP activities with exponential backoff (30s → 5m → 30m → 6h → 24h).
- **DM delivery** uses inline `tokio::spawn`, not `federation_queue`.
- **`remote_actors.inbox_url`** is cached on first WebFinger resolution. `remote_actors::upsert()` uses `COALESCE(EXCLUDED.inbox_url, remote_actors.inbox_url)` — never overwrite a cached value with `None`.
- **HTTP Signatures** are mandatory on all incoming ActivityPub activities and on inter-IdP presence SSE auth. Reuses the AP RSA key pair — no separate key material.

### Database
- **Soft deletes**: messages use `deleted_at TIMESTAMPTZ` — never hard-delete.
- **Keyset pagination**: always `(created_at DESC, id DESC)` — never `LIMIT/OFFSET`.

---

## Database schema — quick reference

```
users                    — local accounts (actor_uri, inbox_url, display_name, username+NanoID)
remote_actors            — cache of federated users (inbox_url, fetched_at TTL)
friendships              — friend graph (friend_actor_uri, friend_avatar_url, status)
federation_queue         — durable AP outbox with backoff retry
conversations            — anchor for every conversation (kind: dm|group, name)
conversation_members     — participants (actor_uri, joined_at, left_at)
direct_messages          — messages (conversation_id, sender_actor_uri, activity_uri, reply_to_id)
conversation_reads       — last_read_at per user per conversation (unread tracking)
message_reactions        — emoji reactions (message_id, reactor_actor_uri, emoji)
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

If a task touches multiple spec files (e.g. adding group conversations affects both
`specs/03-direct-messages.md` and `specs/04-presence.md`):

1. Read all relevant spec files.
2. Make changes consistently across all affected files.
3. Check the quick-reference schema above for any table that needs updating.
4. Note any impact on the architecture diagram (`specs/02-architecture-diagram.md`) — update it if new components or flows are introduced.
5. If the workspace structure change or API endpoints are added/modified/deleted, change the according sections of this file consistently
