# CLAUDE.md — chat-server

## Project Context

This is the **community chat server** of the Pina-i platform, a self-hostable, federated, open-source Discord alternative built under the GitHub organization `Pina-i`.

This service is **Layer 3** of a three-layer architecture:
- Layer 1: Clients (web-client, desktop-client)
- Layer 2: Identity & Messaging Backbone (identity-provider)
- **Layer 3: Chat Servers ← this repo**

## What This Service Does

A community server hosting chat **and voice** rooms. It is **intentionally simple and
stateless regarding credentials**:

- Does NOT store passwords
- Does NOT manage friendships
- Validates identity exclusively via JWT tokens issued by **its own** identity provider

**A chat server is attached to exactly one identity provider.** A room is addressed by a
URL derived from that IdP, the way a Matrix room is addressed by its home server. The
chat server and its IdP deploy together as one unit — this service is not independently
self-hostable.

**Only the attached IdP's users can join, for now.** Opening rooms to remote instances is
the intended direction, but it arrives as server-to-server federation — signed requests
between instances, the model the IdP already runs — not as this service accepting a wider
set of user tokens. Nothing here may foreclose that. See *Key Design Decisions*.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Rust (stable) |
| Web framework | Axum + Tokio |
| Database | PostgreSQL via SQLx |
| Auth | JWT validation via JWKS (RS256 / Ed25519) |
| Real-time | WebSockets (persistent per-client connection) |
| Containerization | Docker / Docker Compose |

## Related Repositories

Everything below `pina-i/pinai` is a subtree of this monorepo.

| Path | Role |
|------|------|
| `identity-provider/` | The attached IdP — issues the JWTs this service validates |
| `crates/jwt-utils/` | Shared JWT validation logic (workspace path dependency) |
| `pina-i/web-client` | Frontend — separate repository, connects via WebSocket |

## Workspace Structure (Cargo)

```
chat-server/
├── Cargo.toml              # workspace root
├── crates/
│   ├── server/             # main Axum application, entrypoint
│   ├── auth/               # JWT validation, JWKS fetching + caching
│   ├── channels/           # Channel CRUD, message handling
│   ├── roles/              # Role & permission management
│   ├── gateway/            # WebSocket connection management
│   ├── db/                 # SQLx models, migrations, repositories
│   └── config/             # Configuration loading, env vars
├── migrations/             # SQLx migrations
└── docker/
    └── Dockerfile
```

Compose and environment live at the **monorepo root**, not here: the IdP and the chat
server are one deployment unit. See the root `CLAUDE.md`.

## Deployment

Deployed together with its identity provider from the monorepo root `compose.yaml`.
There is no standalone compose for this service.

**Key operational notes:**
- TLS must be terminated by a reverse proxy (Caddy or Nginx) in production
- No secrets or credentials belong in this service
- Voice needs an SFU and TURN/STUN for NAT traversal — **not yet chosen**; nothing below
  assumes a particular one

## Key API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `POST /auth/session` | Exchange JWT for a local session/WS ticket |
| `GET /channels` | List channels |
| `POST /channels` | Create a channel (admin) |
| `GET /channels/:id/messages` | Fetch message history |
| `POST /channels/:id/messages` | Post a message |
| `GET /roles` | List roles |
| `POST /roles` | Create a role (admin) |
| `GET /ws` | WebSocket upgrade endpoint |

## JWT Validation Flow

1. Client presents a Bearer JWT in the `Authorization` header
2. Reject it unless `iss` equals `IDP_ISSUER` — the one IdP this server is attached to
3. Fetch JWKS from `{IDP_ISSUER}/.well-known/jwks.json` and cache the keyset with a TTL
4. On cache miss or signature failure, refetch once before rejecting — handles key rotation
5. Validate signature, `exp`, `iat`, `aud`
6. Use the `(iss, sub)` pair as the unique local user key — create a local user record on
   first login

This path authenticates **local users only**, and always will. Federation does not widen
it — see below.

## Key Design Decisions

- **User identity key**: `(issuer, subject)` pair — never just `sub` alone, as `sub` is
  only unique per issuer. Keep the compound key **even while single-tenant**: federated
  users arrive as issuer-scoped actor URIs, so a table keyed on `sub` alone collides the
  first time a remote `@alex@other.example` needs a local record — and retrofitting it
  means a migration plus a rekey of every user row and foreign key.
- **One issuer, not an allowlist**: `iss` must equal `IDP_ISSUER`. The server already
  needs that value to fetch JWKS and to build room URLs, so a separate list of accepted
  issuers would just be a second copy that can drift out of agreement with it.
- **Federation is server-to-server, not more JWTs**: a remote user never presents a token
  here. Their client talks to their own home server, and the two servers exchange signed
  HTTP requests — exactly what `identity-provider/crates/federation/` already does
  keyed at `<issuer>/actor#main-key`. That transport is already extracted to
  `crates/federation-transport/` — actor resolution, signed delivery, and inbound
  signature + digest verification. When rooms open to remote instances, this service
  adds an inbox on top of it and writes only its own verb handlers. The JWT path is
  untouched.
- **No password storage**: The auth module must never touch passwords in any form
- **WebSocket auth**: Authenticate the WS connection at upgrade time using the JWT; do not re-validate on every message
- **Roles are local**: Role assignments are managed entirely by this chat server — the IdP has no knowledge of them

## Environment Variables

```env
DATABASE_URL=postgres://user:pass@localhost/chat_server
DOMAIN=chat.gaming.com
PORT=8081
# The one identity provider this chat server is attached to. Rooms are addressed
# under it and its JWTs are the only ones accepted.
IDP_ISSUER=http://localhost:8080
JWKS_CACHE_TTL_SECONDS=3600
```

## Security Constraints

- Never store or log JWT raw values beyond the request lifecycle
- Always validate `exp` and `iat` claims
- Never trust `sub` alone — always scope it to `iss`
- JWKS must be fetched over HTTPS only (reject HTTP issuers in production)
- WebSocket connections must be authenticated before any message is processed

## Testing Strategy

- Unit tests for JWT validation logic (valid token, expired, wrong issuer, key rotation)
- Integration tests for channel and message APIs using a test JWT signed with a test key
- WebSocket integration tests for real-time message delivery
- Load tests for WebSocket connection handling under concurrency
