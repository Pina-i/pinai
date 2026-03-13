# CLAUDE.md — identity-provider

## Project Context

This is the **core security service** of the Pina-i platform, a self-hostable, federated, open-source Discord alternative built under the GitHub organization `Pina-i`.

This service is **Layer 2** of a three-layer architecture:
- Layer 1: Clients (web-client, desktop-client)
- **Layer 2: Identity & Messaging Backbone ← this repo**
- Layer 3: Chat servers (chat-server)

## What This Service Does

This is a single self-hostable Rust service that bundles:

1. **OIDC Provider** — user registration, authentication, JWT issuance
2. **Messaging Backbone** — friend graph, private DMs over WebSocket
3. **ActivityPub Federation** — federation with other identity-provider instances

A user's permanent identity is expressed as `alice@idp.alice.com`. This identity is portable across all chat servers in the network.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Rust (stable) |
| Web framework | Axum + Tokio |
| Database | PostgreSQL via SQLx |
| Auth protocol | OIDC / OAuth2 (Authorization Code + PKCE) |
| Token format | JWT (RS256, Ed25519) |
| Federation protocol | ActivityPub (W3C standard) |
| Inter-server auth | HTTP Signatures |
| Real-time | WebSockets (for DMs) + Redis Streams (durable broker) |
| Message broker | Redis (Streams for durability, pub-sub for presence) |
| Containerization | Docker / Docker Compose |

## Related Repositories

| Repo | Role |
|------|------|
| `pina-i/chat-server` | Consumes JWTs issued by this service via JWKS |
| `pina-i/core-libs` | Shared crates: JWT utils, HTTP signatures, ActivityPub types |
| `pina-i/web-client` | Frontend that drives the OIDC login flow |

## Workspace Structure (Cargo)

```
identity-provider/
├── Cargo.toml              # workspace root (crates: config, db, oidc, server)
├── crates/
│   ├── server/             # main Axum application, entrypoint + router
│   ├── oidc/               # OIDC/OAuth2 flows, JWT issuance, JWKS
│   │   ├── src/
│   │   │   ├── federation/ # ActivityPub, WebFinger, inbox, friends, DMs (REST), delivery
│   │   │   └── ws/         # WebSocket upgrade handler + hub + events + broker
│   ├── db/                 # SQLx models, migrations, repositories
│   └── config/             # Configuration loading, env vars
├── migrations/             # SQLx migrations (numbered, applied by idp-db on startup)
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml  # Standalone self-hosted deployment
├── keys/                   # JWT signing keys (gitignored)
└── .env.example
```

> **Note**: there is no separate `federation/` or `messaging/` crate. All ActivityPub logic, WebSocket handling, DMs, and friend graph live as modules inside the `oidc` crate.

## Deployment

This repo ships its own `Dockerfile` and `docker-compose.yml`. No external infrastructure repo is needed.

```yaml
# docker/docker-compose.yml
services:
  idp:
    build: ..
    environment:
      DOMAIN: idp.alice.com
      DATABASE_URL: postgres://pina:secret@postgres/identity_provider
      JWT_PRIVATE_KEY_PATH: /run/secrets/ed25519.pem
    volumes:
      - ./keys:/run/secrets:ro
    ports:
      - "8080:8080"
    depends_on:
      - postgres

  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: pina
      POSTGRES_PASSWORD: secret
      POSTGRES_DB: identity_provider
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

**Key operational notes:**
- TLS must be terminated by a reverse proxy (Caddy or Nginx) in production
- JWT private keys are mounted as a file secret — never stored in env vars or the database
- When rotating JWT signing keys, keep the old key in JWKS for at least the maximum JWT lifetime (default: 1h) before removing it
- The `keys/` directory is gitignored — generate keys locally with `openssl genpkey -algorithm ed25519`

## Key OIDC Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | OIDC Discovery document |
| `GET /.well-known/jwks.json` | Public keys for JWT validation |
| `GET /.well-known/webfinger` | ActivityPub actor discovery |
| `GET /authorize` | Authorization endpoint (PKCE flow) |
| `POST /token` | Token exchange endpoint |
| `GET /userinfo` | UserInfo endpoint |
| `POST /register` | User self-registration |
| `POST /users/:handle/inbox` | ActivityPub inbox (receives Follow/Accept/Create/etc.) |
| `GET /users/:handle` | ActivityPub actor profile (JSON-LD) |
| `GET /ws?token=<jwt>` | WebSocket upgrade (DMs + events) |
| `POST /api/dm` | Send a DM (REST) |
| `GET /api/dm` | List DM conversations |
| `GET /api/dm/:address` | Conversation history with paginated keyset cursor |

## Key Design Decisions

- **JWT algorithm**: Ed25519 preferred, RS256 for compatibility
- **PKCE**: Mandatory for all clients (S256 only, plain rejected)
- **Password hashing**: Argon2id
- **No client-side password storage** on chat servers — they only validate JWTs via JWKS
- **JWKS**: Must return an array of keys (not just one) to support key rotation
- **Chat servers cache JWKS** with a TTL and refetch on validation failure — design the JWKS endpoint with this in mind
- **ActivityPub actor == OIDC subject**: The same PostgreSQL row backs both identities — no sync overhead
- **HTTP Signatures**: Used for all ActivityPub POST deliveries between IdP instances
- **`remote_actors.inbox_url`**: Cached on first WebFinger resolution; used for direct ActivityPub delivery without re-resolving. `remote_actors::upsert()` uses `COALESCE(EXCLUDED.inbox_url, remote_actors.inbox_url)` so existing cached values are never overwritten by `None`.
- **Federated address format**: `username@domain` — **no** leading `@`. `User::federated_address(&self, domain)` produces e.g. `alice_xK9mP@idp.alice.com`. Clients receive raw actor URIs in some WS events and normalise to this format client-side via `actorUriToAddress()`.
- **DM delivery (remote)**: ActivityPub `Create{Note}` is delivered inline via a background `tokio::spawn`, not via `federation_queue`. Cache-first: check `remote_actors.inbox_url` → WebFinger on miss. Sender gets a WS echo; recipient's IdP handles real-time push when it receives the AP `Create` on its inbox.
- **DM delivery (local)**: message persisted → `hub.send_to_user()` for live connections + `broker.publish()` to Redis Streams for catch-up on reconnect.

## Federation Trust Model

| Relationship | Mechanism |
|---|---|
| User → this IdP | Password / Passkey via OIDC |
| Chat server → this IdP | JWT + JWKS public key fetch |
| This IdP → remote IdP | HTTP Signatures on ActivityPub activities |

## Development Roadmap (this repo)

Following the platform-wide phased approach:

- **Phase 3** ✅ DONE: OIDC provider — registration, login, JWT issuance, JWKS, discovery, session cookies
- **Phase 4** ✅ DONE: Messaging backbone — friend graph, private DMs (REST + WS), WebSocket hub + Redis broker
- **Phase 5** ✅ DONE: ActivityPub federation — WebFinger, inbox/outbox, Follow/Accept/Undo, HTTP Signatures, remote DM delivery

Phases 1–2 belong to `chat-server` and can be developed in parallel.

## Environment Variables

```env
DATABASE_URL=postgres://user:pass@localhost/identity_provider
DOMAIN=idp.alice.com
JWT_PRIVATE_KEY_PATH=./keys/ed25519.pem
JWT_KEY_ID=key-2024-01
PORT=8080
REDIS_URL=redis://localhost:6379
COOKIE_SECRET=<64-byte-hex-or-random-string>
```

## Security Constraints

- Never log raw passwords, tokens, or private keys
- JWT `iss` claim must always match `DOMAIN`
- Always validate `redirect_uri` against pre-registered clients
- Reject PKCE `plain` challenge method
- HTTP Signature verification is mandatory on all incoming ActivityPub activities
- Private keys must never be stored in the database — use filesystem or secrets manager

## Testing Strategy

- Unit tests for JWT issuance, PKCE validation, HTTP Signature logic
- Integration tests against a real PostgreSQL instance (use `sqlx::test`)
- End-to-end OIDC flow tests using a test OIDC client
- ActivityPub federation tests using mock remote actor servers
