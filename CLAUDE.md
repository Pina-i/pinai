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
| Real-time | WebSockets (for DMs) |
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
├── Cargo.toml              # workspace root
├── crates/
│   ├── server/             # main Axum application, entrypoint
│   ├── oidc/               # OIDC/OAuth2 flows, JWT issuance, JWKS
│   ├── federation/         # ActivityPub, WebFinger, HTTP Signatures
│   ├── messaging/          # Friend graph, DMs, WebSocket handlers
│   ├── db/                 # SQLx models, migrations, repositories
│   └── config/             # Configuration loading, env vars
├── migrations/             # SQLx migrations
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml  # Standalone self-hosted deployment
├── keys/                   # JWT signing keys (gitignored)
└── .env.example
```

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
| `GET /inbox/:username` | ActivityPub inbox |
| `GET /users/:username` | ActivityPub actor profile |

## Key Design Decisions

- **JWT algorithm**: Ed25519 preferred, RS256 for compatibility
- **PKCE**: Mandatory for all clients (S256 only, plain rejected)
- **Password hashing**: Argon2id
- **No client-side password storage** on chat servers — they only validate JWTs via JWKS
- **JWKS**: Must return an array of keys (not just one) to support key rotation
- **Chat servers cache JWKS** with a TTL and refetch on validation failure — design the JWKS endpoint with this in mind
- **ActivityPub actor == OIDC subject**: The same PostgreSQL row backs both identities — no sync overhead
- **HTTP Signatures**: Used for all ActivityPub POST deliveries between IdP instances

## Federation Trust Model

| Relationship | Mechanism |
|---|---|
| User → this IdP | Password / Passkey via OIDC |
| Chat server → this IdP | JWT + JWKS public key fetch |
| This IdP → remote IdP | HTTP Signatures on ActivityPub activities |

## Development Roadmap (this repo)

Following the platform-wide phased approach:

- **Phase 3** (this repo starts here): OIDC provider — registration, login, JWT issuance, JWKS, discovery
- **Phase 4**: Messaging backbone — friend graph, private DMs, WebSocket
- **Phase 5**: ActivityPub federation — WebFinger, inbox/outbox, Follow/Accept activities, HTTP Signatures

Phases 1–2 belong to `chat-server` and can be developed in parallel.

## Environment Variables

```env
DATABASE_URL=postgres://user:pass@localhost/identity_provider
DOMAIN=idp.alice.com
JWT_PRIVATE_KEY_PATH=./keys/ed25519.pem
JWT_KEY_ID=key-2024-01
PORT=8080
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
