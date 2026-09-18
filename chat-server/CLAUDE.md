# CLAUDE.md — chat-server

## Project Context

This is the **community chat server** of the Pina-i platform, a self-hostable, federated, open-source Discord alternative built under the GitHub organization `Pina-i`.

This service is **Layer 3** of a three-layer architecture:
- Layer 1: Clients (web-client, desktop-client)
- Layer 2: Identity & Messaging Backbone (identity-provider)
- **Layer 3: Chat Servers ← this repo**

## What This Service Does

A self-hostable community server managing channels, messages, and roles. It is **intentionally simple and stateless regarding credentials**:

- Does NOT store passwords
- Does NOT manage friendships
- Does NOT implement any federation protocol
- Validates identity exclusively via JWT tokens issued by any Pina-i-compatible identity provider

Any user from any identity provider can join any chat server. The trust boundary is the JWT.

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

| Repo | Role |
|------|------|
| `pina-i/identity-provider` | Issues the JWTs this service validates |
| `pina-i/core-libs` | Shared JWT validation logic (`jwt-utils` crate) |
| `pina-i/web-client` | Frontend that connects to this service via WebSocket |

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
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml  # Standalone self-hosted deployment
└── .env.example
```

## Deployment

This repo ships its own `Dockerfile` and `docker-compose.yml`. No external infrastructure repo is needed.

```yaml
# docker/docker-compose.yml
services:
  chat:
    build: ..
    environment:
      DOMAIN: chat.gaming.com
      DATABASE_URL: postgres://pina:secret@postgres/chat_server
      JWKS_CACHE_TTL_SECONDS: 3600
    ports:
      - "8080:8080"
    depends_on:
      - postgres

  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: pina
      POSTGRES_PASSWORD: secret
      POSTGRES_DB: chat_server
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

**Key operational notes:**
- TLS must be terminated by a reverse proxy (Caddy or Nginx) in production
- JWKS must be fetched over HTTPS only — reject HTTP issuers in production
- No secrets or credentials belong in this service

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
2. Extract `iss` (issuer) claim from the JWT
3. Fetch JWKS from `{iss}/.well-known/jwks.json`
4. Cache the keyset with a TTL (e.g. 1 hour)
5. On cache miss or signature failure: refetch JWKS before rejecting
6. Validate signature, `exp`, `iat`, `aud`
7. Use `(iss, sub)` pair as the unique local user key — create a local user record on first login

## Key Design Decisions

- **User identity key**: `(issuer, subject)` pair — never just `sub` alone, as `sub` is only unique per issuer
- **JWKS caching**: Cache with TTL + refetch on validation failure to handle key rotation gracefully
- **No password storage**: The auth module must never touch passwords in any form
- **WebSocket auth**: Authenticate the WS connection at upgrade time using the JWT; do not re-validate on every message
- **Roles are local**: Role assignments are managed entirely by this chat server — the IdP has no knowledge of them
- **Multi-IdP support**: The server must accept JWTs from any valid OIDC issuer, not just one hardcoded IdP

## Environment Variables

```env
DATABASE_URL=postgres://user:pass@localhost/chat_server
DOMAIN=chat.gaming.com
PORT=8080
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
