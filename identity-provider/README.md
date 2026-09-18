# Pīna'i — Identity Provider

OIDC identity provider and ActivityPub federation server for the Pīna'i platform.

Built with Rust · Axum · SQLx · PostgreSQL · Ed25519

---

## What it does

- **OIDC / OAuth 2.0** — full PKCE authorization code flow for the web client
- **Session SSO** — signed `HttpOnly` cookie skips the login form on repeat visits
- **ActivityPub** — WebFinger discovery, Actor profiles, Follow/DM social graph
- **User handles** — `username-XXXX` format (e.g. `alice-7G4K`), 4-char base36 suffix derived from the user's UUID

---

## Project structure

```
identity-provider/
├── Cargo.toml                  # Workspace root
├── .env.example                # All supported environment variables
├── migrations/                 # SQLx migrations (run automatically on startup)
│   ├── 000001_create_users.sql
│   ├── 000002_create_oauth_clients.sql
│   ├── 000003_create_authorization_codes.sql
│   ├── 000004_add_handle_suffix.sql
│   ├── 000005_create_follows.sql
│   └── 000006_create_direct_messages.sql
├── crates/
│   ├── config/     # Config struct — loads all env vars
│   ├── db/         # SQLx models, repos (users, clients, auth_codes, follows, messages)
│   ├── oidc/       # All HTTP handlers (OIDC + federation)
│   └── server/     # Binary — main.rs + router.rs
└── docker/
    ├── Dockerfile
    └── docker-compose.yml
```

---

## Quick start (local dev)

### 1. Prerequisites

- Rust (stable, 1.88+)
- PostgreSQL 15+
- OpenSSL

### 2. Generate the Ed25519 signing key

```bash
mkdir -p keys
openssl genpkey -algorithm ed25519 -out keys/ed25519.pem
```

> `keys/` is git-ignored. Never commit private keys.

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env — at minimum set DATABASE_URL and SESSION_SECRET
```

### 4. Start PostgreSQL

```bash
docker compose -f docker/docker-compose.yml up -d postgres
```

Or point `DATABASE_URL` at any existing Postgres instance and create the database manually:

```bash
createdb identity_provider
```

### 5. Run the server

```bash
cargo run -p idp-server
```

Migrations are applied automatically on startup. The server listens on `http://localhost:8080` by default.

---

## Environment variables

All variables are documented in [`.env.example`](.env.example). Copy it to `.env` for local development.

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | yes | — | PostgreSQL connection string |
| `DOMAIN` | yes | — | Hostname (no scheme), e.g. `localhost:8080` |
| `JWT_PRIVATE_KEY_PATH` | yes | — | Path to the Ed25519 PKCS#8 PEM private key |
| `JWT_KEY_ID` | yes | — | Key ID included in JWTs and JWKS, e.g. `key-2025-01` |
| `PORT` | no | `8080` | TCP port to listen on |
| `SESSION_SECRET` | no | dev default | ≥ 32-byte secret for signing session cookies — **required in production** |
| `FRONTEND_URL` | no | `http://localhost:5173` | Web-client base URL, used for login/register redirects |
| `CORS_ORIGINS` | no | `http://localhost:5173,http://localhost:3000` | Comma-separated allowed CORS origins |
| `RUST_LOG` | no | `info` | Log filter (e.g. `debug`, `idp_oidc=trace`) |
| `LOG_FORMAT` | no | pretty | Set to `json` for structured production logs |
| `POSTGRES_USER` | Docker | `pina` | Used by the compose Postgres container |
| `POSTGRES_PASSWORD` | Docker | `secret` | Used by the compose Postgres container |
| `POSTGRES_DB` | Docker | `identity_provider` | Used by the compose Postgres container |
| `POSTGRES_PORT` | Docker | `5432` | Host port mapped to Postgres |

---

## Docker

### Build and run the full stack

```bash
cp .env.example .env   # fill in production values
docker compose -f docker/docker-compose.yml up -d
```

The compose file reads everything from `.env` via `env_file`. The only values it overrides are:

- `DATABASE_URL` — hostname swapped from `localhost` to the `postgres` compose service
- `JWT_PRIVATE_KEY_PATH` — points to `/run/secrets/ed25519.pem` (mounted from `./keys/`)

### Running two instances for federation testing

This lets you test ActivityPub federation locally — Alice's instance can follow Bob's and exchange direct messages.

#### Step 1 — Generate two key pairs

```bash
mkdir -p keys/alice keys/bob
openssl genpkey -algorithm ed25519 -out keys/alice/ed25519.pem
openssl genpkey -algorithm ed25519 -out keys/bob/ed25519.pem
```

#### Step 2 — Create two env files

Place both files in the `docker/` folder.

**`docker/.env.alice`**
```env
# ── PostgreSQL ────────────────────────────────────────────────────────────────
POSTGRES_USER=pina
POSTGRES_PASSWORD=secret
POSTGRES_DB=idp_alice
POSTGRES_PORT=5432

# Full connection string used by the application
DATABASE_URL=postgres://pina:secret@localhost:5432/idp_alice

# ── Server ────────────────────────────────────────────────────────────────────
DOMAIN=localhost:8080
PORT=8080

# ── Keys ─────────────────────────────────────────────────────────────────────
JWT_PRIVATE_KEY_PATH=./keys/alice/ed25519.pem
JWT_KEY_ID=alice-key-2025

# ── Session ───────────────────────────────────────────────────────────────────
SESSION_SECRET=alice-replace-with-openssl-rand-hex-32-output-00000000

# ── Frontend ──────────────────────────────────────────────────────────────────
FRONTEND_URL=http://localhost:5173
CORS_ORIGINS=http://localhost:5173

# ── Logging ───────────────────────────────────────────────────────────────────
RUST_LOG=info
```

**`docker/.env.bob`**
```env
# ── PostgreSQL ────────────────────────────────────────────────────────────────
POSTGRES_USER=pina
POSTGRES_PASSWORD=secret
POSTGRES_DB=idp_bob
POSTGRES_PORT=5433

# Full connection string used by the application
DATABASE_URL=postgres://pina:secret@localhost:5433/idp_bob

# ── Server ────────────────────────────────────────────────────────────────────
DOMAIN=localhost:8081
PORT=8081

# ── Keys ─────────────────────────────────────────────────────────────────────
JWT_PRIVATE_KEY_PATH=./keys/bob/ed25519.pem
JWT_KEY_ID=bob-key-2025

# ── Session ───────────────────────────────────────────────────────────────────
SESSION_SECRET=bob-replace-with-openssl-rand-hex-32-output-000000000

# ── Frontend ──────────────────────────────────────────────────────────────────
FRONTEND_URL=http://localhost:5173
CORS_ORIGINS=http://localhost:5173

# ── Logging ───────────────────────────────────────────────────────────────────
RUST_LOG=info
```

#### Step 3a — Run with `cargo run` (recommended for development)

Open two terminals and load the env file before running the server.

**Using `make` (recommended):**

```bash
make alice   # Terminal 1 — Alice on :8080
make bob     # Terminal 2 — Bob on :8081
```

**Or manually from `identity-provider/`:**

```bash
# Terminal 1 — Alice on :8080
set -a && source docker/.env.alice && set +a && cargo run -p idp-server

# Terminal 2 — Bob on :8081
set -a && source docker/.env.bob && set +a && cargo run -p idp-server
```

Each process runs its own migrations automatically and connects to its own database.

#### Step 3b — Run with Docker Compose

```bash
make alice-docker
make bob-docker
```

To stop and remove:

```bash
make alice-down
make bob-down
```

#### Step 4 — Verify both instances are up

```bash
curl http://localhost:8080/health   # → {"ok":true}
curl http://localhost:8081/health   # → {"ok":true}

# Check WebFinger once users are registered
curl "http://localhost:8080/.well-known/webfinger?resource=acct:alice-XXXX@localhost:8080"
curl "http://localhost:8081/.well-known/webfinger?resource=acct:bob-YYYY@localhost:8081"
```

---

## API reference

### OIDC

| Method | Path | Description |
|---|---|---|
| `GET` | `/.well-known/openid-configuration` | OIDC discovery document |
| `GET` | `/.well-known/jwks.json` | Public key set (Ed25519 JWK) |
| `GET` | `/authorize` | Start OIDC flow — serves login form or issues code via SSO cookie |
| `POST` | `/login` | Form submit — validates credentials, sets session cookie, redirects |
| `POST` | `/token` | PKCE code exchange → `access_token` + `id_token` |
| `GET` | `/userinfo` | Bearer token → user claims |
| `POST` | `/register` | JSON `{username, email, password}` → 201 with handle |
| `POST` | `/register-and-login` | Form submit — register + immediately start OIDC flow |
| `GET` | `/logout` | Clears session cookie, redirects to `post_logout_redirect_uri` |

### ActivityPub (public)

| Method | Path | Description |
|---|---|---|
| `GET` | `/.well-known/webfinger` | WebFinger discovery (`?resource=acct:alice-7G4K@domain`) |
| `GET` | `/users/{handle}` | Actor profile (Person, `application/activity+json`) |
| `POST` | `/users/{handle}/inbox` | Receive AP activities (Follow, Accept, Reject, Undo, Create/Note) |
| `GET` | `/users/{handle}/outbox` | Outbox (OrderedCollection) |
| `GET` | `/users/{handle}/followers` | Followers collection |
| `GET` | `/users/{handle}/following` | Following collection |

### Social graph & DMs (Bearer token required)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/users/search?q=` | Search users by username |
| `POST` | `/api/follow` | `{handle}` — follow a user |
| `DELETE` | `/api/follow/{handle}` | Unfollow |
| `GET` | `/api/follow/incoming` | Pending follow requests aimed at me |
| `POST` | `/api/follow/{id}/accept` | Accept a follow request |
| `POST` | `/api/follow/{id}/reject` | Reject a follow request |
| `GET` | `/api/following` | Users I follow (accepted) |
| `GET` | `/api/followers` | My accepted followers |
| `POST` | `/api/dm` | `{recipient_handle, content}` — send a direct message |
| `GET` | `/api/dm` | List DM conversations |
| `GET` | `/api/dm/{handle}` | Conversation history with a user |
| `GET` | `/health` | `{"ok": true}` |
