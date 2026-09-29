# Pīna'i

A self-hostable, federated, open-source Discord alternative. This monorepo holds
the backend services of the platform in a single Cargo workspace:

| Path | What it is |
|---|---|
| `identity-provider/` | Layer 2 — OIDC identity provider, ActivityPub federation, DMs, presence, E2EE device keys |
| `chat-server/` | Layer 3 — chat & voice rooms, attached to one identity provider (not yet implemented) |
| `crates/` | Shared libraries: `common-types`, `jwt-utils`, `http-signatures`, `activitypub`, `observability`, `federation-transport` |
| `specs/` | Platform-wide specifications (architecture, federation authentication) |
| `compose.yaml` | The full platform stack for Docker Compose |

The web client lives in a separate repository (`web-client`) and talks to these
services over HTTP. Each service has its own `README.md` / `CLAUDE.md` with its
internal architecture.

---

## Prerequisites

- **Rust** (stable) with the `clippy` and `rustfmt` components
  ```bash
  rustup component add clippy rustfmt
  ```
- **Docker** with Docker Compose v2 (`docker compose …`)
- **OpenSSL** — used to generate each instance's Ed25519 signing key
- **GNU Make** and **bash**

---

## Setup

### 1. Environment files

Every deployment unit is configured by one env file. Only the template,
`.env.example`, is committed; every other `.env*` file is git-ignored.

The dev targets expect two instances, **Alice** and **Bob**, so federation can be
exercised locally:

```bash
cp .env.example .env.alice
cp .env.example .env.bob
```

Then edit each one. At a minimum:

| Variable | Alice | Bob |
|---|---|---|
| `IDP_ENV` | `development` | `development` |
| `DOMAIN` / `PORT` | `localhost:8080` / `8080` | `localhost:8081` / `8081` |
| `POSTGRES_DB` / `POSTGRES_PORT` | `idp_alice` / `5432` | `idp_bob` / `5433` |
| `DATABASE_URL` | `postgres://pina:secret@localhost:5432/idp_alice` | `postgres://pina:secret@localhost:5433/idp_bob` |
| `REDIS_PORT` / `REDIS_URL` | `6379` / `redis://localhost:6379` | `6380` / `redis://localhost:6380` |
| `RUSTFS_PORT` / `RUSTFS_CONSOLE_PORT` | `9004` / `9005` | `9002` / `9003` |
| `STORAGE_ENDPOINT` | `http://localhost:9004` | `http://localhost:9002` |
| `MAILPIT_SMTP_PORT` / `MAILPIT_UI_PORT` | `1025` / `8025` | `1026` / `8026` |
| `SMTP_HOST` / `SMTP_PORT` | `localhost` / `1025` | `localhost` / `1026` |
| `IDP_KEYS_DIR` | `./identity-provider/keys/alice` | `./identity-provider/keys/bob` |
| `JWT_PRIVATE_KEY_PATH` | `./identity-provider/keys/alice/ed25519.pem` | `./identity-provider/keys/bob/ed25519.pem` |

Leave `SESSION_SECRET` and `EMAIL_OTP_PEPPER` as they are: the next step fills
them in.

`IDP_ENV` defaults to `production` when unset, which switches issuer URLs and
peer calls to `https` and sets the `Secure` cookie flag — always set it to
`development` locally.

All paths in the env files resolve against the working directory, so **run
every command from the repo root**.

### 2. Instance secrets

`SESSION_SECRET` (signs session cookies and attachment URLs) and
`EMAIL_OTP_PEPPER` (hashes email OTPs and TOTP recovery codes) are generated
into the env file with `openssl rand -hex 32`:

```bash
make alice-env    # fills .env.alice
make bob-env      # fills .env.bob
```

A value is generated only when it is missing, empty or still the `change-me`
placeholder. One that is already set is never replaced, so the targets are safe
to rerun, and `make alice`, `make bob` and the Docker targets run them first.

> **Back the env file up with the database.** Replacing `EMAIL_OTP_PEPPER`
> invalidates every stored TOTP recovery code. Replacing `SESSION_SECRET` only
> signs everyone out.

In production (`IDP_ENV` unset or `production`), the IdP refuses to start when
`SESSION_SECRET` is missing, shorter than 32 bytes, or a published placeholder,
and when `EMAIL_OTP_PEPPER` is missing or shorter than 32 bytes.

### 3. Instance signing key

Each instance owns one Ed25519 key that signs its JWTs, federation HTTP
Signatures and E2EE device attestations. It is generated on first run and never
regenerated:

```bash
make alice-keys   # → identity-provider/keys/alice/ed25519.pem
make bob-keys     # → identity-provider/keys/bob/ed25519.pem
```

These targets are idempotent and are already run by `make alice`, `make bob` and
the Docker targets. `docker compose up` does the same through the `idp-keygen`
service.

> **Alice and Bob must never share a key** — a shared key makes every
> cross-instance verification pass whether or not key resolution works.
> **Losing a key cannot be recovered from**: existing devices stop verifying.
> Back `IDP_KEYS_DIR` up together with the database.

---

## Running

### Option A — Docker (full stack)

Brings up Postgres, Redis, RustFS (S3-compatible storage), Mailpit (SMTP
catcher) and the identity provider, then seeds the dev users:

```bash
make alice-docker        # Linux (host networking, debug build)
make bob-docker

make alice-docker-win    # Windows / Docker Desktop (host.docker.internal)
make bob-docker-win
```

Each target copies `.env.<instance>` to `.env` (which compose reads), starts
Postgres, seeds it, then starts the rest under the compose project
`pinai-<instance>`. Stop with:

```bash
make alice-down          # stop containers, keep data
make alice-down-v        # stop containers and delete volumes
```

### Option B — Host (`cargo run`, fastest inner loop)

The IdP runs on your machine; its infrastructure still comes from Docker. Start
the dependencies for the instance first:

```bash
cp .env.alice .env
docker compose --project-name pinai-alice up -d --wait postgres redis rustfs mailpit
```

Then run the instance in the foreground (secrets + key generation + seed + `cargo run`):

```bash
make alice
make bob                 # in another terminal, after starting Bob's dependencies
```

To run a single binary directly:

```bash
set -a && . .env.alice && set +a && cargo run -p idp-server
```

Migrations in `identity-provider/migrations/` are applied automatically on
startup (and by the seed).

### Dev users

The seed (`identity-provider/crates/dev-inject-data`) upserts users with a
verified email and a known password, so the web client can sign in without the
signup OTP flow:

| Instance | User | Handle | Email | Password |
|---|---|---|---|---|
| Alice | Alice | `alice_dev01` | `akasatana83@hotmail.fr` | `yonolulu` |
| Alice | Pierre | `pierre_dev01` | `pierre@test.fr` | `yonolulu` |
| Bob | Bob | `bob_dev01` | `bob@test.fr` | `yonolulu` |

Pierre lives on Alice's instance so group conversations and same-instance E2EE
can be tested without federation.

**Alice and Bob are already friends after seeding**, with the DM between them
ready to open — no friend request, no accept, no federation round-trip. That
only works because the fixture handles are fixed rather than suffixed with a
NanoID: each instance seeds its own half of the pair and has to be able to name
the other's `actor_uri` without ever talking to it. The DM's `conversation_id`
is pinned for the same reason. Add a pair by extending `SEEDED_FRIENDSHIPS` in
the seeder.

Seeding a database created before the handles were pinned rewrites them in
place and drops the friendships and conversations left behind by the old ones —
existing DM history between the dev users does not survive that. Restart the
IdP afterwards so the remote-presence registry reloads the new URIs.

### Local URLs

| Service | Alice | Bob |
|---|---|---|
| Identity provider | http://localhost:8080 | http://localhost:8081 |
| Mailpit (captured emails) | http://localhost:8025 | http://localhost:8026 |
| RustFS console | http://localhost:9001 | http://localhost:9003 |
| Web client (`FRONTEND_URL`) | http://localhost:5173 | http://localhost:5173 |

---

## Building

```bash
cargo build --workspace                  # debug build of every crate
cargo build --release -p idp-server      # release binary → target/release/idp-server
```

Docker images are built from the repo root (the workspace manifest and shared
crates sit above every service):

| Dockerfile | Used by |
|---|---|
| `identity-provider/docker/Dockerfile` | `compose.yaml` — release build with cargo-chef, slim Debian runtime |
| `identity-provider/docker/Dockerfile.dev` | `compose.dev.yml` / `compose-win.dev.yml` — debug profile |

```bash
docker compose build idp
docker compose up -d     # the whole platform, configured by .env
```

---

## Commands

All `make` targets are run from the repo root.

### Dev instances

| Command | Effect |
|---|---|
| `make alice` / `make bob` | Generate secrets and key, seed dev users, `cargo run -p idp-server` on the host |
| `make alice-env` / `make bob-env` | Generate `SESSION_SECRET` / `EMAIL_OTP_PEPPER` in the env file if missing |
| `make alice-keys` / `make bob-keys` | Generate the instance's Ed25519 key if missing |
| `make alice-seed` / `make bob-seed` | Apply migrations and upsert the dev users |
| `make alice-docker` / `make bob-docker` | Full stack in Docker (Linux) |
| `make alice-docker-win` / `make bob-docker-win` | Full stack in Docker (Windows / Docker Desktop) |
| `make alice-down` / `make bob-down` | Stop the instance's containers |
| `make alice-down-v` / `make bob-down-v` | Stop the containers and delete their volumes |

### Quality

| Command | Effect |
|---|---|
| `make fmt` | `cargo fmt --all` |
| `make fmt-check` | Check formatting without writing |
| `make lint` | `cargo clippy --workspace --all-targets -- -D warnings` |
| `make check` | `fmt-check` + `lint` + `cargo test --workspace` — run before every commit |

### Cargo

| Command | Effect |
|---|---|
| `cargo test --workspace` | Run every test |
| `cargo test -p <crate>` | Run one crate's tests (e.g. `-p http-signatures`) |
| `cargo run -p idp-server` | Run the identity provider (env must be loaded) |
| `cargo run -p dev-inject-data -- <users…>` | Seed dev users (`alice`, `bob`, `pierre`) |

---

## Configuration reference

`.env.example` documents every supported variable. The main groups:

- **PostgreSQL** — `POSTGRES_*`, `DATABASE_URL`
- **Server** — `IDP_ENV`, `DOMAIN`, `PORT`
- **Keys** — `IDP_KEYS_DIR`, `JWT_PRIVATE_KEY_PATH`, `JWT_KEY_ID`
- **Session / frontend** — `SESSION_SECRET`, `FRONTEND_URL`, `CORS_ORIGINS`
- **Redis** — `REDIS_URL`, `REDIS_PORT` (event streams and presence pub-sub)
- **Object storage** — `STORAGE_ENDPOINT`, `STORAGE_ACCESS_KEY`, `STORAGE_SECRET_KEY`, optional `STORAGE_PUBLIC_URL` and bucket names
- **Email** — `SMTP_*`, `EMAIL_OTP_PEPPER`, `MAILPIT_*` ports
- **Chat server** — `CHAT_PORT`, `CHAT_POSTGRES_DB`, `IDP_ISSUER`
- **Logging** — `RUST_LOG`, `LOG_FORMAT=json` for structured logs

---

## Documentation

- `specs/02-architecture-diagram.md` — the whole platform at a glance
- `specs/06-federation-authentication.md` — Bearer JWT vs HTTP Signatures, server-to-server trust
- `identity-provider/README.md` — IdP endpoints, OIDC flow, federation
- `identity-provider/specs/` and `chat-server/CLAUDE.md` — service-level design
