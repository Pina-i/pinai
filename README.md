# Pīna'i

A self-hostable, federated, open-source Discord alternative. This monorepo holds
the backend services of the platform in a single Cargo workspace:

| Path | What it is |
|---|---|
| `identity-provider/` | Layer 2 — OIDC identity provider, ActivityPub federation, DMs, presence, E2EE device keys |
| `chat-server/` | Layer 3 — chat & voice rooms, attached to one identity provider (not yet implemented) |
| `crates/` | Shared libraries: `jwt-utils`, `http-signatures`, `activitypub`, `observability`, `federation-transport` |
| `specs/` | Platform-wide specifications (architecture, federation authentication) |
| `compose.yaml` | The development stack for Docker Compose |
| `deploy/` | Hosting an instance: the published image behind Caddy, set up by `deploy/setup.sh` — see `deploy/README.md` |

The web and desktop clients live in their own repository,
[`Pina-i/pinai-client`](https://github.com/Pina-i/pinai-client), and talk to these
services over HTTP. Each service has its own `README.md` / `CLAUDE.md` with its
internal architecture.

- [Install your own instance](#install-your-own-instance) — run Pīna'i for your community
- [Development setup](#development-setup) — two local instances, Alice and Bob, to work on the code

---

## Install your own instance

An instance is the identity provider with its Postgres, Redis and RustFS (file
storage), and Caddy in front of them for HTTPS, all from the published image
`ghcr.io/pina-i/pinai-idp`. Its users sign in with the official web or desktop
app: there is no client to host.

You need:

- a Linux server, amd64 or arm64, with Docker and its Compose plugin;
- a domain pointing at the server, with ports 80 and 443 open. It becomes part of
  every account's address (`alice_xk9mp@your.domain`), so it cannot change later;
- for a public instance, an SMTP relay, over STARTTLS (port 587) or TLS (port 465):
  sign-up codes are mailed. `deploy/README.md` lists some, with their settings;
- for an invite-only instance, the default, its first admin's address and password,
  set in `.env` before the first start ([Public or invite-only](#public-or-invite-only)).

Then, on the server:

```bash
curl -L https://github.com/Pina-i/pinai/releases/latest/download/pinai-deploy.tar.gz | tar xz
cd pinai
./setup.sh               # asks for the domain and SMTP, generates the secrets
docker compose up -d
```

Or write the two files yourself, in an empty directory on the server. This
`compose.yaml` matches the archive's, with the Caddyfile inline; it needs Docker
Compose 2.23 or later:

```yaml
# Needs Docker Compose 2.23 or later, for the Caddyfile inlined at the end.
# Everything the instance stores is under ./data, beside this file.
name: pinai

# Docker keeps container logs forever by default.
x-logging: &logging
  driver: json-file
  options:
    max-size: "10m"
    max-file: "3"

services:
  # HTTPS in front of the identity provider and RustFS; gets and renews the
  # certificate. Its ports are the only published ones (443/udp: HTTP/3).
  caddy:
    image: caddy:2.11-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    environment:
      DOMAIN: ${DOMAIN:?set DOMAIN in .env}
    configs:
      - source: caddyfile
        target: /etc/caddy/Caddyfile
    volumes:
      - ./data/caddy/data:/data
      - ./data/caddy/config:/config
    depends_on:
      - idp
    logging: *logging

  # The identity provider: accounts, messages, federation.
  idp:
    image: ghcr.io/pina-i/pinai-idp:${PINAI_VERSION:?set PINAI_VERSION in .env}
    restart: unless-stopped
    env_file: .env
    environment:
      IDP_ENV: production
      PORT: "8080"
      DATABASE_URL: postgres://pinai:${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env}@postgres:5432/pinai
      REDIS_URL: redis://redis:6379
      STORAGE_ENDPOINT: http://rustfs:9000
      # Avatars are served by RustFS, through Caddy's /avatars/ route.
      STORAGE_PUBLIC_URL: https://${DOMAIN}
      JWT_PRIVATE_KEY_PATH: /run/secrets/ed25519.pem
    volumes:
      - ./data/keys:/run/secrets:ro
    depends_on:
      init:
        condition: service_completed_successfully
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      rustfs:
        condition: service_healthy
    logging: *logging

  postgres:
    image: postgres:18
    restart: unless-stopped
    environment:
      POSTGRES_USER: pinai
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD in .env}
      POSTGRES_DB: pinai
    volumes:
      - ./data/postgres:/var/lib/postgresql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U pinai -d pinai"]
      interval: 5s
      timeout: 5s
      retries: 10
    logging: *logging

  # The append-only file keeps the durable event streams (DMs) across restarts.
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: ["redis-server", "--appendonly", "yes"]
    volumes:
      - ./data/redis:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 10
    logging: *logging

  # File storage, S3-compatible: avatars and attachments.
  rustfs:
    image: rustfs/rustfs:1.0.3
    restart: unless-stopped
    environment:
      RUSTFS_ACCESS_KEY: ${STORAGE_ACCESS_KEY:?set STORAGE_ACCESS_KEY in .env}
      RUSTFS_SECRET_KEY: ${STORAGE_SECRET_KEY:?set STORAGE_SECRET_KEY in .env}
      # Empty: logs to stdout, for `docker compose logs`.
      RUSTFS_OBS_LOG_DIRECTORY: ""
    volumes:
      - ./data/rustfs:/data
    depends_on:
      init:
        condition: service_completed_successfully
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/health"]
      interval: 5s
      timeout: 10s
      retries: 10
      start_period: 30s
    logging: *logging

  # Runs before the others at every start. Generates the instance key in
  # ./data/keys once and never replaces it: it signs tokens, federation requests
  # and device attestations, and losing it cannot be undone. Then lets the
  # identity provider (user 65532) read it and gives ./data/rustfs to RustFS (10001).
  init:
    image: alpine/openssl:3.5.8
    restart: "no"
    entrypoint: ["sh", "-c"]
    command:
      - >-
        if [ -f /keys/ed25519.pem ]; then
          echo "instance key present, keeping it";
        else
          openssl genpkey -algorithm ed25519 -out /keys/ed25519.pem &&
          chown "$$(stat -c '%u' /keys)" /keys/ed25519.pem &&
          echo "generated a new instance key";
        fi &&
        chgrp 65532 /keys/ed25519.pem &&
        chmod 640 /keys/ed25519.pem &&
        chown 10001:10001 /rustfs
    volumes:
      - ./data/keys:/keys
      - ./data/rustfs:/rustfs
    logging: *logging

# Caddy's configuration. $$ is Compose's escape for $: Caddy reads {$DOMAIN}
# from its own environment.
configs:
  caddyfile:
    content: |
      {$$DOMAIN} {
      	header Strict-Transport-Security "max-age=31536000"

      	# Avatars are public objects in RustFS. Only reads reach it, and without the
      	# query string, so no S3 sub-resource (?acl, ?policy…) can be named from outside.
      	@avatar {
      		method GET HEAD
      		path /avatars/*
      	}
      	handle @avatar {
      		rewrite * {path}?
      		reverse_proxy rustfs:9000
      	}

      	handle {
      		reverse_proxy idp:8080
      	}
      }
```

`.env` holds the settings. Replace the example values, and put a value holding
spaces, `#` or `$` in single quotes:

```sh
# The image's minor version: `docker compose pull` gets its fixes.
PINAI_VERSION=0.1
# Without scheme or path. It is part of every account's address: it cannot change.
DOMAIN=chat.example.org

# invite, the default: only people an admin invited can join, and the first
# admin below is required. open: anyone can sign up, and the relay is required.
REGISTRATIONS=invite
ADMIN_EMAIL=you@example.org
ADMIN_PASSWORD='at least 8 bytes'

# The mail relay, required for public registration mode: uncomment these lines and fill them in.
# deploy/README.md lists relays and their settings; SMTP_TLS is starttls for
# port 587, tls for port 465.
# SMTP_HOST=
# SMTP_PORT=587
# SMTP_TLS=starttls
# SMTP_USERNAME=
# SMTP_PASSWORD=
# SMTP_FROM=no-reply@chat.example.org

# The secrets, from the commands below.
JWT_KEY_ID=
SESSION_SECRET=
EMAIL_OTP_PEPPER=
POSTGRES_PASSWORD=
STORAGE_ACCESS_KEY=
STORAGE_SECRET_KEY=
```

Generate the secrets once, with these commands, and paste each line they print
over its empty one in `.env`. Never generate them again, and back them up with
`./data`, as the warning below says:

```bash
echo "JWT_KEY_ID=key-$(date +%Y-%m)"
echo "SESSION_SECRET=$(openssl rand -hex 32)"
echo "EMAIL_OTP_PEPPER=$(openssl rand -hex 32)"
echo "POSTGRES_PASSWORD=$(openssl rand -hex 32)"
echo "STORAGE_ACCESS_KEY=pinai-$(openssl rand -hex 8)"
echo "STORAGE_SECRET_KEY=$(openssl rand -hex 32)"
```

Then start the instance, creating `./data` first so that its directories are
yours rather than root's:

```bash
chmod 600 .env               # the secrets, readable by you alone
mkdir -p data/keys data/postgres data/redis data/rustfs data/caddy/data data/caddy/config
docker compose up -d
docker compose logs -f idp   # "listening" once the database is migrated
```

`https://your.domain/.well-known/nodeinfo` answers once the database is migrated
and Caddy has its certificate. Upgrades, backups, the mail relay and running
behind your own reverse proxy are in [`deploy/README.md`](deploy/README.md),
which the archive carries too.

> **Back up `.env` and `data/` together.** The instance key and the secrets in
> `.env` cannot be regenerated: a new key breaks every device that signed in, a
> new `EMAIL_OTP_PEPPER` every recovery code.

### Public or invite-only

An instance is public or invite-only, set by `REGISTRATIONS` in `.env`:

- **Public** (`REGISTRATIONS=open`): anyone can create an account from the app, and
  a mailed code confirms their address. Add `REGISTRATIONS=open` to `.env`. It needs
  the SMTP relay, which `./setup.sh` asks for, and doesn't start without `SMTP_HOST`.
  Add the DNS records the relay gives you for the sender's domain (SPF, DKIM), or the
  codes land in spam.
- **Invite-only** (`REGISTRATIONS=invite`, the default): only people an admin invited
  can create an account. No code is mailed, so the relay is optional. It needs a
  first admin: add `ADMIN_EMAIL` and `ADMIN_PASSWORD` to `.env` before
  `docker compose up -d`; without an admin, the instance doesn't start.

Invite-only is about who can join, not federation: its members still talk with
people on other instances. [`deploy/README.md`](deploy/README.md#public-or-invite-only)
has the details: the first admin, invitations, password resets, switching modes.

---

## Development setup

Two instances on one machine, **Alice** and **Bob**, so that federation can be
exercised locally. All paths in the env files resolve against the working
directory, so **run every command from the repo root**.

### Prerequisites

- **Rust** (stable) with the `clippy` and `rustfmt` components
  ```bash
  rustup component add clippy rustfmt
  ```
- **Docker** with Docker Compose v2 (`docker compose …`)
- **OpenSSL** — used to generate each instance's Ed25519 signing key
- **GNU Make** and **bash**

### 1. Environment files

Every deployment unit is configured by one env file. Only the template,
`.env.example`, is committed; every other `.env*` file is git-ignored.

```bash
cp .env.example .env.alice
cp .env.example .env.bob
```

Then edit each one. At a minimum:

| Variable | Alice | Bob |
|---|---|---|
| `IDP_ENV` | `development` | `development` |
| `DOMAIN` / `PORT` | `localhost:8088` / `8088` | `localhost:8081` / `8081` |
| `POSTGRES_DB` / `POSTGRES_PORT` | `idp_alice` / `5432` | `idp_bob` / `5433` |
| `REDIS_PORT` | `6379` | `6380` |
| `RUSTFS_PORT` / `RUSTFS_CONSOLE_PORT` | `9004` / `9005` | `9002` / `9003` |
| `MAILPIT_SMTP_PORT` / `MAILPIT_UI_PORT` | `1025` / `8025` | `1026` / `8026` |
| `SMTP_HOST` / `SMTP_PORT` | `localhost` / `1025` | `localhost` / `1026` |
| `REGISTRATIONS` | `open` | `invite` |
| `IDP_KEYS_DIR` | `./identity-provider/keys/alice` | `./identity-provider/keys/bob` |
| `JWT_PRIVATE_KEY_PATH` | `./identity-provider/keys/alice/ed25519.pem` | `./identity-provider/keys/bob/ed25519.pem` |

`DATABASE_URL`, `REDIS_URL` and `STORAGE_ENDPOINT` are not set in the env file:
compose and the Makefile build them from the ports above, so changing a port is
enough.

Leave `SESSION_SECRET` and `EMAIL_OTP_PEPPER` as they are: the next step fills
them in.

`IDP_ENV` defaults to `production` when unset, which switches issuer URLs and
peer calls to `https` and sets the `Secure` cookie flag — always set it to
`development` locally.

### 2. Instance secrets

`SESSION_SECRET` (the session-cookie and attachment-link keys are derived from it) and
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

### 4. Run the instances

#### Option A — Docker (full stack)

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

> A volume created before the move to Postgres 18 stops the target with
> `in 18+, these Docker images are configured to store database data in a format…`.
> `make alice-down-v` deletes it, and the instance's data with it; then run the
> target again.

#### Option B — Host (`cargo run`, fastest inner loop)

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

To run a single binary directly, give it the URLs the Makefile builds from the
ports (`instance-env` in the `Makefile`):

```bash
set -a && . .env.alice && set +a
export DATABASE_URL="postgres://$POSTGRES_USER:$POSTGRES_PASSWORD@localhost:$POSTGRES_PORT/$POSTGRES_DB"
export REDIS_URL="redis://localhost:$REDIS_PORT" STORAGE_ENDPOINT="http://localhost:$RUSTFS_PORT"
cargo run -p idp-app
```

Migrations in `identity-provider/migrations/` are applied automatically on
startup (and by the seed).

### Dev users

The seed (`identity-provider/crates/dev-inject-data`) upserts users with a
verified email and a known password, so the web client can sign in without the
signup OTP flow:

| Instance | User | Handle | Email | Password |
|---|---|---|---|---|
| Alice | Alice | `alice_dev01` | `alice@test.fr` | `yonolulu` |
| Alice | Pierre | `pierre_dev01` | `pierre@test.fr` | `yonolulu` |
| Bob | Bob (admin) | `bob_dev01` | `bob@test.fr` | `yonolulu` |

Pierre lives on Alice's instance so group conversations and same-instance E2EE
can be tested without federation.

Alice's instance is public, so signing up can be tried there. Bob's is
invite-only, and Bob is its admin — an invite-only instance doesn't start without
one, and `ADMIN_EMAIL` never makes the account the seed created first an admin.
Invitations are created there with `POST /api/admin/invitations`, under Bob's
bearer token.

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
| Identity provider | http://localhost:8088 | http://localhost:8081 |
| Mailpit (captured emails) | http://localhost:8025 | http://localhost:8026 |
| RustFS console | http://localhost:9005 | http://localhost:9003 |
| Web client (signs in to either) | http://localhost:5173 | http://localhost:5173 |

### The web client

Clone [`Pina-i/pinai-client`](https://github.com/Pina-i/pinai-client) and follow
its README (Node, pnpm and `wasm-pack`), then:

```bash
pnpm install
pnpm dev                 # http://localhost:5173, pre-filled with Alice's instance
```

Sign in with one of the dev users above; type `localhost:8081` on the landing
page to reach Bob's instance instead.

---

## Building

```bash
cargo build --workspace                  # debug build of every crate
cargo build --release -p idp-app         # release binary → target/release/idp-server
```

Docker images are built from the repo root (the workspace manifest and shared
crates sit above every service):

| Dockerfile | Used by |
|---|---|
| `identity-provider/docker/Dockerfile` | `compose.yaml` — release build with cargo-chef, distroless runtime as the non-root user 65532 |
| `identity-provider/docker/Dockerfile.dev` | `compose.dev.yml` / `compose-win.dev.yml` — debug profile |

```bash
docker compose build idp
docker compose up -d     # the whole platform, configured by .env
```

### Releasing

`.github/workflows/ci.yml` runs `make check-all`, then builds the production
image for amd64 and arm64 on native runners. What it publishes to
`ghcr.io/pina-i/pinai-idp` depends on what triggered it:

| Trigger | Published |
|---|---|
| A pull request | nothing |
| A push to `main` | `edge` and `sha-<short>`, for testing only |
| A tag `vX.Y.Z` | `X.Y.Z`, `X.Y` and `latest`, then a GitHub release carrying `pinai-deploy.tar.gz`: `deploy/` with `PINAI_VERSION` set to `X.Y` |
| A tag `vX.Y.Z-rc.1` | `X.Y.Z-rc.1`, then a pre-release with the bundle pinned to it |

A tag must name the version of `idp-api` (what NodeInfo reports), or a release
candidate of it: the run checks it first. Tag the commit of `main` whose run
passed, and push the tag:

```bash
git tag -a v0.1.0 -m "v0.1.0" && git push origin v0.1.0
```

The Rust toolchain is pinned in both Dockerfiles (the cargo-chef image) and in
the workflow (`RUSTUP_TOOLCHAIN`): change the three together.

---

## Commands

All `make` targets are run from the repo root.

### Dev instances

| Command | Effect |
|---|---|
| `make alice` / `make bob` | Generate secrets and key, seed dev users, `cargo run -p idp-app` on the host |
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
| `make lint` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| `make check` | `fmt-check` + `lint` + `cargo test --workspace` — no Docker; run before every commit |
| `make test-integration` | Throwaway Postgres and Redis (`compose.test.yml`), then every test, the Docker-gated ones included |
| `make check-all` | `check` + `test-integration` — what CI runs, the gate before merging |

### Cargo

| Command | Effect |
|---|---|
| `cargo test --workspace` | Run every test |
| `cargo test -p <crate>` | Run one crate's tests (e.g. `-p http-signatures`) |
| `cargo run -p idp-app` | Run the identity provider (env must be loaded) |
| `cargo run -p dev-inject-data -- <users…>` | Seed dev users (`alice`, `bob`, `pierre`) |

---

## Configuration reference

`.env.example` documents every variable of the development env files; a hosted
instance is configured by `deploy/.env.example`, which `deploy/setup.sh` fills.
The main groups:

- **PostgreSQL** — `POSTGRES_*`; `DATABASE_URL` is built from them
- **Server** — `IDP_ENV`, `DOMAIN`, `PORT`
- **Keys** — `IDP_KEYS_DIR`, `JWT_PRIVATE_KEY_PATH`, `JWT_KEY_ID`
- **Session** — `SESSION_SECRET`
- **Instance** — `INSTANCE_NAME`, `INSTANCE_DESCRIPTION`: how the sign-in pages and NodeInfo present it
- **Who can join** — `REGISTRATIONS`: `open` (anyone signs up; needs an SMTP relay) or `invite` (only people an admin invited; needs an admin), `invite` when unset
- **Admin** — `ADMIN_EMAIL`, `ADMIN_PASSWORD`: the first admin account, created at startup when no account has that address, never written over
- **Web app** — `WEB_APP_ORIGIN`: overrides, in any environment, the built-in address of the official web app, where someone joining by invitation lands signed in (default `http://localhost:5173` in development)
- **Redis** — `REDIS_PORT`, from which `REDIS_URL` is built (event streams and presence pub-sub)
- **Object storage** — `RUSTFS_PORT`, from which `STORAGE_ENDPOINT` is built, `STORAGE_ACCESS_KEY`, `STORAGE_SECRET_KEY`, optional `STORAGE_PUBLIC_URL` and bucket names
- **Email** — `SMTP_*`, `EMAIL_OTP_PEPPER`, `MAILPIT_*` ports
- **Chat server** — `CHAT_PORT`, `CHAT_POSTGRES_DB`, `IDP_ISSUER`
- **Logging** — `RUST_LOG`, `LOG_FORMAT=json` for structured logs

---

## Documentation

- `deploy/README.md` — hosting an instance: install, upgrade, back up, reverse proxy
- `specs/02-architecture-diagram.md` — the whole platform at a glance
- `specs/06-federation-authentication.md` — Bearer JWT vs HTTP Signatures, server-to-server trust
- `identity-provider/README.md` — IdP endpoints, OIDC flow, federation
- `identity-provider/specs/` and `chat-server/CLAUDE.md` — service-level design
