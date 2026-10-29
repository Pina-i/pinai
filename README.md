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
| `deploy/` | Hosting an instance: `compose.yaml`, the published image on one port for your reverse proxy, and `.env.example` — see `deploy/README.md` |

The web and desktop clients live in their own repository,
[`Pina-i/pinai-client`](https://github.com/Pina-i/pinai-client), and talk to these
services over HTTP. Each service has its own `README.md` / `CLAUDE.md` with its
internal architecture.

- [Install your own instance](#install-your-own-instance) — run Pīna'i for your community
- [Development setup](#development-setup) — two local instances, Alice and Bob, to work on the code

---

## Install your own instance

An instance is the identity provider, from the published image
`ghcr.io/pina-i/pinai-idp`, with its Postgres, Redis and RustFS (file storage). It
answers in plain HTTP on one port of the server, and your reverse proxy serves it
over HTTPS at its domain. Its users sign in with the Pīna'i web or desktop app,
which reach any instance. The web app can be hosted too, beside the instance or on
a server of its own, from the published image `ghcr.io/pina-i/pinai-web`:
[Host the web app](https://github.com/Pina-i/pinai-client#host-the-web-app) has its
`compose.yaml`. Then set `WEB_APP_ORIGIN` in the instance's `.env` to its address.

You need:

- a Linux server, amd64 or arm64, with Docker and its Compose plugin;
- a domain whose DNS (A / AAAA records) points at your reverse proxy. It becomes
  part of every account's address (`alice_xk9mp@your.domain`), so it cannot change
  later;
- a reverse proxy that serves the domain over HTTPS, with its certificate: Caddy,
  nginx, Traefik…;
- for a public instance, an SMTP relay, over STARTTLS (port 587) or TLS (port 465):
  sign-up codes are mailed. `deploy/README.md` lists some, with their settings.

Then four steps.

**1. `compose.yaml`.** Take it from the release bundle, which also carries
`.env.example` and a `README.md`, `deploy/README.md` here:

```bash
curl -L https://github.com/Pina-i/pinai/releases/latest/download/pinai-deploy.tar.gz | tar xz
cd pinai
```

Or save this file as `compose.yaml` in an empty directory. It is the bundle's:

<!-- deploy/compose.yaml -->
```yaml
# A Pīna'i instance from the published image, in plain HTTP on one port: your
# reverse proxy serves it over HTTPS at DOMAIN.
# Its settings are in .env beside it. Everything it stores is under ./data,
# its secrets in ./data/secrets, generated at the first start.
name: pinai

# Docker keeps container logs forever by default.
x-logging: &logging
  driver: json-file
  options:
    max-size: "10m"
    max-file: "3"

services:
  # The identity provider: accounts, messages, federation, avatars.
  # PINAI_VERSION in .env picks another version than this minor's latest.
  idp:
    image: ghcr.io/pina-i/pinai-idp:${PINAI_VERSION:-0.1}
    restart: unless-stopped
    env_file: .env
    # The only published port. PORT in .env is the port it listens on and is
    # published on, on loopback unless BIND_ADDRESS says otherwise: ports Docker
    # publishes skip the host's firewall.
    ports:
      - "${BIND_ADDRESS:-127.0.0.1}:${PORT:-8080}:${PORT:-8080}"
    environment:
      IDP_ENV: production
      PORT: ${PORT:-8080}
      DOMAIN: ${DOMAIN:?set it in .env}
      DATABASE_URL: postgres://pinai@postgres:5432/pinai
      DATABASE_PASSWORD_FILE: /run/secrets/postgres/password
      SESSION_SECRET_FILE: /run/secrets/session_secret
      EMAIL_OTP_PEPPER_FILE: /run/secrets/email_otp_pepper
      JWT_PRIVATE_KEY_PATH: /run/secrets/ed25519.pem
      REDIS_URL: redis://redis:6379
      STORAGE_ENDPOINT: http://rustfs:9000
      STORAGE_ACCESS_KEY: pinai
      STORAGE_SECRET_KEY_FILE: /run/secrets/storage_secret_key
    volumes:
      - ./data/secrets:/run/secrets:ro
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
      POSTGRES_PASSWORD_FILE: /run/secrets/password
      POSTGRES_DB: pinai
    volumes:
      - ./data/postgres:/var/lib/postgresql
      # Its own directory only: the entrypoint reads it as root.
      - ./data/secrets/postgres:/run/secrets:ro
    depends_on:
      init:
        condition: service_completed_successfully
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
      # Not a secret: the secret key is.
      RUSTFS_ACCESS_KEY: pinai
      RUSTFS_SECRET_KEY_FILE: /run/secrets/storage_secret_key
      # Empty: logs to stdout, for `docker compose logs`.
      RUSTFS_OBS_LOG_DIRECTORY: ""
    volumes:
      - ./data/rustfs:/data
      - ./data/secrets:/run/secrets:ro
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

  # Runs before the others at every start. Generates each secret in ./data/secrets
  # once and never replaces it: the instance key signs tokens, federation requests
  # and device attestations, the pepper hashes recovery codes, and losing them
  # cannot be undone. Each is written to a temporary file, synced, then renamed,
  # so a start cut short, even by a crash, never leaves one half-written; an empty
  # one is generated again. Then lets each container read only what it needs: the
  # identity provider (user 65532) every secret, RustFS (10001) its key, Postgres
  # only ./data/secrets/postgres; and gives ./data/rustfs to RustFS.
  init:
    # A community image that generates every secret as root: pinned by digest.
    image: alpine/openssl:3.5.8@sha256:3f25da71f70eba788067daac3f3df03bd1de7a7c52ed89fa93b94ad2c92d986b
    restart: "no"
    entrypoint: ["sh", "-c"]
    command:
      - |
        set -eu
        cd /secrets
        umask 077
        mkdir -p postgres
        # A directory in a secret's place, as Docker makes for a missing bind
        # source, would take the secret inside it.
        missing() {
          if [ -e "$$1" ] && [ ! -f "$$1" ]; then
            echo "$$1 is not a file" >&2
            exit 1
          fi
          if [ -s "$$1" ]; then
            echo "$$1 present, keeping it"
            return 1
          fi
        }
        for name in session_secret email_otp_pepper postgres/password storage_secret_key; do
          if missing "$$name"; then
            value=$$(openssl rand -hex 32)
            printf '%s' "$$value" > "$$name.tmp"
            sync
            mv "$$name.tmp" "$$name"
            echo "generated $$name"
          fi
        done
        if missing ed25519.pem; then
          openssl genpkey -algorithm ed25519 -out ed25519.pem.tmp
          sync
          mv ed25519.pem.tmp ed25519.pem
          echo "generated ed25519.pem, the instance key"
        fi
        chown 0:65532 session_secret email_otp_pepper postgres/password ed25519.pem
        chown 10001:65532 storage_secret_key
        chmod 440 session_secret email_otp_pepper postgres/password storage_secret_key ed25519.pem
        chmod 711 /secrets /secrets/postgres
        chown 10001:10001 /rustfs
    volumes:
      - ./data/secrets:/secrets
      - ./data/rustfs:/rustfs
    logging: *logging
```

**2. `.env`**, beside it, holds what only you decide. An invite-only instance, the
default, needs its domain and its first admin:

```sh
DOMAIN=chat.example.org
ADMIN_EMAIL=you@example.org
ADMIN_PASSWORD='at least 8 bytes'
```

A public instance needs its domain and a mail relay:

```sh
DOMAIN=chat.example.org
REGISTRATIONS=open
SMTP_HOST=smtp.example.com
SMTP_USERNAME=…
SMTP_PASSWORD=…
```

The relay is reached on port 587 over STARTTLS; `SMTP_PORT=465` switches to TLS, and
`SMTP_TLS` sets it outright. The instance mails as `Pīna'i <no-reply@chat.example.org>`
unless `SMTP_FROM` says otherwise.

Either kind can also be given a name and a description, both optional. The sign-in
pages and NodeInfo show them; without them, the domain and "An identity provider.".
An admin can change them later in the web app's Settings → Instance, which then takes
over from `.env`:

```sh
INSTANCE_NAME=Aotearoa
INSTANCE_DESCRIPTION='Design and type people, mostly around Wellington.'
```

The name holds 40 characters at most, the description 90. Put a value holding spaces,
`#` or `$` in single quotes. `deploy/.env.example` lists every setting. The file holds
passwords, so make it yours alone: `chmod 600 .env`.

**3. Start it:**

```bash
docker compose up -d
docker compose logs -f idp
```

At the first start, the `init` service generates the instance's secrets in
`./data/secrets`: its signing key, the session secret, the email pepper, and the
database and storage passwords. The identity provider logs `listening`, then
migrates the database; once that is done, `curl http://127.0.0.1:8080/.well-known/nodeinfo`
answers (at your `BIND_ADDRESS` and `PORT`, if set).

**4. Put your proxy in front.** It serves your domain over HTTPS and sends every
request to `127.0.0.1:8080`, keeping its `Host` header; `PORT` in `.env` changes the
port. [`deploy/README.md`](deploy/README.md#put-your-proxy-in-front) says what else it
must do, with Caddy and nginx examples. Then `https://your.domain/.well-known/nodeinfo`
answers.

On an invite-only instance, sign in to the Pīna'i web app with `ADMIN_EMAIL` and
`ADMIN_PASSWORD`, then remove `ADMIN_PASSWORD` from `.env`: the instance warns at
each start while it is there.

Upgrades, backups and the mail relay are in [`deploy/README.md`](deploy/README.md),
which the bundle carries too.

> **Back up `./data`.** It holds everything that cannot be recreated: the database,
> the files, and in `./data/secrets` the instance key and secrets. A lost key breaks
> every device that signed in, a lost pepper every recovery code, a lost session
> secret every session. `.env` holds only what you typed.

### Public or invite-only

An instance is public or invite-only, set by `REGISTRATIONS` in `.env`:

- **Public** (`REGISTRATIONS=open`): anyone can create an account from the app, and
  a mailed code confirms their address. It needs the SMTP relay, and doesn't start
  without `SMTP_HOST`. Add the DNS records the relay gives you for the sender's domain
  (SPF, DKIM), or the codes land in spam.
- **Invite-only** (`REGISTRATIONS=invite`, the default): only people an admin invited
  can create an account. No code is mailed, so the relay is optional. It needs a
  first admin, `ADMIN_EMAIL` and `ADMIN_PASSWORD`, in `.env` before the first
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
| A tag `vX.Y.Z` | `X.Y.Z`, `X.Y` and `latest`, then a GitHub release carrying `pinai-deploy.tar.gz`: `deploy/` and `LICENSE`, its `compose.yaml` running `X.Y`; its notes are the version's section of `CHANGELOG.md` |
| A tag `vX.Y.Z-rc.1` | `X.Y.Z-rc.1`, then a pre-release with the bundle pinned to it |

A tag must name the version of `idp-api` (what NodeInfo reports), or a release
candidate of it: the run checks it first. The workspace has one version,
`[workspace.package]` in `Cargo.toml`, which every crate inherits.

[release-plz](https://release-plz.dev) (`.github/workflows/release-plz.yml`,
configured by `release-plz.toml`) sets it and makes the tags, from commit messages
written as [Conventional Commits](https://www.conventionalcommits.org). On every
push to `main` it opens or refreshes a release PR, which sets the next version and
adds its section to `CHANGELOG.md`. Merging that PR tags `vX.Y.Z`, and the tag
publishes as above.

- **The version.** In 0.x, a breaking change (`feat!:`, `refactor!:`, a
  `BREAKING CHANGE:` footer) opens a new minor, anything else a patch.
  `deploy/compose.yaml` follows its minor's latest patch, so self-hosters get
  every patch and choose when to take a minor.
- **A new minor.** Every run checks that the default of `PINAI_VERSION` in
  `deploy/compose.yaml` (`${PINAI_VERSION:-X.Y}`) names `idp-api`'s minor. The
  release PR of a minor therefore fails until you push to its branch a commit
  that sets it, with the file copied into this README. Merge right after: a new
  commit on `main` makes release-plz close that PR and open a fresh one without
  your commit.
- **The changelog** lists the `feat`, `fix`, `perf` and breaking commits of the
  workspace's crates. Other commits, and commits touching only files outside the
  crates (`deploy/`, `identity-provider/docker/`, `identity-provider/migrations/`),
  are left out, and don't open a release PR on their own.
- **A release candidate.** Tag the head of the release PR with its version and
  push the tag:

  ```bash
  git fetch origin release-plz-<suffix>
  git tag -a v0.2.0-rc.1 FETCH_HEAD -m "v0.2.0-rc.1" && git push origin v0.2.0-rc.1
  ```

- **A release without a crate change** (a fix in `deploy/` alone): commit the
  new version to `Cargo.toml` and `Cargo.lock` on `main`, then tag that commit
  `vX.Y.Z` and push the tag yourself.

The workflow authenticates as a GitHub App: unlike `GITHUB_TOKEN`, its token
runs `ci.yml` on the release PR and on the tag. The App needs read and write
access to Contents and Pull requests, and must be installed on this
repository. Its client ID goes in the `RELEASE_PLZ_CLIENT_ID` variable and a
private key in the `RELEASE_PLZ_PRIVATE_KEY` secret.

The Rust toolchain is pinned in both Dockerfiles (the cargo-chef image) and in
both workflows (`RUSTUP_TOOLCHAIN`): change the four together.

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
| `make check` | `fmt-check` + `readme-compose` + `lint` + `cargo test --workspace` — no Docker; run before every commit |
| `make readme-compose` | Check that the `compose.yaml` this README shows is `deploy/compose.yaml`: change the file, then copy it into the README |
| `make test-integration` | Throwaway Postgres, Redis and RustFS (`compose.test.yml`), then every test, the Docker-gated ones included |
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
instance's `.env` is written from `deploy/.env.example`. Every variable of the
identity provider's configuration, `RUST_LOG` and `LOG_FORMAT` aside, can come from
a file instead: `<VAR>_FILE` names it (Docker secrets), and setting both is refused.
The main groups:

- **PostgreSQL** — `POSTGRES_*`; `DATABASE_URL` is built from them; `DATABASE_PASSWORD`, optional, is set on the connection over any password the URL holds
- **Server** — `IDP_ENV`, `DOMAIN`, `PORT`
- **Keys** — `IDP_KEYS_DIR`, `JWT_PRIVATE_KEY_PATH`, `JWT_KEY_ID` (optional: unset, the key's RFC 7638 thumbprint)
- **Session** — `SESSION_SECRET`
- **Instance** — `INSTANCE_NAME`, `INSTANCE_DESCRIPTION`: how the sign-in pages and NodeInfo present it, until an admin changes them in Settings → Instance; at most 40 and 90 characters
- **Source code** — `SOURCE_URL`: where the code the instance runs can be had, an http(s) URL, as NodeInfo's `software.repository` and the sign-in pages' "Source" link; `https://github.com/Pina-i/pinai` when unset. An instance running modified code points it at that code (see [License](#license))
- **Who can join** — `REGISTRATIONS`: `open` (anyone signs up; needs an SMTP relay) or `invite` (only people an admin invited; needs an admin), `invite` when unset
- **Admin** — `ADMIN_EMAIL`, `ADMIN_PASSWORD`: the first admin account, created at startup when no account has that address, never written over
- **Web app** — `WEB_APP_ORIGIN`: overrides, in any environment, the built-in address of the official web app, where someone joining by invitation lands signed in and the reset pages' Sign in links go (default `http://localhost:5173` in development)
- **Redis** — `REDIS_PORT`, from which `REDIS_URL` is built (event streams and presence pub-sub)
- **Object storage** — `RUSTFS_PORT`, from which `STORAGE_ENDPOINT` is built, `STORAGE_ACCESS_KEY`, `STORAGE_SECRET_KEY`, optional bucket names
- **Email** — `SMTP_*` (in production, `SMTP_PORT` 587 and `SMTP_TLS` `tls` on port 465, `starttls` on any other, when unset; `SMTP_FROM` no-reply at the domain), `EMAIL_OTP_PEPPER`, `MAILPIT_*` ports
- **Chat server** — `CHAT_PORT`, `CHAT_POSTGRES_DB`, `IDP_ISSUER`
- **Logging** — `RUST_LOG`, `LOG_FORMAT=json` for structured logs

---

## Documentation

- `deploy/README.md` — hosting an instance: install, upgrade, back up, reverse proxy
- `specs/02-architecture-diagram.md` — the whole platform at a glance
- `specs/06-federation-authentication.md` — Bearer JWT vs HTTP Signatures, server-to-server trust
- `identity-provider/README.md` — IdP endpoints, OIDC flow, federation
- `identity-provider/specs/` and `chat-server/CLAUDE.md` — service-level design

---

## License

Copyright (C) 2026 Kilian Tozzini

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along
with this program, in [`LICENSE`](LICENSE). If not, see
<https://www.gnu.org/licenses/>.

Anyone who runs a modified version for users over a network must offer those
users its source code (§ 13): set `SOURCE_URL` to where it is published, and the
instance links it from its sign-in pages and its NodeInfo.
