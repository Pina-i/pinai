SHELL := bash
.SHELLFLAGS := -c

.PHONY: alice bob \
        alice-keys bob-keys \
        alice-seed bob-seed \
        alice-docker bob-docker \
        alice-docker-dev bob-docker-dev \
        alice-docker-win bob-docker-win \
        alice-down bob-down alice-down-v bob-down-v \
        fmt fmt-check lint check

# ── Local dev (cargo run on host) ─────────────────────────────────────────────
# Fastest inner loop. Requires the Rust toolchain locally. Each target seeds
# the dev fixture user first (applies migrations + upserts the user), then
# starts the IdP in the foreground. Run from the repo root: JWT_PRIVATE_KEY_PATH
# in the env files is resolved against the working directory.

alice: alice-keys alice-seed
	set -a && . .env.alice && set +a && cargo run -p idp-server

bob: bob-keys bob-seed
	set -a && . .env.bob && set +a && cargo run -p idp-server

# ── Instance signing key ─────────────────────────────────────────────────────
# One Ed25519 key per instance. It signs JWTs, federation HTTP Signatures and
# E2EE device attestations, so Alice and Bob must not share one: with a shared
# key every cross-instance verification passes whether or not key resolution
# actually works, and the bug only shows up in production.
#
# Idempotent — an existing key is never overwritten. There is no recovering from
# losing it, so back the directory up alongside the database.
#
# Generated here on the host rather than left to the compose init service so the
# file is owned by you, not by root, and the host and Docker workflows can share
# an instance.

define gen-instance-key
	@mkdir -p $(dir $(1))
	@if [ -f "$(1)" ]; then \
		echo "instance key present, keeping it: $(1)"; \
	else \
		openssl genpkey -algorithm ed25519 -out "$(1)" && chmod 600 "$(1)" && \
		echo "generated a new instance key: $(1)"; \
	fi
endef

alice-keys:
	$(call gen-instance-key,identity-provider/keys/alice/ed25519.pem)

bob-keys:
	$(call gen-instance-key,identity-provider/keys/bob/ed25519.pem)

# ── Dev fixtures (idempotent) ────────────────────────────────────────────────
# Inserts users with a fully-verified email and a known password so the
# web-client can sign in without walking the signup OTP flow. See
# identity-provider/crates/dev-inject-data/.
#
# Alice's instance gets Pierre too, so there are two local users to exercise
# group conversations and same-instance E2EE without involving federation.

alice-seed:
	set -a && . .env.alice && set +a && cargo run -p dev-inject-data -- alice pierre

bob-seed:
	set -a && . .env.bob && set +a && cargo run -p dev-inject-data -- bob

# ── Docker — dev (Linux, host networking + Dockerfile.dev) ───────────────────
# Same network model as prod; only the IdP image switches to debug profile.
# Each target spins up Postgres first (with --wait so the healthcheck completes),
# runs the dev-inject-data seed against it, then brings up the rest of the
# stack. The IdP's own startup migration is a no-op because the seed already
# applied them.

alice-docker: alice-keys
	cp .env.alice .env
	docker compose -f compose.yaml -f compose.dev.yml \
		--project-name pinai-alice up -d --wait postgres
	$(MAKE) alice-seed
	docker compose -f compose.yaml -f compose.dev.yml \
		--project-name pinai-alice up -d --build

bob-docker: bob-keys
	cp .env.bob .env
	docker compose -f compose.yaml -f compose.dev.yml \
		--project-name pinai-bob up -d --wait postgres
	$(MAKE) bob-seed
	docker compose -f compose.yaml -f compose.dev.yml \
		--project-name pinai-bob up -d --build

# ── Docker — dev (Windows / Docker Desktop) ──────────────────────────────────
# Standalone compose because Windows can't use host networking; instead the
# container reaches its peer IdP via host.docker.internal. Seeding still
# happens against host-mapped Postgres, same as the Linux variant.

alice-docker-win: alice-keys
	cp .env.alice .env
	docker compose -f compose-win.dev.yml --project-name pinai-alice up -d --wait postgres
	$(MAKE) alice-seed
	docker compose -f compose-win.dev.yml --project-name pinai-alice up -d --build

bob-docker-win: bob-keys
	cp .env.bob .env
	docker compose -f compose-win.dev.yml --project-name pinai-bob up -d --wait postgres
	$(MAKE) bob-seed
	docker compose -f compose-win.dev.yml --project-name pinai-bob up -d --build

# ── Teardown ──────────────────────────────────────────────────────────────────
# `down` works regardless of which compose flavor brought the stack up — the
# project name is what matters.

alice-down:
	docker compose -f compose.yaml --project-name pinai-alice down

bob-down:
	docker compose -f compose.yaml --project-name pinai-bob down

alice-down-v:
	docker compose -f compose.yaml --project-name pinai-alice down -v

bob-down-v:
	docker compose -f compose.yaml --project-name pinai-bob down -v

# ── Lint & format ─────────────────────────────────────────────────────────────
# Requires the clippy and rustfmt components (`rustup component add clippy
# rustfmt`). The tree is clean at stock rustfmt defaults and clippy's default
# lint set, so `lint` denies warnings outright to keep it that way.

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings

check: fmt-check lint
	cargo test --workspace
