SHELL := bash
.SHELLFLAGS := -c

.PHONY: alice bob \
        alice-seed bob-seed \
        alice-docker bob-docker \
        alice-docker-dev bob-docker-dev \
        alice-docker-win bob-docker-win \
        alice-down bob-down alice-down-v bob-down-v \
        fmt fmt-check lint check

# ── Local dev (cargo run on host) ─────────────────────────────────────────────
# Fastest inner loop. Requires the Rust toolchain locally. Each target seeds
# the dev fixture user first (applies migrations + upserts the user), then
# starts the IdP in the foreground.

alice: alice-seed
	set -a && . docker/.env.alice && set +a && cargo run -p idp-server

bob: bob-seed
	set -a && . docker/.env.bob && set +a && cargo run -p idp-server

# ── Dev fixtures (idempotent) ────────────────────────────────────────────────
# Inserts Alice / Bob with a fully-verified email and a known password so the
# web-client can sign in without walking the signup OTP flow. See
# crates/dev-inject-data/.

alice-seed:
	set -a && . docker/.env.alice && set +a && cargo run -p dev-inject-data -- alice

bob-seed:
	set -a && . docker/.env.bob && set +a && cargo run -p dev-inject-data -- bob

# ── Docker — dev (Linux, host networking + Dockerfile.dev) ───────────────────
# Same network model as prod; only the IdP image switches to debug profile.
# Each target spins up Postgres first (with --wait so the healthcheck completes),
# runs the dev-inject-data seed against it, then brings up the rest of the
# stack. The IdP's own startup migration is a no-op because the seed already
# applied them.

alice-docker:
	cp docker/.env.alice docker/.env
	docker compose -f docker/docker-compose.yml -f docker/docker-compose.dev.yml \
		--project-name pinai-alice up -d --wait postgres
	set -a && . docker/.env.alice && set +a && cargo run -p dev-inject-data -- alice
	docker compose -f docker/docker-compose.yml -f docker/docker-compose.dev.yml \
		--project-name pinai-alice up -d --build

bob-docker:
	cp docker/.env.bob docker/.env
	docker compose -f docker/docker-compose.yml -f docker/docker-compose.dev.yml \
		--project-name pinai-bob up -d --wait postgres
	set -a && . docker/.env.bob && set +a && cargo run -p dev-inject-data -- bob
	docker compose -f docker/docker-compose.yml -f docker/docker-compose.dev.yml \
		--project-name pinai-bob up -d --build

# ── Docker — dev (Windows / Docker Desktop) ──────────────────────────────────
# Standalone compose because Windows can't use host networking; instead the
# container reaches its peer IdP via host.docker.internal. Seeding still
# happens against host-mapped Postgres, same as the Linux variant.

alice-docker-win:
	cp docker/.env.alice docker/.env
	docker compose -f docker/docker-compose-win.dev.yml --project-name pinai-alice up -d --wait postgres
	set -a && . docker/.env.alice && set +a && cargo run -p dev-inject-data -- alice
	docker compose -f docker/docker-compose-win.dev.yml --project-name pinai-alice up -d --build

bob-docker-win:
	cp docker/.env.bob docker/.env
	docker compose -f docker/docker-compose-win.dev.yml --project-name pinai-bob up -d --wait postgres
	set -a && . docker/.env.bob && set +a && cargo run -p dev-inject-data -- bob
	docker compose -f docker/docker-compose-win.dev.yml --project-name pinai-bob up -d --build

# ── Teardown ──────────────────────────────────────────────────────────────────
# `down` works regardless of which compose flavor brought the stack up — the
# project name is what matters.

alice-down:
	docker compose -f docker/docker-compose.yml --project-name pinai-alice down

bob-down:
	docker compose -f docker/docker-compose.yml --project-name pinai-bob down

alice-down-v:
	docker compose -f docker/docker-compose.yml --project-name pinai-alice down -v

bob-down-v:
	docker compose -f docker/docker-compose.yml --project-name pinai-bob down -v

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
