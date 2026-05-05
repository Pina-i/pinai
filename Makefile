SHELL := bash
.SHELLFLAGS := -c

.PHONY: alice bob \
        alice-docker bob-docker \
        alice-docker-dev bob-docker-dev \
        alice-docker-win bob-docker-win \
        alice-down bob-down alice-down-v bob-down-v

# ── Local dev (cargo run on host) ─────────────────────────────────────────────
# Fastest inner loop. Requires the Rust toolchain locally.

alice:
	set -a && . docker/.env.alice && set +a && cargo run -p idp-server

bob:
	set -a && . docker/.env.bob && set +a && cargo run -p idp-server

# ── Docker — dev (Linux, host networking + Dockerfile.dev) ───────────────────
# Same network model as prod; only the IdP image switches to debug profile.

alice-docker:
	cp docker/.env.alice docker/.env
	docker compose -f docker/docker-compose.yml -f docker/docker-compose.dev.yml \
		--project-name pinai-alice up -d --build

bob-docker:
	cp docker/.env.bob docker/.env
	docker compose -f docker/docker-compose.yml -f docker/docker-compose.dev.yml \
		--project-name pinai-bob up -d --build

# ── Docker — dev (Windows / Docker Desktop) ──────────────────────────────────
# Standalone compose because Windows can't use host networking; instead the
# container reaches its peer IdP via host.docker.internal.

alice-docker-win:
	cp docker/.env.alice docker/.env
	docker compose -f docker/docker-compose-win.dev.yml --project-name pinai-alice up -d --build

bob-docker-win:
	cp docker/.env.bob docker/.env
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
