SHELL := bash
.SHELLFLAGS := -c

.PHONY: alice bob alice-docker bob-docker alice-down bob-down

# ── Local dev (cargo run) ─────────────────────────────────────────────────────

alice:
	set -a && . docker/.env.alice && set +a && cargo run -p idp-server

bob:
	set -a && . docker/.env.bob && set +a && cargo run -p idp-server

# ── Docker ────────────────────────────────────────────────────────────────────

alice-docker:
	cp docker/.env.alice docker/.env
	docker compose -f docker/docker-compose.yml --project-name pinai-alice up -d

bob-docker:
	cp docker/.env.bob docker/.env
	docker compose -f docker/docker-compose.yml --project-name pinai-bob up -d

alice-down:
	docker compose -f docker/docker-compose.yml --project-name pinai-alice down

bob-down:
	docker compose -f docker/docker-compose.yml --project-name pinai-bob down
