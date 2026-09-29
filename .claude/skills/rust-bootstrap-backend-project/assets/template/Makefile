# A port of its own, clear of development databases; override with TEST_PG_PORT=….
TEST_PG_PORT ?= 55432
# Explicit, so sqlx::test never falls back to a developer .env found up the tree.
TEST_DATABASE_URL := postgres://test:test@localhost:$(TEST_PG_PORT)/test

.PHONY: check fmt test test-integration check-all

check: ## fmt + clippy (every target, every feature) + fast tests — no Docker
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo test --workspace

fmt:
	cargo fmt --all

test:
	cargo test --workspace

test-integration: ## Docker: throwaway Postgres, then every test including the gated ones
	TEST_PG_PORT=$(TEST_PG_PORT) docker compose -f compose.test.yml up -d --wait
	DATABASE_URL=$(TEST_DATABASE_URL) cargo test --workspace --all-features

check-all: check test-integration
