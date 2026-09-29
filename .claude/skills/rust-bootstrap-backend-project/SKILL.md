---
name: rust-bootstrap-backend-project
description: MANDATORY when creating a new Rust backend service — a standalone Cargo workspace, or a new service joining an existing workspace such as a monorepo's next server. Scaffolds the hexagonal layout of rust-backend-architecture (domain / application / infrastructure / api / app crates), the workspace dependencies (Axum, Tokio, SQLx/Postgres, tracing, thiserror, anyhow, async-trait), an ApiError with its tests, the Application::build composition root with a spawn_app end-to-end harness, TEST_LOG tracing, embedded migrations, an `integration` feature gating Docker tests, compose.test.yml and the Make targets check / test-integration / check-all — then verifies it compiles and passes. Load it for any request to create, initialise, scaffold, bootstrap, set up or start a new Rust backend, API, server or service, however it is phrased.
---

# Rust Bootstrap Backend Project

Create a service in the shape `rust-backend-architecture` describes, and prove it works before any
feature code exists. Load `rust-backend-architecture` as well: it governs every file written after
the scaffold.

## Workflow

Follow every step in order.

### Step 1 — Name and mode

- **Name**: kebab-case (`chat-server`). It prefixes the package names (`chat-server-domain`, …)
  and names the binary. Library names stay unprefixed — `domain`, `application`,
  `infrastructure`, `api`, `app` — so code reads `use domain::…` in every service.
- **Mode**: *member* when the target sits inside an existing Cargo workspace (a parent
  `Cargo.toml` with `[workspace]`), *standalone* otherwise.

### Step 2 — Scaffold

```bash
python3 <this-skill>/scripts/scaffold.py <target-dir> --name <name>            # standalone
python3 <this-skill>/scripts/scaffold.py <target-dir> --name <name> --member   # joins a workspace
```

The script refuses a non-empty target and a name that isn't kebab-case.

### Step 3 — Member mode only: merge into the workspace

The script prints what to merge instead of writing a second workspace manifest.

- Add `"<service-dir>/crates/*"` to the root `members`.
- Add the missing `[workspace.dependencies]` entries. Keep the root's versions; union the features
  the template needs: sqlx `postgres`, `runtime-tokio`, `uuid`, `macros`, `migrate`; tower
  `util`; tracing-subscriber `env-filter`; uuid `v4`, `serde`.
- Merge the template Makefile's `check` / `test-integration` targets into the root Makefile.
- Give `compose.test.yml` a port no running database uses (`TEST_PG_PORT`, default 55432 —
  development Postgres commonly sit on 5432/5433).

### Step 4 — Verify

```bash
make check              # no Docker: fmt, clippy -D warnings on every target and feature, fast tests
make test-integration   # Docker: throwaway Postgres, then the gated tests
docker compose -f compose.test.yml down
```

Both must pass before any feature work. `make check` runs the `ApiError` and route tests;
`make test-integration` adds the migration test and the `spawn_app` health journey over real HTTP.
Offline, `CARGO_NET_OFFLINE=true` works when the crates are already in the local registry.

### Step 5 — Report

Tell the user what was created, that both targets pass, and the next step: the first bounded
context, test-first (below).

## What the template contains

| Path | Purpose |
|---|---|
| `Cargo.toml` | workspace + `[workspace.dependencies]` (standalone only) |
| `Makefile`, `compose.test.yml` | `check` / `test-integration` / `check-all`; throwaway Postgres (tmpfs, `fsync=off`) |
| `migrations/` | SQLx migrations, embedded by `infrastructure` |
| `crates/domain` | `ValidationError`; the `test-utils` feature for fakes and contract suites |
| `crates/application` | empty; use cases go here |
| `crates/infrastructure` | `MIGRATOR`, `postgres::connect`, `build.rs` rerun on migrations, gated `tests/postgres` |
| `crates/api` | `router`, `AppState`, `ApiError` (`{error, error_description}` + extras), `/health`, oneshot route tests |
| `crates/app` | `Config`, `Application::build(config, pool)` / `port()` / `run_until_stopped()`, `telemetry::init_tracing(writer)`, thin `main.rs`, gated `tests/api` with `spawn_app` + `TestApp` |

## Adding the first feature

Follow `rust-backend-architecture`. In the scaffold specifically:

- The first entity brings `domain/src/ids.rs` with the `id!` macro
  (`rust-backend-architecture/references/domain-types.md`).
- A port, its in-memory fake and its contract suite live in `domain` behind `test-utils`; the
  Postgres adapter runs the same suite in `infrastructure/tests/postgres`.
- Use cases are wired in `app::state(pool)`, and `api::AppState` gains one `Arc<UseCase>` field
  per use case.
- Add `proptest` (domain) and `wiremock` (infrastructure) as dev-dependencies when the first test
  needs them.
- A consumer loop, broadcaster, relay or sweep: an inbound or outbound adapter by direction, spawned
  in `app` in a `JoinSet` with a `CancellationToken` so it stops with the HTTP server
  (`rust-backend-architecture/references/streams.md`).
- Another backing service (Redis, object storage): add it to `compose.test.yml`, and give
  `spawn_app` an in-memory adapter for it so end-to-end tests don't require it unless they
  exercise it.

## Conventions baked in — keep them

- The Makefile exports `DATABASE_URL` for test runs: `sqlx::test` otherwise falls back to a
  developer `.env` found up the directory tree.
- Docker-backed tests sit in `[[test]]` targets with `required-features = ["integration"]`, and
  clippy runs `--all-features`, so they compile and lint without Docker.
- `main.rs` stays thin (configuration, tracing, pool, migrations, `build`, `run`); startup logic
  lives in `app`'s library so tests share it.
- Tracing is installed once per process — tests go through the `LazyLock` in
  `tests/api/helpers.rs`, which honours `TEST_LOG`.
