# Testing

## Contents
1. Tiers and the TDD loop
2. Unit tests and naming
3. Fakes and port contract suites
4. Database tests
5. Outbound HTTP with wiremock
6. Route tests
7. End-to-end with `spawn_app`
8. Gating, Make targets, logs

## 1. Tiers and the TDD loop

| Tier | Needs | Speed | Purpose |
|---|---|---|---|
| domain + application | nothing | ms | rules and flows — **TDD runs here** |
| port contract suites | fake: nothing; adapter: Postgres | ms / s | fakes behave like the real adapters |
| adapters (SQLx, Redis, HTTP clients) | Postgres / Redis / wiremock | s | the SQL and wire formats |
| routes | nothing | ms | status codes, error bodies, DTO parsing |
| inbound stream adapters | nothing | ms | decoding, and the ack / retry / dead-letter policy per outcome |
| end-to-end | Postgres (+ wiremock peers) | s | a few critical journeys |

Red → green at the domain/application tier: one behaviour, one failing test, the minimal code.
When a use case needs a new port method, add it to the port's contract suite first, make the fake
pass it, then the adapter in the integration tier.

## 2. Unit tests and naming

```rust
// src/social/friendship.rs — at the end of the file, nothing after it
#[cfg(test)]
mod tests;
```

```rust
// src/social/friendship/tests.rs
use super::*;

#[test]
fn a_request_to_oneself_is_refused() {
    let alice = UserId::generate();
    assert!(matches!(request_friendship(alice, alice), Err(SocialError::SelfRequest)));
}
```

- A crate root (`lib.rs`, `mod.rs`) puts its tests in `src/tests.rs`.
- Names are behaviour sentences, subject first, present tense; the module path carries the
  feature. Not `test_accept_1`, not `accept_returns_400_when…`.
- Expected values are literals or worked examples, never recomputed the way the code computes them.
- Assert on typed variants (`matches!`), not on error strings.

## 3. Fakes and port contract suites

Fakes live in the crate that defines the port, behind a feature, so every consumer's tests share
one implementation and release builds never contain it:

```toml
# domain/Cargo.toml
[features]
test-utils = []

# application/Cargo.toml — consumers enable it for tests only
[dev-dependencies]
domain = { path = "../domain", features = ["test-utils"] }
```

```rust
// domain/src/social/testing.rs  —  #[cfg(any(test, feature = "test-utils"))] pub mod testing;
#[derive(Default)]
pub struct InMemorySocialGraph {
    rows: std::sync::Mutex<Vec<Friendship>>,
}

#[async_trait::async_trait]
impl SocialGraph for InMemorySocialGraph { /* … */ }

/// Contract every `SocialGraph` must satisfy — run against the fake and the Postgres adapter.
pub mod contract {
    use super::*;

    pub async fn accepting_twice_is_a_conflict(graph: &dyn SocialGraph) {
        let (request, owner) = seed_pending_request(graph).await;
        graph.accept(request, owner).await.unwrap();
        assert!(matches!(graph.accept(request, owner).await, Err(SocialStoreError::Conflict)));
    }
}
```

- Prefer fakes (`Mutex<HashMap>` / `Vec`) to mocks: they test behaviour, not call counts. Reach for
  `mockall` only to assert that something is *not* called.
- A fake that passes the same contract suite as the adapter cannot drift from it unnoticed.
- `std::sync::Mutex` is fine in a fake as long as no guard is held across an `.await`.

## 4. Database tests

```rust
// infrastructure/tests/postgres/main.rs  — one binary; modules per port
mod social;

// infrastructure/tests/postgres/social.rs
use infrastructure::{postgres::PgSocialGraph, MIGRATOR};

#[sqlx::test(migrator = "MIGRATOR")]
async fn accepting_twice_is_a_conflict(pool: sqlx::PgPool) {
    domain::social::testing::contract::accepting_twice_is_a_conflict(&PgSocialGraph::new(pool)).await;
}
```

- `#[sqlx::test]` creates a fresh database per test, runs the migrator and drops it on success —
  no hand-written `configure_database`. It needs sqlx's `migrate` and `macros` features.
- It reads `DATABASE_URL` **at runtime** through `dotenvy`, which walks up the directory tree
  looking for `.env`. A developer `.env` would point it at a real dev database: always export
  `DATABASE_URL` explicitly for test runs (see §8).
- Check side effects through the port or the API; query tables directly only when nothing else
  exposes the state.

## 5. Outbound HTTP with wiremock

```rust
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn a_delivery_posts_the_activity_to_the_peer_inbox() {
    let peer = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/users/bob/inbox"))
        .respond_with(ResponseTemplate::new(202))
        .expect(1)
        .mount(&peer)
        .await;

    let client = FederationClient::new(test_http_client());
    client.deliver(&format!("{}/users/bob/inbox", peer.uri()), &activity()).await.unwrap();
} // `expect(1)` is verified when `peer` drops
```

- `MockServer::start()` binds a random port; unmatched requests get a 404.
- Test the failure modes too: non-2xx, malformed bodies, timeouts (`ResponseTemplate::set_delay`) —
  with short client timeouts in tests (≈ 200 ms).
- Route every outbound request of a kind through one client adapter so a single mock covers it.
- Add `wiremock` (and `proptest`) as dev-dependencies when the first test needs them.

## 6. Route tests

Build the real router over real use cases wired to in-memory fakes, and call it without a socket:

```rust
use tower::ServiceExt; // oneshot

#[tokio::test]
async fn a_request_to_oneself_answers_400_with_the_error_body() {
    let app = api::router(test_state()); // use cases over InMemory* fakes
    let response = app
        .oneshot(Request::post("/api/friends/request").header("content-type", "application/json")
            .body(Body::from(r#"{"address":"alice@idp.test"}"#)).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["error"], "invalid_request");
}
```

`tower` needs its `util` feature; `collect()` comes from `http_body_util::BodyExt`.

### Inbound stream adapters

Drive the consumer loop with a fake source — a `Vec` of messages behind the same trait the real
consumer implements — over the real use case wired to in-memory fakes, and assert what the adapter
did with each message: acked after success, left unacked after `Unexpected`, dead-lettered after a
refusal or a decoding failure. A redelivered message must leave the state unchanged (idempotency).

## 7. End-to-end with `spawn_app`

Black-box tests through real HTTP, sharing the production startup path.

- `app` is a library plus a thin binary: `Application::build(config)` wires everything and binds
  the listener; `main.rs` only loads configuration, initialises tracing and calls
  `run_until_stopped()`.
- `spawn_app` builds a `Config` directly (never from the environment), binds `127.0.0.1:0`, reads
  the port back, and `tokio::spawn`s the server — each `#[tokio::test]` runtime drops it at the end.
- Swap external services the test does not exercise for in-memory adapters through
  `Application::build`'s arguments; point peers at wiremock servers.
- A `TestApp` struct carries the address, an HTTP client and the pool, with one method per
  endpoint (`post_friend_request(&body)`), so tests read as journeys.
- One binary — `app/tests/api/main.rs` declaring `mod helpers; mod friendships; …` — instead of one
  file per test in `tests/`: every file there links a separate binary, and shared helpers compiled
  into each of them warn about dead code.
- Keep this tier small: journeys that cross several layers (sign-up → login, a federated
  friendship). Everything else is cheaper one tier down.

## 8. Gating, Make targets, logs

Tests needing Docker are gated so the default check stays runnable anywhere:

```toml
# infrastructure/Cargo.toml
[features]
integration = []

[[test]]
name = "postgres"
path = "tests/postgres/main.rs"
required-features = ["integration"]
```

```make
check:            ## fmt + clippy (every target, every feature) + fast tests — no Docker
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo test --workspace

TEST_PG_PORT ?= 55432
TEST_DATABASE_URL := postgres://test:test@localhost:$(TEST_PG_PORT)/test

test-integration: ## Docker: compose.test.yml, then every test
	TEST_PG_PORT=$(TEST_PG_PORT) docker compose -f compose.test.yml up -d --wait
	DATABASE_URL=$(TEST_DATABASE_URL) cargo test --workspace --all-features

check-all: check test-integration
```

- Clippy runs with `--all-features`, so gated tests still compile and lint without Docker.
- `compose.test.yml` runs a throwaway Postgres on a port of its own (tmpfs, `fsync=off`, high
  `max_connections`) — never the development database. Pick a default clear of the dev instances
  (development Postgres often sit on 5432/5433) and let `TEST_PG_PORT` override it.
- A runtime skip when `DATABASE_URL` is unset is ruled out: it turns a missing database into a green
  run.
- Without CI, `check-all` is the gate before merging.
- Test logs: initialise tracing once per test binary through a `LazyLock`, writing to stdout when
  `TEST_LOG` is set and to `std::io::sink` otherwise. `SubscriberInitExt::init` panics on a second
  call, hence the `LazyLock`.
