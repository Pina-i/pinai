---
name: rust-backend-architecture
description: MANDATORY rules for every change to Rust backend code (Axum + Tokio + SQLx/Postgres services and their shared crates). Enforces hexagonal architecture with layers as crates (domain → application → infrastructure → api → app), adapters placed by direction (inbound HTTP, WebSocket read loops and stream consumers in api; outbound SQL, HTTP clients, publishers and WebSocket push in infrastructure), ports as trait objects behind Arc with async-trait, typed thiserror errors with one ApiError at the HTTP edge, domain newtypes (parse, don't validate), adapter-owned transactions and the outbox, background tasks with graceful shutdown, and the test tiers (fakes, contract suites, sqlx::test, wiremock, spawn_app). Load it whenever you create, modify, move or delete any Rust entity, value object, port, use case, adapter, SQL query, migration, handler, WebSocket or stream adapter, background task, error type, wiring or test, fixes and refactors included. On layering, errors and ports it overrides rust-async-patterns.
---

# Rust Backend Architecture

Hexagonal architecture (ports & adapters). Each layer is a crate, so the compiler enforces the
dependency rule — no lint needed.

```
<service>/
├── crates/
│   ├── domain/          # entities, value objects, port traits, domain errors
│   ├── application/     # use cases: orchestrate ports, one flow each
│   ├── infrastructure/  # outbound (driven) adapters: SQLx, Redis, HTTP clients, publishers, WS push
│   ├── api/             # inbound (driving) adapters: Axum routes, WS read loops, stream consumers;
│   │                    #   DTOs, ApiError, AppState
│   └── app/             # composition root: lib.rs (Application::build) + thin main.rs
└── migrations/          # SQLx migrations, embedded by infrastructure
```

| Crate | May depend on | Never on |
|---|---|---|
| `domain` | `serde`, `serde_json` (when the concept *is* a JSON document), `thiserror`, `anyhow` (opaque error payload only), `async-trait`, `futures-core` (a `Stream` in a port), `uuid`, `time`, `url` | `sqlx`, `axum`, `tokio`, `reqwest`, `redis`, broker clients |
| `application` | `domain`, `async-trait` | `sqlx`, `axum`, `reqwest` |
| `infrastructure` | `domain`, `sqlx`, `redis`, `reqwest`, `tokio`, broker producers, the shared transport crate | `axum`, `application`, `api` |
| `api` | `application`, `domain`, `axum`, broker consumers, the shared transport crate | `sqlx`, `infrastructure` |
| `app` | every crate | — |

**Direction decides the adapter crate.** A transport that *drives* the application — an HTTP
request, a WebSocket frame, a consumed message — is an inbound adapter in `api`, and calls a use
case. One the application *drives* — a query, a publish, a push to connected clients — is an
outbound adapter in `infrastructure`, behind a port. A WebSocket is both: its upgrade and read loop
in `api`, its push side in `infrastructure`, and the connection registry they share in a small
transport crate both depend on. Details: [references/streams.md](references/streams.md).

Inside each layer crate, organise by **bounded context** (`domain::social`, `application::social`,
`infrastructure::postgres::social`…), not by technical kind.

## Where does a change go?

Decide the layer **before** writing, by what the change *is* — not by where the symptom shows, and
not by what neighbouring code does. Legacy code breaking this table is not a precedent.

| The change is… | It goes in |
|---|---|
| A rule about data — validation, invariant, state transition, "may X do Y?" | `domain`: a pure function, or a method on an entity / value object |
| A new kind of value with rules (address, URI, id, bounded string, closed set) | `domain` value object — [references/domain-types.md](references/domain-types.md) |
| A flow: load, decide, persist, notify | `application` use case |
| Something the domain needs from outside (storage, clock, outbound message) | a port trait in `domain` + its adapter in `infrastructure` |
| SQL, Redis, HTTP clients, SQLSTATE codes | `infrastructure` adapter |
| Publishing an event, pushing to connected WebSocket clients | a port in `domain` + its adapter in `infrastructure` |
| Routes, request/response DTOs, status codes, error bodies | `api` |
| A consumer loop or WebSocket read loop: decode, call the use case, ack / retry / dead-letter | `api` inbound adapter |
| Wiring, configuration, startup, spawning background tasks, graceful shutdown | `app` |

A handler does three things only: parse the DTO into a command, call the use case, map the result
or the error to a response. No SQL, no business decision.

## Ports and dependency injection

```rust
// domain/src/social/ports.rs
#[async_trait::async_trait]
pub trait SocialGraph: Send + Sync {
    async fn accept(&self, request: FriendshipId, by: UserId) -> Result<Accepted, SocialStoreError>;
}

// application/src/social/accept_friendship.rs
pub struct AcceptFriendship {
    graph: Arc<dyn SocialGraph>,
    notifier: Arc<dyn FriendshipNotifier>,
}
```

- **Ports are traits in `domain`**, `#[async_trait]`, `Send + Sync`, held as `Arc<dyn Port>`. Native
  `async fn` in traits is not dyn-compatible; `async-trait` makes it so.
- **A trait only with two implementations**: the real adapter and an in-memory fake. Otherwise use
  a concrete struct or a plain function. Pure rules never need a port (functional core,
  imperative shell). In-memory hot paths (caches, registries) stay concrete.
- **A port models a business operation, not a table**: `SocialGraph::accept` writes every row the
  acceptance needs, rather than `FriendshipRepo::set_status` + `ConversationRepo::create` called in
  turn. This is also what makes it atomic — see Persistence.
- **Use cases are concrete structs** holding `Arc<dyn Port>`s, built only in `app`. They have no
  trait: API tests build the real use cases over in-memory fakes.
- **DI is manual**: `Application::build` in `app` constructs adapters, then use cases, then the Axum
  `AppState` holding `Arc<UseCase>`s. No container, no generics threaded through handlers.

## Errors

- `domain` / `application`: a `thiserror` enum per bounded context, with an
  `Unexpected(#[source] anyhow::Error)` variant; a per-use-case enum only when its caller reacts
  differently. Never one variant per fallible call.
- Ports return a domain-owned error carrying only the cases callers react to (`Conflict`, …),
  `Option` for absence, `Unexpected` for the rest. The domain never sees `sqlx::Error`.
- Adapters wrap foreign errors with `.context("what we were doing")` and own SQLSTATE mapping.
- `api` owns one `ApiError`; `impl From<ContextError> for ApiError` is the status-code policy. The
  body is `{ "error", "error_description" }`; a 500 carries a fixed description, never the cause.
- Log an error **once, where it is handled** — the HTTP edge or the background task. Never in a
  constructor, never while propagating.

Details and code: [references/errors.md](references/errors.md).

## Domain types

- **Parse, don't validate**: private inner field, `parse(...) -> Result<Self, ValidationError>`,
  read access through `AsRef` / getters, no `inner_mut`. A function taking the type can rely on its
  invariant.
- Typed ids (`UserId(Uuid)`, from an `id!` macro) instead of bare `Uuid`; closed enums instead of
  string literals. `serde` is allowed on domain types; SQLx derives are not.
- Parse at every boundary with `TryFrom`: request DTO → command (400), DB row → entity (a corrupt
  row is `Unexpected`), inbound external JSON → domain types (the least trusted input).

Details and code: [references/domain-types.md](references/domain-types.md).

## Persistence and transactions

- One port method per atomic business operation. Its adapter opens the transaction, commits it,
  and passes `&mut PgConnection` to private helpers. A unit-of-work abstraction only when one use
  case must combine two ports atomically.
- Side effects — WebSocket pushes, broker events, outbound HTTP — happen **after** the commit, in
  the use case. Never HTTP inside a transaction.
- When the write and its event must agree, the event goes to an **outbox** table in the same
  transaction and a relay (an outbound adapter) publishes it.
- READ COMMITTED, with correctness from constraints: unique keys, guarded `UPDATE … RETURNING`,
  `ON CONFLICT`, `FOR UPDATE SKIP LOCKED`. A redelivered inbound message answers 2xx.
- Runtime queries (`sqlx::query_as::<_, Row>`) with row structs private to `infrastructure`, so a
  build needs no database.

Details and code: [references/persistence.md](references/persistence.md).

## Streams, WebSockets and background tasks

- An inbound stream adapter owns the loop, decoding and transport concerns (acks, offset commits,
  framing, pings), and calls one use case per message — like a handler. The use case only succeeds
  or fails; the adapter decides what that means for the broker: ack after success, retry on
  `Unexpected`, dead-letter a refusal.
- Delivery is at-least-once: every use case an inbound stream calls is **idempotent**.
- Outbound streams are ports (`EventPublisher`, a narrower notifier) with a broker, WebSocket or
  in-memory adapter behind them; the use case never knows which.
- A port may return a stream as `BoxStream<'static, T>` from `futures-core` — never a tokio channel
  or a broker type.
- Consumers, broadcasters, relays and sweeps are spawned in `app` beside the HTTP server, in a
  `JoinSet` with a `CancellationToken`, and stop together.

Details and code: [references/streams.md](references/streams.md).

## Tests

| Tier | How | Where |
|---|---|---|
| domain, application — **TDD runs here** | pure tests; use cases over in-memory fakes | child module `src/<module>/tests.rs` |
| port contracts | one suite per port, run against the fake **and** the real adapter | suites + fakes behind the `test-utils` feature of the crate defining the port |
| SQLx / Redis adapters | `#[sqlx::test]`: a fresh database per test | `infrastructure/tests/postgres/main.rs` |
| outbound HTTP adapters | `wiremock` as the remote service | `infrastructure/tests/<client>/main.rs` |
| Axum routes | router + real use cases over fakes, `tower::ServiceExt::oneshot` | child modules in `api` |
| inbound stream adapters | a fake message source, real use cases over fakes: the ack / retry / dead-letter policy | child modules in `api` |
| end-to-end | a few journeys through `spawn_app` | `app/tests/api/main.rs` (one binary) |

- Unit tests live in their own file: `src/foo.rs` ends with `#[cfg(test)] mod tests;` and nothing
  after it; `src/foo/tests.rs` starts with `use super::*;`. A crate root puts them in `src/tests.rs`.
- Tests needing Docker are gated behind the `integration` feature, so `make check` never needs it.
- Test names are behaviour sentences: `a_request_to_oneself_is_refused`.

Details and code: [references/testing.md](references/testing.md).

## Code that is not in this shape yet

- Never extend the legacy pattern you are touching: put the new rule in `domain` and call it from
  the legacy site.
- Follow the project's migration plan or decisions record when one exists; it wins on
  project-specific choices.
- Structure-only commits preserve behaviour. A bug found on the way gets a failing test and its fix
  in a separate commit.
- Keep the service's `CLAUDE.md` and specs in step when crates, endpoints or tables change.
