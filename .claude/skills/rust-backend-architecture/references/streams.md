# Streams, WebSockets and background tasks

The transport is always an adapter. The only question is its **direction**: does it drive the
application (a request, a client frame, a consumed message) or is it driven by it (a query, a
publish, a push to a connected client)?

## Contents
1. Direction decides the crate
2. Inbound stream adapters
3. Outbound stream adapters
4. WebSockets: both at once
5. `Stream` in a port
6. Wiring tasks and graceful shutdown
7. When a write and a publish must agree

## 1. Direction decides the crate

| Direction | Examples | Crate |
|---|---|---|
| Inbound (driving) | HTTP handlers, the WebSocket upgrade + read loop, a Kafka / Redis Streams / queue consumer | `api` — beside the HTTP handlers |
| Outbound (driven) | SQL, HTTP clients, publishing to a broker, pushing to connected WebSocket clients | `infrastructure` — behind a port in `domain` |

`api` and `infrastructure` are the *inbound* and *outbound* adapter crates; some projects name them
`adapters/inbound/{http, ws, kafka}` and `adapters/outbound/{postgres, kafka, ws}`. Same rule
either way: neither depends on the other, and both reach the application only through use cases
(inbound) or ports (outbound).

## 2. Inbound stream adapters

An inbound stream adapter is a handler with a loop around it. It owns everything about the
transport — the consumer loop, decoding, offset commits or acks, WebSocket framing and pings — and
calls **one use case per message**, exactly as an HTTP handler would:

```rust
// api/src/consumers/vehicles.rs
pub async fn run(
    mut consumer: VehicleConsumer,
    register: Arc<RegisterVehicle>,
    dead_letter: DeadLetterQueue,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        let message = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            message = consumer.recv() => match message? {
                Some(message) => message,
                None => return Ok(()),
            },
        };
        // Transport DTO → command. A message that cannot be decoded never succeeds on retry.
        let command = match RegisterVehicleMessage::decode(&message).and_then(RegisterVehicle::command) {
            Ok(command) => command,
            Err(e) => {
                dead_letter.send(&message, &e).await?;
                consumer.commit(&message).await?;
                continue;
            }
        };
        match register.execute(command).await {
            Ok(_) => consumer.commit(&message).await?, // ack only after success
            Err(VehicleError::Unexpected(e)) => {
                // Transient (database, network): don't ack — the broker redelivers.
                tracing::warn!(error = ?e, "vehicle registration will be retried");
            }
            Err(refused) => {
                // A business refusal fails the same way every time: park it, then move on.
                dead_letter.send(&message, &refused).await?;
                consumer.commit(&message).await?;
            }
        }
    }
}
```

- **The use case only succeeds or fails.** What that means for the broker — ack, retry,
  dead-letter — is transport policy and lives in the adapter. Map the context error there:
  `Unexpected` is retryable, a business refusal is not.
- **Delivery is at-least-once**, so every use case an inbound stream calls must be **idempotent**:
  a redelivered message is a no-op (unique keys, `ON CONFLICT DO NOTHING`, a processed-message id).
- Decoding goes through `TryFrom` into the command, as for request DTOs — the least trusted input.
- An error is logged once, where the adapter handles it (see errors.md).

## 3. Outbound stream adapters

Publishing and pushing are outbound: a port in `domain`, an adapter in `infrastructure`.

```rust
// domain/src/social/ports.rs
#[async_trait::async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(&self, event: SocialEvent) -> Result<(), PublishError>;
}
```

- `KafkaEventPublisher` implements it with the broker client; `WsBroadcaster` implements the same
  trait over the connection registry (§4); `RecordingEventPublisher` is the in-memory fake. The use
  case sees only `EventPublisher` — never which transport is behind it.
- Events are domain types (`SocialEvent::FriendshipAccepted { … }`); the adapter serialises them
  into its wire format, as `ApiError` does for HTTP.
- A notifier to one audience (`SettingsNotifier::settings_updated(user, …)`) is the same shape with
  a narrower port; prefer the narrow port until two use cases need the same event stream.

## 4. WebSockets: both at once

A WebSocket is inbound **and** outbound:

- The Axum upgrade and the read loop are an **inbound** adapter in `api`: decode each client frame,
  call a use case, answer or ignore.
- The push side — reaching clients when something happens elsewhere — is an **outbound** adapter
  behind a port (`EventPublisher`, `SettingsNotifier`…) in `infrastructure`.
- Both need the **connection registry** (a `DashMap` of senders, or a `tokio::sync::broadcast`
  channel). It is transport, not domain: put it in a small transport crate that `api` and
  `infrastructure` both depend on, create one `Arc` of it in `app`, and hand it to both. It never
  appears in `domain` or `application`, and it knows no business rule.

## 5. `Stream` in a port

A port may produce or consume a sequence when a use case genuinely needs one — watching positions,
following a feed:

```rust
use futures_core::stream::BoxStream;

pub trait PositionFeed: Send + Sync {
    fn watch(&self, vehicle: VehicleId) -> BoxStream<'static, Position>;
}
```

- `futures-core` is tiny and technology-neutral, like `serde` — allowed in `domain`.
- Ports are `Arc<dyn Port>`, and `-> impl Stream` is not dyn-compatible, so a port returns
  `BoxStream<'static, T>` (`Pin<Box<dyn Stream<Item = T> + Send>>`).
- Never leak `tokio::sync::mpsc::Receiver`, broker message types or WebSocket frames into the
  domain: the adapter converts them into the stream of domain values.

## 6. Wiring tasks and graceful shutdown

Consumer loops, broadcast tasks, relays and sweeps are spawned in the composition root, beside the
HTTP server, and stop together:

```rust
// app/src/lib.rs
pub async fn run_until_stopped(self) -> anyhow::Result<()> {
    let shutdown = CancellationToken::new();
    let mut tasks = JoinSet::new();

    tasks.spawn(api::consumers::vehicles::run(
        self.consumer, self.register_vehicle, self.dead_letter, shutdown.clone(),
    ));
    tasks.spawn(infrastructure::outbox::relay(self.pool.clone(), self.publisher, shutdown.clone()));
    tasks.spawn({
        let stop = shutdown.clone();
        async move {
            axum::serve(self.listener, self.router)
                .with_graceful_shutdown(stop.cancelled_owned())
                .await
                .map_err(anyhow::Error::from)
        }
    });

    // Stop on a signal, or as soon as one task ends — a dead consumer must not go unnoticed.
    let first = tokio::select! {
        _ = tokio::signal::ctrl_c() => None,
        ended = tasks.join_next() => ended,
    };
    shutdown.cancel();
    while tasks.join_next().await.is_some() {}
    match first {
        Some(Ok(Err(e))) => Err(e),
        Some(Err(join)) => Err(join.into()),
        _ => Ok(()),
    }
}
```

- `CancellationToken` comes from `tokio-util`; every loop selects on `shutdown.cancelled()`.
- Every task returns `anyhow::Result<()>`, so a failure surfaces instead of vanishing inside a
  detached `tokio::spawn`.
- In `spawn_app` tests, tasks the test does not exercise are simply not spawned.

## 7. When a write and a publish must agree

Publishing right after a commit can lose the event (the process dies between the two), and
publishing inside the transaction can announce a change that then rolls back. When the two must
agree, use the **transactional outbox**: see persistence.md § 3.
