# Persistence and transactions

## Contents
1. Adapter shape
2. Atomic operations
3. Side effects after the commit
4. Concurrency without stricter isolation
5. Migrations

## 1. Adapter shape

```rust
// infrastructure/src/postgres/social.rs
pub struct PgSocialGraph {
    pool: PgPool,
}

#[async_trait::async_trait]
impl SocialGraph for PgSocialGraph {
    async fn friends_of(&self, owner: UserId) -> Result<Vec<Friendship>, SocialStoreError> {
        let rows = sqlx::query_as::<_, FriendshipRow>(
            "SELECT id, status, friend_actor_uri FROM friendships WHERE owner_user_id = $1",
        )
        .bind(owner.as_uuid())
        .fetch_all(&self.pool)
        .await
        .context("list friendships")?;
        rows.into_iter().map(|row| Friendship::try_from(row).map_err(SocialStoreError::from)).collect()
    }
}
```

- **Runtime queries** (`query_as::<_, Row>`, `query_scalar`, `query`) with `#[derive(sqlx::FromRow)]`
  row structs private to `infrastructure`: `cargo build` needs no database and no offline cache.
  The SQL is covered by the adapter's `sqlx::test`s instead of compile-time checks.
- Rows convert into domain entities with `TryFrom<Row>` (see domain-types.md); writes bind
  `.as_uuid()` / `.as_str()`.
- Expose `pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");` from
  `infrastructure`: the app runs it at startup and `#[sqlx::test(migrator = "...")]` reuses it.

## 2. Atomic operations

A port method is one business operation, and its adapter owns the transaction:

```rust
async fn accept(&self, request: FriendshipId, by: UserId) -> Result<Accepted, SocialStoreError> {
    let mut tx = self.pool.begin().await.context("begin accept")?;
    let friendship = claim_pending(&mut tx, request, by).await?;   // guarded UPDATE … RETURNING
    flip_reverse_row(&mut tx, &friendship).await?;
    let conversation = ensure_dm(&mut tx, &friendship).await?;
    tx.commit().await.context("commit accept")?;
    Ok(Accepted { friendship, conversation })
}

async fn claim_pending(c: &mut PgConnection, id: FriendshipId, by: UserId) -> Result<Friendship, SocialStoreError> {
    // `&mut tx` derefs to `&mut PgConnection`; helpers take the connection, not the pool.
    todo!()
}
```

- A `Transaction` dropped without `commit()` rolls back — an early `?` is safe, a forgotten
  `commit()` silently loses every write.
- Helpers are private functions taking `&mut PgConnection`; they are not ports.
- Repository traits generic over `sqlx::Executor` are ruled out: a generic method is not
  dyn-compatible, and it leaks SQLx into the domain.
- A **unit of work** (a transaction context shared by several ports) only when one use case must
  combine two ports atomically — typically writing a state change and an outbox row together.

## 3. Side effects after the commit

- The use case calls the store port, and only once it returns `Ok` does it call the notifier /
  delivery ports (WebSocket push, broker event, outbound HTTP).
- Never make an HTTP call inside a transaction: it holds row locks and a pooled connection across
  network latency.
- WebSocket and broker events are hints; the database is the source of truth, and clients refetch
  on reconnect.
- Outbound delivery that the flow does not have to guarantee is fire-and-forget: never `?` a
  delivery after the local commit — the local change has happened, so the request succeeded.
- When a lost side effect is tolerable but unwelcome, prefer **forward recovery** over
  compensation: make the operation idempotent and let a retry, a peer's re-send or a startup sweep
  complete it.
- When the write and the event **must agree** — an event that must never be lost, nor announce a
  change that rolled back — use the **transactional outbox** below. Publishing right after the
  commit loses the event if the process dies in between.

### The transactional outbox

The event is written to an `outbox` table **in the same transaction** as the state change; a relay
publishes it afterwards.

```rust
// infrastructure/src/postgres/social.rs — the port method writes the change and its event together
async fn accept(&self, request: FriendshipId, by: UserId) -> Result<Accepted, SocialStoreError> {
    let mut tx = self.pool.begin().await.context("begin accept")?;
    let accepted = claim_and_accept(&mut tx, request, by).await?;
    insert_outbox(&mut tx, &SocialEvent::FriendshipAccepted { friendship: accepted.id }).await?;
    tx.commit().await.context("commit accept")?;
    Ok(accepted)
}

// infrastructure/src/outbox.rs — the relay: an outbound adapter, spawned in `app` (streams.md § 6)
pub async fn relay(pool: PgPool, publisher: Arc<dyn EventPublisher>, shutdown: CancellationToken) -> anyhow::Result<()> {
    while !shutdown.is_cancelled() {
        let mut tx = pool.begin().await?;
        // `FOR UPDATE SKIP LOCKED`: several relays never publish the same row.
        let batch = claim_unsent(&mut tx, 100).await?;
        for row in &batch {
            publisher.publish(row.event()?).await?;
        }
        mark_sent(&mut tx, &batch).await?;
        tx.commit().await?;
        if batch.is_empty() {
            tokio::select! { _ = shutdown.cancelled() => {}, _ = tokio::time::sleep(POLL) => {} }
        }
    }
    Ok(())
}
```

- When the state change and the event belong to **one port**, that port's method writes both, as
  above — no new abstraction. When they belong to **two ports**, this is the case a **unit of work**
  exists for (§ 2): the use case writes both through one transaction context.
- The relay publishes **at least once** (a crash between publish and commit republishes the batch),
  so consumers must be idempotent — which inbound stream adapters already require (streams.md § 2).
- The relay is just another outbound adapter; the use case never sees it.
- The outbox is for flows whose events must agree with the database. A project may decide a flow is
  best-effort instead — its decisions record says which.

## 4. Concurrency without stricter isolation

Stay on Postgres's default READ COMMITTED; REPEATABLE READ and SERIALIZABLE turn waits into
serialisation failures that need retry loops. Get correctness from the database instead:

| Race | Fix |
|---|---|
| find-then-create (two DMs for one pair) | a unique key on a normalised pair, then `INSERT … ON CONFLICT DO NOTHING RETURNING` + re-select |
| state transition (accept twice) | guarded `UPDATE … SET status = 'accepted' WHERE id = $1 AND status = 'pending' RETURNING …`; no row → `Conflict` |
| claim one item among many | `SELECT … FOR UPDATE SKIP LOCKED LIMIT 1` |
| redelivered inbound message | `INSERT … ON CONFLICT (activity_uri) DO NOTHING` + `rows_affected()` — answer 2xx either way |
| ordered log (epochs, versions) | a `UNIQUE (stream_id, version)` constraint; a violation is a typed `Conflict` carrying the winner |

## 5. Migrations

- `migrations/YYYYMMDDNNNNNN_snake_case.sql` — the date plus a sequence number within the day.
- Open each file with a `--` comment stating why the change exists, citing the spec section.
- Never edit an applied migration; add a new one.
- A new mandatory column on a live table goes in steps: add it nullable, backfill, then
  `SET NOT NULL`.
- `sqlx::migrate!` embeds the directory at compile time; add a `build.rs` to the crate that invokes
  it so adding a `.sql` file triggers a rebuild:

```rust
// infrastructure/build.rs
fn main() {
    println!("cargo:rerun-if-changed=../../migrations");
}
```
