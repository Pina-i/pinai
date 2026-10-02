# Pina'i — Event delivery

Naively pushing events directly over WebSockets creates several problems:

- Events are lost if the client is temporarily disconnected.
- No catch-up mechanism on reconnect.
- No fan-out to multiple devices (web + desktop).

The solution is a **message broker** as the backbone for durable client-event
delivery. Given Redis is already in the stack for presence/pub-sub,
**Redis Streams** is the pragmatic choice to avoid adding a new infrastructure
dependency.

## 1. Redis transport split

| Channel | Type | Use case |
|---|---|---|
| Presence (online/offline/typing) | Redis pub-sub | Ephemeral — losing an event is acceptable |
| DMs, profile updates, friend requests | Redis Streams | Durable client-side — survives a recipient's disconnect |

Redis pub-sub remains appropriate for presence events since they are high-frequency and inherently transient. Redis Streams handles everything that must survive a recipient disconnect.

> The streams carry **client-facing events** so a reconnecting tab can catch
> up. They are **not** the inter-IdP outbox — outbound ActivityPub delivery
> is covered separately below.

## 2. Federation delivery semantics

> Delivery covered here is the outbound half. Every activity leaves signed, and every
> activity arriving at `POST /users/:username/inbox` is authenticated before any state is
> touched — see `specs/06-federation-authentication.md` for the signing scheme, the three inbound
> checks, and the peer request policy.

Outbound ActivityPub activities are delivered **inline** via `tokio::spawn`
per remote inbox — there is no persistent outbox queue. Every activity we
emit is either time-sensitive (durable retry actively makes it worse) or
idempotent and naturally self-healing through another mechanism:

| Activity | Property | Recovery on delivery failure |
|---|---|---|
| `Create{Note}` (1:1 DM) | Time-sensitive | Outcome recorded in `direct_messages.federation_status`; a failure is pushed to the sender (`dm_delivery_failed`), whose client sends the message again as a new one — see `identity-provider/specs/direct-messages.md § 3` |
| `Update{Note}` (edit) | Time-sensitive | Same — recipients see the original until they can refetch |
| `Like` / `Undo{Like}` (reaction) | Idempotent | Reconciles on next conversation fetch |
| `Follow` / `Accept` | Idempotent, low-frequency | The requester can send the request again; a `Follow` for a friendship already accepted here is answered with the `Accept` again |
| `Reject` / `Undo{Follow}` | Idempotent, low-frequency | The peer keeps its row until either side touches the relationship again — see `identity-provider/specs/social.md § 1`, Declining a request and ending a friendship |
| `Update{Person}` (profile) | Idempotent, carries the whole shown profile | The next change sends it whole again; until then the peer shows the profile it had, and a card for it more than 24 h old discovers the actor again — see `identity-provider/specs/profile-and-settings.md § 1` |

Each activity type owns its own reconciliation story (the next change,
next user interaction, sender-driven resend), so a missed delivery never produces a
permanently inconsistent state. This avoids the failure modes a generic
queue introduces (silent worker death, queue growth, attempt-counter
overflow, mis-tuned backoff). If a future activity does require durable
retry, that activity earns its own scoped queue at that point — rather
than a one-size-fits-all outbox up front.

## 3. Client reconnect & catch-up

The WebSocket layer becomes a thin delivery mechanism that reads from Redis Streams rather than being the source of truth. On reconnect, the client sends its last received event ID, and the server replays any undelivered stream entries:

```
Client reconnects ──▶ sends last_event_id ──▶ server replays missed entries from Redis Stream
```

This naturally handles multi-device scenarios too: each device maintains its own consumer position in the stream.

## 4. Scaling consideration

Redis Streams is the right starting point. If federation traffic grows significantly, **NATS JetStream** is a better long-term fit — it is designed for exactly this kind of federated, multi-instance messaging topology. Migrating later is straightforward since the broker is behind an abstraction layer in the Msg Backbone.
