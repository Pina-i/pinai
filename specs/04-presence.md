# Pina'i — Presence System

### Overview

The presence system is split into two fully independent subsystems with separate Redis channels, separate fan-out logic, and separate SSE event types:

| Subsystem | Redis channel | Fan-out target | Replay on reconnect |
|---|---|---|---|
| **Presence** | `presence:<domain>` | All friends of the actor | Yes — last known state |
| **Typing** | `typing:<convId>` | One recipient only | Never |

Both are **ephemeral** — never persisted to PostgreSQL. Redis pub-sub is the sole transport. Losing any event is always acceptable.

---

### Part A — Presence states

#### States

| State | Meaning |
|---|---|
| `online` | User has at least one active WebSocket connection |
| `away` | User is connected but has been idle for 10 minutes |
| `offline` | User has no active WebSocket connections |

#### Redis channel

One global channel per IdP instance:

```
presence:<domain>
```

Example: `presence:idp.alice.com`

Every WebSocket worker on the instance subscribes to this channel on startup. Fan-out to individual connected clients is done in the application-level hub (`HashMap<UserId, Vec<WsSender>>`).

#### Payload envelope

```json
{
  "type": "presence",
  "event": "online" | "away" | "offline",
  "actorUri": "https://idp.alice.com/users/alice_xK9mP",
  "timestamp": "2026-03-24T12:00:00Z"
}
```

#### Publishing rules

| Trigger | Event published |
|---|---|
| WebSocket connection established | `online` |
| Last WebSocket connection closed | `offline` |
| No `heartbeat` received for 10 minutes | `away` |
| `away` user sends any message or heartbeat | `online` |

#### Heartbeat

The client sends a heartbeat every **30 seconds** over the existing WebSocket connection:

```json
{ "type": "heartbeat" }
```

The server responds immediately:

```json
{ "type": "heartbeat_ack" }
```

The server keeps a `last_heartbeat: Instant` per connection. A background task runs every 60 seconds and marks any connection whose `last_heartbeat` is older than 10 minutes as `away` by publishing an `away` event to Redis. The connection is **not closed** — the user is still connected, just idle.

#### Fan-out logic

When the WebSocket worker receives a presence event from Redis:

1. Looks up the actor's friends list from an in-memory cache (refreshed on connect, invalidated on `friend_accepted` events).
2. For each friend with an active **local** connection, calls `hub.send_to_user()`.
3. Remote friends are served via the inter-IdP SSE stream — the local worker does not handle them.

#### WebSocket event pushed to clients

```json
{
  "event": "presence_update",
  "actorUri": "https://idp.alice.com/users/alice_xK9mP",
  "state": "online" | "away" | "offline",
  "timestamp": "2026-03-24T12:00:00Z"
}
```

---

### Part B — Typing indicators

Typing is an independent subsystem. It shares no Redis channel, no payload envelope, and no fan-out path with presence states.

#### Redis channel

One channel per conversation, derived directly from the conversation UUID:

```
typing:<conversation_id>
```

Example: `typing:018e1b2c-3d4f-7a8b-9c0d-1e2f3a4b5c6d`

The `conversation_id` is the UUID assigned at conversation creation (see §5). It is stable for the lifetime of the conversation regardless of participant count — adding a member does not change it. No hashing needed since UUIDs are already compact and safe as Redis channel names.

#### Payload envelope

```json
{
  "type": "typing",
  "actorUri": "https://idp.alice.com/users/alice_xK9mP",
  "conversationId": "<conversation_id>",
  "timestamp": "2026-03-24T12:00:05Z"
}
```

`conversationId` is the raw (pre-hash) conversation ID string. Recipients use it to match the typing event to the correct conversation in their local state.

#### Client → server message

The client sends over WebSocket when the user starts typing:

```json
{ "type": "typing_start", "conversationId": "<conversation_id>" }
```

There is no `typing_stop` — the recipient clears the indicator after a **3-second timeout** with no new `typing` event for that conversation.

#### Publishing rules

| Trigger | Action |
|---|---|
| Client sends `typing_start` | Publish to `typing:<conversation_id>` |
| No further `typing_start` from client | Channel goes silent; recipients time out after 3s |

Rate-limit: the server ignores `typing_start` messages sent more than once per second per user, to avoid flooding Redis.

#### Fan-out logic

When the WebSocket worker receives a typing event from Redis:

1. Looks up the conversation's member list (from in-memory cache for active conversations).
2. For each member **except the sender** who has an active local connection, calls `hub.send_to_user()`.
3. The sender is **never** echoed the typing event back.

For DMs the member list always has exactly one entry, making this identical in cost to the previous single-recipient lookup. For future group conversations the same logic fans out to all local members without any structural change.

#### WebSocket event pushed to client

```json
{
  "event": "typing",
  "actorUri": "https://idp.alice.com/users/alice_xK9mP",
  "conversationId": "<conversation_id>",
  "timestamp": "2026-03-24T12:00:05Z"
}
```

---

### Cross-instance — inter-IdP SSE stream

Both presence states and typing indicators are propagated cross-instance via a single authenticated SSE endpoint. The two subsystems are distinguished by the SSE `event:` field.

#### Principle

Each IdP exposes an SSE endpoint that proxies its local Redis channels (both `presence:<domain>` and relevant `typing:<convId>` channels), filtered to a requested set of actors. A remote IdP connects once per domain and receives a real-time filtered stream for all actors it cares about.

```
idp.bob.com  ──SSE──▶  GET idp.alice.com/api/presence/stream
                        ?actors[]=alice_xK9mP
```

#### Endpoint

```
GET /api/presence/stream?actors[]=<username>&actors[]=...
Content-Type: text/event-stream
Authorization: (HTTP Signature — see below)
```

- Response is a persistent SSE stream.
- The remote IdP reconnects automatically on disconnect using `Last-Event-ID` + `retry:`.
#### Authentication — HTTP Signatures

The requesting IdP signs the request using its existing ActivityPub RSA key pair, identical to the scheme used for AP activity delivery.

Required signed headers: `(request-target)`, `host`, `date`.

The receiving IdP verifies by:
1. Extracting `keyId` from the `Signature` header (e.g. `https://idp.bob.com/actor#main-key`).
2. Fetching the public key from that URI (cached — reuses existing AP actor fetch).
3. Verifying the signature. Reject `401` if invalid or `date` is older than 5 minutes (replay protection).

No new key material — fully reuses AP infrastructure.

#### SSE event format

The two subsystems use distinct SSE `event:` names so the receiving IdP can route them without inspecting the payload:

```
// Presence state event
id: <uuid>
event: presence
data: {"type":"presence","event":"online","actorUri":"https://idp.alice.com/users/alice_xK9mP","timestamp":"2026-03-24T12:00:00Z"}

// Typing event
id: <uuid>
event: typing
data: {"type":"typing","actorUri":"https://idp.alice.com/users/alice_xK9mP","conversationId":"alice_xK9mP@idp.alice.com:bob_aB3cD@idp.bob.com","timestamp":"2026-03-24T12:00:05Z"}
```

On SSE reconnect (`Last-Event-ID`), the server replays the **last known presence state** for each requested actor. Typing events are **never replayed** — a stale "is typing" indicator would be worse than no indicator.

#### Which typing channels does Alice's IdP subscribe to?

Alice's IdP subscribes to `typing:<conversation_id>` channels only for conversations where **at least one participant is local** and the other is the requesting remote instance's actor. It derives the relevant channel IDs by joining `conversation_members` against the `actors[]` query parameter.

#### Connection management on Bob's IdP

Bob's IdP maintains one outbound SSE connection per remote domain:

```
RemotePresenceRegistry:
  HashMap<domain, SSEConnection>
```

When Bob's IdP receives an SSE event:
- `event: presence` → publishes to local `presence:idp.bob.com` Redis channel → fans out to all Bob's friends who need it.
- `event: typing` → publishes to local `typing:<convId>` Redis channel → fans out to all local conversation members except the sender.

The cross-instance path is fully transparent to the WebSocket layer, which always reads from local Redis regardless of event origin.

```
Alice comes online
  → idp.alice.com: PUBLISH presence:idp.alice.com
  → SSE stream (event: presence) → idp.bob.com
  → idp.bob.com: PUBLISH presence:idp.bob.com
  → Bob's WS worker → hub.send_to_user() → Bob's clients

Alice types in DM with Bob
  → idp.alice.com: PUBLISH typing:<convId>
  → SSE stream (event: typing) → idp.bob.com
  → idp.bob.com: PUBLISH typing:<convId>
  → Bob's WS worker → looks up conversation members → hub.send_to_user() → all local members except Alice
```

---

### Initial presence state on connect

When a user opens the friends list or a DM conversation, their IdP serves current presence states immediately from the in-memory store:

```
GET /api/presence?actors[]=alice_xK9mP@idp.alice.com&actors[]=...
Authorization: Bearer <access_token>
```

Response:

```json
{
  "presence": [
    { "actorUri": "https://idp.alice.com/users/alice_xK9mP", "state": "online"  },
    { "actorUri": "https://idp.bob.com/users/carol_zZ1wX",   "state": "away"    },
    { "actorUri": "https://idp.bob.com/users/dave_mN4pQ",    "state": "offline" }
  ]
}
```

For remote actors, the state reflects the last event received via the inter-IdP SSE stream. If the SSE connection to that domain is currently down, `offline` is returned as the safe fallback.

Typing state is **not** included in this endpoint — it is too ephemeral to be meaningful as a snapshot.

---

### In-memory presence state store

Each IdP maintains one store, updated by the Redis `presence:<domain>` subscriber:

```rust
struct PresenceStore {
    states: DashMap<ActorUri, (PresenceState, Instant)>,
}
```

`Instant` records the time of the last state change. Used for `GET /api/presence` responses and for SSE reconnect replay. No persistence — on server restart all actors are `offline` until clients reconnect and heartbeat.

---

### Scaling strategy — tiered hybrid

The baseline design (one persistent SSE connection per remote domain for all friends) works well at small-to-medium scale. As the number of remote friendships grows, the system transitions to a **tiered hybrid** model that splits presence and typing across two transport modes based on context:

| Context | Transport | What it carries | Latency |
|---|---|---|---|
| Active conversation | SSE (1 connection per involved remote domain) | Typing + presence for that conversation's remote members only | Real-time |
| Friends list sidebar | Batch poll every ~10s | Presence snapshot for all remote friends | ≤10s |
| No conversation open, no sidebar visible | Nothing | — | — |

#### Why this works

- **Typing is already scoped.** The SSE stream only subscribes to `typing:<convId>` channels for conversations with active local participants (§ "Which typing channels does Alice's IdP subscribe to?"). No change needed — typing is already "tiered."
- **Presence is the expensive part.** The domain-wide `presence:<domain>` channel streams all requested actors continuously, even for friends the user hasn't interacted with in weeks. Batch polling replaces this for the sidebar, where 10s staleness is imperceptible.
- **The `PresenceStore` is transparent.** Whether state arrives via SSE or batch poll, the `DashMap` is updated the same way. Downstream consumers (`GET /api/presence`, WS fan-out) are unaffected.
- **Connection count drops dramatically.** With no active cross-domain conversations open, an IdP maintains zero outbound SSE connections — compared to one per remote domain in the baseline.

#### Batch presence endpoint (server-to-server)

The existing `GET /api/presence` endpoint uses Bearer token auth (client-facing). For server-to-server batch polling, a separate endpoint uses HTTP Signatures:

```
POST /api/presence/batch
Authorization: (HTTP Signature — same scheme as AP activity delivery)

{ "actors": ["alice_xK9mP", "bob_aB3cD", ...] }
```

Response:

```json
{
  "presence": [
    { "actorUri": "https://idp.alice.com/users/alice_xK9mP", "state": "online" },
    { "actorUri": "https://idp.alice.com/users/bob_aB3cD",   "state": "offline" }
  ]
}
```

State is read directly from the `PresenceStore`. No database access, no persistence. If the requesting IdP asks about an actor not in the store, `offline` is returned as the safe fallback.

#### SSE connection lifecycle under the tiered model

Under the tiered model, the `RemotePresenceRegistry` changes behavior:

- **Baseline**: one persistent SSE connection per remote domain, created on first friendship, kept alive indefinitely.
- **Tiered**: SSE connections are opened on-demand when a user opens a conversation with a remote participant, and closed when no local user has an active conversation involving that remote domain. The batch poller runs independently on a fixed interval for all remote domains that have friends.

```
RemotePresenceRegistry:
  batch_poll_domains: HashSet<domain>          -- polled every ~10s
  active_sse: HashMap<domain, SSEConnection>   -- only for active conversations
```

---

### Summary — data flow

```
── Local presence ──────────────────────────────────────────────────
Client connect / disconnect / heartbeat timeout
  → Msg Backbone updates PresenceStore
  → PUBLISH presence:<domain>
  → WS worker: hub.send_to_user() → all local friends

── Local typing ────────────────────────────────────────────────────
Client typing_start (rate-limited: 1/s)
  → PUBLISH typing:<convId>
  → WS worker: hub.send_to_user() → recipient only (never sender)
  → recipient clears indicator after 3s silence

── Cross-instance presence (active conversation) ──────────────────
PUBLISH presence:idp.alice.com
  → SSE stream (event: presence) → idp.bob.com
  → PUBLISH presence:idp.bob.com
  → WS worker → all local friends of Alice on Bob's instance

── Cross-instance presence (sidebar / batch poll) ─────────────────
idp.bob.com → POST idp.alice.com/api/presence/batch (every ~10s)
  ← { presence: [ { actorUri, state }, ... ] }
  → update local PresenceStore
  → WS worker → push presence_update to relevant local users

── Cross-instance typing ───────────────────────────────────────────
PUBLISH typing:<convId>
  → SSE stream (event: typing) → idp.bob.com
  → PUBLISH typing:<convId> (local)
  → WS worker → Bob's client only

── Initial state on page load ──────────────────────────────────────
Client → GET /api/presence?actors[]=...
       ← PresenceStore snapshot (typing excluded)
```
