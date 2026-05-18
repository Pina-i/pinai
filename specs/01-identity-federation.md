# Pina'i — Identity, Friends & Federation Backbone

In this architecture, users can be on **different IdPs** (e.g. Alice on `idp.alice.com`, Bob on `idp.bob.com`). Each IdP's PostgreSQL stores its own local users and a *remote actor* cache. So a friend's username can be either **local** or **remote**.

---

### Data model

```sql
-- Local users registered on this IdP instance
CREATE TABLE users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username      TEXT NOT NULL UNIQUE,       -- user input + NanoID suffix, e.g. "alice_xK9mP"
                                            -- used for federation: @alice_xK9mP@idp.alice.com
  display_name  TEXT NOT NULL,              -- set to user input at creation, e.g. "alice"
                                            -- freeform, no uniqueness constraint, shown in UI
  avatar_url    TEXT,                       -- public RustFS URL with `?v=<unix_secs>` cache-bust
                                            -- (avatars bucket is public-read; see § Avatar storage)
  pronouns      TEXT,                       -- closed enum, see CHECK below
  bio           TEXT,                       -- ≤ 190 chars, freeform; enforced server-side
  email         TEXT NOT NULL UNIQUE,       -- used by OIDC
  password_hash TEXT NOT NULL,
  actor_uri     TEXT NOT NULL UNIQUE,       -- e.g. "https://idp.alice.com/users/alice"
  inbox_url     TEXT NOT NULL,              -- e.g. "https://idp.alice.com/users/alice/inbox"
  outbox_url    TEXT NOT NULL,              -- e.g. "https://idp.alice.com/users/alice/outbox"
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT users_pronouns_check
    CHECK (pronouns IS NULL OR pronouns IN ('he', 'she', 'non-binary'))
);

-- Cache of remote users fetched via ActivityPub / WebFinger from other IdP instances
CREATE TABLE remote_actors (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_uri     TEXT NOT NULL UNIQUE,       -- e.g. "https://idp.bob.com/users/bob"
  inbox_url     TEXT,                       -- e.g. "https://idp.bob.com/users/bob/inbox"
                                            -- cached on first WebFinger resolution to avoid repeated lookups
  instance      TEXT NOT NULL,              -- e.g. "idp.bob.com"
  display_name  TEXT,
  avatar_url    TEXT,
  fetched_at    TIMESTAMPTZ NOT NULL DEFAULT now(),  -- used for cache invalidation
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Friends relationships — owner is always local (FK), friend can be local or remote (actor_uri)
CREATE TABLE friendships (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,  -- always local
  friend_actor_uri  TEXT NOT NULL,   -- e.g. "https://idp.bob.com/users/bob" (local or remote)
  friend_avatar_url TEXT,            -- cached to avoid extra S3/RustFS lookup at render time
  status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted')),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE (owner_user_id, friend_actor_uri)
);
```

> **Federated address format**
>
> The canonical address format used throughout the system is `username@domain` (e.g. `alice_xK9mP@idp.alice.com`), **without** a leading `@`. This is produced by `User::federated_address(&self, domain: &str)` on the server side. Clients receive actor URIs (`https://idp.alice.com/users/alice_xK9mP`) in some events and normalise them to `username@domain` via `actorUriToAddress()` before using them as conversation keys.

> **`username` vs `display_name`**
>
> - `username` is the unique internal identifier used for federation and ActivityPub addressing. It is composed of the user-chosen name + a NanoID 5-character suffix appended by the backend at account creation (e.g. `alice_xK9mP`). This guarantees uniqueness per instance with no coordination needed. It is never shown in the UI.
> - `display_name` is the only name shown client-side. It is automatically set by the backend at account creation to the user-chosen part, before the NanoID suffix (e.g. user types `alice` → `display_name = "alice"`). It is freeform, has no uniqueness constraint, and can be changed freely at any time.
>
> Example flow at account creation:
> - User inputs: `alice`
> - Backend sets: `username = "alice_xK9mP"`, `display_name = "alice"`, `actor_uri = "https://idp.alice.com/users/alice_xK9mP"`

---

### Querying the friends list

Using `actor_uri` as the universal key, a JOIN across `users` and `remote_actors` gives the full friends list, whether local or federated:

```sql
SELECT
  COALESCE(u.username,
    split_part(f.friend_actor_uri, '/', -1)) AS username,  -- derived from actor_uri for remote
  COALESCE(u.display_name, ra.display_name)  AS display_name,
  f.friend_avatar_url                        AS avatar_url,
  f.friend_actor_uri,
  COALESCE(ra.instance, 'local')             AS instance
FROM friendships f
LEFT JOIN users u          ON f.friend_actor_uri = u.actor_uri
LEFT JOIN remote_actors ra ON f.friend_actor_uri = ra.actor_uri
WHERE f.owner_user_id = $1     -- pass the caller's local user id
  AND f.status = 'accepted';
```

### Friendship-accept also creates the DM conversation

When a friendship transitions to `accepted` (via `POST /api/friends/:id/accept`, local auto-accept in `friend_request_local`, the local-to-local Follow path in `federation::inbox::handle_follow`, or `handle_accept` for cross-IdP), the accepter's IdP creates the DM conversation in the same logical transaction. The new id flows out two ways:

- **Locally**: the WS `friend_accepted` payload carries it on `FriendshipPayload.conversation_id` (`Option<Uuid>`, absent on `friend_request`/`friend_removed`). Web clients invalidate the `dm-conversations` query on this event so `localDmConvos` populates with the new row immediately.
- **Cross-IdP**: the outbound AP `Accept{Follow}` activity carries it in a non-standard `conversationId` field on the activity body (a sibling of `id`/`type`/`actor`/`object`). The peer IdP's `handle_accept` reads it and calls `conversations::get_or_create_dm_with_id` so both sides persist the row under the same UUID. A pre-refactor peer omits the field; the receiver falls back to `get_or_create_dm`, ending up with a divergent id — exactly matching the pre-refactor state. This is a safe degradation.

The migration `20260512000001_backfill_friendship_conversations.sql` retroactively creates a DM for every accepted friendship that doesn't yet have one (deduplicated by ordering the actor pair lexicographically so the two friendship rows don't each get their own conversation).

---

## 1.5. Profile editing API

The user's editable profile fields (`display_name`, `pronouns`, `bio`) and their
avatar are exposed through two endpoints:

| Endpoint | Body | Notes |
|---|---|---|
| `PATCH /api/profile` | `{ display_name, pronouns?, bio? }` | All three fields sent on every save. `display_name` required & ≤50 chars. `pronouns` ∈ {`he`,`she`,`non-binary`} or `null`. `bio` ≤190 chars; empty clears. Returns the updated `UserinfoResponse`. |
| `PUT /api/avatar` | raw image bytes (`image/jpeg|png|webp|gif`, ≤2 MiB) | Replaces any prior avatar. Stored URL ends in `?v=<unix_secs>` to bypass browser cache on re-upload. |
| `DELETE /api/avatar` | — | Clears the user's avatar. |

After any successful change, `propagate_profile_update(user_id)` is invoked
(see § 2). Pronouns and bio are **local-only today**; only `display_name` and
`avatar_url` federate. Mastodon-style federation of `summary` (bio) and
`attachment[].PropertyValue` (pronouns) is the planned upgrade path.

### Avatar storage

The avatars bucket is **public-read** (`s3:GetObject` for `Principal: *`),
unlike the attachments bucket. The IdP stores the public URL directly on
`users.avatar_url`:

```
{STORAGE_PUBLIC_URL}/avatars/{user_id}.{ext}?v={unix_secs}
```

The query param is appended at upload time. Storage keys are stable per user,
so without `?v` the browser keeps the old bytes after a re-upload — the
version param forces a fresh fetch and propagates verbatim through the AP
`Update{Person}` activity to peer `remote_actors.avatar_url` and
`friendships.friend_avatar_url`.

---

## 2. Real-time profile propagation when a friend updates their profile

Regardless of whether the friend is local or remote, the downstream propagation is always the same. The only difference is *how the update is triggered*.

1. A profile update occurs:
   - **Local friend**: the Msg Backbone updates the `users` table directly and publishes an event to the message broker.
   - **Remote friend**: Bob's IdP sends an ActivityPub `Update` activity to Alice's IdP, which updates `remote_actors` and publishes an event to the broker.

```json
{
  "@context": "https://www.w3.org/ns/activitystreams",
  "type": "Update",
  "actor": "https://idp.bob.com/users/bob",
  "object": {
    "type": "Person",
    "id": "https://idp.bob.com/users/bob",
    "preferredUsername": "new_bob",
    "name": "New Bob Display Name",
    "icon": { "type": "Image", "url": "https://idp.bob.com/avatars/bob.webp" }
  }
}
```

2. The IdP updates `friend_avatar_url` on all matching `friendships` rows.
3. The broker fans out a `friend_profile_updated` event to all users who have that actor as a friend.
4. The WebSocket layer consumes the event from the broker and pushes it to all connected clients:

```json
{
  "event": "friend_profile_updated",
  "actorUri": "https://idp.bob.com/users/bob",
  "displayName": "New Bob",
  "avatarUrl": "https://idp.bob.com/avatars/bob.webp"
}
```

5. Alice's client receives it and updates its local state immediately.

```
Profile update ──▶ IdP (DB + friendships cache) ──▶ Broker ──▶ WebSocket layer ──▶ Alice's client
```

---

### Summary

| Trigger | Transport | Who updates the cache? |
|---|---|---|
| Local profile update | Broker → WebSocket | `users` table + `friendships.friend_avatar_url` |
| Remote profile update | ActivityPub `Update` → Broker → WebSocket | `remote_actors` table + `friendships.friend_avatar_url` |

---

## 3. Message broker strategy

Naively pushing events directly over WebSockets creates several problems:

- Events are lost if the client is temporarily disconnected.
- No catch-up mechanism on reconnect.
- No fan-out to multiple devices (web + desktop).

The solution is a **message broker** as the backbone for durable client-event
delivery. Given Redis is already in the stack for presence/pub-sub,
**Redis Streams** is the pragmatic choice to avoid adding a new infrastructure
dependency.

### Redis transport split

| Channel | Type | Use case |
|---|---|---|
| Presence (online/offline/typing) | Redis pub-sub | Ephemeral — losing an event is acceptable |
| DMs, profile updates, friend requests | Redis Streams | Durable client-side — survives a recipient's disconnect |

Redis pub-sub remains appropriate for presence events since they are high-frequency and inherently transient. Redis Streams handles everything that must survive a recipient disconnect.

> The streams carry **client-facing events** so a reconnecting tab can catch
> up. They are **not** the inter-IdP outbox — outbound ActivityPub delivery
> is covered separately below.

### Federation delivery semantics

Outbound ActivityPub activities are delivered **inline** via `tokio::spawn`
per remote inbox — there is no persistent outbox queue. Every activity we
emit is either time-sensitive (durable retry actively makes it worse) or
idempotent and naturally self-healing through another mechanism:

| Activity | Property | Recovery on delivery failure |
|---|---|---|
| `Create{Note}` (DM) | Time-sensitive | A 24h-late delivery is worthless; sender retries manually if needed (ADR-0001) |
| `Update{Note}` (edit) | Time-sensitive | Same — recipients see the original until they can refetch |
| `Like` / `Undo{Like}` (reaction) | Idempotent | Reconciles on next conversation fetch |
| `Follow` / `Accept` / `Reject` / `Undo{Follow}` | Idempotent, low-frequency | User can re-trigger; relationships are bidirectional |
| `Update{Person}` (profile) | Idempotent | Self-heals via `remote_actors.fetched_at` TTL re-fetch |

Each activity type owns its own reconciliation story (TTL re-fetch, next
user interaction, manual retry), so a missed delivery never produces a
permanently inconsistent state. This avoids the failure modes a generic
queue introduces (silent worker death, queue growth, attempt-counter
overflow, mis-tuned backoff). If a future activity does require durable
retry, that activity earns its own scoped queue at that point — rather
than a one-size-fits-all outbox up front.

### Client reconnect & catch-up

The WebSocket layer becomes a thin delivery mechanism that reads from Redis Streams rather than being the source of truth. On reconnect, the client sends its last received event ID, and the server replays any undelivered stream entries:

```
Client reconnects ──▶ sends last_event_id ──▶ server replays missed entries from Redis Stream
```

This naturally handles multi-device scenarios too: each device maintains its own consumer position in the stream.

### Scaling consideration

Redis Streams is the right starting point. If federation traffic grows significantly, **NATS JetStream** is a better long-term fit — it is designed for exactly this kind of federated, multi-instance messaging topology. Migrating later is straightforward since the broker is behind an abstraction layer in the Msg Backbone.

---
