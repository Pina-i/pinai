# Pina'i — Direct messages

DMs live on the Msg Backbone (IdP layer). Since Alice and Bob can be on different instances, each IdP stores its own full copy of the conversation (Option 1 — mirrored). Each message is delivered via ActivityPub (`Create` activity wrapping a `Note` object) and persisted on both ends. `activity_uri` is the canonical ActivityPub object ID used to correlate federated copies across instances for edits and deletes.

> **End-to-end encryption (Phase 3 onward).** Every message body is an
> opaque MLS ciphertext on the wire and at rest — `direct_messages.content`
> was dropped, and `mls_ciphertext BYTEA NOT NULL` took its place. Reactions
> are no longer a server-side table; they're MLS application messages of
> `kind = "reaction"` inside the encrypted body. Reply previews
> (`reply_to_content`, `reply_to_sender`) likewise moved into the
> encrypted body — `reply_to_id` stays plaintext for thread routing.
> See [`e2ee.md`](./e2ee.md) for the protocol-level design.

## 1. Schema

Conversations are anchored by a stable UUID that never changes regardless of participant count. This is the single key used for message storage, typing channels, unread tracking, and federation.

```sql
-- Conversation anchor — one row per conversation, DM or group
CREATE TABLE conversations (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  kind         TEXT NOT NULL DEFAULT 'dm'
                 CHECK (kind IN ('dm', 'group')),
  name         TEXT,                          -- NULL for DMs (title derived client-side from
                                              -- the other member's display_name)
                                              -- Required for groups; defaults at creation to
                                              -- the joined display_names of all initial members
                                              -- e.g. "Alice, Bob, Harry" — editable afterwards
  name_at      TIMESTAMPTZ NOT NULL DEFAULT now(),  -- when the name was set, wherever that was
                                              -- (identity-provider/specs/groups.md § 7)
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  dm_low       TEXT,                          -- a DM's pair of actor URIs, the smaller first;
  dm_high      TEXT,                          -- NULL for groups
  CHECK ((dm_low IS NULL AND dm_high IS NULL) OR (kind = 'dm' AND dm_low < dm_high))
);

-- One DM per pair: concurrent first messages or accepts share it
CREATE UNIQUE INDEX conversations_dm_pair ON conversations (dm_low, dm_high)
  WHERE dm_low IS NOT NULL;

-- Members of a conversation — local or remote actors
-- left_at IS NULL means the member is still active
CREATE TABLE conversation_members (
  conversation_id  UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  actor_uri        TEXT NOT NULL,             -- local or remote
  joined_at        TIMESTAMPTZ NOT NULL DEFAULT now(),  -- the latest join or rejoin
  left_at          TIMESTAMPTZ,               -- NULL = still a member
  role             TEXT NOT NULL DEFAULT 'member'
                     CHECK (role IN ('member', 'admin')),  -- group management gate; ignored for DMs
  role_at          TIMESTAMPTZ NOT NULL DEFAULT now(),  -- when the role was set
  -- The three stamps are set where a change is made, and copied as received elsewhere
  -- (identity-provider/specs/groups.md § 7).
  removed_by       TEXT,                      -- the admin who removed them; NULL for a leave
  departure_view   JSONB,                     -- a removal's { name, members[] }: the group as
                                              -- it stood, for the removed member's list
  dismissed_at     TIMESTAMPTZ,               -- they cleared it from their list
  -- Each departure sets these three anew (identity-provider/specs/groups.md § 3).
  PRIMARY KEY (conversation_id, actor_uri)
);

CREATE INDEX idx_conv_members_actor
  ON conversation_members (actor_uri) WHERE left_at IS NULL;

-- Messages — keyed by conversation_id instead of sender/recipient pair.
-- Body is opaque MLS ciphertext; the server never decrypts.
--
-- `id` is derived from the trailing UUID of `activity_uri`
-- (`<issuer>/users/<username>/activities/<uuid>`), NOT freshly
-- generated. This bridges row ids across IdPs in cross-server DMs:
-- both the sender's IdP and the recipient's IdP see the same
-- activity_uri, so both compute the same row id. Without this,
-- payloads that reference a message by its server-side id (reactions'
-- `target_message_id` inside the encrypted MLS body, edits' PATCH
-- url, replies' `reply_to_id` as observed by the client) silently
-- fail on the receiver because each IdP would have picked its own
-- random UUID. `DEFAULT gen_random_uuid()` stays as a fallback for
-- legacy / malformed URIs that fail the extraction.
CREATE TABLE direct_messages (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id   UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  sender_actor_uri  TEXT NOT NULL,
  mls_ciphertext    BYTEA NOT NULL,           -- TLS-encoded MLSMessage
  activity_uri      TEXT NOT NULL UNIQUE,     -- e.g. "https://idp.alice.com/users/alice/activities/uuid"
                                              -- used to correlate federated copies for edits/deletes
                                              -- AND as the source for `id` (see above)
  federation_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (federation_status IN ('pending', 'delivered', 'failed')),
  reply_to_id       UUID REFERENCES direct_messages(id) ON DELETE SET NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  edited_at         TIMESTAMPTZ,
  deleted_at        TIMESTAMPTZ               -- soft delete, NULL = not deleted
);

-- Keyset pagination index
CREATE INDEX idx_dm_conversation_cursor
  ON direct_messages (conversation_id, created_at DESC, id DESC);
```

> **Conversation ID ownership**: DM `conversation_id` is decided at **friendship-accept time** by the accepter's IdP, not by the first-message sender, and both IdPs of a cross-IdP pair file the DM under the same id — see `identity-provider/specs/social.md § 1`, Friendship-accept also creates the DM conversation. Clients always read `dmData.id` from `localDmConvos` and pin it on `POST /api/dm`; the WS `dm-conversations` query is invalidated on `friend_accepted` so the new row appears immediately.

> **One DM per pair, and whose id**: a pair of actors has exactly one DM — its pair is a unique key, so two concurrent first messages or accepts open the same one. An id a client pins (`POST /api/dm`'s `conversation_id`, the MLS group it already bootstrapped) or a peer advertises (a Note's `context`, an Accept's `conversationId`) is used only when the pair has no DM yet, and only if it names no conversation, or a DM none but the pair ever belonged to. Any other id — a group's, another pair's DM — is ignored and the DM opens under a fresh one: honouring it would add the pair to someone else's conversation.

## 2. Delivery flow

Whether the sender may reach the recipient is decided first, before any conversation is opened or
message stored: a sender who blocked the recipient is refused with 403 `You blocked this user`, and
a local recipient who doesn't admit the sender — a block, or their contact setting — with 403
`Message could not be delivered`. A remote recipient's own IdP decides on its side, with the same
refusal (`identity-provider/specs/social.md § 2`).

**Local DM** (sender and recipient on the same IdP):

```
Alice types → WS handler persists message
            → publishes JSON event to Redis Streams (broker) for both users
            → pushes `new_dm` to both Alice's and Bob's live connections
```

**Remote DM** (sender and recipient on different IdPs):

```
Alice types → WS handler resolves Bob's inbox_url
                ├─ cache hit:  read from remote_actors.inbox_url (no WebFinger needed)
                └─ cache miss: resolve via WebFinger → upsert into remote_actors (async)
            → persists message (federation_status = 'pending')
            → echoes `new_dm` to Alice only (Bob is remote)
            → builds ActivityPub Create{Note} activity
            → delivers to Bob's inbox_url via HTTP Signatures (background task)
            → records the outcome: federation_status = 'delivered' | 'failed'
            → on failure, pushes `dm_delivery_failed` to Alice

Bob's IdP ← receives HTTP POST to /users/bob/inbox
          → verifies HTTP Signature
          → persists its own copy of the message (a redelivered activity — same
            activity URI — is answered 202 without a second copy or event)
          → pushes `new_dm` to Bob's live connections
          → writes the event to Bob's Redis stream, for his catch-up
```

> **Note on `sender_address`**: the `DmPayload.sender_address` field sent over WebSocket is the
> sender's `username@domain`, for local and delivered messages alike — the actor URI only when
> the sender's URI is not of the `…/users/{username}` form. `kind` is the conversation's (`dm` or
> `group`), delivered messages included. The `conversation_id` UUID is the stable key used for
> all conversation routing — the client never derives a conversation key from actor URIs.

> **Note on outbound delivery**: ActivityPub delivery for DMs (and every
> other activity type) runs in a background `tokio::spawn`, best-effort.
> No persistent outbox queue — see `identity-provider/specs/event-delivery.md § 2`
> for the rationale and the per-activity recovery story. A 1:1 DM's story
> is below.
## 3. Delivery failure

The sender's IdP answers `POST /api/dm` (or processes `send_dm`) as soon as the
message is stored, before it contacts the recipient's IdP. Delivery happens
afterwards, once, and is never retried by the IdP. So a delivery failure cannot
be an error on the send. Instead the IdP records it and tells the sender, and
the sender decides whether to send the message again.

- **Outcome on the row.** The delivery task (`application::messaging::DeliverDirectMessage`,
  shared by both send paths) sets `direct_messages.federation_status` to
  `'delivered'` or `'failed'`. A peer that is unreachable, times out, or answers
  non-2xx counts as `'failed'`. Local DMs and group messages keep `'pending'`:
  a local DM is never delivered over federation, and a group message goes to
  several inboxes, which one status cannot describe.
- **`dm_delivery_failed`.** On failure the IdP pushes this event to the
  sender's live connections:

  ```json
  { "type": "dm_delivery_failed",
    "data": { "message_id": "uuid", "conversation_id": "uuid" } }
  ```

- **Ordering.** The sender's `new_dm` echo is sent *before* delivery starts,
  and both travel through the same per-connection channel. So the echo, which
  carries the sender's `client_id` and turns the optimistic row into the
  server row, always arrives first, and `dm_delivery_failed` always finds the
  row it names.
- **Retry is a new message.** The failed row stays in the sender's history as
  the record of the attempt. Sending it again re-encrypts the plaintext at the
  current MLS ratchet position and posts it as a new message, so the retry is
  always decryptable for the recipient. The original row is never re-delivered.
- **Attachments move.** An attachment linked to one of the sender's own
  `'failed'` messages may be named again in `attachment_ids`. The new message
  takes the rows over, in the transaction that stores it, with the same
  ids, so the `AttachmentBlobKey.id`s in the new encrypted body stay valid and
  nothing is uploaded again. The recipient's IdP has never seen those ids,
  because the failed activity never reached it.

```mermaid
sequenceDiagram
    participant C as Alice's client
    participant A as Alice's IdP
    participant B as Bob's IdP (down)

    C->>A: POST /api/dm (client_id)
    A->>A: persist row (federation_status = pending)
    A-->>C: WS new_dm (client_id) — optimistic row becomes the server row
    A-->>C: 201 Created
    A->>B: signed Create{Note}
    B--xA: connection refused
    A->>A: federation_status = failed
    A-->>C: WS dm_delivery_failed (message_id)
    Note over C: row shows ⚠ "not delivered" + Retry
    C->>A: Retry → POST /api/dm (new ciphertext, same attachment_ids)
    A->>B: signed Create{Note}
    B-->>A: 202 Accepted
    A->>A: federation_status = delivered
```

Scenarios:

| Scenario | What the sender sees |
|---|---|
| Recipient's IdP is down while the sender is online | The message turns undelivered within the delivery timeout; Retry sends it as a new message at the bottom of the conversation, and the original keeps its warning without a Retry button |
| The sender's tab closed before the failure landed | Next time the conversation loads, history carries `federation_status: "failed"` and the client applies it over its cached row |
| The failed message had attachments | Retry reuses the same attachment ids; the server moves them to the new message |
| The failure reaches another of the sender's devices, which never held the plaintext | The row turns undelivered there too, but its Retry is disabled — only a device holding the plaintext can re-encrypt it |
| The sender's IdP stopped before the delivery ended (a crash, a restart) | The row would stay `pending` for good: a sweep, every minute, marks `failed` each DM to another IdP still `pending` five minutes after it was stored — well past the delivery timeout — and pushes `dm_delivery_failed` to its sender |
| The recipient doesn't admit the sender — a block, or their contact setting (`identity-provider/specs/social.md § 2`) | Their IdP refuses the message with 403, so it turns undelivered exactly as for an unreachable IdP, and so does every retry |
| The recipient's IdP persisted the message but answered non-2xx (or too late) | The row is marked failed although the recipient has it; a retry then gives the recipient a duplicate, whose attachment rows stay with the first copy (same ids, so the recipient's inbox skips them). The sender's IdP cannot tell this apart from a lost delivery |

## 4. Pagination — infinite scroll upward

Keyset pagination on `(created_at, id)` is used instead of `LIMIT/OFFSET` to avoid drift when new messages arrive during scrolling.

```sql
-- Initial load (most recent messages)
-- $1 = conversation_id UUID
SELECT * FROM direct_messages
WHERE conversation_id = $1
  AND deleted_at IS NULL
ORDER BY created_at DESC, id DESC
LIMIT 50;

-- Subsequent pages (scroll up: fetch older messages)
-- $2 = oldest created_at from previous page, $3 = oldest id from previous page
SELECT * FROM direct_messages
WHERE conversation_id = $1
  AND deleted_at IS NULL
  AND (created_at, id) < ($2, $3)
ORDER BY created_at DESC, id DESC
LIMIT 50;
```

With `include=events`, a group's history is its **timeline**: its messages and its changes
(`identity-provider/specs/groups.md § 6`) in one keyset order on `(created_at, id)`, each item
tagged `kind: "message"` or `kind: "event"`; the cursor names the oldest item read, of either
kind. Without it, the history holds messages only, still tagged.

A member removed from a group reads its history up to their removal (`created_at <= left_at`), until they clear the group (`identity-provider/specs/groups.md § 3`); anyone else outside the conversation is answered 404.

The client keeps track of the oldest `(created_at, id)` it has received and passes it as the cursor for the next page request: `GET /api/dm/:conversation_id?cursor_created_at=<RFC 3339>&cursor_id=<uuid>&limit=<≤ 100>`, `cursor_created_at` exactly as the message's `created_at` was returned. Both halves are needed — either alone reads the first page, which also marks the conversation read.

## 5. DM unread notification tracking

When a user is offline or viewing a different conversation, incoming DMs must not be silently lost — they need to surface as unread counts when the user returns.

### Schema

```sql
-- Tracks the last time a user opened each conversation.
-- Used to compute per-conversation unread counts on login / reconnect.
CREATE TABLE conversation_reads (
  user_id          UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  conversation_id  UUID        NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  last_read_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, conversation_id)
);
```

### Unread count query

Computed inline in the `GET /api/dm` (list conversations) response via a SQL CTE + LEFT JOIN:

```sql
-- $1 = caller actor_uri, $2 = caller user_id (local UUID)
-- After Phase 3 there's no plaintext preview — message bodies are opaque
-- ciphertext. The client maintains its own preview cache by replaying its
-- decrypted MLS stream. We still expose `last_message_sender` (the
-- sender_actor_uri of the most recent message) since that's plaintext.
WITH ranked_messages AS (
    SELECT
        dm.conversation_id,
        dm.sender_actor_uri,
        dm.created_at,
        ROW_NUMBER() OVER (
            PARTITION BY dm.conversation_id
            ORDER BY dm.created_at DESC, dm.id DESC
        ) AS rn
    FROM direct_messages dm
    WHERE dm.deleted_at IS NULL
)
SELECT
    c.id                                        AS conversation_id,
    c.kind,
    c.name,
    cm_self.conversation_id                     AS _check,
    MAX(rm.created_at)                          AS last_message_at,
    (SELECT rm2.sender_actor_uri
     FROM ranked_messages rm2
     WHERE rm2.conversation_id = c.id AND rm2.rn = 1)
                                                AS last_message_sender,
    COUNT(CASE
        WHEN rm.sender_actor_uri != $1
             AND (r.last_read_at IS NULL OR rm.created_at > r.last_read_at)
             AND NOT EXISTS (SELECT 1 FROM user_blocks b
                             WHERE b.owner_user_id = $2
                               AND b.blocked_actor_uri = rm.sender_actor_uri)
        THEN 1 ELSE NULL
    END)                                        AS unread_count,
    -- all active members except the caller, as a JSON array
    COALESCE(
        JSON_AGG(
            JSON_BUILD_OBJECT(
                'actorUri',    cm_other.actor_uri,
                'displayName', COALESCE(u.display_name, ra.display_name),
                'avatarUrl',   COALESCE(u.avatar_url, ra.avatar_url)
            )
        ) FILTER (WHERE cm_other.actor_uri != $1),
        '[]'
    )                                           AS members
FROM conversation_members cm_self
JOIN conversations c
    ON c.id = cm_self.conversation_id
JOIN conversation_members cm_other
    ON cm_other.conversation_id = c.id
   AND cm_other.left_at IS NULL
LEFT JOIN users u
    ON u.actor_uri = cm_other.actor_uri
LEFT JOIN remote_actors ra
    ON ra.actor_uri = cm_other.actor_uri
LEFT JOIN ranked_messages rm
    ON rm.conversation_id = c.id
LEFT JOIN conversation_reads r
    ON r.user_id = $2 AND r.conversation_id = c.id
WHERE cm_self.actor_uri = $1
  AND cm_self.left_at IS NULL
GROUP BY c.id, c.kind, c.name, cm_self.conversation_id
ORDER BY last_message_at DESC NULLS LAST;
```

Only messages **not sent by the caller** count as unread — this works correctly for both DMs and group conversations. Messages from actors the caller blocked don't count either, so a group shared with someone blocked doesn't light up for their messages (`identity-provider/specs/social.md § 2`). A `NULL` `last_read_at` means the user has never opened that conversation.

The `members` array contains all active participants **except the caller**. The client uses this to:
- **DM** (`kind = 'dm'`): use `members[0].displayName` as the conversation title.
- **Group** (`kind = 'group'`): use `conversations.name` as the title; display `members` list as the subtitle.

The list also holds each group the caller was **removed** from and hasn't cleared, with
`removed_at` set (it is `null` everywhere else). Such a row is the group as it stood at the
removal — `name` and `members` from `departure_view`, `last_message_at` and
`last_message_sender` from the messages up to `left_at` — with `unread_count` 0:

```sql
SELECT c.id AS conversation_id, c.kind,
       cm.departure_view->>'name' AS name,
       (SELECT MAX(dm.created_at) FROM direct_messages dm
        WHERE dm.conversation_id = c.id AND dm.deleted_at IS NULL
          AND dm.created_at <= cm.left_at) AS last_message_at,
       (SELECT dm.sender_actor_uri FROM direct_messages dm
        WHERE dm.conversation_id = c.id AND dm.deleted_at IS NULL
          AND dm.created_at <= cm.left_at
        ORDER BY dm.created_at DESC, dm.id DESC LIMIT 1) AS last_message_sender,
       0 AS unread_count,
       COALESCE(cm.departure_view->'members', '[]') AS members,
       cm.left_at AS removed_at
FROM conversation_members cm
JOIN conversations c ON c.id = cm.conversation_id
WHERE cm.actor_uri = $1 AND cm.left_at IS NOT NULL
  AND cm.removed_by IS NOT NULL AND cm.dismissed_at IS NULL;
```

Both lists are merged, the most recently active first.

### Mark-as-read

`GET /api/dm/:conversation_id` (conversation history, initial page only — no cursor) fires a background upsert:

```sql
INSERT INTO conversation_reads (user_id, conversation_id, last_read_at)
VALUES ($user_id, $conversation_id, NOW())
ON CONFLICT (user_id, conversation_id) DO UPDATE SET last_read_at = NOW();
```

This runs in a `tokio::spawn` so it never blocks the response.

### End-to-end flow

```
Bob logs in
  → GET /api/dm returns conversations with unread_count per conversation
  → client seeds its in-memory unread store from the response
  → sidebar shows badges immediately

Alice sends a DM while Bob is connected but on a different page
  → Bob's WS receives new_dm event
  → client checks active conversation: not this one → increments unread counter + plays sound
  → badge appears on Alice's conversation in Bob's sidebar

Bob clicks Alice's conversation
  → GET /api/dm/:conversation_id called (initial page, no cursor)
  → server upserts last_read_at = NOW() in background
  → client clears the in-memory unread counter for that conversation
  → badge disappears
```

### DM API response — display names

All DM API responses include resolved display names to avoid requiring clients to do additional lookups:

| Endpoint | Fields returned | Notes |
|---|---|---|
| `GET /api/dm` | `conversation_id`, `kind`, `name`, `members[]` (`actorUri` + `displayName` + `avatarUrl`, excluding caller), `last_message_sender`, `last_message_at`, `unread_count` | Single query — see above. Client derives DM title from `members[0].displayName`, avatar from `members[0].avatarUrl`. Plaintext preview is gone with E2EE — client computes one from the decrypted MLS stream |
| `GET /api/dm/:conversation_id` | messages with `sender_display_name`, `mls_ciphertext` (base64), `attachments[]` per row | Display name resolved from `users` or `remote_actors`; ciphertext is opaque; attachments resolved from `message_attachments` |
| `POST /api/dm` | Bearer; body `{ recipient_address, mls_ciphertext: <base64>, reply_to_id?, attachment_ids[], conversation_id?, client_id? }` | `mls_ciphertext` is mandatory, non-empty and at most 64 KiB decoded — on every path: REST, WebSocket `send_dm`, group sends, edits, and what the inbox receives. `client_id` is echoed on the sender's own `new_dm` (see below) |
| WS `new_dm` event | `conversation_id`, `kind`, `sender_actor_uri`, `sender_display_name`, `mls_ciphertext` (base64), `attachments[]` | Client uses `conversation_id` to route, then decrypts `mls_ciphertext` to recover the application message. WS `send_dm` shortcut path doesn't carry `attachment_ids` — anything with attachments must use REST `POST /api/dm` |

### Optimistic-send reconciliation (`client_id`)

When the client sends a DM — over WebSocket (`send_dm`) or REST (`POST /api/dm`) — it MAY include an opaque `client_id` correlation token. The server echoes that token back **only on the sender's own `new_dm`** event (never on the recipient's), so the client can swap its optimistic placeholder for the persisted message rather than appending a duplicate. Recipients never see another user's `client_id`.

On the REST path the echo and the HTTP response race; whichever lands first reconciles the row and the other is a no-op. Reconciling from the echo is what lets a `dm_delivery_failed` find the row (see § 3), so the echo carries everything the optimistic row held, attachment keys included.

Own echoes without a `client_id` — group sends (`POST /api/groups/:id/messages` doesn't take one) and broker replays — are a no-op, except that they heal a `"sending"` or `"failed"` row forward to `"sent"` via `message_id`: the "REST succeeded but the response was lost" edge.

### Send status indicator (client-side)

Clients render a small status icon next to each own-message timestamp, driven by an optional `status` field on the rendered `Message` model:

| `status` | When | Render |
|---|---|---|
| `"sending"` | Optimistic push, network in flight | Clock icon |
| `"sent"` | Server returned 201 / WS echo with matching `client_id` arrived | Check icon, auto-hides ~3 s after the transition |
| `"failed"` | Caught error in encrypt / `POST /api/dm` / WS-send — the IdP never accepted the message | Warning icon + retry icon-button |
| `"undelivered"` | `dm_delivery_failed`, or history reporting `federation_status: "failed"` — the IdP stored the message but couldn't reach the recipient's IdP | Warning icon + retry icon-button, hidden once the message was sent again |

The status lives on the client's persisted `Message`; the server's side of it is `federation_status`, which only ever moves a row to `"undelivered"` (`applyFederationStatus` in `@pinai/domain/models/dm`). The two failure states retry differently:

- **`"failed"`** retries in place: the same optimistic row is sent again.
- **`"undelivered"`** retries as a new message, pushed at the bottom of the conversation; the original stays with its warning and is marked `resent`, which hides its retry button so the content can't be sent twice by accident.

Both rebuild the send from the cached message when the in-memory send intent is gone (after a reload, or once the IdP accepted the message): plaintext, reply target, and attachment keys, whose ids are the attachment ids. The retry button is disabled only on a device that never held the plaintext — one that learned of the message from another device's echo.

## 6. Replies & reactions

### Reactions

Reactions are **MLS application messages** of `kind = "reaction"` inside the encrypted body — there is no server-side reaction state. Each client maintains its own reaction bar for a conversation by replaying its decrypted MLS stream and folding `{ target_message_id, emoji, op: "add"|"remove" }` operations.

The `message_reactions` table was dropped in Phase 3. The `Like` / `Undo{Like}` AP handlers were removed from the inbox; peer IdPs that try to send a `Like` for an MLS-era message see it silently dropped with a warning.

### Replies

Replies still reference the parent via the server-visible `reply_to_id` self-FK on `direct_messages`. The server uses it for thread routing and the soft-delete cascade rule (`ON DELETE SET NULL` — Discord-style "Original message was deleted").

The **preview** (parent body excerpt + sender display name) is no longer fetched server-side — it would leak plaintext from the parent's encrypted body. Instead, the sender includes a `kind = "reply_meta"` application message piggy-backed on the reply itself: `{ target_message_id, preview_text, preview_sender }`. Recipients render the preview from the decrypted body.

```sql
-- The conversation history query no longer joins `parent.content` /
-- `parent.sender_actor_uri`. `reply_to_id` flows through plaintext.
SELECT * FROM direct_messages
WHERE conversation_id = $1
  AND deleted_at IS NULL
  AND (created_at, id) < ($2, $3)
ORDER BY created_at DESC, id DESC
LIMIT 50;
```

A reply names a message of **its own conversation**. `POST /api/dm` and `POST /api/groups/:id/messages` answer 404 `Parent message not found` for a parent that is unknown or belongs to another conversation; an inbound `inReplyTo` naming one is dropped, and the message is stored unthreaded.

The conversation remains a **flat list** — no recursive thread fetching. Threads (a sub-conversation branching off a message) would require a separate `thread_id` column + table, deferred until needed.

#### Federation

A reply is federated as a `Create{Note}` with the same MLS envelope as a regular DM, plus an `inReplyTo` field pointing to the parent's `activity_uri`:

```json
{
  "@context": "https://www.w3.org/ns/activitystreams",
  "type": "Create",
  "actor": "https://idp.alice.com/users/alice_xK9mP",
  "object": {
    "type": "Note",
    "id": "https://idp.alice.com/users/alice_xK9mP/activities/<uuid>",
    "mediaType": "application/mls",
    "mlsKind": "application",
    "context": "<conversation_id>",
    "inReplyTo": "https://idp.bob.com/users/bob_aB3cD/activities/parent-uuid",
    "content": "<base64(MLSMessage carrying the reply text + reply_meta)>"
  }
}
```

### Real-time delivery

```json
// new_dm — every DM, reply, reaction, edit goes through this same shape
{
  "event": "new_dm",
  "messageId": "uuid",
  "conversationId": "uuid",
  "senderActorUri": "https://idp.alice.com/users/alice_xK9mP",
  "senderDisplayName": "alice",
  "mlsCiphertext": "<base64(MLSMessage)>",
  "replyToId": "parent-uuid",
  "createdAt": "2026-03-20T12:00:00Z"
}
```

Reactions are *invisible* on the wire — they look exactly like text DMs. The client decrypts and inspects the application-message `kind` to route the body into its reaction bar instead of its message list.

## 7. Message editing

### REST endpoint

```
PATCH /api/dm/:message_id/edit
Authorization: Bearer <access_token>
Content-Type: application/json

{ "mls_ciphertext": "<base64(new MLSMessage)>" }
```

**Authorization**: only the original sender can edit, and in a 1:1 only while they may still write to the other member — an edit is a message there, refused as a new one would be: 403 `You blocked this user`, or 403 `Message could not be delivered` (`identity-provider/specs/social.md § 2`). Edits in a group are never checked. The `WHERE` clause enforces ownership atomically at the DB level:

```sql
UPDATE direct_messages
SET mls_ciphertext = $3, edited_at = now()
WHERE id         = $1
  AND sender_actor_uri = $2
  AND deleted_at IS NULL
RETURNING *;
```

Returns `404` if the message does not exist, is already deleted, or belongs to a different sender. The new content lives entirely inside the new `mls_ciphertext` blob; the server stamps `edited_at` for ordering but stays opaque to what changed.

### Real-time delivery

After a successful update the server pushes a `message_edited` WS event to both parties:

```json
{
  "event": "message_edited",
  "messageId": "uuid",
  "newMlsCiphertext": "<base64(new MLSMessage)>",
  "editedAt": "2026-03-20T12:05:00Z"
}
```

- **Local recipient**: pushed via `hub.send_to_user()` + published to Redis Streams for catch-up.
- **Sender (multi-device)**: echoed via `hub.send_to_user()`.
- **Remote recipient**: an `Update{Note}` ActivityPub activity carrying the new ciphertext is delivered to the recipient's IdP inbox in a background `tokio::spawn`. The remote IdP applies the edit via `edit_message_by_activity_uri` (matches by `activity_uri` instead of `id`) and then pushes `message_edited` to the remote recipient over their local WS. In a 1:1, a recipient who doesn't admit the sender refuses it with 403, and nothing changes there.

### Federation — `Update{Note}` (MLS)

```json
{
  "@context": "https://www.w3.org/ns/activitystreams",
  "type": "Update",
  "id": "https://idp.alice.com/users/alice_xK9mP/activities/<uuid>",
  "actor": "https://idp.alice.com/users/alice_xK9mP",
  "object": {
    "type": "Note",
    "id": "https://idp.alice.com/users/alice_xK9mP/activities/original-uuid",
    "mediaType": "application/mls",
    "mlsKind": "edit",
    "context": "<conversation_id>",
    "content": "<base64(new MLSMessage)>"
  }
}
```

The `object.id` is the original `activity_uri` stored in `direct_messages.activity_uri`, which is the stable cross-instance identifier used to correlate the two mirrored copies of the message. The receiving inbox rejects any `Update{Note}` without `mediaType: application/mls` — peers must run an MLS-capable build.
