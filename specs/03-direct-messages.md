# Pina'i — Direct Messages

DMs live on the Msg Backbone (IdP layer). Since Alice and Bob can be on different instances, each IdP stores its own full copy of the conversation (Option 1 — mirrored). Each message is delivered via ActivityPub (`Create` activity wrapping a `Note` object) and persisted on both ends. `activity_uri` is the canonical ActivityPub object ID used to correlate federated copies across instances for edits and deletes.

### Schema

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
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Members of a conversation — local or remote actors
-- left_at IS NULL means the member is still active
CREATE TABLE conversation_members (
  conversation_id  UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  actor_uri        TEXT NOT NULL,             -- local or remote
  joined_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  left_at          TIMESTAMPTZ,               -- NULL = still a member
  PRIMARY KEY (conversation_id, actor_uri)
);

CREATE INDEX idx_conv_members_actor
  ON conversation_members (actor_uri) WHERE left_at IS NULL;

-- Messages — keyed by conversation_id instead of sender/recipient pair
CREATE TABLE direct_messages (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id   UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  sender_actor_uri  TEXT NOT NULL,
  content           TEXT NOT NULL,
  activity_uri      TEXT NOT NULL UNIQUE,     -- e.g. "https://idp.alice.com/activities/uuid"
                                              -- used to correlate federated copies for edits/deletes
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

> **Conversation ID ownership**: the instance that sends the first message generates the UUID and includes it in the `Create{Note}` ActivityPub activity (`context` field). The receiving instance stores it as-is. No coordination needed — one round-trip in the first message suffices to establish the shared ID on both ends.

> **Group name default**: when a group conversation is created, the server sets `name` to the comma-joined `display_name` values of all initial members excluding the creator, e.g. `"Bob, Harry"`. The creator's own name is omitted since the conversation list is always shown from the perspective of the local user. The name is stored as plain text and can be updated freely via `PATCH /api/dm/:conversation_id` (group only).

### Delivery flow

**Local DM** (sender and recipient on the same IdP):

```
Alice types → WS handler persists message
            → publishes JSON event to Redis Streams (broker) for both users
            → hub.send_to_user() pushes WsEvent::NewDm to both Alice and Bob's live connections
```

**Remote DM** (sender and recipient on different IdPs):

```
Alice types → WS handler resolves Bob's inbox_url
                ├─ cache hit:  read from remote_actors.inbox_url (no WebFinger needed)
                └─ cache miss: resolve via WebFinger → upsert into remote_actors (async)
            → persists message (federation_status = 'pending')
            → builds ActivityPub Create{Note} activity
            → delivers to Bob's inbox_url via HTTP Signatures (background task)
            → hub.send_to_user() echoes WsEvent::NewDm to Alice only (Bob is remote)

Bob's IdP ← receives HTTP POST to /users/bob/inbox
          → verifies HTTP Signature
          → persists its own copy of the message
          → hub.send_to_user() pushes WsEvent::NewDm to Bob's live connections
          → broker.publish() writes event to Redis Streams for Bob's catch-up
```

> **Note on `sender_address`**: the `DmPayload.sender_address` field sent over WebSocket contains
> the raw actor URI (e.g. `https://idp.alice.com/users/alice`). The client normalises it to
> `username@domain` format using `actorUriToAddress()` for display purposes.
> The `conversation_id` UUID is the stable key used for all conversation routing — the client
> no longer needs to derive a conversation key from actor URIs.

> **Note on `federation_queue`**: for DMs, ActivityPub delivery is done inline in a background
> `tokio::spawn` task rather than via `federation_queue`. This is sufficient for the current
> implementation. Profile updates and other non-time-critical activities still go through
> `federation_queue` with exponential backoff.

### Pagination — infinite scroll upward

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

The client keeps track of the oldest `(created_at, id)` it has received and passes it as the cursor for the next page request.

---

## 6. DM unread notification tracking

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
WITH ranked_messages AS (
    SELECT
        dm.conversation_id,
        dm.sender_actor_uri,
        dm.content,
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
    -- last message preview (content truncated server-side to 100 chars)
    (SELECT LEFT(rm2.content, 100)
     FROM ranked_messages rm2
     WHERE rm2.conversation_id = c.id AND rm2.rn = 1)
                                                AS last_message_preview,
    (SELECT rm2.sender_actor_uri
     FROM ranked_messages rm2
     WHERE rm2.conversation_id = c.id AND rm2.rn = 1)
                                                AS last_message_sender,
    COUNT(CASE
        WHEN rm.sender_actor_uri != $1
             AND (r.last_read_at IS NULL OR rm.created_at > r.last_read_at)
        THEN 1 ELSE NULL
    END)                                        AS unread_count,
    -- all active members except the caller, as a JSON array
    COALESCE(
        JSON_AGG(
            JSON_BUILD_OBJECT(
                'actorUri',    cm_other.actor_uri,
                'displayName', COALESCE(u.display_name, ra.display_name)
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

Only messages **not sent by the caller** count as unread — this works correctly for both DMs and group conversations. A `NULL` `last_read_at` means the user has never opened that conversation.

The `members` array contains all active participants **except the caller**. The client uses this to:
- **DM** (`kind = 'dm'`): use `members[0].displayName` as the conversation title.
- **Group** (`kind = 'group'`): use `conversations.name` as the title; display `members` list as the subtitle.

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
| `GET /api/dm` | `conversation_id`, `kind`, `name`, `members[]` (actorUri + displayName, excluding caller), `last_message_preview`, `last_message_sender`, `last_message_at`, `unread_count` | Single query — see above. Client derives DM title from `members[0].displayName`; group title from `name` |
| `GET /api/dm/:conversation_id` | messages with `sender_display_name` per row | Display name resolved from `users` or `remote_actors` |
| `POST /api/dm` (response) | `conversation_id`, `kind`, `name`, `sender_display_name` | `conversation_id` created here if first message |
| WS `new_dm` event | `conversation_id`, `kind`, `sender_actor_uri`, `sender_display_name` | Client uses `conversation_id` to route to the right conversation in its local state |

---

## 7. Message reactions & replies

### Reactions

Reactions are stored in a dedicated table linked to a message by its `id`. The `UNIQUE` constraint on `(message_id, reactor_actor_uri, emoji)` enforces that a user can only react once with the same emoji on the same message.

```sql
CREATE TABLE message_reactions (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id        UUID NOT NULL REFERENCES direct_messages(id) ON DELETE CASCADE,
  reactor_actor_uri TEXT NOT NULL,       -- local or remote actor
  emoji             TEXT NOT NULL,       -- e.g. "👍" or a custom emoji identifier
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE (message_id, reactor_actor_uri, emoji)
);
```

To render the reaction bar on a message, reactions are grouped by emoji with a count and a flag indicating whether the current user has reacted:

```sql
SELECT
  emoji,
  COUNT(*)                                    AS count,
  bool_or(reactor_actor_uri = $1)             AS reacted_by_me
FROM message_reactions
WHERE message_id = $2
GROUP BY emoji
ORDER BY count DESC;
```

This produces the classic Discord-style reaction bar: `👍 3 · ❤️ 2` with the current user's reactions highlighted.

#### Federation

A reaction is federated as a `Like` activity pointing to the `activity_uri` of the target message:

```json
{
  "@context": "https://www.w3.org/ns/activitystreams",
  "type": "Like",
  "actor": "https://idp.alice.com/users/alice_xK9mP",
  "object": "https://idp.bob.com/activities/uuid",
  "content": "👍"
}
```

Removing a reaction is federated as an `Undo{Like}` activity.

---

### Replies

Replies are messages that reference another message via a `reply_to_id` self-referential foreign key on `direct_messages` (already included in the schema defined in §5):

```sql
reply_to_id UUID REFERENCES direct_messages(id) ON DELETE SET NULL
```

`ON DELETE SET NULL` is intentional — if the parent message is deleted, the reply becomes a standalone message rather than disappearing with it. This matches the expected behavior: Discord shows "Original message was deleted" in this case.

When fetching a conversation page, a single LEFT JOIN pulls the parent message preview inline — only one level deep, never recursive:

```sql
-- $1 = conversation_id, $2 = cursor created_at, $3 = cursor id
SELECT
  dm.*,
  parent.id                AS reply_to_id,
  parent.content           AS reply_to_content,
  parent.sender_actor_uri  AS reply_to_sender
FROM direct_messages dm
LEFT JOIN direct_messages parent ON dm.reply_to_id = parent.id
WHERE dm.conversation_id = $1
  AND dm.deleted_at IS NULL
  AND (dm.created_at, dm.id) < ($2, $3)
ORDER BY dm.created_at DESC, dm.id DESC
LIMIT 50;
```

The conversation remains a **flat list** with inline reply previews — no recursive thread fetching. Threads (a sub-conversation branching off a message) are a separate product decision that would require a `thread_id` column and a `threads` table, deferred until needed.

#### Federation

A reply is federated as a `Create{Note}` activity where the `Note` object includes an `inReplyTo` field pointing to the parent's `activity_uri`:

```json
{
  "@context": "https://www.w3.org/ns/activitystreams",
  "type": "Create",
  "actor": "https://idp.alice.com/users/alice_xK9mP",
  "object": {
    "type": "Note",
    "id": "https://idp.alice.com/activities/uuid",
    "inReplyTo": "https://idp.bob.com/activities/parent-uuid",
    "content": "Hey, replying to your message!"
  }
}
```

---

### Real-time delivery

Both reactions and replies are delivered via the same broker → WebSocket pipeline as DMs. The WebSocket events are:

```json
// New reaction
{
  "event": "message_reaction_added",
  "messageId": "uuid",
  "reactorActorUri": "https://idp.alice.com/users/alice_xK9mP",
  "emoji": "👍"
}

// Reaction removed
{
  "event": "message_reaction_removed",
  "messageId": "uuid",
  "reactorActorUri": "https://idp.alice.com/users/alice_xK9mP",
  "emoji": "👍"
}

// New reply (same shape as new_dm, with reply fields added)
{
  "event": "new_dm",
  "messageId": "uuid",
  "senderActorUri": "https://idp.alice.com/users/alice_xK9mP",
  "senderDisplayName": "alice",
  "content": "Hey, replying to your message!",
  "replyToId": "parent-uuid",
  "replyToContent": "Original message preview...",
  "replyToSender": "https://idp.bob.com/users/bob_aB3cD",
  "createdAt": "2026-03-20T12:00:00Z"
}
```

---

## 8. Message editing

### REST endpoint

```
PATCH /api/dm/:message_id
Authorization: Bearer <access_token>
Content-Type: application/json

{ "content": "corrected text" }
```

**Authorization**: only the original sender can edit. The `WHERE` clause enforces ownership atomically at the DB level — no separate fetch + check:

```sql
UPDATE direct_messages
SET content = $3, edited_at = now()
WHERE id         = $1
  AND sender_actor_uri = $2
  AND deleted_at IS NULL
RETURNING *;
```

Returns `404` if the message does not exist, is already deleted, or belongs to a different sender. Content must be 1–4096 characters.

### Real-time delivery

After a successful update the server pushes a `message_edited` WebSocket event to both parties:

```json
{
  "event": "message_edited",
  "messageId": "uuid",
  "newContent": "corrected text",
  "editedAt": "2026-03-20T12:05:00Z"
}
```

- **Local recipient**: pushed via `hub.send_to_user()` + published to Redis Streams for catch-up.
- **Sender (multi-device)**: echoed via `hub.send_to_user()`.
- **Remote recipient**: an `Update{Note}` ActivityPub activity is delivered to the recipient's IdP inbox in a background `tokio::spawn`. The remote IdP applies the edit via `edit_message_by_activity_uri` (matches by `activity_uri` instead of `id`) and then pushes `message_edited` to the remote recipient over their local WS.

### Federation — `Update{Note}`

```json
{
  "@context": "https://www.w3.org/ns/activitystreams",
  "type": "Update",
  "id": "https://idp.alice.com/users/alice_xK9mP/activities/uuid",
  "actor": "https://idp.alice.com/users/alice_xK9mP",
  "object": {
    "type": "Note",
    "id": "https://idp.alice.com/activities/original-uuid",
    "content": "corrected text"
  }
}
```

The `object.id` is the original `activity_uri` stored in `direct_messages.activity_uri`, which is the stable cross-instance identifier used to correlate the two mirrored copies of the message.

---

