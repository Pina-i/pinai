# Friendship creates the DM conversation — design

**Date:** 2026-05-12
**Scope:** Backend (identity-provider Rust) + client (web-client TS). Touches: friend-accept handler, AP Accept{Follow} envelope, AP inbox, one migration, conversation-page viewmodel, spec docs.

## Why

Today a DM `conversation_id` is minted at **first-message-send** time by whichever client sends first. Every recent papercut traces back to this:

- The route param is the recipient's address (`username@host`), not a UUID. The viewmodel has to disambiguate "haven't sent yet" from "have a conversation_id" using a regex (`UUID_RE.test(conversationKey)`).
- `pendingFirstMessageConvId` exists because the freshly-minted UUID needs to be visible to the render path *before* `localDmConvos` refreshes.
- Cross-IdP needs id bridging at the message and attachment level because the conversation_id was minted unilaterally and has to travel through the AP envelope.
- The race the user just hit: after a reload, if the user clicks Send before `useLoadDmConversations` resolves, `dmData` is undefined → `isFirstMessage` is *wrongly* true → a fresh UUID is minted, a parallel MLS group is bootstrapped, and the server's `find_dm_between` reuses the existing conversation under a different id. Receiver can't decrypt, sender's view points at a fictional conversation.

Each fix-on-top makes the system more correct but more brittle. The root cause is that **the moment a logical conversation starts is the friendship accept, not the first message**.

## The change

Move conversation creation to friendship-accept. The `conversation_id` is decided once, at that moment, by the accepting IdP, and is communicated to the other IdP via the AP `Accept{Follow}` activity. Both clients learn the id as soon as `localDmConvos` refreshes after the WS `friend_accepted` event — which already happens, so the race window collapses.

## Server changes (identity-provider)

### Migration

A new migration `2026XXXXXXXX_backfill_friendship_conversations.sql`:

```sql
-- For every accepted friendship that doesn't yet have a DM conversation
-- between the owner and the friend, create one. Idempotent — re-running
-- is safe because `find_dm_between` short-circuits.
INSERT INTO conversations (id, kind, name)
SELECT gen_random_uuid(), 'dm', NULL
FROM friendships f
JOIN users owner ON owner.id = f.owner_user_id
WHERE f.status = 'accepted'
  AND owner.actor_uri IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM conversation_members cm1
      JOIN conversation_members cm2
          ON cm2.conversation_id = cm1.conversation_id
         AND cm2.actor_uri = f.friend_actor_uri
         AND cm2.left_at IS NULL
      JOIN conversations c
          ON c.id = cm1.conversation_id
         AND c.kind = 'dm'
      WHERE cm1.actor_uri = owner.actor_uri
        AND cm1.left_at IS NULL
  )
RETURNING id;
```

Plus a follow-up `INSERT INTO conversation_members` for both sides. (Actually the cleanest implementation is a one-shot Rust migration script or a CTE — the SQL above is illustrative.)

No schema change to the `friendships` table. The link friendship↔conversation is implicit (both members of one DM); `find_dm_between` already serves the lookup.

### `social::handlers::accept_friendship` (local user accepting)

After `set_status('accepted')`, in the same transaction:

1. `let (conversation_id, _) = conversations::get_or_create_dm(state.pool, caller_actor_uri, &friendship.friend_actor_uri).await?;`
   - Idempotent: reuses an existing DM if there is one (e.g., refriend after prior unfriend).

2. **Local friend**: include `conversation_id` in the `WsEvent::FriendAccepted` payload (extend the payload type with `conversation_id: Uuid`). Receiving client invalidates its `dm-conversations` query — the new conversation appears in `localDmConvos`.

3. **Remote friend**: include `conversationId` in the outbound AP `Accept{Follow}` activity body. Use the same post-build-injection pattern the codebase already uses for `inReplyTo`:

   ```rust
   let mut activity_json = serde_json::to_value(&accept)?;
   if let Some(obj) = activity_json.as_object_mut() {
       obj.insert("conversationId".to_string(), serde_json::Value::String(conversation_id.to_string()));
   }
   ```

   The receiving IdP reads this key and creates its own row with the same id.

### `federation::inbox::handle_accept` (remote friend accepting)

After `set_status('accepted')`, read the `conversationId` from the activity body. If present, `conversations::get_or_create_dm_with_id(state.pool, conv_id, owner.actor_uri, accepter_uri)`. Same idempotent semantics.

Also extend the WS `FriendAccepted` payload (here too) with the conversation_id.

If the field is missing (older peer IdP), fall back to `get_or_create_dm` so the local-side conversation still gets created. Both sides agreeing on the id requires the field, but unilateral creation is a safe degradation — they're just at the pre-refactor state.

### `messaging::handlers::handle_send_dm` — no change

The handler already calls `get_or_create_dm_with_id` when the client pins a `conversation_id`. After this refactor, the client always pins one (it has it from `dmData`), so the existing path keeps working. The "client_id None → server picks" branch is unreachable for first-message-bootstrap; it could stay as a defensive fallback or be removed in a follow-up.

### Lazy-create-on-founding-commit in `post_commit` — keep, demote

The `epoch ≤ 1 → lazy-create DM` fallback can stay for defense in depth but is no longer load-bearing. The conversation row will exist before any commit. If we're being principled, we can drop it later.

## Client changes (web-client)

### `useLoadDmConversations`

No behavioral change — the new conversation just appears in the list once the WS `friend_accepted` event invalidates the query. The hook already handles that.

### `ConversationPage.viewmodel.ts`

Significant simplification:

- **Drop** `pendingFirstMessageConvId` state and its setter.
- **Drop** the `UUID_RE.test(conversationKey)` discriminator and the `isFirstMessage` flag.
- **Drop** the `effectiveConvId = isFirstMessage ? crypto.randomUUID() : conversationKey` ternary.
- The route param `/dm/<address>` stays — `dmData` resolves the conversation_id from `localDmConvos`. If `dmData` is undefined and there's no path to discover the conversation_id, **block sending** (no friendship → no conversation → user shouldn't even be on this page). Show "This user is not your friend" or similar.

`sendMessage` becomes:

```ts
if (!user || !accessToken || !idpUrl || !dmData) return
const conversationId = dmData.id
// ... build optimistic, push, run send through the EXISTING conversation_id ...
```

`runSend` no longer needs `isFirstMessage` either — the `conversation_id` is always pinned on `POST /api/dm`.

### `addContactToGroup` semantics

`addContactToGroup(idpUrl, accessToken, conversationId, recipientActorUri)` is called the first time anyone encrypts in a conversation. With this refactor, `conversationId` is always the server-known id (from `dmData.id`). The MLS group is created with `mls.createGroup(conversationId)`. Subsequent sends `ensureGroupExists` short-circuits. Cross-IdP still works the same — the welcome carries the same `conversation_id` (it's the AP envelope's `context` field).

### `addressToActorUri`

Stays useful — `ensureGroupExists` still needs the recipient's actor URI when bootstrapping the MLS group, and `dmData.actorUri` is the canonical source. The fallback for the empty-`dmData` case becomes a "shouldn't happen on a friend's DM" guard.

## Spec updates

- `specs/01-identity-federation.md`: the friendship-accept flow now also creates a DM conversation. Add a subsection or an inline note.
- `specs/03-direct-messages.md`: the "Conversation ID ownership" note changes — it's now decided at friendship-accept by the accepter's IdP, not by the first-message sender. Update accordingly. The cross-IdP message-id and attachment-id bridging notes stay valid (still needed for the message and attachment row ids).
- `specs/05-e2ee.md`: the §4 Add/Remove flow text mentions "first message bootstraps the MLS group with a freshly-minted UUID" — update to "MLS group_id = the conversation_id assigned at friendship-accept."

## Edge cases

1. **Pre-existing accepted friendships** (no conversation row): handled by migration.
2. **Pre-existing accepted friendships across IdPs where peer is on old code**: migration backfills *each side independently*, so the conversation ids will differ. Mitigation: this is the existing state today — these conversations also don't share a conversation_id (they're pre-refactor). They keep working under the message-id and attachment-id bridging fixes already in place. New friendships post-deploy use the shared id.
3. **Unfriend + refriend**: `get_or_create_dm` reuses the existing conversation, picking up message history. Whether that's desirable UX or a privacy concern is a product question — for now we match how the system already behaves (the `delete_friendship` handler doesn't touch the conversation row).
4. **Reject**: no conversation created.
5. **Concurrent accept double-clicks**: friendships table presumably has unique constraints; conversation create is idempotent via `find_dm_between`.

## Out of scope

- **UI for "empty DMs"**: friends who have never messaged each other. `GET /api/dm` returns the empty conversation now (sorts to the bottom via `last_message_at DESC NULLS LAST`). Choosing whether to show it in the sidebar, hide it, or show as "Start a conversation" is a UX call; for this turn we just let it appear at the bottom of the list.
- **Removing the lazy-create-on-founding-commit defense in `post_commit`**: keep for now, can drop later.
- **Removing the "no `conversation_id` pinned" path in `POST /api/dm`**: keep for now, defensive.

## Testing scope

- One Rust unit test for the migration's idempotency (run twice, assert no duplicates).
- One Rust unit test for `accept_friendship`: after accepting, both members are in `conversation_members` and `find_dm_between` returns the conversation_id.
- Manual smoke: existing friend-accept end-to-end across two IdPs, send a first message, hard-reload, send another message — should not mint a parallel conversation.

## File touch list

```
identity-provider/
├── migrations/                                                   # new
│   └── 2026XXXXXXXX_backfill_friendship_conversations.sql
├── crates/social/src/handlers.rs                                # accept_friendship: create conversation
├── crates/realtime/src/events.rs                                # FriendshipPayload: +conversation_id
├── crates/federation/src/inbox.rs                               # handle_accept: read conversationId, create local row
├── specs/01-identity-federation.md                              # docs
├── specs/03-direct-messages.md                                  # docs (conversation_id ownership note)
└── specs/05-e2ee.md                                             # docs

web-client/
├── src/domain/models/ws.ts                                      # FriendshipPayload: +conversation_id
├── src/presentation/pages/conversation/ConversationPage.viewmodel.ts  # simplify
└── (docs/CLAUDE.md if relevant)
```
