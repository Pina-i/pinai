# ADR 0001 — Bounded contexts and crate layout

- **Status**: Accepted (partially implemented — see Follow-ups)
- **Date**: 2026-05-05
- **Deciders**: Kilian
- **Supersedes**: —

## Context

The `oidc/` crate has accreted responsibilities far beyond OIDC: ActivityPub
federation, WebSocket transport, direct messaging, friendships, presence, and
inter-IdP SSE. The crate name no longer describes its contents, files are
growing, and cross-domain coupling is informal — there is no compiler-enforced
boundary between, for example, presence logic and OIDC token issuance.

A DDD strategic pass (see `docs/ddd/strategic-model.md` if added later)
identified seven bounded contexts in the system. The current single-crate
layout collapses six of them into `oidc/`, which is the root cause of the
sprawl.

## Decision

Split `crates/oidc/` along bounded-context lines. The implemented crate layout is:

```
crates/
├── auth/            # OIDC/OAuth2 flows, JWT issuance, JWKS, cookies, PKCE,
│                    # registration, avatar profile. Also hosts the residual
│                    # WS upgrade handler and presence HTTP/SSE handlers that
│                    # still depend on AppState (transitional).
├── federation/      # ActivityPub: inbox/outbox, WebFinger, HTTP Signatures,
│                    # remote_actors, delivery, Bearer-auth helper.
├── messaging/       # Conversation aggregate, DM REST API, reactions, reads.
├── social/          # Friendship aggregate, REST API.
├── presence/        # online/away/offline, typing indicators, inter-IdP SSE.
├── realtime/        # WS hub, connection registry, typed WsEvent envelopes.
├── state/           # Shared AppState + OidcError (integration seam).
├── broker/          # (existing) pub-sub + Streams abstraction.
├── db/              # (existing) shared SQLx models + repos.
├── storage/         # (existing) RustFS / object storage.
├── config/          # (existing).
└── server/          # (existing) Axum entrypoint, router, wiring.
```

**Note on `identity/`**: the original target included a separate `identity/`
crate. After the split, the only candidate material was the `User` model
(which lives in `db/` due to `sqlx::FromRow` coupling), the avatar profile
handlers, and registration. Registration is tightly coupled to session
cookies (which belong to `auth/`), and the User aggregate has minimal
domain logic at present. Promoting `identity/` to its own crate would
produce a stub. **Deferred until either the User aggregate accumulates
non-trivial invariants or registration grows beyond the cookie boundary.**

**Note on `state/`**: not in the original ADR but emerged as the natural
home for `AppState` and `OidcError`. Without it, every domain crate would
either need to depend on `auth/` (creating cycles) or carry its own
substate type (much larger refactor). `state/` is the integration seam
mentioned in the context-map's "Shared Kernel" — kept deliberately small.

### Dependency direction (no cycles)

Implemented graph:

```
server  ──► auth, federation, messaging, social, presence, realtime, state
auth    ──► state, federation, presence, realtime, db, storage, broker, config
messaging  ──► state, federation, realtime, db
social     ──► state, federation, realtime, db
presence   ──► realtime, db, broker, config
federation ──► state, db, broker, config, realtime
realtime   ──► (no internal deps)
state      ──► realtime, presence, db, broker, storage, config
db, broker, storage, config ──► (leaves)
```

### Inbound federation dispatch

**Plan**: To break the natural cycle between Federation and
Messaging/Social/Presence, Federation does not call into the consuming
contexts directly. The ActivityPub inbox parses incoming activities,
persists side-effects it owns (e.g. `remote_actors` upserts), and publishes
typed events to the broker. Messaging, Social, and Presence subscribe to
the topics they care about.

**Current state (2026-05-05)**: not yet implemented. `federation/inbox.rs`
still persists DMs and friendships directly via `idp-db` repos and emits
WS events. Cycles are avoided because `federation` does not import
`messaging` or `social` — both downstream crates depend on `federation`,
not the other way around. Messaging/social only own the *outbound* and
*REST* sides today. Topic-based dispatch is a follow-up (see below).

### Cross-cutting rules

- Each crate exposes a narrow `pub` API; everything else is `pub(crate)`.
- Shared domain primitives (`actor_uri`, `FederationAddress`, `ConversationId`)
  live in `identity` and are re-exported where needed — they do **not** sink
  into `db` or get duplicated.
- Repos stay centralized in `db/` for now. Promoting them into per-context
  crates is a follow-up decision once the split is stable.
- The crate names match the spec files (`01-identity-federation.md`,
  `03-direct-messages.md`, `04-presence.md`).

## Consequences

### Positive

- Compiler-enforced boundaries via `pub(crate)` and crate seams.
- Faster incremental compiles — most edits touch one or two crates.
- The crate name reflects its content; new contributors can navigate by domain.
- Cycle-free dependency graph; broker-mediated inbound dispatch is now an
  explicit architectural pattern, not an emergent one.
- Specs and code share the same vocabulary.

### Negative

- Multi-day refactor with broad import churn.
- Seven new `Cargo.toml`s to maintain.
- Possible short-term duplication of small types until shared-kernel
  boundaries settle (`identity` will have to host a few cross-cutting types).
- The broker becomes load-bearing for inbound federation; broker outages now
  affect AP delivery semantics. (Mitigated: `federation_queue` already exists
  for durability of outbound; inbound durability needs a similar story.)

### Neutral

- No runtime behaviour change; this is a structural refactor.
- Database schema is untouched.
- API surface (`/authorize`, `/users/:handle/inbox`, etc.) is unchanged.

## Alternatives considered

1. **Keep one crate, split into deeper modules.** Cheapest, but does not give
   compiler-enforced boundaries and does not address compile times. Rejected:
   the crate is already too big to introspect comfortably.

2. **Layered split (`domain/`, `application/`, `infrastructure/`).** Common in
   hexagonal/clean-architecture write-ups, but cuts orthogonally to the
   problem here — the pain is *which domain*, not *which layer*. Rejected.

3. **Merge `auth` into `identity`.** Tempting (one User aggregate, one crate)
   but `identity` should remain usable for ActivityPub-only consumers without
   pulling in JWT/OIDC machinery. Rejected.

4. **Promote repos into per-context crates immediately.** Clean DDD, but
   doubles the migration cost. Deferred — revisit after the context split has
   stabilized.

## Follow-ups

**Done**:
- ✅ `CLAUDE.md` workspace-structure section updated.

**Outstanding**:
- Update `specs/02-architecture-diagram.md` to show the new crate boundaries.
- **Implement broker-mediated inbound dispatch.** Define topics
  (`federation.inbox.create.note`, `federation.inbox.follow`,
  `federation.inbox.accept`, `federation.inbox.like`,
  `federation.inbox.update.person`, …). Move persistence of inbound DMs out
  of `federation::inbox` into `messaging` (subscriber); same for friendships
  into `social`; same for profile updates into `social`/`auth` as appropriate.
- Decide on inbound-durability story (Redis Streams ack vs. dedicated
  `federation_inbound_queue` table). Without this, broker outages drop
  inbound activities silently.
- **Move residual `auth/src/{ws/handler.rs, presence/{handlers,sse}.rs}`** to
  their natural domain crates (`realtime`, `presence`). Currently held in
  `auth/` because they take `State<AppState>` and would either create cycles
  or require `FromRef` substate plumbing. Resolution path: introduce
  `RealtimeState`/`PresenceState` substates in their crates and use
  Axum's `FromRef<AppState>` pattern.
- **Identity bounded context.** Either (a) accumulate enough domain logic on
  `User` to justify extracting an `identity/` crate, or (b) explicitly fold
  the identity concept into `auth/` and document it as such.
- Consider renaming `OidcError` → `AppError` in `state/`. It is no longer
  OIDC-specific; the name is misleading now that federation, messaging, and
  social all use it.
- Tighten `pub` to `pub(crate)` where each crate's API surface is wider than
  needed (the bulk extraction left everything `pub` for expedience).
