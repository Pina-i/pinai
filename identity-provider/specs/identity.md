# Pina'i — Accounts and federated identity

In this architecture, users can be on **different IdPs** (e.g. Alice on `idp.alice.com`, Bob on `idp.bob.com`). Each IdP's PostgreSQL stores its own local users and a *remote actor* cache. So a friend's username can be either **local** or **remote**.

## 1. Data model

```sql
-- Local users registered on this IdP instance
CREATE TABLE users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT NOT NULL UNIQUE,       -- the handle: chosen name + "_" + 5 of a–z0–9,
                                            -- e.g. "alice_xk9mp"; used for federation:
                                            -- alice_xk9mp@idp.alice.com (identity-provider/specs/auth.md § 2)
  display_name  TEXT NOT NULL,              -- set to user input at creation, e.g. "alice"
                                            -- freeform, no uniqueness constraint, shown in UI
  avatar_url    TEXT,                       -- public RustFS URL with `?v=<unix_secs>` cache-bust
                                            -- (avatars bucket is public-read; see identity-provider/specs/profile-and-settings.md § 1)
  pronouns      TEXT,                       -- closed enum, see CHECK below
  bio           TEXT,                       -- ≤ 190 chars, freeform; enforced server-side
    email         TEXT NOT NULL UNIQUE,       -- used by OIDC; kept lowercase, and unique
                                            -- whatever its case (users_email_lower_key)
  password_hash TEXT NOT NULL,
  actor_uri     TEXT NOT NULL UNIQUE,       -- e.g. "https://idp.alice.com/users/alice"
  inbox_url     TEXT NOT NULL,              -- e.g. "https://idp.alice.com/users/alice/inbox"
  outbox_url    TEXT NOT NULL,              -- e.g. "https://idp.alice.com/users/alice/outbox"
  email_verified_at TIMESTAMPTZ,            -- NULL until the signup OTP is consumed;
                                            -- /login refuses to issue a session while NULL
  contact_policy TEXT NOT NULL DEFAULT 'friends_and_groups',
                                            -- who may message the account (identity-provider/specs/social.md § 2):
                                            -- everyone | friends_and_groups | friends
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
                                            -- cached on first WebFinger resolution to avoid repeated lookups;
                                            -- NULL for an actor first seen through an inbound Follow,
                                            -- which is then reached at "{actor_uri}/inbox"
  instance      TEXT NOT NULL,              -- e.g. "idp.bob.com"
  display_name  TEXT,
  avatar_url    TEXT,
  fetched_at    TIMESTAMPTZ NOT NULL DEFAULT now(),  -- used for cache invalidation
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## 2. Remote actor cache

`remote_actors` is written whenever an actor is resolved (WebFinger, on an outgoing request) or
discovered (its first inbound `Follow`), with the inbox, name and avatar (`icon`) its actor
document gives. A fetch that brings no inbox, name or avatar — an unreachable peer, a document
without them — keeps the cached value rather than erasing it. Discovery accepts only a URI of the
form `…/users/{handle}`; any other actor is refused with `400 Cannot parse remote actor URL`. A
name or avatar outside the peer profile limits (`identity-provider/specs/profile-and-settings.md § 3`) counts as
none. The friendship keeps the
avatar the actor was met with, on either side of the request, so a new friend is shown with it
at once.

The cache is never what tells a user whether someone exists, or what they are called: that would
tell them who on this instance has met whom. Where a user names an arbitrary actor — a group's
invitees — the actor is resolved anew on its own instance, cached or not
(`identity-provider/specs/groups.md § 2`).

A resolution the actor's instance fails — it doesn't answer, or answers a WebFinger or actor
document no instance would send — is `502 the account's instance did not answer`: for a friend
request, a DM to an address not cached here, and a group invitee (with its `actor_uri`). An
instance that answers it knows no such account is `404`.

A group's members reach this instance in the rosters other members' instances send, so a member
may be someone nobody here has met. What goes to each remote member — a group message, an edit,
an MLS commit — is delivered at the inbox cached for them, else at the one their instance names
over WebFinger, asked in the background so that no request waits on a slow peer, and cached from
then on (`infrastructure::federation::Inboxes`). A send asks at most 10 instances; a member whose
instance didn't answer, knew no such account or named another actor gets nothing and isn't asked
for again for 10 minutes, so a dead or made-up member costs one lookup. An account of this
instance is never looked up.

## 3. What peers read of an account

`GET /.well-known/webfinger?resource=acct:{handle}@{domain}` points at the account's actor, for
an account of this instance only (`404 User not found` for any other). `GET /users/{handle}` is
its `Person` — display name (else the handle), inbox, `icon` when it has an avatar, and the
instance key as `publicKey`; `GET /actor` is the instance's `Application` actor, whose key signs
the inter-instance requests. The outbox and the `followers` / `following` collections are always
empty: nothing is published, and whom an account is friends with is not for anyone to read.

## 4. Federated address format

The canonical address format used throughout the system is `username@domain` (e.g. `alice_xk9mp@idp.alice.com`), **without** a leading `@` — `/userinfo` answers it as `address`. Clients receive actor URIs (`https://idp.alice.com/users/alice_xk9mp`) in some events and normalise them to `username@domain` via `actorUriToAddress()` before using them as conversation keys.

An actor URI is an `http(s)` URL with a host, no query and no fragment, of 2 KiB at most once
normalised (`domain::identity::ActorUri`) — whether a peer or a user hands it over, anything else is
refused.

## 5. `username` vs `display_name`

- `username` is the unique internal identifier used for federation and ActivityPub addressing. It is composed of the user-chosen name + `_` + a 5-character suffix of `a–z0–9` appended by the backend at account creation (e.g. `alice_xk9mp`; `identity-provider/specs/auth.md § 2`). This guarantees uniqueness per instance with no coordination needed. It is never shown in the UI.
- `display_name` is the only name shown client-side. It is automatically set by the backend at account creation to the user-chosen part, before the suffix (e.g. user types `alice` → `display_name = "alice"`). It has no uniqueness constraint and can be changed at any time, within the rules of `identity-provider/specs/profile-and-settings.md § 1`.

Example flow at account creation:
- User inputs: `alice`
- Backend sets: `username = "alice_xk9mp"`, `display_name = "alice"`, `actor_uri = "https://idp.alice.com/users/alice_xk9mp"`
