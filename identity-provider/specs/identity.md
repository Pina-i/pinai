# Pina'i — Accounts and federated identity

In this architecture, users can be on **different IdPs** (e.g. Alice on `idp.alice.com`, Bob on `idp.bob.com`). Each IdP's PostgreSQL stores its own local users and a *remote actor* cache. So a friend's username can be either **local** or **remote**.

## 1. Data model

```sql
-- Local users registered on this IdP instance
CREATE TABLE users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT NOT NULL UNIQUE,       -- the handle: the display name in ASCII + "_" +
                                            -- 5 of a–z0–9, e.g. "hoku_xk9mp"; used for federation:
                                            -- hoku_xk9mp@idp.alice.com (identity-provider/specs/auth.md § 2)
  display_name  TEXT NOT NULL,              -- typed at sign-up, e.g. "Hōkū"
                                            -- freeform, no uniqueness constraint, shown in UI
  avatar_url    TEXT,                       -- `{issuer}/avatars/{id}.{ext}?v=<unix_secs>`: served by
                                            -- the IdP from its private bucket (identity-provider/specs/profile-and-settings.md § 1)
  pronouns      TEXT,                       -- closed enum, see CHECK below
  bio           TEXT,                       -- ≤ 190 chars, freeform; enforced server-side
    email         TEXT NOT NULL UNIQUE,       -- used by OIDC; kept lowercase, and unique
                                            -- whatever its case (users_email_lower_key)
  password_hash TEXT NOT NULL,
  actor_uri     TEXT NOT NULL UNIQUE,       -- e.g. "https://idp.alice.com/users/alice"
  inbox_url     TEXT NOT NULL,              -- e.g. "https://idp.alice.com/users/alice/inbox"
  outbox_url    TEXT NOT NULL,              -- e.g. "https://idp.alice.com/users/alice/outbox"
  email_verified_at TIMESTAMPTZ,            -- NULL until the signup OTP is consumed;
                                            -- /login refuses to issue a session while NULL,
                                            -- unless the account is admitted
  admitted_at   TIMESTAMPTZ,                -- let in without confirming its address: signs in
                                            -- without a code, never swept as unconfirmed
                                            -- (identity-provider/specs/auth.md § 4)
  is_admin      BOOLEAN NOT NULL DEFAULT false, -- an admin of this instance; the first is created
                                            -- from ADMIN_EMAIL (identity-provider/specs/auth.md § 4)
  invited_by    UUID REFERENCES users(id) ON DELETE SET NULL,
                                            -- who vouched for it: the admin whose invitation let
                                            -- it in (identity-provider/specs/auth.md § 5)
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
  pronouns      TEXT CHECK (pronouns IN ('he', 'she', 'non-binary')),
  bio           TEXT,                       -- the Person's `summary`, as text
  fetched_at    TIMESTAMPTZ NOT NULL DEFAULT now(),  -- last resolved or discovered; a profile card
                                                     -- older than 24 h discovers the actor again
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- How the instance introduces itself, as an admin saved it (§ 6): one row, none until the first save
CREATE TABLE instance_intro (
  only_row      BOOLEAN PRIMARY KEY DEFAULT true CHECK (only_row),
  name          TEXT,                       -- NULL: the instance's domain
  description   TEXT,                       -- NULL: none
  updated_by    UUID REFERENCES users (id) ON DELETE SET NULL,
  updated_at    TIMESTAMPTZ NOT NULL        -- these two for whoever reads the database
);
```

## 2. Remote actor cache

`remote_actors` is written whenever an actor is resolved (WebFinger, on an outgoing request) or
discovered (its first inbound `Follow`, or a stale profile card —
`identity-provider/specs/profile-and-settings.md § 1`), with the inbox, name, avatar (`icon`), bio
(`summary`) and pronouns its actor document gives. A fetch that brings no inbox, name or avatar —
an unreachable peer, a document without them — keeps the cached value rather than erasing it. The
bio and pronouns are those of the document read: one without them clears them, and only an
unreachable peer keeps them. Discovery accepts only a URI of the
form `…/users/{handle}`; any other actor is refused with `400 Cannot parse remote actor URL`. A
name, avatar, bio or pronouns outside the peer profile limits
(`identity-provider/specs/profile-and-settings.md § 3`) count as none. The friendship keeps the
avatar the actor was met with, on either side of the request, so a new friend is shown with it
at once.

The cache is never what tells a user whether someone exists, or what they are called: that would
tell them who on this instance has met whom. Where a user names an arbitrary actor — a group's
invitees — the actor is resolved anew on its own instance, cached or not
(`identity-provider/specs/groups.md § 2`).

What a peer answers is kept only as `specs/06-federation-authentication.md` "Resolving an actor"
has it: an address resolves only to an actor of the instance it names, and a document describes
only the actor at the URL it was asked at — so no instance changes what this one holds of
another's accounts. A resolution the actor's instance fails — it doesn't answer, or answers what
no instance would send: a WebFinger or actor document breaking that rule, an `id` that is no
actor URI (§ 4), or an inbox URL past an actor URI's 2 KiB (`RemoteActor::parse_inbox`) — is
`502 the account's instance did not answer`, and nothing of its answer is written: for a friend
request, a DM to an address not cached here, and a group invitee (with its `actor_uri`). An
instance that answers it knows no such account is `404`. A discovery whose document breaks the
rule, or brings such an inbox, reads as an unreachable peer's: what was cached stays.

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
an account of this instance only (`404 User not found` for any other). Only an account that has
joined — its address confirmed, or admitted — is read so: a sign-up still to confirm its address is
`404 User not found` on every route here, its inbox included
(`identity-provider/specs/social.md § 2` "An account still signing up"). `GET /users/{handle}` is
its `Person` — display name (else the handle), inbox, `icon` when it has an avatar, `summary` and
`pronouns` when it has a bio and pronouns (`identity-provider/specs/profile-and-settings.md § 3`),
and the instance key as `publicKey`; `GET /actor` is the instance's `Application` actor, whose key signs
the inter-instance requests. The outbox and the `followers` / `following` collections are always
empty: nothing is published, and whom an account is friends with is not for anyone to read.

## 4. Federated address format

The canonical address format used throughout the system is `username@domain` (e.g. `alice_xk9mp@idp.alice.com`), **without** a leading `@` — `/userinfo` answers it as `address`. Clients receive actor URIs (`https://idp.alice.com/users/alice_xk9mp`) in some events and normalise them to `username@domain` via `actorUriToAddress()` before using them as conversation keys.

The domain is a host name, lowercased, then optionally `:port` — 1–65535 in digits, kept without
leading zeros, so `:0443` is `:443` (`domain::identity::Domain`). The host is 253 characters at
most, its labels between the dots 1–63 of `a–z0–9-`, none starting or ending with `-` — the names
DNS can answer —, and a last label of digits only is an IPv4 address or nothing, as a URL reads
it. `x@reef..chat`, `x@a.-b`, `x@reef.123` or `x@reef.chat:+443` is no address (`400`), never an
instance that didn't answer.

This instance's own domain matches in any case, and with its scheme's default port written out —
`hoku_xk9mp@idp.alice.com:443` on an `https` instance, `:80` on an `http` one, name the same
account as `hoku_xk9mp@idp.alice.com` (`InstanceOrigin`): such an address is never looked up as
another instance's, in a request, a lookup or a WebFinger `resource`. Any other port is another
instance.

An actor URI is an `http(s)` URL with a host, no user name or password, no query and no fragment,
of 2 KiB at most once normalised (`domain::identity::ActorUri`) — whether a peer or a user hands it
over, anything else is refused: `http://reef.chat@evil.example/users/x` is evil.example's, and
would name one account by two URIs.

## 5. `username` vs `display_name`

- `display_name` is the only name shown client-side. The user types it at sign-up — `Hōkū`,
  `Ana Tane` — within the rules of `identity-provider/specs/profile-and-settings.md § 1`
  (trimmed, 1–50 characters). It has no uniqueness constraint and can be changed at any time.
  It is also the only name the instance's own pages and its admins' API give an account: an
  invitation's inviter, a reset link's member, the members list
  (`identity-provider/specs/auth.md` § 4, § 5, § 7).
- `username` is the unique internal identifier used for federation and ActivityPub addressing,
  derived from the display name at account creation and never changed. It is never shown in the
  UI.

The username is the display name made a chosen name (`UsernameChoice::derived_from`), then `_` and
a 5-character suffix of `a–z0–9` (`identity-provider/specs/auth.md § 2`):
1. transliterated to ASCII (`Hōkū` → `Hoku`, `Ærø` → `AEro`, `李雷` → `Li Lei`);
2. lowercased;
3. every run of anything but `a–z0–9` made one `_`, none at either end;
4. cut at 32 characters.

A name with fewer than 2 characters left gives `user`. The suffix keeps every username unique
without asking anyone, so two people named Hōkū are `hoku_xk9mp` and `hoku_3t8qa`.

Example flow at account creation:
- User inputs: `Hōkū Tane`
- Backend sets: `username = "hoku_tane_xk9mp"`, `display_name = "Hōkū Tane"`,
  `actor_uri = "https://idp.alice.com/users/hoku_tane_xk9mp"`

## 6. The instance's description

An instance says what it is to whoever is about to sign in to it: on its sign-in pages
(`identity-provider/specs/auth.md § 1` "The sign-in pages"), and in its NodeInfo, the document
every fediverse server publishes about itself.

| What | From |
|---|---|
| Name | What an admin saved in Settings → Instance; otherwise `INSTANCE_NAME`. Trimmed, 40 characters at most; blank or unset, the instance's domain |
| Description | What an admin saved in Settings → Instance; otherwise `INSTANCE_DESCRIPTION`. Trimmed, 90 characters at most; blank or unset, none |
| People | Every local account that has joined — its address confirmed, or admitted —, counted at most a minute ago (`Accounts::count`) |
| Open registration | `REGISTRATIONS`: yes for `open`, no for `invite`, the default (`identity-provider/specs/auth.md § 6`) |
| Source | `SOURCE_URL`, an `http(s)` URL; unset or blank, Pīna'i's own repository, `https://github.com/Pina-i/pinai` (`PINAI_SOURCE_URL`) |

A `SOURCE_URL` that is no `http(s)` URL with a host stops the instance at startup (`SourceUrl`).

**The name and the description** are one text, written either in `.env` by whoever sets the
instance up, or in Settings → Instance by an admin (`GET` / `PUT /api/admin/intro`,
`identity-provider/specs/auth.md § 4`). Both go through one rule, `IntroText::parse`: each field
trimmed, a blank one the default — the domain for the name, no description, which the pages read
"An identity provider." —, the name 40 characters at most and the description 90, counted in
characters (the description is set as the pages' headline). What is in force:

1. the text an admin saved, whole, once one has saved (`intro_in_force`): `.env` is no longer read
   for either field;
2. otherwise `INSTANCE_NAME` and `INSTANCE_DESCRIPTION`, as read at the start: a changed value
   takes effect at the next restart;
3. otherwise the defaults.

An admin saves the name and the description together; the text is kept in `instance_intro`'s one
row (§ 1), which doesn't exist until the first save. There is no "use `.env` again": an admin who
wants its values back types them in the form.

```mermaid
flowchart TD
    S[The instance starts] --> E{INSTANCE_NAME and INSTANCE_DESCRIPTION within the rule?}
    E -- no --> X[refuse to start, naming the rule broken]
    E -- yes --> R{a row in instance_intro?}
    R -- no --> C[".env's text in force, the defaults for what it leaves unset"]
    R -- yes --> V{the row within the rule?}
    V -- no --> X2[refuse to start, naming instance_intro]
    V -- yes --> W["the saved text in force; a warning for each .env field it overrides"]
    C --> M[held in memory]
    W --> M
    M -- an admin saves --> M
```

- **`.env` is checked whatever is in force**: a value past its limit stops the start even when a
  saved text overrides it. So does a row that breaks the rule — edited by hand —, the error naming
  the table.
- **An overridden variable is reported at each start**, field by field, while it is set and
  differs from the saved field (`overridden_settings`): `INSTANCE_NAME is not used: an admin
  changed the name in Settings → Instance. Change it there, or remove INSTANCE_NAME from .env`. A
  variable unset, or equal to what was saved, is not reported.
- **The text in force is held in memory** (`IntroInForce`): loaded at the start, replaced by each
  save once the row is written, so a refused or failed save leaves it as it was. No request from a
  visitor reads the database for it. This assumes one process per instance, as the presence board
  and the reset mail budget already do. Two admins saving at the same moment are taken one after
  the other (`EditIntro`), so the row and memory end on the same text.

A change shows:

| Where | When |
|---|---|
| Sign-in, invitation, reset and forgot pages | The next page load (they are `no-store`) |
| NodeInfo | At once; a browser or a client may keep the last answer for up to 60 s (`max-age=60`) |
| A reset link asked for by mail | The next mail: its subject and text name the instance |
| The client's landing and Settings | At their next NodeInfo read, within a minute; Settings → Instance shows the saved text at once, from the `PUT`'s answer |

The instance's `Application` actor (whose `name` is its base URL), the mail sender (`SMTP_FROM`)
and the sign-up code mail, which doesn't name the instance, don't take it.

Scenarios:

- **Setting up an instance.** The operator sets `INSTANCE_NAME` and `INSTANCE_DESCRIPTION` in
  `.env`: the instance introduces itself so from its first start, rather than by its domain.
- **An admin changes it.** They save a new name in Settings → Instance; the next sign-in page and
  NodeInfo show it. At each start after, while `.env` still sets another name, the log says
  `INSTANCE_NAME` is not used.
- **The operator edits `.env` after an admin saved.** The change has no effect, and the warning
  says where to change the name instead.
- **A name left blank in the form.** It is saved as the default: the pages show the domain, and the
  form shows the domain as its placeholder, not as a value.

**The source.** Pīna'i is under the GNU AGPL-3.0-or-later, whose § 13 has whoever runs a modified
version offer its users, over the network, the source of the version they run. The instance offers
it in two places: NodeInfo's `software.repository`, for software, and a "↳ Source" link at the foot
of its sign-in pages, for people. An instance running the code unmodified keeps the default; one
running a fork points `SOURCE_URL` at the fork, and both places follow.

**NodeInfo 2.1**, answered to any origin:
- `GET /.well-known/nodeinfo` links to the document:
  `{"links":[{"rel":"http://nodeinfo.diaspora.software/ns/schema/2.1","href":"<issuer>/nodeinfo/2.1"}]}`.
- `GET /nodeinfo/2.1` is the document, `Content-Type: application/json;
  profile="http://nodeinfo.diaspora.software/ns/schema/2.1#"`, kept a minute by caches:

```json
{
  "version": "2.1",
  "software": { "name": "pinai", "version": "0.1.0", "repository": "<SOURCE_URL>" },
  "protocols": ["activitypub"],
  "services": { "inbound": [], "outbound": [] },
  "openRegistrations": true,
  "usage": { "users": { "total": 1204 } },
  "metadata": {
    "nodeName": "Aotearoa",
    "nodeDescription": "Design and type people.",
    "gifs": { "provider": "klipy", "apiKey": "<KLIPY_API_KEY>" }
  }
}
```

`openRegistrations` follows `REGISTRATIONS`: `true` on an open instance, `false` on an invite-only
one. `software.repository` is `SOURCE_URL`, normalised (`https://github.com/Pina-i/pinai` by
default). `nodeDescription` is left out when there is none. The web client's landing reads it while the user
types an instance's address, to show `✓ resolved · Aotearoa · 1,204 people` before sending them
there; a client tells a Pīna'i instance by `software.name`.

**The GIF picker's key.** `metadata.gifs` hands the instance's clients — the web app, the desktop
app, whichever deployment or build they come from — the Klipy API key their GIF picker searches
with: `KLIPY_API_KEY`, left out when unset, and the picker then says GIFs aren't set up. The key is
the instance's, made in Klipy's Partner Panel, so its quota and its standing with Klipy are the
instance's own. It is no secret: Klipy expects every client to hold a copy, and NodeInfo answers
anyone. A key of anything but ASCII letters, digits, `-` and `_` (256 at most), which a client
writes into a URL path, stops the instance at startup (`KlipyKey`), without quoting it.

```mermaid
sequenceDiagram
    participant C as Client (web or desktop)
    participant I as Identity provider
    participant K as Klipy
    C->>I: GET /nodeinfo/2.1
    I-->>C: metadata.gifs { provider: klipy, apiKey }
    C->>K: GET /api/v1/{apiKey}/gifs/search?q=…
    K-->>C: results, then the GIF's bytes
    Note over C: the GIF is sent as an attachment,<br/>encrypted like any other file
```

## 7. Finding people

A user finds whom to befriend two ways: by name, among the people this instance already holds —
its own accounts, and the people of other instances the user shares a group with —, and by exact
address, anywhere. Nothing asks another instance by name: only an exact address goes out, as a
friend request's does.

### How a person is answered

```json
{
  "actor_uri": "https://reef.chat/users/mahealani_q1x8c",
  "address": "mahealani_q1x8c@reef.chat",
  "display_name": "Mahealani",
  "avatar_url": null,
  "relation": "request_received",
  "friendship_id": "7b1e…"
}
```

- `address` is § 4's `username@domain`. A search never lists someone whose actor URI names no
  address (`ActorUri::federated_address`: not `…/users/{handle}`): no friend request could name
  them. A lookup answers an account of this instance with its own address — a bare handle comes
  back with this instance's domain —, and another instance's with the address as looked up.
- `display_name` and `avatar_url` are another instance's account's as this instance holds them.
  `display_name` is `null` in a search only for an account of this instance that has none, found
  by its handle — another instance's account whose name the cache doesn't hold never matches —; in
  a lookup, also for another instance's account that never gave one.
- `relation` is how the person stands with the caller, from the caller's side: the first that
  holds, read from the caller's own rows (`domain::social::Ties::standing`) — in a search, with the
  person in the same query.

  | `relation` | Holds when |
  |---|---|
  | `blocked` | the caller blocked them |
  | `friend` | the caller's side of a friendship with them is `accepted` |
  | `request_received` | it is `pending` and `incoming`: they asked |
  | `request_sent` | it is `pending` and `outgoing`: the caller asked |
  | `none` | none of these |

  A block the person made on the caller never shows: they read like anyone else, as nobody can
  tell a block (`identity-provider/specs/social.md § 2`).
- `friendship_id` is the caller's `incoming` side, the id `POST /api/friends/:id/accept` takes:
  with `request_received` only, `null` otherwise.

### Searching by name

`GET /api/users/search?q=&limit=`, Bearer. `q` is trimmed, then holds 2 characters at least
besides combining marks — which folding drops, so `a` and an accent is one letter —, 100 characters
at most, marks included, and no control character (`domain::social::SearchQuery`); anything else
is `400`. It is taken literally — `%`, `_` and `\` are characters like any other. `limit` counts
per section: 20 by default, clamped to 1–50.

```json
{ "server": [Person], "groups": [Person & { "group": "Federation lab" }] }
```

| Section | Who is listed |
|---|---|
| `server` | This instance's accounts with their address confirmed, or admitted — the members list's rule (`identity-provider/specs/auth.md § 4` "The members list"). Never the caller, never a sign-up still to confirm its address |
| `groups` | Other instances' accounts that are active members of a conversation of kind `group` the caller is an active member of — not a 1:1, not a group either of them left. A co-member of this instance is in `server` only. `group` is the name of the most recently created group the two share, `null` when that group has none |

**Accents and case never matter**, on both sides of the comparison: a name and `q` are folded
alike — Postgres's `unaccent`, an extension a migration enables, then lower case — so "hoku" finds
"Hōkū", and "Hōkū" finds "Hoku". A person is listed in the first tier that holds:

| Tier | Holds when |
|---|---|
| 0 | the folded display name starts with `q` |
| 1 | it holds `q` |
| 2 (`server` only) | the handle holds `q` — handles are ASCII and lower case already |

Anyone else is not listed; another instance's handle is never searched. The order is the tier,
then the folded display name (byte order, a missing name last), then the actor URI, so the same
search lists the same people in the same order.

Each section is one query (`PgPeopleSearch`): the candidates from `users`, or from
`conversation_members` and the `remote_actors` cache, with the caller's `friendships` side and
`user_blocks` row for each.

```mermaid
flowchart TD
    C[someone this instance holds] --> L{an account of this instance?}
    L -- yes --> V{confirmed or admitted, and not the caller?}
    V -- no --> X[not listed]
    V -- yes --> T{the name starts with q, holds it, or the handle holds it?}
    T -- no --> X
    T -- yes --> S["server, tier 0, 1 or 2"]
    L -- no --> G{an active member of a group the caller is active in?}
    G -- no --> X
    G -- yes --> N{the name starts with q, or holds it?}
    N -- no --> X
    N -- yes --> A{an address?}
    A -- no --> X
    A -- yes --> GR["groups, tier 0 or 1, with the latest group's name"]
```

Scenarios:

- **Alice types "hoku".** Hōkū, on her instance, is in `server`; Hoku from reef.chat, whom she
  met in "Federation lab", is in `groups`, with `group: "Federation lab"`.
- **Hōkū asked Alice to be friends.** He is listed `request_received` with the id of Alice's side,
  so her client accepts there rather than asking him back.
- **Alice blocked Pua.** Pua is listed `blocked`: a request to her would be refused with
  `Unblock this user first` (`identity-provider/specs/social.md § 2`).
- **Pua blocked Alice.** Alice finds Pua as she finds anyone, `none` or whatever her own side says.
- **Kai signed up but hasn't confirmed his address.** Nobody finds him until he does.
- **Alice left the group she shared with Mahina.** Mahina is no longer in her `groups` section,
  unless they share another group.

### Looking up an address

`GET /api/users/lookup?address=`, Bearer, 60 a caller then one a second (`429 too_many_requests`,
`api::LookupLimiter`): each may ask another instance twice and write to its cache. `address` is
trimmed and read by `InstanceOrigin::sought`: a bare name is this instance's, a leading `@` is
dropped, and an address on this instance's own domain (§ 4) is one of its accounts. Only
what is no address at all is `400`; a name on this instance that no handle could be — `alice`,
`Hoku_T3ST0@{domain}` — is `404 No account at this address`, as it would be on any other instance.

| Where | Answer |
|---|---|
| This instance | The account with that handle, confirmed or admitted — the members list's rule, as in a search —, else `404 No account at this address`. The caller's own address is answered like anyone's: the client tells it apart |
| Another instance | Resolved there — WebFinger, then the actor document — every time, never answered from the cache, and remembered as a friend request remembers it (§ 2): the name and avatar answered are the document's, or, when it gives none, those held before — `null` only when none was ever known. An instance that knows no such account is `404 No account at this address`; one that doesn't answer, answers what no instance would, or that this instance may not ask (`specs/06-federation-authentication.md` "Peer request policy") is `502 the account's instance did not answer`, whatever the cache holds of the account |

`200` is one person, as above, its `relation` read from the caller's `user_blocks` and
`friendships` rows: for this instance, in the query that finds the account (`PeopleSearch::local`);
for another, once it is resolved (`PeopleSearch::ties`).

```mermaid
sequenceDiagram
    participant C as Alice's client
    participant A as idp.alice.com
    participant R as reef.chat
    C->>A: GET /api/users/lookup?address=mahealani_q1x8c@reef.chat
    A->>R: WebFinger, then the actor document
    alt an account
        R-->>A: the Person
        A->>A: remember it in remote_actors, read Alice's ties to it
        A-->>C: 200 Person
    else no such account
        R-->>A: 404
        A-->>C: 404 No account at this address
    else no answer
        A-->>C: 502 the account's instance did not answer
    end
```

Scenarios:

- **Alice types Mahealani's full address.** Her instance asks reef.chat, which describes her: she
  is answered with `relation: "none"`, with the name her document gives — or, when it gives none,
  the one this instance held before, `null` if it never knew one.
- **Alice already asked her.** The answer is `request_sent`; on reef.chat, Mahealani looking up
  Alice's address gets `request_received` and the id to accept with.
- **Alice types her own address.** She is answered like anyone, `none`; her client says it's her.
- **Alice types `kai@` her own domain, without the suffix.** No handle reads so: `404`, as the
  same typed for another instance would be.
- **reef.chat is down.** `502`, whatever its cache here says of Mahealani.
