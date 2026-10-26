//! Dev-only seeder. Inserts fully-verified users into the local IdP database
//! so `make alice` / `make bob` come up with sign-in ready accounts — no signup
//! OTP dance required. Takes one or more fixture names; which IdP they land in
//! is decided by the sourced env, not by the name. Pierre seeds alongside Alice
//! so her instance has two local users, which is what testing a group
//! conversation without federation needs.
//!
//! Beyond the users themselves the seed materialises the friendships listed in
//! [`SEEDED_FRIENDSHIPS`], so Alice and Bob are already friends the first time
//! either of them signs in. Alice and Bob live in *different* databases that
//! never talk to each other during a seed, so each invocation writes only its
//! own half of the pair and the two halves are made to agree by construction —
//! see [`SEEDED_FRIENDSHIPS`] and [`Fixture::username`] for the two things that
//! have to be pinned down for that to work.
//!
//! Idempotent: re-running the seed against an existing user updates the
//! password hash + display name + handle + admin flag and flips `email_verified_at`
//! back to the current time, and every friendship write is an upsert. Applies sqlx
//! migrations first so it can race the IdP's own startup safely (whoever runs
//! `MIGRATE` first wins; the other is a no-op).
//!
//! Argon2id params mirror `crates/auth/src/register.rs` exactly — drift
//! here would create users the IdP can't authenticate.

use anyhow::{anyhow, Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHasher, Version,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::env;
use uuid::Uuid;

struct Fixture {
    /// Name accepted on the command line.
    key: &'static str,
    display_name: &'static str,
    /// Fixed, unlike the random suffix real signup mints, and valid under the handle rules
    /// (`domain::identity::Handle`): lowercase chosen name, `_`, 5 of `a–z0–9`. The peer
    /// instance has to be able to name this user's `actor_uri` without ever
    /// having seen the database it lives in, which a random suffix makes
    /// impossible. Fixtures trade collision-resistance for predictability;
    /// nothing else in the dev corpus competes for these handles.
    username: &'static str,
    email: &'static str,
    password: &'static str,
    /// The dev instance this fixture belongs to, per the README's port table.
    /// Only used to derive *peer* URIs and to tell a local friend from a
    /// federated one — where a fixture actually lands is still decided by the
    /// sourced `DOMAIN`.
    home_domain: &'static str,
    /// An admin of its instance. Bob's is invite-only, which won't start without one, and
    /// `ADMIN_EMAIL` never promotes an account the seed created first.
    admin: bool,
}

const ALICE: Fixture = Fixture {
    key: "alice",
    display_name: "Alice",
    username: "alice_dev01",
    email: "alice@test.fr",
    password: "yonolulu",
    home_domain: "localhost:8088",
    admin: false,
};

const BOB: Fixture = Fixture {
    key: "bob",
    display_name: "Bob",
    username: "bob_dev01",
    email: "bob@test.fr",
    password: "yonolulu",
    home_domain: "localhost:8081",
    admin: true,
};

const PIERRE: Fixture = Fixture {
    key: "pierre",
    display_name: "Pierre",
    username: "pierre_dev01",
    email: "pierre@test.fr",
    password: "yonolulu",
    home_domain: "localhost:8088",
    admin: false,
};

const FIXTURES: &[Fixture] = &[ALICE, BOB, PIERRE];

/// Friendships the seed materialises, as `(fixture key, fixture key, DM id)`.
///
/// The conversation id is a hardcoded constant rather than a fresh UUID
/// because both instances must independently arrive at the same value. In the
/// live flow `accept_friendship` mints one and ships it to the peer inside the
/// AP `Accept` envelope (the non-standard `conversationId` field) so the two
/// IdPs agree from the first moment the DM exists; a seed has no handshake to
/// carry it, so the id is agreed on ahead of time instead. Give every new pair
/// its own constant.
///
/// No MLS state is seeded: the group is created lazily by whichever client
/// opens the conversation first (`ensureGroupExists`), so an empty DM row is
/// all the E2EE layer needs to bootstrap itself.
const SEEDED_FRIENDSHIPS: &[(&str, &str, Uuid)] = &[(
    "alice",
    "bob",
    Uuid::from_u128(0xa11ceb0b_0000_4000_8000_000000000001),
)];

fn fixture(key: &str) -> Option<&'static Fixture> {
    FIXTURES.iter().find(|f| f.key == key)
}

fn scheme_for(domain: &str) -> &'static str {
    if domain.starts_with("localhost") || domain.starts_with("127.0.0.1") {
        "http"
    } else {
        "https"
    }
}

fn actor_uri(username: &str, domain: &str) -> String {
    format!("{}://{}/users/{}", scheme_for(domain), domain, username)
}

#[tokio::main]
async fn main() -> Result<()> {
    let names: Vec<String> = env::args().skip(1).collect();
    if names.is_empty() {
        return Err(anyhow!("Usage: dev-inject-data <alice|bob|pierre>..."));
    }
    let fixtures = names
        .iter()
        .map(|name| {
            fixture(name).ok_or_else(|| {
                anyhow!("Unknown fixture: {name} (expected 'alice', 'bob' or 'pierre')")
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let database_url = env::var("DATABASE_URL")
        .context("DATABASE_URL must be set (`make alice-seed` / `make bob-seed` build it)")?;
    let domain =
        env::var("DOMAIN").context("DOMAIN must be set (matches the IdP's configured domain)")?;

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .context("connecting to Postgres")?;

    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .context("applying migrations")?;

    let mut seeded: Vec<(&Fixture, Uuid)> = Vec::new();
    for fixture in &fixtures {
        let password_hash = hash_password(fixture.password)?;
        let user_id = upsert_user(&pool, fixture, &password_hash, &domain).await?;
        seeded.push((fixture, user_id));

        println!(
            "dev-inject-data: seeded {} ({}) into {}",
            fixture.display_name, fixture.email, database_url
        );
    }

    // Before writing friendships: drop rows left behind by a previous
    // generation of these fixtures, so the friend list doesn't end up with two
    // Bobs. Must run after the user upsert (which heals the handles) and
    // before the seeding (which would otherwise delete what it just wrote).
    prune_superseded_fixture_rows(&pool).await?;

    seed_friendships(&pool, &seeded, &domain).await?;

    Ok(())
}

/// Deletes rows pointing at a handle a fixture *used* to own.
///
/// Fixture handles were random (`Bob_w2_TK`) before they were pinned, and
/// `upsert_user` rewrites them in place on an existing database. Everything
/// keyed to the old `actor_uri` survives that rewrite: the friendship Alice
/// accepted against the old Bob, the DM they shared, the remote-actor cache
/// entry. None of it resolves any more — the peer instance no longer serves
/// that handle — so the friend list would show a live Bob next to a dead one.
///
/// A superseded handle is one on the fixture's own instance, prefixed with the
/// fixture's display name in any case (`Alice_dev` before the handle rules,
/// `alice_dev01` after), that isn't the handle the fixture holds now. In a dev
/// database those are by construction earlier generations of this seed.
async fn prune_superseded_fixture_rows(pool: &PgPool) -> Result<()> {
    for fixture in FIXTURES {
        let canonical = actor_uri(fixture.username, fixture.home_domain);
        // `\_` keeps LIKE from reading the handle separator as a wildcard.
        let superseded = format!(
            "{}://{}/users/{}\\_%",
            scheme_for(fixture.home_domain),
            fixture.home_domain,
            fixture.display_name
        );

        // Conversations go first and whole: a DM whose other member is a dead
        // handle is unusable, and ON DELETE CASCADE clears its members,
        // messages and read marks with it.
        let conversations = sqlx::query(
            r#"
            DELETE FROM conversations
            WHERE id IN (
                SELECT conversation_id FROM conversation_members
                WHERE actor_uri ILIKE $1 AND actor_uri <> $2
            )
            "#,
        )
        .bind(&superseded)
        .bind(&canonical)
        .execute(pool)
        .await
        .context("pruning conversations with a superseded fixture member")?;

        let friendships = sqlx::query(
            "DELETE FROM friendships WHERE friend_actor_uri ILIKE $1 AND friend_actor_uri <> $2",
        )
        .bind(&superseded)
        .bind(&canonical)
        .execute(pool)
        .await
        .context("pruning superseded fixture friendships")?;

        sqlx::query("DELETE FROM remote_actors WHERE actor_uri ILIKE $1 AND actor_uri <> $2")
            .bind(&superseded)
            .bind(&canonical)
            .execute(pool)
            .await
            .context("pruning superseded fixture remote actors")?;

        let (conversations, friendships) =
            (conversations.rows_affected(), friendships.rows_affected());
        if conversations > 0 || friendships > 0 {
            println!(
                "dev-inject-data: pruned {conversations} conversation(s) and {friendships} \
                 friendship(s) left by an earlier {} handle",
                fixture.display_name
            );
        }
    }
    Ok(())
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(65536, 3, 4, None).map_err(|e| anyhow!("argon2 params: {e}"))?,
    );
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("hashing password: {e}"))?
        .to_string())
}

/// Upserts the user and returns its id — the existing row's id on conflict,
/// since the primary key can't move without orphaning everything that
/// references it.
///
/// The handle columns are part of the `DO UPDATE` set so a database seeded by
/// an older build (which minted `Name_<nanoid>` handles) is healed in place
/// rather than keeping a URI the peer instance can't predict. Anything already
/// keyed to the old `actor_uri` — stale conversations, messages — is left
/// behind; wipe the volume (`make alice-down-v`) if that matters.
async fn upsert_user(
    pool: &PgPool,
    fixture: &Fixture,
    password_hash: &str,
    domain: &str,
) -> Result<Uuid> {
    let actor_uri = actor_uri(fixture.username, domain);
    let inbox_url = format!("{actor_uri}/inbox");
    let outbox_url = format!("{actor_uri}/outbox");
    let id = Uuid::new_v4();

    let user_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO users (
            id, username, email, password_hash,
            actor_uri, inbox_url, outbox_url,
            display_name, email_verified_at, is_admin
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), $9)
        ON CONFLICT (email) DO UPDATE SET
            password_hash      = EXCLUDED.password_hash,
            display_name       = EXCLUDED.display_name,
            username           = EXCLUDED.username,
            actor_uri          = EXCLUDED.actor_uri,
            inbox_url          = EXCLUDED.inbox_url,
            outbox_url         = EXCLUDED.outbox_url,
            email_verified_at  = now(),
            is_admin           = EXCLUDED.is_admin
        RETURNING id
        "#,
    )
    .bind(id)
    .bind(fixture.username)
    .bind(fixture.email)
    .bind(password_hash)
    .bind(&actor_uri)
    .bind(&inbox_url)
    .bind(&outbox_url)
    .bind(fixture.display_name)
    .bind(fixture.admin)
    .fetch_one(pool)
    .await
    .context("upserting user row")?;

    Ok(user_id)
}

/// Writes this database's half of every [`SEEDED_FRIENDSHIPS`] pair that
/// involves a fixture we just seeded.
async fn seed_friendships(pool: &PgPool, seeded: &[(&Fixture, Uuid)], domain: &str) -> Result<()> {
    for (owner, owner_id) in seeded {
        for (a, b, conversation_id) in SEEDED_FRIENDSHIPS {
            let peer_key = match (*a == owner.key, *b == owner.key) {
                (true, _) => *b,
                (_, true) => *a,
                _ => continue,
            };

            // The pair's URIs are derived from the fixtures' declared home
            // domains, so seeding a fixture somewhere other than its own
            // instance would write a friendship pointing at a URI this
            // deployment never serves. Skip rather than write a dangling row.
            if owner.home_domain != domain {
                eprintln!(
                    "dev-inject-data: {} seeded into {domain} but its fixture lives on {} \
                     — skipping the {a}↔{b} friendship",
                    owner.display_name, owner.home_domain
                );
                continue;
            }

            let peer = fixture(peer_key).ok_or_else(|| {
                anyhow!("SEEDED_FRIENDSHIPS references unknown fixture {peer_key}")
            })?;

            seed_friendship_half(pool, owner, *owner_id, peer, *conversation_id, domain).await?;

            println!(
                "dev-inject-data: {} is friends with {} (DM {conversation_id})",
                owner.display_name, peer.display_name
            );
        }
    }
    Ok(())
}

/// Seeds the rows the *owner's* instance needs to consider `peer` an accepted
/// friend: the remote-actor cache entry (federated peers only), the friendship
/// itself, and the DM both sides share.
async fn seed_friendship_half(
    pool: &PgPool,
    owner: &Fixture,
    owner_id: Uuid,
    peer: &Fixture,
    conversation_id: Uuid,
    domain: &str,
) -> Result<()> {
    let owner_uri = actor_uri(owner.username, domain);
    let peer_uri = actor_uri(peer.username, peer.home_domain);

    // A local friend is resolved straight off the `users` table by the friend
    // list's LEFT JOIN, and `instance` falls back to 'local'. Only a federated
    // one needs the cache row.
    if peer.home_domain != domain {
        sqlx::query(
            r#"
            INSERT INTO remote_actors (actor_uri, inbox_url, instance, display_name)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (actor_uri) DO UPDATE SET
                inbox_url    = COALESCE(EXCLUDED.inbox_url, remote_actors.inbox_url),
                display_name = EXCLUDED.display_name,
                fetched_at   = now(),
                updated_at   = now()
            "#,
        )
        .bind(&peer_uri)
        .bind(format!("{peer_uri}/inbox"))
        .bind(peer.home_domain)
        .bind(peer.display_name)
        .execute(pool)
        .await
        .context("upserting remote actor for seeded friendship")?;
    }

    sqlx::query(
        r#"
        INSERT INTO friendships (owner_user_id, friend_actor_uri, status, direction, accepted_at)
        VALUES ($1, $2, 'accepted', 'incoming', now())
        ON CONFLICT (owner_user_id, friend_actor_uri) DO UPDATE SET
            status      = 'accepted',
            accepted_at = COALESCE(friendships.accepted_at, now()),
            updated_at  = now()
        "#,
    )
    .bind(owner_id)
    .bind(&peer_uri)
    .execute(pool)
    .await
    .context("upserting seeded friendship")?;

    sqlx::query(
        r#"
        INSERT INTO conversations (id, kind, name)
        VALUES ($1, 'dm', NULL)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(conversation_id)
    .execute(pool)
    .await
    .context("creating seeded DM conversation")?;

    for member_uri in [&owner_uri, &peer_uri] {
        sqlx::query(
            r#"
            INSERT INTO conversation_members (conversation_id, actor_uri)
            VALUES ($1, $2)
            ON CONFLICT (conversation_id, actor_uri) DO UPDATE SET left_at = NULL
            "#,
        )
        .bind(conversation_id)
        .bind(member_uri)
        .execute(pool)
        .await
        .context("adding member to seeded DM conversation")?;
    }

    Ok(())
}
