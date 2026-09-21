//! Dev-only seeder. Inserts fully-verified users into the local IdP database
//! so `make alice` / `make bob` come up with sign-in ready accounts — no signup
//! OTP dance required. Takes one or more fixture names; which IdP they land in
//! is decided by the sourced env, not by the name. Pierre seeds alongside Alice
//! so her instance has two local users, which is what testing a group
//! conversation without federation needs.
//!
//! Idempotent: re-running the seed against an existing user updates the
//! password hash + display name + flips `email_verified_at` back to the
//! current time. Applies sqlx migrations first so it can race the IdP's
//! own startup safely (whoever runs `MIGRATE` first wins; the other is a
//! no-op).
//!
//! Argon2id params mirror `crates/auth/src/register.rs` exactly — drift
//! here would create users the IdP can't authenticate.

use anyhow::{anyhow, Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHasher, Version,
};
use sqlx::postgres::PgPoolOptions;
use std::env;
use uuid::Uuid;

struct Fixture {
    display_name: &'static str,
    email: &'static str,
    password: &'static str,
}

const ALICE: Fixture = Fixture {
    display_name: "Alice",
    email: "akasatana83@hotmail.fr",
    password: "yonolulu",
};

const BOB: Fixture = Fixture {
    display_name: "Bob",
    email: "bob@test.fr",
    password: "yonolulu",
};

const PIERRE: Fixture = Fixture {
    display_name: "Pierre",
    email: "pierre@test.fr",
    password: "yonolulu",
};

fn fixture(name: &str) -> Option<Fixture> {
    match name {
        "alice" => Some(ALICE),
        "bob" => Some(BOB),
        "pierre" => Some(PIERRE),
        _ => None,
    }
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
        .context("DATABASE_URL must be set (source docker/.env.alice or .env.bob)")?;
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

    for fixture in &fixtures {
        let password_hash = hash_password(fixture.password)?;
        upsert_user(&pool, fixture, &password_hash, &domain).await?;

        println!(
            "dev-inject-data: seeded {} ({}) into {}",
            fixture.display_name, fixture.email, database_url
        );
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

async fn upsert_user(
    pool: &sqlx::PgPool,
    fixture: &Fixture,
    password_hash: &str,
    domain: &str,
) -> Result<()> {
    let scheme = if domain.starts_with("localhost") || domain.starts_with("127.0.0.1") {
        "http"
    } else {
        "https"
    };
    let base = format!("{scheme}://{domain}");
    let username = format!("{}_{}", fixture.display_name, nanoid::nanoid!(5));
    let actor_uri = format!("{base}/users/{username}");
    let inbox_url = format!("{base}/users/{username}/inbox");
    let outbox_url = format!("{base}/users/{username}/outbox");
    let id = Uuid::new_v4();

    sqlx::query(
        r#"
        INSERT INTO users (
            id, username, email, password_hash,
            actor_uri, inbox_url, outbox_url,
            display_name, email_verified_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
        ON CONFLICT (email) DO UPDATE SET
            password_hash      = EXCLUDED.password_hash,
            display_name       = EXCLUDED.display_name,
            email_verified_at  = now()
        "#,
    )
    .bind(id)
    .bind(&username)
    .bind(fixture.email)
    .bind(password_hash)
    .bind(&actor_uri)
    .bind(&inbox_url)
    .bind(&outbox_url)
    .bind(fixture.display_name)
    .execute(pool)
    .await
    .context("upserting user row")?;

    Ok(())
}
