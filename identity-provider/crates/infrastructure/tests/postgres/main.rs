//! Adapter tests against a real Postgres — one module per port.

mod auth;
mod e2ee;
mod identity;
mod messaging;
mod presence;
mod profile;
mod reach;
mod settings;
mod social;

use domain::UserId;
use domain::identity::{Account, ActorUri};
use sqlx::PgPool;

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_migrations_apply_to_an_empty_database(pool: PgPool) {
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(one, 1);
}

/// A local account, for tables that reference `users`.
async fn a_user(pool: &PgPool) -> UserId {
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, 'x') RETURNING id",
    )
    .bind(format!("user_{suffix}"))
    .bind(format!("{suffix}@idp.test"))
    .fetch_one(pool)
    .await
    .expect("seed a user");
    id.into()
}

/// A local account with its actor URI, for the contexts that address accounts by URI.
async fn an_account(pool: &PgPool, name: &str) -> Account {
    let username = format!("{name}_{}", &uuid::Uuid::new_v4().simple().to_string()[..5]);
    let actor_uri = format!("http://localhost:8080/users/{username}");
    let id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash, display_name, actor_uri) \
         VALUES ($1, $2, 'x', $3, $4) RETURNING id",
    )
    .bind(&username)
    .bind(format!("{username}@idp.test"))
    .bind(name)
    .bind(&actor_uri)
    .fetch_one(pool)
    .await
    .expect("seed an account");
    Account {
        id: id.into(),
        actor_uri: ActorUri::parse(&actor_uri).unwrap(),
        username,
        display_name: Some(name.to_owned()),
        avatar_url: None,
    }
}
