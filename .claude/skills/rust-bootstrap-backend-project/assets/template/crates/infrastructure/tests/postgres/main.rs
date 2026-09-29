//! Adapter tests against a real Postgres — one module per port.

use sqlx::PgPool;

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_migrations_apply_to_an_empty_database(pool: PgPool) {
    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(one, 1);
}
