pub mod models;
pub mod repos;

pub use sqlx::PgPool;

/// Run all pending SQLx migrations.
/// The path is relative to this crate's root (crates/db/), so
/// "../../migrations" resolves to identity-provider/migrations/.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("../../migrations").run(pool).await
}
