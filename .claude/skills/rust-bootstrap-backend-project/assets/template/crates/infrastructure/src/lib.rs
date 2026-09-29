pub mod postgres;

/// Every migration, embedded. Run at startup by `app`; reused by `#[sqlx::test]`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");
