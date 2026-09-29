pub mod attestation;
pub mod auth;
pub mod blob_tokens;
pub mod federation;
pub mod postgres;
pub mod presence;
pub mod realtime;
pub mod storage;

/// Every migration, embedded: run at startup and by `#[sqlx::test]`. `build.rs` rebuilds this crate
/// when a migration is added, so a binary never runs a stale set.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");
