//! MLS-based E2EE: key directory + Delivery Service.
//!
//! ## Phase 1 — key directory
//! - Per-user identity-key publication (MSK / SSK / USK fingerprints).
//! - Single-use KeyPackage stash (cap, refill threshold, lifetime — see
//!   `idp_config::Config::e2ee_*`).
//! - Optional passphrase-wrapped Recovery Key blob.
//!
//! ## Phase 2 — Delivery Service
//! - Per-conversation total order of MLS Commits, with `409 Conflict`
//!   carrying the winning row on race.
//! - Pull-based catch-up via `?since=<epoch>`.
//! - Outbound queue for MLS Welcomes, atomically claim-and-consume per
//!   `(user, device)` pair.
//! - Inbound AP routing handled by `crates/federation/src/inbox.rs` based
//!   on `mediaType: application/mls` + `mlsKind` discriminator.
//!
//! Server stores public-key material only — every private key (MSK private,
//! SSK private, USK private, per-device leaf) lives exclusively on user
//! devices. The Recovery Key ciphertext is opaque to the server; the
//! Argon2id-derived KEK never leaves the user's device.
//!
//! See `specs/05-e2ee.md` for the protocol-level design.

pub mod attestation;
pub mod auth;
pub mod devices;
pub mod ds;
pub mod history;
pub mod packages;
pub mod rate_limit;

pub use devices::{get_devices, register_device, revoke_device};
pub use ds::{get_commits_since, get_welcomes, post_commit, post_welcome};
pub use history::{
    delete_all as delete_history, get_page as get_history_page, get_salt as get_history_salt,
    post_batch as post_history_batch, post_salt as post_history_salt,
};
pub use packages::{get_packages_status, post_packages, post_packages_claim};
