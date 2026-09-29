//! User search — the friend graph itself lives in the layer crates (`domain::social`).

pub mod handlers;

pub use handlers::{search_users, SearchQuery, UserSummary};
