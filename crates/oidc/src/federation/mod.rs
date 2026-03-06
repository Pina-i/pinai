//! ActivityPub federation module.
//!
//! Exposes two groups of endpoints:
//!
//! **ActivityPub (public)**
//! - `GET  /.well-known/webfinger`          — WebFinger discovery
//! - `GET  /users/:handle`                  — Actor profile
//! - `POST /users/:handle/inbox`            — Receive AP activities
//! - `GET  /users/:handle/outbox`           — Outbox (OrderedCollection)
//! - `GET  /users/:handle/followers`        — Followers collection
//! - `GET  /users/:handle/following`        — Following collection
//!
//! **REST API (Bearer-auth required, for the local web-client)**
//! - `GET  /api/users/search`               — Search users
//! - `POST /api/follow`                     — Send follow request
//! - `DELETE /api/follow/:handle`           — Unfollow
//! - `GET  /api/follow/incoming`            — Pending follow requests aimed at me
//! - `POST /api/follow/:follow_id/accept`   — Accept a follow request
//! - `POST /api/follow/:follow_id/reject`   — Reject a follow request
//! - `GET  /api/following`                  — People I follow (accepted)
//! - `GET  /api/followers`                  — My accepted followers
//! - `POST /api/dm`                         — Send a direct message
//! - `GET  /api/dm`                         — List DM conversations
//! - `GET  /api/dm/:handle`                 — Conversation with a specific user

pub mod actor;
pub(crate) mod delivery;
pub mod follow;
pub mod inbox;
pub mod messages;
pub mod outbox;
pub mod webfinger;

/// Shared auth helper — validates Bearer token and returns the caller's user UUID.
pub(crate) mod auth;
