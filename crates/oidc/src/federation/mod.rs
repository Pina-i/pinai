//! ActivityPub federation module.
//!
//! Exposes two groups of endpoints:
//!
//! **ActivityPub (public)**
//! - `GET  /.well-known/webfinger`          — WebFinger discovery
//! - `GET  /users/:username`                — Actor profile
//! - `POST /users/:username/inbox`          — Receive AP activities
//! - `GET  /users/:username/outbox`         — Outbox (OrderedCollection)
//! - `GET  /users/:username/followers`      — Followers collection
//! - `GET  /users/:username/following`      — Following collection
//!
//! **REST API (Bearer-auth required, for the local web-client)**
//! - `GET    /api/users/search`             — Search users
//! - `POST   /api/friends/request`          — Send friend request
//! - `DELETE /api/friends/{actor_uri}`       — Unfriend
//! - `GET    /api/friends/incoming`          — Pending friend requests aimed at me
//! - `POST   /api/friends/{id}/accept`       — Accept a friend request
//! - `DELETE /api/friends/{id}/reject`       — Reject (delete) a friend request
//! - `GET    /api/friends`                   — My friends list
//! - `POST   /api/dm`                        — Send a direct message
//! - `GET    /api/dm`                        — List DM conversations
//! - `GET    /api/dm/:address`               — Conversation with a specific user

pub mod actor;
pub(crate) mod delivery;
pub mod friendship;
pub mod inbox;
pub mod messages;
pub mod outbox;
pub mod webfinger;

/// Shared auth helper — validates Bearer token and returns the caller's user UUID.
pub(crate) mod auth;
