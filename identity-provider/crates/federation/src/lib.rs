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
//! - `DELETE /api/friends/{actor_uri}`       — Unfriend (both sides; Undo{Follow} to a remote IdP)
//! - `GET    /api/friends/incoming`          — Pending friend requests aimed at me
//! - `POST   /api/friends/{id}/accept`       — Accept a friend request
//! - `DELETE /api/friends/{id}/reject`       — Decline a pending request (Reject{Follow} to a remote IdP)
//! - `GET    /api/friends`                   — My friends list
//! - `POST   /api/dm`                        — Send a direct message (supports replies via reply_to_id)
//! - `GET    /api/dm`                        — List DM conversations
//! - `GET    /api/dm/:address`               — Conversation with a specific user (includes reactions + reply previews)
//! - `POST   /api/dm/:message_id/reactions`  — Add a reaction to a message
//! - `DELETE /api/dm/:message_id/reactions`  — Remove a reaction from a message

pub mod actor;
pub mod actors;
pub mod attachments;
pub mod auth;
pub mod delivery;
pub mod friendship;
pub mod http_signature;
pub mod inbox;
pub mod mls;
pub mod outbox;
pub mod profile;
pub mod webfinger;
