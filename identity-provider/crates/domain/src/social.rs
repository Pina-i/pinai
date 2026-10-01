//! The friend graph: requests, acceptance, the end of a friendship, blocks, and who may reach an
//! account — see identity-provider/specs/01-identity-federation.md § 1.7.

mod block;
mod error;
mod friendship;
mod ports;
mod reach;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use block::{BlockedActor, Ending, MAX_BLOCKS, room_for};
pub use error::SocialError;
pub use friendship::{Direction, Friendship, FriendshipStatus};
pub use ports::{
    ContactPolicies, FriendPresence, FriendView, FriendshipEvent, LocalRequest, Reachability,
    SocialFederation, SocialGraph, SocialNotifier, SocialStoreError, Unfriended,
};
pub use reach::{ContactPolicy, Relation, Unreachable, YouBlocked};
