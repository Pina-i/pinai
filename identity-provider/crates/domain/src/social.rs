//! The friend graph: requests, acceptance, the end of a friendship, blocks, who may reach an
//! account — see identity-provider/specs/social.md § 2 —, and finding people to befriend —
//! identity-provider/specs/identity.md § 7.

mod block;
mod error;
mod friendship;
mod people;
mod ports;
mod reach;
mod search;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use block::{BlockedActor, Ending, MAX_BLOCKS, room_for};
pub use error::SocialError;
pub use friendship::{Direction, Friendship, FriendshipStatus};
pub use people::{FoundPerson, GroupPerson, PeopleFound, Standing, Ties};
pub use ports::{
    ContactPolicies, FriendPresence, FriendView, FriendshipEvent, LocalRequest, PeopleSearch,
    Reachability, SocialFederation, SocialGraph, SocialNotifier, SocialStoreError, Unfriended,
};
pub use reach::{ContactPolicy, Relation, Unreachable, YouBlocked};
pub use search::SearchQuery;
