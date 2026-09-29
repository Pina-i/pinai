//! The friend graph: requests, acceptance, and the end of a friendship.

mod error;
mod friendship;
mod ports;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use error::SocialError;
pub use friendship::{Direction, Friendship, FriendshipStatus};
pub use ports::{
    FriendPresence, FriendView, FriendshipEvent, LocalRequest, SocialFederation, SocialGraph,
    SocialNotifier, SocialStoreError, Unfriended,
};
