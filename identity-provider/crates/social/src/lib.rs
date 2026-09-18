//! Social graph domain: friend requests, accept/reject, unfriend, friend list,
//! user search. Outbound federation is delegated to `idp-federation`. Inbound
//! Follow/Accept activities are persisted by `idp-federation::inbox` directly
//! (a future revision will route this through the broker per ADR-0001).

pub mod handlers;

pub use handlers::{
    accept_friendship, delete_friendship, get_friends, get_incoming_requests, post_friend_request,
    reject_friendship, search_users, FriendRequest, FriendRequestSummary, FriendResponse,
    SearchQuery, UserSummary,
};
