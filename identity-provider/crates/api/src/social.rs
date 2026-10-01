//! Friend requests and the friends list — see identity-provider/specs/01-identity-federation.md.

use std::sync::Arc;

use application::social::{
    AcceptFriendRequest, DeclineFriendRequest, IncomingRequest, ListFriends, ListIncomingRequests,
    SendFriendRequest, Unfriend,
};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use domain::FriendshipId;
use domain::identity::{ActorUri, InstanceOrigin};
use domain::social::{FriendView, MAX_BLOCKS, SocialError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ApiError;
use crate::auth::Authenticated;

#[derive(Deserialize)]
pub struct FriendRequestBody {
    /// A bare name for a local account, or `user@domain`.
    address: String,
}

#[derive(Serialize)]
pub struct FriendshipCreated {
    friendship_id: Uuid,
    status: &'static str,
}

#[derive(Serialize)]
pub struct IncomingRequestBody {
    friendship_id: Uuid,
    actor_uri: String,
    username: String,
    display_name: Option<String>,
    status: &'static str,
}

#[derive(Serialize)]
pub struct FriendBody {
    username: Option<String>,
    display_name: Option<String>,
    avatar_url: Option<String>,
    friend_actor_uri: String,
    instance: String,
}

pub async fn send_request(
    State(send): State<Arc<SendFriendRequest>>,
    State(origin): State<InstanceOrigin>,
    Authenticated(user): Authenticated,
    Json(body): Json<FriendRequestBody>,
) -> Result<(StatusCode, Json<FriendshipCreated>), ApiError> {
    let recipient = origin
        .resolve(&body.address)
        .map_err(|_| SocialError::UserNotFound)?;
    let sent = send.execute(user, recipient).await?;
    tracing::info!(user_id = %user, friendship_id = %sent.id, "friend request sent");
    Ok((
        StatusCode::CREATED,
        Json(FriendshipCreated {
            friendship_id: sent.id.as_uuid(),
            status: sent.status.as_str(),
        }),
    ))
}

pub async fn incoming(
    State(list): State<Arc<ListIncomingRequests>>,
    Authenticated(user): Authenticated,
) -> Result<Json<Vec<IncomingRequestBody>>, ApiError> {
    let incoming = list.execute(user).await?;
    Ok(Json(
        incoming
            .into_iter()
            .map(IncomingRequestBody::from)
            .collect(),
    ))
}

pub async fn accept(
    State(accept): State<Arc<AcceptFriendRequest>>,
    Authenticated(user): Authenticated,
    Path(request): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    accept
        .execute(user, FriendshipId::from(request))
        .await
        .map_err(answer_refused("accept"))?;
    tracing::info!(user_id = %user, friendship_id = %request, "friend request accepted");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn reject(
    State(decline): State<Arc<DeclineFriendRequest>>,
    Authenticated(user): Authenticated,
    Path(request): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    decline
        .execute(user, FriendshipId::from(request))
        .await
        .map_err(answer_refused("reject"))?;
    tracing::info!(user_id = %user, friendship_id = %request, "friend request declined");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn unfriend(
    State(unfriend): State<Arc<Unfriend>>,
    Authenticated(user): Authenticated,
    Path(friend): Path<String>,
) -> Result<StatusCode, ApiError> {
    let friend = ActorUri::parse(&friend).map_err(|_| SocialError::NotFriends)?;
    unfriend.execute(user, friend).await?;
    tracing::info!(user_id = %user, "unfriended");
    Ok(StatusCode::NO_CONTENT)
}

pub async fn friends(
    State(list): State<Arc<ListFriends>>,
    Authenticated(user): Authenticated,
) -> Result<Json<Vec<FriendBody>>, ApiError> {
    let friends = list.execute(user).await?;
    Ok(Json(friends.into_iter().map(FriendBody::from).collect()))
}

/// The refusal names the route's verb, as the web client shows it.
fn answer_refused(verb: &'static str) -> impl Fn(SocialError) -> ApiError {
    move |error| match error {
        SocialError::NotYours => {
            ApiError::bad_request(format!("Not authorised to {verb} this request"))
        }
        other => other.into(),
    }
}

impl From<IncomingRequest> for IncomingRequestBody {
    fn from(request: IncomingRequest) -> Self {
        Self {
            friendship_id: request.friendship.as_uuid(),
            actor_uri: request.actor_uri.as_str().to_owned(),
            username: request.username,
            display_name: request.display_name,
            status: "pending",
        }
    }
}

impl From<FriendView> for FriendBody {
    fn from(friend: FriendView) -> Self {
        Self {
            username: friend.username,
            display_name: friend.display_name,
            avatar_url: friend.avatar_url,
            friend_actor_uri: friend.actor_uri.as_str().to_owned(),
            instance: friend.instance,
        }
    }
}

impl From<SocialError> for ApiError {
    fn from(error: SocialError) -> Self {
        match error {
            SocialError::UserNotFound => ApiError::not_found("User not found"),
            SocialError::SelfRequest => ApiError::bad_request("Cannot friend yourself"),
            SocialError::AlreadyFriends => ApiError::bad_request("Already friends"),
            SocialError::NotFriends => ApiError::not_found("Friendship not found"),
            SocialError::RequestNotFound => ApiError::not_found("Friend request not found"),
            SocialError::NotYours => ApiError::bad_request("Not authorised to answer this request"),
            SocialError::NotAnIncomingRequest => {
                ApiError::bad_request("Not an incoming friend request")
            }
            SocialError::SelfBlock => ApiError::bad_request("You can't block yourself"),
            SocialError::NotBlocked => ApiError::not_found("Not blocked"),
            SocialError::YouBlocked => ApiError::bad_request("Unblock this user first"),
            SocialError::BlockListFull => {
                ApiError::bad_request(format!("You can't block more than {MAX_BLOCKS} people"))
            }
            SocialError::PeerNotAllowed(reason) => {
                ApiError::new(StatusCode::FORBIDDEN, "access_denied", reason)
            }
            SocialError::PeerUnavailable(reason) => ApiError::upstream(anyhow::anyhow!(reason)),
            SocialError::Unexpected(e) => ApiError::internal(e),
        }
    }
}

#[cfg(test)]
mod tests;
