use std::sync::Arc;

use connections::Hub;
use domain::UserId;
use domain::social::{FriendshipEvent, SocialNotifier};

use super::events::{BlocksUpdatedPayload, FriendshipPayload, WsEvent};

/// Pushes `friend_request` / `friend_accepted` / `friend_removed` / `blocks_updated` to the
/// account's live sessions.
pub struct HubSocialNotifier {
    hub: Arc<Hub>,
}

impl HubSocialNotifier {
    pub fn new(hub: Arc<Hub>) -> Self {
        Self { hub }
    }
}

fn payload(event: &FriendshipEvent) -> FriendshipPayload {
    FriendshipPayload {
        friendship_id: event.friendship.as_uuid(),
        actor_uri: event.actor_uri.as_str().to_owned(),
        username: event.username.clone(),
        display_name: event.display_name.clone(),
        conversation_id: event.conversation.map(|c| c.as_uuid()),
    }
}

impl SocialNotifier for HubSocialNotifier {
    fn friend_request(&self, to: UserId, event: &FriendshipEvent) {
        super::push(
            &self.hub,
            &to.as_uuid(),
            WsEvent::FriendRequest(payload(event)),
        );
    }

    fn friend_accepted(&self, to: UserId, event: &FriendshipEvent) {
        super::push(
            &self.hub,
            &to.as_uuid(),
            WsEvent::FriendAccepted(payload(event)),
        );
    }

    fn friend_removed(&self, to: UserId, event: &FriendshipEvent) {
        super::push(
            &self.hub,
            &to.as_uuid(),
            WsEvent::FriendRemoved(payload(event)),
        );
    }

    fn blocks_updated(&self, to: UserId) {
        super::push(
            &self.hub,
            &to.as_uuid(),
            WsEvent::BlocksUpdated(BlocksUpdatedPayload {}),
        );
    }
}
