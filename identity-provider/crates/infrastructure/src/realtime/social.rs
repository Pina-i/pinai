use std::sync::Arc;

use domain::UserId;
use domain::social::{FriendshipEvent, SocialNotifier};
use idp_realtime::{FriendshipPayload, WsEvent, WsHub};

/// Pushes `friend_request` / `friend_accepted` / `friend_removed` to the account's live sessions.
pub struct HubSocialNotifier {
    hub: Arc<WsHub>,
}

impl HubSocialNotifier {
    pub fn new(hub: Arc<WsHub>) -> Self {
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
        self.hub
            .send_to_user(&to.as_uuid(), WsEvent::FriendRequest(payload(event)));
    }

    fn friend_accepted(&self, to: UserId, event: &FriendshipEvent) {
        self.hub
            .send_to_user(&to.as_uuid(), WsEvent::FriendAccepted(payload(event)));
    }

    fn friend_removed(&self, to: UserId, event: &FriendshipEvent) {
        self.hub
            .send_to_user(&to.as_uuid(), WsEvent::FriendRemoved(payload(event)));
    }
}
