use std::sync::Arc;

use domain::UserId;
use domain::profile::{ProfileNotifier, PublicProfile};
use idp_realtime::{ProfileUpdatePayload, WsEvent, WsHub};

/// Pushes `friend_profile_updated` to every live session of the account.
pub struct HubProfileNotifier {
    hub: Arc<WsHub>,
}

impl HubProfileNotifier {
    pub fn new(hub: Arc<WsHub>) -> Self {
        Self { hub }
    }
}

impl ProfileNotifier for HubProfileNotifier {
    fn friend_profile_updated(&self, to: UserId, profile: &PublicProfile) {
        self.hub.send_to_user(
            &to.as_uuid(),
            WsEvent::FriendProfileUpdated(ProfileUpdatePayload {
                actor_uri: profile.actor.as_str().to_owned(),
                display_name: profile.display_name.clone(),
                avatar_url: profile.avatar_url.clone(),
            }),
        );
    }
}
