use std::sync::Arc;

use connections::Hub;
use domain::UserId;
use domain::profile::{ProfileNotifier, PublicProfile};

use super::events::{ProfileUpdatePayload, WsEvent};

/// Pushes `friend_profile_updated` to every live session of the account.
pub struct HubProfileNotifier {
    hub: Arc<Hub>,
}

impl HubProfileNotifier {
    pub fn new(hub: Arc<Hub>) -> Self {
        Self { hub }
    }
}

impl ProfileNotifier for HubProfileNotifier {
    fn friend_profile_updated(&self, to: UserId, profile: &PublicProfile) {
        super::push(
            &self.hub,
            &to.as_uuid(),
            WsEvent::FriendProfileUpdated(ProfileUpdatePayload {
                actor_uri: profile.actor.as_str().to_owned(),
                display_name: profile.display_name.clone(),
                avatar_url: profile.avatar_url.clone(),
            }),
        );
    }
}
