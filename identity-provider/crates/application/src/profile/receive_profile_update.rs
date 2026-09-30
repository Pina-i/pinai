use std::sync::Arc;

use domain::identity::{ActorUri, InstanceOrigin};
use domain::profile::{
    PeerProfiles, ProfileAudience, ProfileError, ProfileNotifier, PublicProfile,
};

/// An inbound `Update{Person}`: a peer's account's name and avatar, kept and pushed to its
/// friends here. Only the account itself tells it, and never of an account here: the signature
/// proves who sent the activity, not whose profile it names.
pub struct ReceiveProfileUpdate {
    origin: InstanceOrigin,
    peers: Arc<dyn PeerProfiles>,
    audience: Arc<dyn ProfileAudience>,
    notifier: Arc<dyn ProfileNotifier>,
}

impl ReceiveProfileUpdate {
    pub fn new(
        origin: InstanceOrigin,
        peers: Arc<dyn PeerProfiles>,
        audience: Arc<dyn ProfileAudience>,
        notifier: Arc<dyn ProfileNotifier>,
    ) -> Self {
        Self {
            origin,
            peers,
            audience,
            notifier,
        }
    }

    /// `sender` is the actor whose key signed the activity.
    pub async fn execute(
        &self,
        sender: &ActorUri,
        profile: PublicProfile,
    ) -> Result<(), ProfileError> {
        if &profile.actor != sender || self.origin.owns(sender) {
            return Err(ProfileError::NotItsOwn);
        }
        let profile = profile.within_limits();
        self.peers.record(&profile).await?;
        for friend in self.audience.friends_here(&profile.actor).await? {
            self.notifier.friend_profile_updated(friend, &profile);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
