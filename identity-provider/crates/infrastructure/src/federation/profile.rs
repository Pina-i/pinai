//! `Update{Person}`, delivered best-effort — see
//! identity-provider/specs/01-identity-federation.md § Federation delivery semantics.

use std::sync::Arc;

use activitypub::Activity;
use domain::identity::{Account, RemoteActor};
use domain::profile::ProfileFederation;
use federation_transport::UrlPolicy;
use jwt_utils::EdKeyPair;
use serde_json::Value;

use super::delivery::SignedDelivery;

/// Signs the account's name and avatar as the account and posts them to the friend's inbox in
/// the background.
pub struct ApProfileFederation {
    delivery: SignedDelivery,
}

impl ApProfileFederation {
    pub fn new(keypair: Arc<EdKeyPair>, policy: UrlPolicy) -> Self {
        Self {
            delivery: SignedDelivery::new(keypair, policy),
        }
    }
}

impl ProfileFederation for ApProfileFederation {
    fn send_update(&self, from: &Account, to: &RemoteActor) {
        self.delivery
            .post_in_background(&from.actor_uri, &to.inbox, update_person(from));
    }
}

fn update_person(account: &Account) -> Value {
    let activity = Activity::update_person(
        account.actor_uri.as_str(),
        &account.username,
        account.display_name.as_deref(),
        account.avatar_url.as_deref(),
    );
    serde_json::to_value(activity).expect("an activity is plain JSON")
}

#[cfg(test)]
mod tests;
