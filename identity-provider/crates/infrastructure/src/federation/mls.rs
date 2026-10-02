//! Commits and Welcomes for members on other instances — identity-provider/specs/05-e2ee.md § 5.

use std::sync::Arc;

use domain::e2ee::{Commit, MlsFederation, OutgoingWelcome};
use domain::identity::{ActorUri, RemoteActor};
use federation_transport::UrlPolicy;
use jwt_utils::EdKeyPair;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::delivery::SignedDelivery;
use super::inboxes::Inboxes;
use super::messaging::{mls_note, roster};

pub struct ApMlsFederation {
    delivery: SignedDelivery,
    inboxes: Arc<Inboxes>,
}

impl ApMlsFederation {
    pub fn new(keypair: Arc<EdKeyPair>, policy: UrlPolicy, inboxes: Arc<Inboxes>) -> Self {
        Self {
            delivery: SignedDelivery::new(keypair, policy),
            inboxes,
        }
    }
}

impl MlsFederation for ApMlsFederation {
    fn send_commit(&self, from: &ActorUri, to: &[ActorUri], commit: &Commit) {
        let posts = to
            .iter()
            .map(|member| (member.clone(), commit_activity(from, member, commit)))
            .collect();
        self.delivery
            .post_each_in_background(&self.inboxes, from, posts);
    }

    fn send_welcome(&self, from: &ActorUri, to: &RemoteActor, welcome: &OutgoingWelcome) {
        self.delivery.post_in_background(
            from,
            &to.inbox,
            welcome_activity(from, &to.actor_uri, welcome),
        );
    }
}

/// A `Create` around an MLS Note; neither is an object anyone fetches, so both get fresh ids.
fn create(from: &ActorUri, to: &ActorUri, note: impl FnOnce(&str) -> Value) -> Value {
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{from}/activities/{}", Uuid::new_v4()),
        "type": "Create",
        "actor": from.as_str(),
        "to": [to.as_str()],
        "object": note(&format!("{from}/objects/{}", Uuid::new_v4())),
    })
}

fn commit_activity(from: &ActorUri, to: &ActorUri, commit: &Commit) -> Value {
    let mut extra = Map::new();
    extra.insert("mlsEpoch".to_owned(), json!(commit.epoch.value()));
    create(from, to, |id| {
        mls_note(
            id,
            from,
            to,
            commit.conversation,
            commit.blob.as_bytes(),
            "commit",
            extra,
        )
    })
}

fn welcome_activity(from: &ActorUri, to: &ActorUri, welcome: &OutgoingWelcome) -> Value {
    let mut extra = Map::new();
    extra.insert(
        "mlsRecipientDeviceId".to_owned(),
        json!(welcome.device.to_string()),
    );
    if let Some(group) = &welcome.roster {
        extra.insert("mlsGroup".to_owned(), roster(group));
    }
    create(from, to, |id| {
        mls_note(
            id,
            from,
            to,
            welcome.conversation,
            welcome.blob.as_bytes(),
            "welcome",
            extra,
        )
    })
}

#[cfg(test)]
mod tests;
