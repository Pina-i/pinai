//! Friendship activities, delivered best-effort — see
//! identity-provider/specs/01-identity-federation.md § Federation delivery semantics.

use std::sync::Arc;

use activitypub::Activity;
use domain::identity::{Account, ActorUri, RemoteActor};
use domain::social::SocialFederation;
use domain::{ConversationId, FriendshipId};
use federation_transport::UrlPolicy;
use jwt_utils::EdKeyPair;
use serde_json::{Value, json};
use uuid::Uuid;

use super::delivery::SignedDelivery;

/// Signs each activity as its sender and posts it to the peer's inbox in the background.
pub struct ApSocialFederation {
    delivery: SignedDelivery,
}

impl ApSocialFederation {
    pub fn new(keypair: Arc<EdKeyPair>, policy: UrlPolicy) -> Self {
        Self {
            delivery: SignedDelivery::new(keypair, policy),
        }
    }

    fn deliver(&self, from: &Account, to: &RemoteActor, activity: Value) {
        self.delivery
            .post_in_background(&from.actor_uri, &to.inbox, activity);
    }
}

impl SocialFederation for ApSocialFederation {
    fn send_follow(&self, from: &Account, to: &RemoteActor) {
        self.deliver(from, to, follow(&from.actor_uri, &to.actor_uri));
    }

    fn send_undo_follow(&self, from: &Account, to: &RemoteActor) {
        self.deliver(from, to, undo_follow(&from.actor_uri, &to.actor_uri));
    }

    fn send_reject(&self, from: &Account, to: &RemoteActor, request: FriendshipId) {
        self.deliver(from, to, reject(&from.actor_uri, &to.actor_uri, request));
    }

    fn send_accept(
        &self,
        from: &Account,
        to: &RemoteActor,
        request: FriendshipId,
        conversation: ConversationId,
    ) {
        self.deliver(
            from,
            to,
            accept(&from.actor_uri, &to.actor_uri, request, conversation),
        );
    }
}

fn value(activity: Activity) -> Value {
    serde_json::to_value(activity).expect("an activity is plain JSON")
}

fn follow(from: &ActorUri, to: &ActorUri) -> Value {
    let id = format!("{from}/friendships/{}", Uuid::new_v4());
    value(Activity::follow(&id, from.as_str(), to.as_str()))
}

/// The Follow behind `request`, rebuilt for the answer to name it.
fn requested_follow(requester: &ActorUri, of: &ActorUri, request: FriendshipId) -> Value {
    let id = format!("{requester}/follows/{request}");
    value(Activity::follow(&id, requester.as_str(), of.as_str()))
}

fn accept(
    from: &ActorUri,
    requester: &ActorUri,
    request: FriendshipId,
    conversation: ConversationId,
) -> Value {
    let id = format!("{from}/accepts/{}", Uuid::new_v4());
    let follow = requested_follow(requester, from, request);
    let mut accept = value(Activity::accept(&id, from.as_str(), follow));
    // Pina'i extension: the requester's instance files the DM under the same id.
    accept["conversationId"] = json!(conversation.to_string());
    accept
}

fn reject(from: &ActorUri, requester: &ActorUri, request: FriendshipId) -> Value {
    let id = format!("{from}/rejects/{}", Uuid::new_v4());
    let follow = requested_follow(requester, from, request);
    value(Activity::reject(&id, from.as_str(), follow))
}

fn undo_follow(from: &ActorUri, friend: &ActorUri) -> Value {
    let id = format!("{from}/undos/{}", Uuid::new_v4());
    let follow = value(Activity::follow(
        &format!("{from}/follows/{}", Uuid::new_v4()),
        from.as_str(),
        friend.as_str(),
    ));
    value(Activity::undo_follow(&id, from.as_str(), follow))
}

#[cfg(test)]
mod tests;
