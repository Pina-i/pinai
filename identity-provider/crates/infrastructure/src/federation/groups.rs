//! A group's changes for the other instances holding its members: `Add`, `Remove`, `Leave`, and
//! `Update` of the group's name or of a member's role — identity-provider/specs/03-direct-messages.md
//! § 10, Group changes.

use std::sync::Arc;

use domain::identity::{Account, ActorUri};
use domain::messaging::{GroupChange, GroupChangeKind, GroupFederation};
use federation_transport::UrlPolicy;
use jwt_utils::EdKeyPair;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use super::delivery::SignedDelivery;
use super::inboxes::Inboxes;

pub struct ApGroupFederation {
    delivery: SignedDelivery,
    inboxes: Arc<Inboxes>,
}

impl ApGroupFederation {
    pub fn new(keypair: Arc<EdKeyPair>, policy: UrlPolicy, inboxes: Arc<Inboxes>) -> Self {
        Self {
            delivery: SignedDelivery::new(keypair, policy),
            inboxes,
        }
    }
}

impl GroupFederation for ApGroupFederation {
    fn announce(&self, from: &Account, to: &[ActorUri], change: &GroupChange) {
        let posts = to
            .iter()
            .map(|member| (member.clone(), activity(member, change)))
            .collect();
        self.delivery
            .post_each_in_background(&self.inboxes, &from.actor_uri, posts);
    }
}

/// The group rides in `context`, as on its Notes; `published` is the change's stamp.
pub(crate) fn activity(to: &ActorUri, change: &GroupChange) -> Value {
    let group = change.group.to_string();
    let (kind, object) = match &change.kind {
        GroupChangeKind::Added(member) => ("Add", json!(member.as_str())),
        GroupChangeKind::Removed(member) => ("Remove", json!(member.as_str())),
        GroupChangeKind::Left => ("Leave", json!(group)),
        GroupChangeKind::Renamed(name) => {
            ("Update", json!({ "type": "Group", "name": name.as_str() }))
        }
        GroupChangeKind::RoleChanged(member, role) => (
            "Update",
            json!({ "type": "Membership", "member": member.as_str(), "role": role.as_str() }),
        ),
    };
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{}/activities/{}", change.by, Uuid::new_v4()),
        "type": kind,
        "actor": change.by.as_str(),
        "to": [to.as_str()],
        "object": object,
        "context": group,
        "published": change.at.format(&Rfc3339).unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests;
