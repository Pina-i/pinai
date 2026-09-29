use std::sync::Arc;

use domain::identity::ActorUri;
use domain::messaging::{Conversation, GroupNotifier, Member};
use domain::{ConversationId, UserId};
use idp_realtime::{
    GroupCreatedPayload, GroupRenamedPayload, MemberAddedPayload, MemberRemovedPayload,
    MemberRoleChangedPayload, WsEvent, WsHub,
};

/// Pushes membership events to an account's live sessions; clients refetch the group on
/// reconnect.
pub struct HubGroupNotifier {
    hub: Arc<WsHub>,
}

impl HubGroupNotifier {
    pub fn new(hub: Arc<WsHub>) -> Self {
        Self { hub }
    }

    fn push(&self, to: UserId, event: WsEvent) {
        self.hub.send_to_user(&to.as_uuid(), event);
    }
}

impl GroupNotifier for HubGroupNotifier {
    fn joined(&self, to: UserId, group: &Conversation, creator: &ActorUri) {
        self.push(
            to,
            WsEvent::GroupCreated(GroupCreatedPayload {
                conversation_id: group.id.as_uuid(),
                name: group.name.clone(),
                creator_actor_uri: creator.to_string(),
                created_at: group.created_at,
            }),
        );
    }

    fn member_added(&self, to: UserId, group: ConversationId, member: &Member, by: &ActorUri) {
        self.push(
            to,
            WsEvent::MemberAdded(MemberAddedPayload {
                conversation_id: group.as_uuid(),
                actor_uri: member.actor_uri.to_string(),
                role: member.role.as_str().to_owned(),
                added_by_actor_uri: by.to_string(),
            }),
        );
    }

    fn member_removed(
        &self,
        to: UserId,
        group: ConversationId,
        member: &ActorUri,
        by: Option<&ActorUri>,
    ) {
        self.push(
            to,
            WsEvent::MemberRemoved(MemberRemovedPayload {
                conversation_id: group.as_uuid(),
                actor_uri: member.to_string(),
                removed_by_actor_uri: by.map(ToString::to_string),
            }),
        );
    }

    fn renamed(&self, to: UserId, group: &Conversation, by: &ActorUri) {
        self.push(
            to,
            WsEvent::GroupRenamed(GroupRenamedPayload {
                conversation_id: group.id.as_uuid(),
                name: group.name.clone(),
                renamed_by_actor_uri: by.to_string(),
            }),
        );
    }

    fn role_changed(&self, to: UserId, group: ConversationId, member: &Member, by: &ActorUri) {
        self.push(
            to,
            WsEvent::MemberRoleChanged(MemberRoleChangedPayload {
                conversation_id: group.as_uuid(),
                actor_uri: member.actor_uri.to_string(),
                role: member.role.as_str().to_owned(),
                changed_by_actor_uri: by.to_string(),
            }),
        );
    }
}
