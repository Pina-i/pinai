use super::*;

#[test]
fn delivery_failure_serializes_to_the_shape_clients_match_on() {
    let message_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let event = WsEvent::DmDeliveryFailed(DmDeliveryFailedPayload {
        message_id,
        conversation_id,
    });

    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(
        json,
        serde_json::json!({
            "type": "dm_delivery_failed",
            "data": {
                "message_id": message_id.to_string(),
                "conversation_id": conversation_id.to_string(),
            },
        })
    );
}

/// An unfriend reaches the friend's clients as a refresh signal only, so it
/// carries no conversation: the DM outlives the friendship.
#[test]
fn friend_removed_serializes_without_a_conversation() {
    let friendship_id = Uuid::new_v4();
    let event = WsEvent::FriendRemoved(FriendshipPayload {
        friendship_id,
        actor_uri: "https://idp.alice.test/users/alice_xK9mP".to_string(),
        username: "alice_xK9mP".to_string(),
        display_name: Some("alice".to_string()),
        conversation_id: None,
    });

    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(
        json,
        serde_json::json!({
            "type": "friend_removed",
            "data": {
                "friendship_id": friendship_id.to_string(),
                "actor_uri": "https://idp.alice.test/users/alice_xK9mP",
                "username": "alice_xK9mP",
                "display_name": "alice",
            },
        })
    );
}

/// Clients replace their copy of the account settings with this document.
#[test]
fn settings_updated_carries_the_whole_document() {
    let event = WsEvent::SettingsUpdated(SettingsPayload {
        settings: serde_json::json!({ "appearance": { "family": "lagoon", "motif": "raranga" } }),
    });

    let json = serde_json::to_value(&event).unwrap();

    assert_eq!(
        json,
        serde_json::json!({
            "type": "settings_updated",
            "data": { "settings": { "appearance": { "family": "lagoon", "motif": "raranga" } } },
        })
    );
}

/// A refresh signal: the list itself never travels over the socket.
#[test]
fn blocks_updated_carries_nothing_but_its_type() {
    let json = serde_json::to_value(WsEvent::BlocksUpdated(BlocksUpdatedPayload {})).unwrap();

    assert_eq!(
        json,
        serde_json::json!({ "type": "blocks_updated", "data": {} })
    );
}

/// The heartbeat ack is `api::ws`'s own frame; the rest of the wire format is here.
#[test]
fn every_event_is_a_type_and_its_data() {
    let event = WsEvent::DmDeliveryFailed(DmDeliveryFailedPayload {
        message_id: Uuid::nil(),
        conversation_id: Uuid::nil(),
    });

    let json: serde_json::Value = serde_json::from_str(&super::super::frame(&event)).unwrap();

    assert_eq!(json["type"], "dm_delivery_failed");
    assert!(json["data"].is_object());
}
