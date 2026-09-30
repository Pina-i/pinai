use serde_json::json;

use super::*;

#[test]
fn a_heartbeat_is_acknowledged_as_a_type_and_its_data() {
    let ack: serde_json::Value = serde_json::from_str(HEARTBEAT_ACK).unwrap();

    assert_eq!(ack, json!({ "type": "heartbeat_ack", "data": {} }));
}

#[test]
fn the_frames_a_client_sends_are_read() {
    let conversation = Uuid::new_v4();
    let read = |frame: serde_json::Value| serde_json::from_value::<WsClientMessage>(frame).unwrap();

    assert!(matches!(
        read(json!({ "type": "heartbeat" })),
        WsClientMessage::Heartbeat
    ));
    assert!(matches!(
        read(json!({ "type": "typing_start", "data": { "conversationId": conversation } })),
        WsClientMessage::TypingStart(t) if t.conversation_id == conversation
    ));
    assert!(matches!(
        read(json!({ "type": "set_presence", "data": { "state": "dnd" } })),
        WsClientMessage::SetPresence(p) if p.state == "dnd"
    ));
    assert!(matches!(
        read(json!({
            "type": "send_dm",
            "data": { "recipient_address": "bob_k2m9x@idp.bob.test", "mls_ciphertext": "AAEC" }
        })),
        WsClientMessage::SendDm(dm) if dm.client_id.is_none()
    ));
    assert!(matches!(
        read(json!({ "type": "watch_conversation", "data": { "conversationId": conversation } })),
        WsClientMessage::WatchConversation(_)
    ));
    assert!(matches!(
        read(json!({ "type": "unwatch_conversation", "data": { "conversationId": conversation } })),
        WsClientMessage::UnwatchConversation(_)
    ));
}
