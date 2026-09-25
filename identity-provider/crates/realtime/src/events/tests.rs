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
