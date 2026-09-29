use time::OffsetDateTime;

use super::*;

fn alice() -> ActorUri {
    ActorUri::parse("https://idp.alice.test/users/alice_k2m9x").unwrap()
}

#[test]
fn a_message_is_published_under_its_senders_actor_uri() {
    let id = MessageId::generate();

    assert_eq!(
        id.activity_uri(&alice()),
        format!("https://idp.alice.test/users/alice_k2m9x/activities/{id}")
    );
}

#[test]
fn a_message_keeps_the_id_its_activity_uri_carries() {
    let id = MessageId::generate();

    assert_eq!(MessageId::of_activity(&id.activity_uri(&alice())), id);
}

#[test]
fn an_activity_uri_without_a_trailing_uuid_gets_a_fresh_id() {
    let a = MessageId::of_activity("https://peer.test/notes/latest");
    let b = MessageId::of_activity("https://peer.test/notes/latest");

    assert_ne!(a, b);
}

#[test]
fn a_delivery_status_round_trips_through_its_stored_form() {
    for status in [
        DeliveryStatus::Pending,
        DeliveryStatus::Delivered,
        DeliveryStatus::Failed,
    ] {
        assert_eq!(status.as_str().parse::<DeliveryStatus>().unwrap(), status);
    }
    assert!("lost".parse::<DeliveryStatus>().is_err());
}

#[test]
fn a_message_is_answered_only_in_its_own_conversation() {
    let conversation = ConversationId::generate();
    let id = MessageId::generate();
    let message = Message {
        id,
        conversation,
        sender: alice(),
        ciphertext: MlsCiphertext::parse(vec![1]).unwrap(),
        activity_uri: id.activity_uri(&alice()),
        delivery: DeliveryStatus::Pending,
        created_at: OffsetDateTime::now_utc(),
        edited_at: None,
        reply_to: None,
        attachments: Vec::new(),
    };

    assert!(message.can_be_answered_in(conversation));
    assert!(!message.can_be_answered_in(ConversationId::generate()));
}
