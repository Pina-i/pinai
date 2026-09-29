use domain::identity::testing::{account, remote_actor};
use domain::messaging::{AttachmentView, DeliveryStatus, Member, MlsCiphertext, Role};
use domain::{AttachmentId, ConversationId, MessageId};

use super::*;

const ISSUER: &str = "http://localhost:8080";

fn message(sender: &ActorUri) -> Message {
    let id = MessageId::generate();
    Message {
        id,
        conversation: ConversationId::generate(),
        sender: sender.clone(),
        ciphertext: MlsCiphertext::parse(vec![1, 2, 3]).unwrap(),
        activity_uri: id.activity_uri(sender),
        delivery: DeliveryStatus::Pending,
        created_at: time::OffsetDateTime::now_utc(),
        edited_at: None,
        reply_to: None,
        attachments: Vec::new(),
    }
}

#[test]
fn a_message_travels_as_a_create_whose_note_carries_the_opaque_body() {
    let (alice, carol) = (account("alice"), remote_actor("carol_k2m9x@idp.carol.test"));
    let m = message(&alice.actor_uri);

    let activity = create(ISSUER, &m, &carol.actor_uri, None, None);

    assert_eq!(
        (&activity["type"], &activity["id"], &activity["actor"]),
        (
            &json!("Create"),
            &json!(m.activity_uri),
            &json!(alice.actor_uri.as_str())
        )
    );
    assert_eq!(activity["to"], json!([carol.actor_uri.as_str()]));
    let note = &activity["object"];
    assert_eq!(
        note,
        &json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": m.activity_uri,
            "type": "Note",
            "attributedTo": alice.actor_uri.as_str(),
            "to": [carol.actor_uri.as_str()],
            "directMessage": true,
            "mediaType": "application/mls",
            "context": m.conversation.to_string(),
            "content": "AQID",
            "mlsKind": "application",
        })
    );
}

#[test]
fn a_group_message_carries_its_roster_and_a_reply_names_its_parent() {
    let (alice, carol) = (account("alice"), remote_actor("carol_k2m9x@idp.carol.test"));
    let group = GroupSnapshot {
        name: Some("crew".to_owned()),
        members: vec![Member {
            actor_uri: alice.actor_uri.clone(),
            role: Role::Admin,
        }],
    };

    let activity = create(
        ISSUER,
        &message(&alice.actor_uri),
        &carol.actor_uri,
        Some("https://idp.carol.test/users/carol_k2m9x/activities/1"),
        Some(&group),
    );

    let note = &activity["object"];
    assert_eq!(
        note["inReplyTo"],
        json!("https://idp.carol.test/users/carol_k2m9x/activities/1")
    );
    assert_eq!(
        note["mlsGroup"],
        json!({
            "name": "crew",
            "members": [{ "actorUri": alice.actor_uri.as_str(), "role": "admin" }],
        })
    );
}

#[test]
fn attachments_are_described_at_their_content_url_on_this_instance() {
    let (alice, carol) = (account("alice"), remote_actor("carol_k2m9x@idp.carol.test"));
    let id = AttachmentId::generate();
    let m = Message {
        attachments: vec![AttachmentView {
            id,
            mime_type: "image/png".to_owned(),
            byte_size: 512,
            original_filename: "cat.png".to_owned(),
        }],
        ..message(&alice.actor_uri)
    };

    let activity = create(ISSUER, &m, &carol.actor_uri, None, None);

    assert_eq!(
        activity["object"]["attachment"],
        json!([{
            "type": "Document",
            "mediaType": "image/png",
            "url": format!("{ISSUER}/api/attachments/{id}/content"),
            "name": "cat.png",
            "size": 512,
        }])
    );
}

#[test]
fn an_edit_travels_as_an_update_whose_note_names_the_message() {
    let (alice, carol) = (account("alice"), remote_actor("carol_k2m9x@idp.carol.test"));
    let m = message(&alice.actor_uri);

    let activity = update(&m, &carol.actor_uri);

    assert_eq!(activity["type"], "Update");
    assert_ne!(activity["id"], json!(m.activity_uri), "a fresh activity");
    assert_eq!(
        (&activity["object"]["id"], &activity["object"]["mlsKind"]),
        (&json!(m.activity_uri), &json!("edit"))
    );
    assert_eq!(activity["object"]["content"], "AQID");
}
