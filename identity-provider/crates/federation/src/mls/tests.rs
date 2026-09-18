use super::*;

use time::OffsetDateTime;

const ALICE: &str = "https://idp.alice.com/users/alice_xK9mP";
const PIERRE: &str = "https://idp.bob.com/users/pierre_q4Rt";
const ACTIVITY_ID: &str = "https://idp.alice.com/users/alice_xK9mP/activities/1";
const NOTE_ID: &str = "https://idp.alice.com/users/alice_xK9mP/objects/1";

fn member(actor_uri: &str, role: &str) -> ConversationMember {
    ConversationMember {
        conversation_id: Uuid::nil(),
        actor_uri: actor_uri.to_string(),
        joined_at: OffsetDateTime::UNIX_EPOCH,
        left_at: None,
        role: role.to_string(),
    }
}

fn note_of(activity: &Value) -> &Value {
    activity.get("object").expect("Create carries an object")
}

#[test]
fn group_snapshot_carries_every_member_with_its_role() {
    let snapshot = GroupSnapshot::new(
        Some("Weekend trip".to_string()),
        &[member(ALICE, "admin"), member(PIERRE, "member")],
    );

    assert_eq!(
        snapshot.to_json(),
        json!({
            "name": "Weekend trip",
            "members": [
                { "actorUri": ALICE, "role": "admin" },
                { "actorUri": PIERRE, "role": "member" },
            ],
        })
    );
}

#[test]
fn unnamed_group_still_advertises_its_roster() {
    let json = GroupSnapshot::new(None, &[member(ALICE, "admin")]).to_json();

    assert_eq!(json["name"], Value::Null);
    assert_eq!(json["members"].as_array().map(Vec::len), Some(1));
}

/// The bug this field exists for: with no roster on the wire the recipient's
/// IdP has no `conversation_members` row to write, and `GET /api/dm` — driven
/// entirely off that table — can never surface the group.
#[test]
fn group_application_message_advertises_the_roster() {
    let snapshot = GroupSnapshot::new(
        Some("Weekend trip".to_string()),
        &[member(ALICE, "admin"), member(PIERRE, "member")],
    );
    let activity = build_application_create_activity(
        ACTIVITY_ID,
        NOTE_ID,
        ALICE,
        PIERRE,
        Uuid::nil(),
        b"ciphertext",
        None,
        Some(&snapshot),
    );

    assert_eq!(note_of(&activity)["mlsGroup"], snapshot.to_json());
}

/// A 1:1 DM's row is minted on both IdPs at friendship-accept, so it carries
/// no snapshot — and must not, or the receiving side would materialise a
/// parallel `kind = 'group'` conversation for it.
#[test]
fn dm_application_message_carries_no_snapshot() {
    let activity = build_application_create_activity(
        ACTIVITY_ID,
        NOTE_ID,
        ALICE,
        PIERRE,
        Uuid::nil(),
        b"ciphertext",
        None,
        None,
    );

    assert!(note_of(&activity).get("mlsGroup").is_none());
}

#[test]
fn reply_threading_survives_alongside_the_snapshot() {
    let snapshot = GroupSnapshot::new(None, &[member(ALICE, "admin")]);
    let parent = "https://idp.alice.com/users/alice_xK9mP/activities/parent";
    let activity = build_application_create_activity(
        ACTIVITY_ID,
        NOTE_ID,
        ALICE,
        PIERRE,
        Uuid::nil(),
        b"ciphertext",
        Some(parent),
        Some(&snapshot),
    );

    let note = note_of(&activity);
    assert_eq!(note["inReplyTo"], parent);
    assert_eq!(note["mlsGroup"], snapshot.to_json());
}
