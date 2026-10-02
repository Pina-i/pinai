use domain::e2ee::{CommitBlob, Epoch, WelcomeBlob};
use domain::identity::testing::{account, remote_actor};
use domain::messaging::testing::unstamped;
use domain::messaging::{GroupSnapshot, Member, Role};
use domain::{CommitId, ConversationId, DeviceId};

use super::*;

fn commit(proposer: &ActorUri) -> Commit {
    Commit {
        id: CommitId::generate(),
        conversation: ConversationId::generate(),
        epoch: Epoch::parse(3).unwrap(),
        blob: CommitBlob::parse(vec![1, 2, 3]).unwrap(),
        proposer: proposer.clone(),
        created_at: time::OffsetDateTime::now_utc(),
    }
}

fn welcome(roster: Option<GroupSnapshot>) -> OutgoingWelcome {
    OutgoingWelcome {
        device: DeviceId::generate(),
        conversation: ConversationId::generate(),
        blob: WelcomeBlob::parse(vec![4, 5]).unwrap(),
        roster,
    }
}

#[test]
fn a_commit_travels_as_a_create_whose_note_names_its_epoch() {
    let (alice, carol) = (account("alice"), remote_actor("carol_k2m9x@idp.carol.test"));
    let c = commit(&alice.actor_uri);

    let activity = commit_activity(&alice.actor_uri, &carol.actor_uri, &c, None);

    assert_eq!(
        (&activity["type"], &activity["actor"], &activity["to"]),
        (
            &json!("Create"),
            &json!(alice.actor_uri.as_str()),
            &json!([carol.actor_uri.as_str()])
        )
    );
    let note = &activity["object"];
    assert_eq!(
        (&note["mediaType"], &note["mlsKind"], &note["mlsEpoch"]),
        (&json!("application/mls"), &json!("commit"), &json!(3))
    );
    assert_eq!(
        (&note["context"], &note["content"]),
        (&json!(c.conversation.to_string()), &json!("AQID"))
    );
    assert!(
        activity["id"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{}/activities/", alice.actor_uri))
    );
}

#[test]
fn a_groups_commit_carries_its_roster_and_a_dms_none() {
    let (alice, carol) = (account("alice"), remote_actor("carol_k2m9x@idp.carol.test"));
    let roster = unstamped(
        Some("Weekend trip"),
        &[Member {
            actor_uri: carol.actor_uri.clone(),
            role: Role::Member,
        }],
    );
    let c = commit(&alice.actor_uri);

    let group = commit_activity(&alice.actor_uri, &carol.actor_uri, &c, Some(&roster));
    let dm = commit_activity(&alice.actor_uri, &carol.actor_uri, &c, None);

    assert_eq!(group["object"]["mlsGroup"]["name"], json!("Weekend trip"));
    assert_eq!(
        group["object"]["mlsGroup"]["members"][0]["actorUri"],
        json!(carol.actor_uri.as_str())
    );
    assert_eq!(dm["object"].get("mlsGroup"), None);
}

#[test]
fn a_groups_welcome_carries_its_device_and_its_roster() {
    let (alice, carol) = (account("alice"), remote_actor("carol_k2m9x@idp.carol.test"));
    let roster = unstamped(
        Some("Weekend trip"),
        &[
            Member {
                actor_uri: alice.actor_uri.clone(),
                role: Role::Admin,
            },
            Member {
                actor_uri: carol.actor_uri.clone(),
                role: Role::Member,
            },
        ],
    );
    let w = welcome(Some(roster));

    let note = welcome_activity(&alice.actor_uri, &carol.actor_uri, &w)["object"].clone();

    assert_eq!(
        (
            &note["mlsKind"],
            &note["mlsRecipientDeviceId"],
            &note["content"]
        ),
        (
            &json!("welcome"),
            &json!(w.device.to_string()),
            &json!("BAU=")
        )
    );
    assert_eq!(
        note["mlsGroup"],
        json!({
            "name": "Weekend trip",
            "nameAt": null,
            "members": [
                { "actorUri": alice.actor_uri.as_str(), "role": "admin", "joinedAt": null, "roleAt": null },
                { "actorUri": carol.actor_uri.as_str(), "role": "member", "joinedAt": null, "roleAt": null },
            ],
        })
    );
}

#[test]
fn a_dms_welcome_carries_no_roster() {
    let (alice, carol) = (account("alice"), remote_actor("carol_k2m9x@idp.carol.test"));

    let note =
        welcome_activity(&alice.actor_uri, &carol.actor_uri, &welcome(None))["object"].clone();

    assert_eq!(note.get("mlsGroup"), None);
}
