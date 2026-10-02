use domain::ConversationId;
use domain::identity::testing::{account, remote_actor};
use domain::messaging::{GroupName, Role};
use time::OffsetDateTime;

use super::*;

fn change(kind: GroupChangeKind) -> GroupChange {
    GroupChange {
        group: ConversationId::generate(),
        by: account("alice").actor_uri,
        at: OffsetDateTime::parse("2026-10-01T09:30:00.25Z", &Rfc3339).unwrap(),
        kind,
    }
}

#[test]
fn each_change_names_its_maker_its_group_and_its_stamp() {
    let carol = remote_actor("carol_k2m9x@idp.carol.test").actor_uri;
    let bob = remote_actor("bob_k2m9x@idp.bob.test").actor_uri;

    for (kind, expected_type, expected_object) in [
        (
            GroupChangeKind::Added(bob.clone()),
            "Add",
            json!(bob.as_str()),
        ),
        (
            GroupChangeKind::Removed(bob.clone()),
            "Remove",
            json!(bob.as_str()),
        ),
        (
            GroupChangeKind::Renamed(GroupName::parse("new crew").unwrap()),
            "Update",
            json!({ "type": "Group", "name": "new crew" }),
        ),
        (
            GroupChangeKind::RoleChanged(bob.clone(), Role::Admin),
            "Update",
            json!({ "type": "Membership", "member": bob.as_str(), "role": "admin" }),
        ),
    ] {
        let change = change(kind);

        let activity = activity(&carol, &change);

        assert_eq!(
            (
                &activity["type"],
                &activity["actor"],
                &activity["to"],
                &activity["object"],
                &activity["context"],
                &activity["published"],
            ),
            (
                &json!(expected_type),
                &json!(change.by.as_str()),
                &json!([carol.as_str()]),
                &expected_object,
                &json!(change.group.to_string()),
                &json!("2026-10-01T09:30:00.25Z"),
            )
        );
    }
}

#[test]
fn a_leave_is_of_the_group_by_the_member_leaving() {
    let carol = remote_actor("carol_k2m9x@idp.carol.test").actor_uri;
    let left = change(GroupChangeKind::Left);

    let activity = activity(&carol, &left);

    assert_eq!(
        (&activity["type"], &activity["object"]),
        (&json!("Leave"), &json!(left.group.to_string()))
    );
}
