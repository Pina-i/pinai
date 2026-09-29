use time::OffsetDateTime;

use super::*;

fn uri(name: &str) -> ActorUri {
    ActorUri::parse(&format!("https://idp.test/users/{name}")).unwrap()
}

fn member(name: &str, role: Role) -> Member {
    Member {
        actor_uri: uri(name),
        role,
    }
}

fn group(name: Option<&str>) -> Conversation {
    Conversation {
        id: ConversationId::generate(),
        kind: ConversationKind::Group,
        name: name.map(str::to_owned),
        created_at: OffsetDateTime::now_utc(),
    }
}

fn snapshot(name: Option<&str>, members: &[Member]) -> GroupSnapshot {
    GroupSnapshot {
        name: name.map(str::to_owned),
        members: members.to_vec(),
    }
}

#[test]
fn a_roster_held_in_full_with_its_name_is_mirrored() {
    let roster = [member("ana", Role::Admin), member("bo", Role::Member)];

    assert!(snapshot(Some("crew"), &roster).is_mirrored_by(Some(&group(Some("crew"))), &roster));
}

#[test]
fn a_missing_member_a_changed_role_or_a_new_name_is_not_mirrored() {
    let local = [member("ana", Role::Admin), member("bo", Role::Member)];
    let conversation = group(Some("crew"));

    for advertised in [
        snapshot(
            Some("crew"),
            &[member("ana", Role::Admin), member("cy", Role::Member)],
        ),
        snapshot(
            Some("crew"),
            &[member("ana", Role::Admin), member("bo", Role::Admin)],
        ),
        snapshot(Some("new crew"), &local),
    ] {
        assert!(
            !advertised.is_mirrored_by(Some(&conversation), &local),
            "{advertised:?}"
        );
    }
}

#[test]
fn a_group_this_instance_has_never_seen_is_not_mirrored() {
    let roster = [member("ana", Role::Admin)];

    assert!(!snapshot(Some("crew"), &roster).is_mirrored_by(None, &[]));
}

#[test]
fn local_members_the_snapshot_lacks_are_left_alone() {
    let local = [member("ana", Role::Admin), member("bo", Role::Member)];

    assert!(snapshot(Some("crew"), &local[..1]).is_mirrored_by(Some(&group(Some("crew"))), &local));
}

#[test]
fn an_unnamed_snapshot_never_renames_the_group() {
    let roster = [member("ana", Role::Admin)];

    assert!(snapshot(None, &roster).is_mirrored_by(Some(&group(Some("crew"))), &roster));
}

#[test]
fn a_group_is_announced_as_created_by_its_first_admin_else_the_sender() {
    let sender = uri("bo");
    let with_admins = snapshot(
        None,
        &[
            member("bo", Role::Member),
            member("ana", Role::Admin),
            member("cy", Role::Admin),
        ],
    );
    let without = snapshot(None, &[member("bo", Role::Member)]);

    assert_eq!(with_admins.creator(&sender), &uri("ana"));
    assert_eq!(without.creator(&sender), &sender);
}

#[test]
fn kinds_and_roles_round_trip_through_their_stored_form() {
    for kind in [ConversationKind::Dm, ConversationKind::Group] {
        assert_eq!(kind.as_str().parse::<ConversationKind>().unwrap(), kind);
    }
    for role in [Role::Admin, Role::Member] {
        assert_eq!(role.as_str().parse::<Role>().unwrap(), role);
    }
    assert!("channel".parse::<ConversationKind>().is_err());
    assert!("owner".parse::<Role>().is_err());
}

#[test]
fn an_existing_conversation_holds_a_pairs_dm_only_when_it_is_a_dm_of_that_pair() {
    let (ana, bo) = (uri("ana"), uri("bo"));

    for (kind, members, expected) in [
        (ConversationKind::Dm, vec![uri("ana"), uri("bo")], true),
        (ConversationKind::Dm, vec![uri("bo")], true),
        (ConversationKind::Dm, vec![], true),
        (ConversationKind::Dm, vec![uri("ana"), uri("cy")], false),
        (ConversationKind::Group, vec![uri("ana"), uri("bo")], false),
    ] {
        assert_eq!(
            may_hold_dm(kind, &members, &ana, &bo),
            expected,
            "{kind:?} {members:?}"
        );
    }
}

#[test]
fn a_roster_is_asserted_only_by_a_member_of_the_group() {
    let local = [member("ana", Role::Admin), member("bo", Role::Member)];
    let roster = snapshot(
        None,
        &[member("ana", Role::Admin), member("mallory", Role::Admin)],
    );
    let dm = Conversation {
        kind: ConversationKind::Dm,
        ..group(None)
    };

    assert!(roster.may_be_asserted_by(&uri("bo"), Some(&group(None)), &local));
    assert!(!roster.may_be_asserted_by(&uri("mallory"), Some(&group(None)), &local));
    assert!(
        roster.may_be_asserted_by(&uri("ana"), None, &[]),
        "a new group, by a member it lists"
    );
    assert!(!roster.may_be_asserted_by(&uri("eve"), None, &[]));
    assert!(
        !roster.may_be_asserted_by(&uri("ana"), Some(&dm), &local),
        "never into a DM"
    );
}
