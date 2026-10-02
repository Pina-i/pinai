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
        name_at: at(10),
        created_at: at(0),
    }
}

/// `n` minutes into the group's life.
fn at(n: i64) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(n)
}

fn entry(name: &str, role: Role, joined: Option<i64>, role_set: Option<i64>) -> SnapshotMember {
    SnapshotMember {
        member: member(name, role),
        joined_at: joined.map(at),
        role_at: role_set.map(at),
    }
}

fn held(name: &str, role: Role, joined: i64, role_set: i64, left: Option<i64>) -> Membership {
    Membership {
        member: member(name, role),
        joined_at: at(joined),
        role_at: at(role_set),
        left_at: left.map(at),
    }
}

fn snapshot(name: Option<&str>, name_at: Option<i64>, members: &[SnapshotMember]) -> GroupSnapshot {
    GroupSnapshot {
        name: name.map(str::to_owned),
        name_at: name_at.map(at),
        members: members.to_vec(),
    }
}

const NOW: i64 = 1_000;

fn active(name: &str, role: Role, joined: i64, role_set: i64) -> Membership {
    held(name, role, joined, role_set, None)
}

#[test]
fn a_snapshot_the_copy_already_holds_changes_nothing() {
    let local = [
        active("ana", Role::Admin, 0, 0),
        active("bo", Role::Member, 5, 5),
    ];

    let same = snapshot(
        Some("crew"),
        Some(10),
        &[
            entry("ana", Role::Admin, Some(0), Some(0)),
            entry("bo", Role::Member, Some(5), Some(5)),
        ],
    );

    assert!(
        same.changes(Some(&group(Some("crew"))), &local, at(NOW))
            .is_empty()
    );
}

#[test]
fn a_group_new_here_is_taken_whole_with_the_snapshots_stamps() {
    let new = snapshot(
        Some("crew"),
        Some(10),
        &[
            entry("ana", Role::Admin, Some(0), Some(0)),
            entry("bo", Role::Member, Some(5), Some(7)),
        ],
    );

    assert_eq!(
        new.changes(None, &[], at(NOW)),
        GroupChanges {
            name: Some(StampedName {
                name: Some("crew".to_owned()),
                at: at(10)
            }),
            members: vec![
                active("ana", Role::Admin, 0, 0),
                active("bo", Role::Member, 5, 7)
            ],
        }
    );
}

#[test]
fn what_an_unstamped_snapshot_adds_is_stamped_now() {
    let legacy = snapshot(None, None, &[entry("ana", Role::Admin, None, None)]);

    assert_eq!(
        legacy.changes(None, &[], at(NOW)),
        GroupChanges {
            name: Some(StampedName {
                name: None,
                at: at(NOW)
            }),
            members: vec![active("ana", Role::Admin, NOW, NOW)],
        }
    );
}

#[test]
fn a_member_never_held_here_joins_whatever_the_stamps() {
    let local = [active("ana", Role::Admin, 0, 0)];

    for joined in [Some(3), None] {
        let changes = snapshot(None, None, &[entry("cy", Role::Member, joined, joined)]).changes(
            Some(&group(None)),
            &local,
            at(NOW),
        );

        assert_eq!(
            changes.members,
            vec![active(
                "cy",
                Role::Member,
                joined.unwrap_or(NOW),
                joined.unwrap_or(NOW)
            )],
            "{joined:?}"
        );
    }
}

#[test]
fn a_member_who_left_comes_back_only_from_a_later_join() {
    let local = [
        active("ana", Role::Admin, 0, 0),
        held("bo", Role::Member, 5, 5, Some(20)),
    ];

    for (joined, back) in [
        (Some(5), false),
        (Some(20), false),
        (None, false),
        (Some(30), true),
    ] {
        let changes = snapshot(None, None, &[entry("bo", Role::Member, joined, joined)]).changes(
            Some(&group(None)),
            &local,
            at(NOW),
        );

        let expected = if back {
            vec![active("bo", Role::Member, 30, 30)]
        } else {
            vec![]
        };
        assert_eq!(changes.members, expected, "joined at {joined:?}");
    }
}

#[test]
fn a_role_changes_only_with_a_newer_stamp() {
    let local = [active("bo", Role::Admin, 5, 20)];

    for (role_set, taken) in [
        (Some(10), false),
        (Some(20), false),
        (None, false),
        (Some(25), true),
    ] {
        let changes = snapshot(None, None, &[entry("bo", Role::Member, Some(5), role_set)])
            .changes(Some(&group(None)), &local, at(NOW));

        let expected = if taken {
            vec![active("bo", Role::Member, 5, 25)]
        } else {
            vec![]
        };
        assert_eq!(changes.members, expected, "role set at {role_set:?}");
    }
}

#[test]
fn a_later_join_than_the_copys_moves_the_stamp_and_keeps_a_newer_role() {
    // Removed and added back elsewhere: a removal stamped in between must lose to that join.
    let local = [active("bo", Role::Admin, 5, 20)];

    let changes = snapshot(None, None, &[entry("bo", Role::Member, Some(30), Some(15))]).changes(
        Some(&group(None)),
        &local,
        at(NOW),
    );

    assert_eq!(changes.members, vec![active("bo", Role::Admin, 30, 20)]);
}

#[test]
fn a_name_is_taken_only_with_a_newer_stamp() {
    let local = group(Some("crew"));

    for (name_at, taken) in [
        (Some(5), false),
        (Some(10), false),
        (None, false),
        (Some(15), true),
    ] {
        let changes = snapshot(Some("new crew"), name_at, &[]).changes(Some(&local), &[], at(NOW));

        let expected = taken.then(|| StampedName {
            name: Some("new crew".to_owned()),
            at: at(15),
        });
        assert_eq!(changes.name, expected, "named at {name_at:?}");
    }
}

#[test]
fn a_copy_takes_newcomers_only_while_it_has_room_for_them() {
    let mut local: Vec<Membership> = (1..super::MAX_MEMBERS)
        .map(|i| active(&format!("m{i}"), Role::Member, 0, 0))
        .collect();
    local.push(held("bo", Role::Member, 0, 0, Some(5)));

    let changes = snapshot(
        None,
        None,
        &[
            entry("m1", Role::Admin, Some(0), Some(30)),
            entry("bo", Role::Member, Some(20), Some(20)),
            entry("cy", Role::Member, Some(20), Some(20)),
        ],
    )
    .changes(Some(&group(None)), &local, at(NOW));

    assert_eq!(
        changes.members,
        vec![
            active("m1", Role::Admin, 0, 30),
            active("bo", Role::Member, 20, 20)
        ],
        "a role change needs no room; one newcomer fits, the next waits"
    );
}

#[test]
fn local_members_the_snapshot_lacks_are_left_alone() {
    let local = [
        active("ana", Role::Admin, 0, 0),
        active("bo", Role::Member, 5, 5),
    ];

    let changes = snapshot(None, None, &[entry("ana", Role::Admin, Some(0), Some(0))]).changes(
        Some(&group(None)),
        &local,
        at(NOW),
    );

    assert!(changes.is_empty());
}

#[test]
fn a_snapshot_of_a_group_lists_its_active_members_with_every_stamp() {
    let crew = group(Some("crew"));
    let held = [
        active("ana", Role::Admin, 0, 2),
        held("bo", Role::Member, 5, 5, Some(20)),
    ];

    assert_eq!(
        GroupSnapshot::of(&crew, &held),
        snapshot(
            Some("crew"),
            Some(10),
            &[entry("ana", Role::Admin, Some(0), Some(2))]
        )
    );
}

#[test]
fn a_group_is_announced_as_created_by_its_first_admin_else_the_sender() {
    let sender = uri("bo");
    let with_admins = snapshot(
        None,
        None,
        &[
            entry("bo", Role::Member, None, None),
            entry("ana", Role::Admin, None, None),
            entry("cy", Role::Admin, None, None),
        ],
    );
    let without = snapshot(None, None, &[entry("bo", Role::Member, None, None)]);

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
        None,
        &[
            entry("ana", Role::Admin, None, None),
            entry("mallory", Role::Admin, None, None),
        ],
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

#[test]
fn a_former_member_reads_the_group_up_to_their_removal_until_they_clear_it() {
    let departure = |removed_by: Option<&str>, dismissed| Departure {
        left_at: at(20),
        removed_by: removed_by.map(uri),
        dismissed,
    };

    assert_eq!(departure(Some("ana"), false).reads_until(), Some(at(20)));
    assert_eq!(departure(Some("ana"), true).reads_until(), None);
    assert_eq!(departure(None, false).reads_until(), None, "one who left");
}
