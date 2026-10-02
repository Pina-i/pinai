use super::*;
use crate::messaging::ConversationKind;

fn uri(name: &str) -> ActorUri {
    ActorUri::parse(&format!("https://idp.test/users/{name}")).unwrap()
}

/// `n` minutes into the group's life.
fn at(n: i64) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(n)
}

fn group() -> Conversation {
    Conversation {
        id: ConversationId::generate(),
        kind: ConversationKind::Group,
        name: Some("crew".to_owned()),
        name_at: at(10),
        created_at: at(0),
    }
}

fn held(name: &str, role: Role, joined: i64, role_set: i64, left: Option<i64>) -> Membership {
    Membership {
        member: Member {
            actor_uri: uri(name),
            role,
        },
        joined_at: at(joined),
        role_at: at(role_set),
        left_at: left.map(at),
    }
}

/// Ana administers it; Bo has been a member since minute 5; Cy left at minute 20.
fn crew() -> Vec<Membership> {
    vec![
        held("ana", Role::Admin, 0, 0, None),
        held("bo", Role::Member, 5, 5, None),
        held("cy", Role::Member, 5, 5, Some(20)),
    ]
}

fn active(held: &[Membership]) -> Vec<Member> {
    held.iter()
        .filter(|m| m.is_active())
        .map(|m| m.member.clone())
        .collect()
}

fn change(by: &str, minute: i64, kind: GroupChangeKind) -> GroupChange {
    GroupChange {
        group: ConversationId::generate(),
        by: uri(by),
        at: at(minute),
        kind,
    }
}

fn joining(name: &str, minute: i64) -> GroupEffect {
    GroupEffect::Take(GroupChanges {
        name: None,
        members: vec![held(name, Role::Member, minute, minute, None)],
    })
}

#[test]
fn an_admin_makes_any_change_and_a_member_only_their_own_leave() {
    let members = active(&crew());
    let kinds = [
        GroupChangeKind::Added(uri("dee")),
        GroupChangeKind::Removed(uri("bo")),
        GroupChangeKind::Renamed(GroupName::parse("new crew").unwrap()),
        GroupChangeKind::RoleChanged(uri("bo"), Role::Admin),
    ];

    for kind in kinds {
        assert!(
            change("ana", 30, kind.clone()).is_entitled(&members),
            "{kind:?}"
        );
        assert!(
            !change("bo", 30, kind.clone()).is_entitled(&members),
            "{kind:?}"
        );
    }
    assert!(change("bo", 30, GroupChangeKind::Left).is_entitled(&members));
    assert!(
        !change("cy", 30, GroupChangeKind::Left).is_entitled(&members),
        "no longer a member"
    );
    assert!(!change("eve", 30, GroupChangeKind::Left).is_entitled(&members));
}

#[test]
fn a_change_comes_in_only_through_a_members_inbox_or_the_one_it_adds() {
    let members = active(&crew());
    let rename = change(
        "ana",
        30,
        GroupChangeKind::Renamed(GroupName::parse("x").unwrap()),
    );
    let adds_dee = change("ana", 30, GroupChangeKind::Added(uri("dee")));

    assert!(rename.may_arrive_through(&uri("bo"), &members));
    assert!(!rename.may_arrive_through(&uri("eve"), &members));
    assert!(!rename.may_arrive_through(&uri("cy"), &members), "who left");
    assert!(adds_dee.may_arrive_through(&uri("dee"), &members));
    assert!(!adds_dee.may_arrive_through(&uri("eve"), &members));
}

#[test]
fn an_add_brings_in_a_newcomer_or_one_who_left_before_it() {
    let crew = crew();

    for (name, minute, expected) in [
        ("dee", 30, Some(joining("dee", 30))),
        ("cy", 30, Some(joining("cy", 30))),
        ("cy", 15, None),
        ("cy", 20, None),
    ] {
        let added = change("ana", minute, GroupChangeKind::Added(uri(name)));

        assert_eq!(
            added.effect(&group(), &crew),
            expected,
            "{name} at {minute}"
        );
    }
}

#[test]
fn an_add_of_an_active_member_only_moves_a_stamp_forward() {
    let crew = crew();

    let later = change("ana", 30, GroupChangeKind::Added(uri("bo"))).effect(&group(), &crew);
    let earlier = change("ana", 3, GroupChangeKind::Added(uri("bo"))).effect(&group(), &crew);

    assert_eq!(
        later,
        Some(GroupEffect::Take(GroupChanges {
            name: None,
            members: vec![held("bo", Role::Member, 30, 5, None)],
        }))
    );
    assert_eq!(earlier, None);
}

#[test]
fn an_add_to_a_full_copy_waits() {
    let full: Vec<Membership> = (0..MAX_MEMBERS)
        .map(|i| held(&format!("m{i}"), Role::Member, 0, 0, None))
        .collect();

    assert_eq!(
        change("m0", 30, GroupChangeKind::Added(uri("dee"))).effect(&group(), &full),
        None
    );
}

#[test]
fn a_removal_or_a_leave_takes_out_an_active_member_after_their_join() {
    let crew = crew();
    let out = |member: &str, minute, removed_by: Option<&str>| {
        Some(GroupEffect::Depart {
            member: uri(member),
            at: at(minute),
            removed_by: removed_by.map(uri),
        })
    };

    assert_eq!(
        change("ana", 30, GroupChangeKind::Removed(uri("bo"))).effect(&group(), &crew),
        out("bo", 30, Some("ana"))
    );
    assert_eq!(
        change("bo", 30, GroupChangeKind::Left).effect(&group(), &crew),
        out("bo", 30, None)
    );
    for stale in [
        change("ana", 4, GroupChangeKind::Removed(uri("bo"))),
        change("ana", 30, GroupChangeKind::Removed(uri("cy"))),
        change("ana", 30, GroupChangeKind::Removed(uri("eve"))),
    ] {
        assert_eq!(stale.effect(&group(), &crew), None, "{stale:?}");
    }
}

#[test]
fn a_rename_or_a_role_takes_only_with_a_newer_stamp() {
    let crew = crew();
    let rename = |minute| {
        change(
            "ana",
            minute,
            GroupChangeKind::Renamed(GroupName::parse("new crew").unwrap()),
        )
    };
    let promote = |member: &str, minute| {
        change(
            "ana",
            minute,
            GroupChangeKind::RoleChanged(uri(member), Role::Admin),
        )
    };

    assert_eq!(
        rename(30).effect(&group(), &crew),
        Some(GroupEffect::Take(GroupChanges {
            name: Some(StampedName {
                name: Some("new crew".to_owned()),
                at: at(30)
            }),
            members: Vec::new(),
        }))
    );
    assert_eq!(rename(10).effect(&group(), &crew), None);
    assert_eq!(
        promote("bo", 30).effect(&group(), &crew),
        Some(GroupEffect::Take(GroupChanges {
            name: None,
            members: vec![held("bo", Role::Admin, 5, 30, None)],
        }))
    );
    assert_eq!(promote("bo", 5).effect(&group(), &crew), None);
    assert_eq!(promote("cy", 30).effect(&group(), &crew), None, "who left");
}
