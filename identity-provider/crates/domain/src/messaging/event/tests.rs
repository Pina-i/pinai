use super::*;
use crate::messaging::{GroupName, Member, Role};

fn uri(name: &str) -> ActorUri {
    ActorUri::parse(&format!("https://idp.test/users/{name}")).unwrap()
}

fn at(n: i64) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + time::Duration::minutes(n)
}

fn membership(joined: i64, left: Option<i64>) -> Membership {
    Membership {
        member: Member {
            actor_uri: uri("bo"),
            role: Role::Member,
        },
        joined_at: at(joined),
        role_at: at(joined),
        left_at: left.map(at),
    }
}

fn departure(removed_by: Option<&str>, dismissed: bool) -> Departure {
    Departure {
        left_at: at(20),
        removed_by: removed_by.map(uri),
        dismissed,
    }
}

#[test]
fn a_member_sees_the_events_from_their_latest_join_on() {
    let window = EventWindow::for_reader(&membership(10, None), None).unwrap();

    assert_eq!(
        [5, 10, 99].map(|m| window.contains(at(m))),
        [false, true, true]
    );
}

#[test]
fn a_removed_member_sees_them_up_to_their_removal_until_they_clear_the_group() {
    let removed = EventWindow::for_reader(
        &membership(10, Some(20)),
        Some(&departure(Some("ana"), false)),
    )
    .unwrap();

    assert_eq!(
        [5, 10, 20, 21].map(|m| removed.contains(at(m))),
        [false, true, true, false]
    );
    for gone in [departure(Some("ana"), true), departure(None, false)] {
        assert_eq!(
            EventWindow::for_reader(&membership(10, Some(20)), Some(&gone)),
            None,
            "{gone:?}"
        );
    }
}

#[test]
fn an_event_is_about_the_member_a_change_names_or_the_one_leaving() {
    let group = ConversationId::generate();
    let event = |kind| GroupEvent {
        id: GroupEventId::generate(),
        group,
        by: uri("ana"),
        at: at(1),
        kind,
    };

    assert_eq!(event(GroupEventKind::Created).subject(), None);
    for (kind, subject) in [
        (GroupEventKind::Added(uri("bo")), Some(uri("bo"))),
        (GroupEventKind::Removed(uri("bo")), Some(uri("bo"))),
        (
            GroupEventKind::RoleChanged(uri("bo"), Role::Admin),
            Some(uri("bo")),
        ),
        (GroupEventKind::Left, Some(uri("ana"))),
        (GroupEventKind::Renamed("crew".to_owned()), None),
    ] {
        assert_eq!(event(kind.clone()).subject(), subject.as_ref(), "{kind:?}");
    }
}

#[test]
fn an_event_shows_the_change_it_records() {
    let change = |kind| GroupChange {
        group: ConversationId::generate(),
        by: uri("ana"),
        at: at(1),
        kind,
    };

    for (kind, shown) in [
        (
            GroupChangeKind::Added(uri("bo")),
            GroupEventKind::Added(uri("bo")),
        ),
        (
            GroupChangeKind::Removed(uri("bo")),
            GroupEventKind::Removed(uri("bo")),
        ),
        (GroupChangeKind::Left, GroupEventKind::Left),
        (
            GroupChangeKind::Renamed(GroupName::parse(" crew ").unwrap()),
            GroupEventKind::Renamed("crew".to_owned()),
        ),
        (
            GroupChangeKind::RoleChanged(uri("bo"), Role::Admin),
            GroupEventKind::RoleChanged(uri("bo"), Role::Admin),
        ),
    ] {
        let change = change(kind);
        let event = GroupEvent::of(&change);

        assert_eq!(
            (event.group, &event.by, event.at, &event.kind),
            (change.group, &change.by, change.at, &shown)
        );
    }
}
