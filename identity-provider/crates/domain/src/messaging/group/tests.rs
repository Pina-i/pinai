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

#[test]
fn a_group_name_is_trimmed_and_never_empty() {
    assert_eq!(GroupName::parse("  crew \n").unwrap().as_str(), "crew");
    assert!(GroupName::parse("   ").is_err());
}

#[test]
fn a_new_group_starts_with_its_creator_as_admin_and_each_invitee_once() {
    let roster = initial_roster(&uri("ana"), &[uri("bo"), uri("ana"), uri("cy"), uri("bo")]);

    assert_eq!(
        roster,
        vec![
            member("ana", Role::Admin),
            member("bo", Role::Member),
            member("cy", Role::Member),
        ]
    );
}

#[test]
fn only_an_admin_manages_a_group() {
    let members = [member("ana", Role::Admin), member("bo", Role::Member)];

    assert!(authorize_admin(&members, &uri("ana")).is_ok());
    assert!(matches!(
        authorize_admin(&members, &uri("bo")),
        Err(MessagingError::NotAnAdmin)
    ));
    assert!(matches!(
        authorize_admin(&members, &uri("eve")),
        Err(MessagingError::ConversationNotFound)
    ));
}

#[test]
fn a_group_keeps_an_admin_while_it_has_other_members() {
    let alone = [member("ana", Role::Admin)];
    let one_admin = [member("ana", Role::Admin), member("bo", Role::Member)];
    let two_admins = [member("ana", Role::Admin), member("bo", Role::Admin)];

    assert!(
        !may_stop_being_admin(&one_admin, &uri("ana")),
        "the last admin, with others left"
    );
    assert!(may_stop_being_admin(&two_admins, &uri("ana")));
    assert!(
        may_stop_being_admin(&alone, &uri("ana")),
        "nobody left to manage"
    );
    assert!(
        may_stop_being_admin(&one_admin, &uri("bo")),
        "not an admin to begin with"
    );
}

#[test]
fn a_group_name_holds_at_most_100_characters() {
    assert!(
        GroupName::parse(&"é".repeat(100)).is_ok(),
        "characters, not bytes"
    );

    let refused = GroupName::parse(&"a".repeat(101)).unwrap_err();

    assert_eq!(refused.reason, "is longer than 100 characters");
}

#[test]
fn a_blank_name_at_creation_leaves_the_group_unnamed() {
    assert_eq!(GroupName::parse_optional(None).unwrap(), None);
    assert_eq!(GroupName::parse_optional(Some("  ")).unwrap(), None);
    assert_eq!(
        GroupName::parse_optional(Some(" crew "))
            .unwrap()
            .map(|n| n.as_str().to_owned()),
        Some("crew".to_owned())
    );
    assert!(GroupName::parse_optional(Some(&"a".repeat(101))).is_err());
}
