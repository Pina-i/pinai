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
    let roster =
        initial_roster(&uri("ana"), &[uri("bo"), uri("ana"), uri("cy"), uri("bo")]).unwrap();

    assert_eq!(
        roster,
        vec![
            member("ana", Role::Admin),
            member("bo", Role::Member),
            member("cy", Role::Member),
        ]
    );
}

fn invitees(count: usize) -> Vec<ActorUri> {
    (0..count).map(|i| uri(&format!("guest{i}"))).collect()
}

#[test]
fn a_new_group_holds_fifty_members_its_creator_included() {
    let mut full = invitees(MAX_MEMBERS - 1);

    assert_eq!(
        initial_roster(&uri("ana"), &full).unwrap().len(),
        MAX_MEMBERS
    );
    full.extend([uri("ana"), full[0].clone()]);
    assert!(
        initial_roster(&uri("ana"), &full).is_ok(),
        "the creator and repeats count once"
    );
    assert!(matches!(
        initial_roster(&uri("ana"), &invitees(MAX_MEMBERS)),
        Err(MessagingError::TooManyMembers(MAX_MEMBERS))
    ));
}

#[test]
fn a_group_has_room_until_it_holds_fifty_members() {
    let members = |count: usize| -> Vec<Member> {
        invitees(count)
            .into_iter()
            .map(|actor_uri| Member {
                actor_uri,
                role: Role::Member,
            })
            .collect()
    };

    assert!(has_room(&members(MAX_MEMBERS - 1)));
    assert!(!has_room(&members(MAX_MEMBERS)));
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
fn any_member_renames_a_group() {
    let members = [member("ana", Role::Admin), member("bo", Role::Member)];

    assert!(authorize_rename(&members, &uri("ana")).is_ok());
    assert!(authorize_rename(&members, &uri("bo")).is_ok());
    assert!(matches!(
        authorize_rename(&members, &uri("eve")),
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
fn a_group_name_holds_at_most_50_characters() {
    assert!(
        GroupName::parse(&"é".repeat(50)).is_ok(),
        "characters, not bytes"
    );

    let refused = GroupName::parse(&"a".repeat(51)).unwrap_err();

    assert_eq!(refused.reason, "is longer than 50 characters");
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
    assert!(GroupName::parse_optional(Some(&"a".repeat(51))).is_err());
}

#[test]
fn a_group_name_must_read_as_what_it_is() {
    let refused = |raw: &str| GroupName::parse_optional(Some(raw)).unwrap_err().reason;

    assert_eq!(refused("\u{3164}"), "cannot contain invisible characters");
    assert_eq!(refused("crew\nmates"), "cannot contain control characters");
    assert_eq!(refused(" \u{200D} "), "cannot be empty");
    let coders = "\u{1F469}\u{200D}\u{1F4BB} crew";
    assert_eq!(GroupName::parse(coders).unwrap().as_str(), coders);
}
