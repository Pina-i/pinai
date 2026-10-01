use super::*;

const POLICIES: [ContactPolicy; 3] = [
    ContactPolicy::Everyone,
    ContactPolicy::FriendsAndGroups,
    ContactPolicy::Friends,
];

fn relation(policy: ContactPolicy, blocked: bool, friends: bool, share_a_group: bool) -> Relation {
    Relation {
        policy,
        blocked,
        friends,
        share_a_group,
    }
}

#[test]
fn a_block_keeps_anyone_out_whatever_else_holds() {
    for policy in POLICIES {
        for (friends, share_a_group) in [(false, false), (true, false), (false, true), (true, true)]
        {
            assert_eq!(
                relation(policy, true, friends, share_a_group).admits(),
                Err(Unreachable),
                "{policy:?} friends={friends} group={share_a_group}"
            );
        }
    }
}

#[test]
fn the_contact_setting_decides_who_else_gets_in() {
    // (policy, friends, share_a_group) → admitted
    let table = [
        (ContactPolicy::Everyone, false, false, true),
        (ContactPolicy::Everyone, true, false, true),
        (ContactPolicy::Everyone, false, true, true),
        (ContactPolicy::Everyone, true, true, true),
        (ContactPolicy::FriendsAndGroups, false, false, false),
        (ContactPolicy::FriendsAndGroups, true, false, true),
        (ContactPolicy::FriendsAndGroups, false, true, true),
        (ContactPolicy::FriendsAndGroups, true, true, true),
        (ContactPolicy::Friends, false, false, false),
        (ContactPolicy::Friends, true, false, true),
        (ContactPolicy::Friends, false, true, false),
        (ContactPolicy::Friends, true, true, true),
    ];
    for (policy, friends, share_a_group, admitted) in table {
        assert_eq!(
            relation(policy, false, friends, share_a_group)
                .admits()
                .is_ok(),
            admitted,
            "{policy:?} friends={friends} group={share_a_group}"
        );
    }
}

#[test]
fn an_owner_may_write_to_anyone_but_those_they_blocked() {
    for policy in POLICIES {
        assert_eq!(relation(policy, false, false, false).may_write(), Ok(()));
        assert_eq!(
            relation(policy, true, true, true).may_write(),
            Err(YouBlocked)
        );
    }
}

#[test]
fn a_new_account_takes_messages_from_friends_and_groups() {
    assert_eq!(ContactPolicy::default(), ContactPolicy::FriendsAndGroups);
}

#[test]
fn a_contact_policy_reads_back_as_written() {
    for policy in POLICIES {
        assert_eq!(policy.as_str().parse::<ContactPolicy>().ok(), Some(policy));
    }
    assert_eq!(
        ContactPolicy::FriendsAndGroups.as_str(),
        "friends_and_groups"
    );
    assert!("nobody".parse::<ContactPolicy>().is_err());
}

#[test]
fn only_a_block_keeps_a_friend_request_out() {
    for policy in POLICIES {
        assert!(
            relation(policy, false, false, false).hears_requests(),
            "{policy:?}"
        );
        assert!(
            !relation(policy, true, false, false).hears_requests(),
            "{policy:?}"
        );
    }
}

#[test]
fn a_group_is_mirrored_off_a_message_only_from_someone_admitted_and_with_no_one_blocked_in_it() {
    let admitted = relation(ContactPolicy::Everyone, false, false, false);
    let kept_out = relation(ContactPolicy::Friends, false, false, false);

    assert_eq!(admitted.admits_group_from(false), Ok(()));
    assert_eq!(admitted.admits_group_from(true), Err(Unreachable));
    assert_eq!(kept_out.admits_group_from(false), Err(Unreachable));
}
