use crate::e2ee::{
    ATTESTATION_LIFETIME, Approval, ApprovalRequired, Approver, Attestation, Device, DeviceLabel,
    DeviceRequired, DeviceRootKey, Ed25519Signature, HistoryGeneration,
};
use crate::identity::testing::{account, remote_actor};
use crate::messaging::Role;

use super::*;

fn member(actor: &ActorUri) -> Member {
    Member {
        actor_uri: actor.clone(),
        role: Role::Member,
    }
}

#[test]
fn an_epoch_is_never_negative() {
    assert_eq!(Epoch::parse(0).unwrap().value(), 0);
    assert_eq!(Epoch::parse(7).unwrap().value(), 7);
    assert!(Epoch::parse(-1).is_err());
}

#[test]
fn a_members_commit_goes_only_right_after_the_latest_epoch() {
    let at = |n| Epoch::parse(n).unwrap();

    assert_eq!(Epoch::after(None), at(1));
    assert_eq!(Epoch::after(Some(at(3))), at(4));
    assert!(at(1).follows(None));
    assert!(at(4).follows(Some(at(3))));
    for (epoch, latest) in [
        (0, None),
        (2, None),
        (3, Some(3)),
        (2, Some(3)),
        (5, Some(3)),
    ] {
        assert!(
            !at(epoch).follows(latest.map(at)),
            "{epoch} after {latest:?}"
        );
    }
    assert_eq!(Epoch::after(Some(at(i64::MAX))), at(i64::MAX));
}

#[test]
fn an_mls_message_is_never_empty() {
    assert_eq!(CommitBlob::parse(vec![1, 2]).unwrap().as_bytes(), &[1, 2]);
    assert_eq!(WelcomeBlob::parse(vec![3]).unwrap().as_bytes(), &[3]);
    assert!(CommitBlob::parse(Vec::new()).is_err());
    assert!(WelcomeBlob::parse(Vec::new()).is_err());
}

#[test]
fn a_group_info_is_never_empty() {
    assert_eq!(GroupInfoBlob::parse(vec![5]).unwrap().as_bytes(), &[5]);
    assert!(GroupInfoBlob::parse(Vec::new()).is_err());
}

const MEMBER: u8 = 1;
const PROPOSAL: u8 = 2;

/// An MLS message as it starts on the wire: `version`, `wire_format`, the group id after its
/// `length_prefix`, epoch 7, then `next` — a `PublicMessage`'s sender type, a `PrivateMessage`'s
/// content type —, and some more.
fn message(
    version: u16,
    wire_format: u16,
    length_prefix: &[u8],
    group_id_len: usize,
    next: u8,
) -> Vec<u8> {
    let mut bytes = version.to_be_bytes().to_vec();
    bytes.extend(wire_format.to_be_bytes());
    bytes.extend(length_prefix);
    bytes.extend(vec![9; group_id_len]);
    bytes.extend(7u64.to_be_bytes());
    bytes.push(next);
    bytes.extend([0, 0, 0, 2, 0xaa, 0xbb]);
    bytes
}

fn kind(bytes: Vec<u8>) -> Option<CommitKind> {
    CommitBlob::parse(bytes).unwrap().kind()
}

#[test]
fn a_members_commit_is_a_private_message_carrying_a_commit() {
    assert_eq!(
        kind(message(MLS10, PRIVATE_MESSAGE, &[16], 16, COMMIT)),
        Some(CommitKind::Member)
    );
    for (content_type, what) in [(1, "an application message"), (PROPOSAL, "a proposal")] {
        assert_eq!(
            kind(message(MLS10, PRIVATE_MESSAGE, &[16], 16, content_type)),
            None,
            "{what}"
        );
    }
}

#[test]
fn an_external_commit_is_a_public_message_from_a_new_member_committing_itself() {
    assert_eq!(
        kind(message(MLS10, PUBLIC_MESSAGE, &[16], 16, NEW_MEMBER_COMMIT)),
        Some(CommitKind::External)
    );
    for (sender_type, who) in [
        (MEMBER, "a member"),
        (2, "an external sender"),
        (3, "a new member's join proposal"),
    ] {
        assert_eq!(
            kind(message(MLS10, PUBLIC_MESSAGE, &[16], 16, sender_type)),
            None,
            "{who}"
        );
    }
}

#[test]
fn another_wire_format_or_version_is_no_commit() {
    for (version, wire_format, what) in [
        (MLS10, 3, "a Welcome"),
        (MLS10, 4, "a GroupInfo"),
        (MLS10, 5, "a KeyPackage"),
        (2, PRIVATE_MESSAGE, "another version"),
    ] {
        assert_eq!(
            kind(message(version, wire_format, &[16], 16, COMMIT)),
            None,
            "{what}"
        );
    }
}

#[test]
fn the_group_ids_length_is_read_on_one_two_or_four_bytes() {
    for (prefix, length) in [
        (vec![0x00], 0),
        (vec![0x3f], 63),
        (vec![0x41, 0x2c], 300),
        (vec![0x80, 0x01, 0x00, 0x00], 65_536),
    ] {
        assert_eq!(
            kind(message(
                MLS10,
                PUBLIC_MESSAGE,
                &prefix,
                length,
                NEW_MEMBER_COMMIT
            )),
            Some(CommitKind::External),
            "{prefix:?}"
        );
        assert_eq!(
            kind(message(MLS10, PRIVATE_MESSAGE, &prefix, length, COMMIT)),
            Some(CommitKind::Member),
            "{prefix:?}"
        );
        assert_eq!(
            kind(message(MLS10, PUBLIC_MESSAGE, &prefix, length, MEMBER)),
            None,
            "{prefix:?}"
        );
    }
    let eight_bytes = [0xc0, 0, 0, 0, 0, 0, 0, 16];
    assert_eq!(
        kind(message(MLS10, PRIVATE_MESSAGE, &eight_bytes, 16, COMMIT)),
        None,
        "`11` is no length"
    );
}

#[test]
fn a_message_cut_before_its_sender_or_content_type_is_no_commit() {
    for (wire_format, next) in [
        (PUBLIC_MESSAGE, NEW_MEMBER_COMMIT),
        (PRIVATE_MESSAGE, COMMIT),
    ] {
        let whole = message(MLS10, wire_format, &[0x41, 0x2c], 300, next);
        let next_at = 2 + 2 + 2 + 300 + 8;

        for end in 1..=next_at {
            assert_eq!(kind(whole[..end].to_vec()), None, "cut at {end}");
        }
        assert!(kind(whole[..=next_at].to_vec()).is_some());
    }
}

#[test]
fn the_test_blobs_are_the_commits_they_stand_for() {
    use crate::e2ee::testing::{external_commit, join_proposal, member_commit};

    assert_eq!(member_commit(1).kind(), Some(CommitKind::Member));
    assert_ne!(member_commit(1), member_commit(2));
    assert_eq!(external_commit().kind(), Some(CommitKind::External));
    assert_eq!(join_proposal().kind(), None);
}

// Made by the client's openmls wrapper (`crypto/openmls-wasm`, openmls 0.8.1) in a group whose id
// is sixteen `0x11` bytes: a member's update, a device's external join, a join proposal, a message.
const OPENMLS_MEMBER_COMMIT: &str = concat!(
    "AAEAAhARERERERERERERERERERERAAAAAAAAAAEDABx94j9hRO81Qne43Rx3deaCCOR//A3O08hT3NBPQbYn",
    "T0y3JJ12lV8zi8n6xvSbk8RQcBwhDhz9YCFrxktfk7LF0KTakjTEBH6VW1RUPX5PKBgPG9AZMQRUlm6CuVV1",
    "ewWlGhnCjb6UmqNmKfI5JFp5sUw4XT09oV2vJZZCPvn6whE4NQhB9buooLtF9i84/BmY4ZpFtHQQfTstFdjP",
    "J5SVFPXcK90hh3WL9xYy+zPt/RgpQq9RQy9ort/GadIXpsC4ggiPezqa8vihgwN3S83agEu8rEGGxuc/Q+JW",
    "jCL0w9XHhblYLS7KuKAsz+7NIvP5l8ILGocz+D3WHy9TkYbYk5aXRZk6NIDe/NqmG1P8IqQF3Dt/O8E7+28H",
    "mrTnyVWObBiRBmapvcI+fMYsJBUxxm5uBBbzBb4p+ftLzviv0LoTaf7wrqk+jMq3P4F33Ett2g8cvwKawtU2",
    "T7ZkZwwZdMqBJTeXiKBCwe8R/0w1NIhRqfbTBmEcvvTut00MZoJJYVIBg2IiZrQV/h/0ClTFY20N4XG4x3O6",
    "yifmczZP7RCiRA/0yTwMjXOeVz+1iQ4xBIUNRh77lx2sAf5Tc7IRSxpRZXDCpQb8Y2+Qu187axs6KsA=",
);
const OPENMLS_EXTERNAL_COMMIT: &str = concat!(
    "AAEAARARERERERERERERERERERERAAAAAAAAAAIEAAMkAQAGIH5p9PkBc9sLISTtOzOKYy8uH5zWVRmg7rk4",
    "SaUmpYVaASBkreFkJQWV7dYITc/2G/KUtR+1x6HuUJMIMPHtPLoyUiBdjll2p0hTYxJpyIdZMhthYmUmPGKO",
    "vINYTHC824VWFAABDmFsaWNlJ3MgbGFwdG9wAgABCAABAAIAAwBNAAACAAEDICTCRa8vgb9W0qwFZHe+22J8",
    "zFahyVJMU2X6JvyiFF0/AEBAbQAMbhtwDlUBuTfE0MKhf2xE4UNYw2SCMqX2l9J7bLDF6Bq3t/2pqN3RU8dR",
    "ig40GQeB6gdZc61Y+hYWjlsXBUB1IL17b4Qj77whmth/w+KN67AV/DWVC30Zbvo1l3mrFV11QFIgZeJkauUq",
    "WkTJVQoL7V+EGp6qz5vJjtdv96cjAE09USwwOBPZBbwBtiD2ctQDr4i4nb083BRUOUHbDHRHjl5lHy2LmHOH",
    "zv/PWaO7jhKCAK15QEBKFAb4n81nZM3I6SWitqSLBrwnkHEluDv/EejY3wLP5FR2Gj8AVGcfstY6/efmKzeu",
    "ZuAYmSD7BLVYJxZFi8APIHFM36/a7AxQirdO1wQ2c70N1dcTYbQb7c5IBzUSwk7w",
);
const OPENMLS_JOIN_PROPOSAL: &str = concat!(
    "AAEAARARERERERERERERERERERERAAAAAAAAAAMDAAIAAQABAAMgbrAesjwMqqh4VDLO1HNgJdZTJHm4SJVw",
    "bSISOV/qtCAgbaizXaf27KEHqvxTw3Bro/Tc6ksNEz1W4VSo6NAzhhog5kesoFHVFuQu3O/oIf0kDrnVIHL8",
    "CJb1uAanomuZUJ4AAQdtYWxsb3J5AgABCAABAAIAAwBNAAACAAEBAAAAAGr6zPkAAAAAa2mZCQBAQHAUwBim",
    "0IJm5VnpzHPS15ua5KNBOCHZZLN8gJyz0e5SK6s1jemoJbCmhMRLegNoi5irv13mGfr5tnG4vn/eUw0AQEBi",
    "7Pm3zo6JDWu1QXMBwcLm+5lF4rjJY4Hq8MeFo9/BLl7akOawdo7l2XtqomCN5w6PDCd0WBT0ptVyd/F/Mk4D",
    "QEBQXrIa2m5OT/yBrdspQvEvVw3uyPVQbcx2+5iYvNZDprzRsmS9oQvmhVdfjyHJ7fHUDBpJhON4S91VMvhN",
    "kkUH",
);
const OPENMLS_APPLICATION_MESSAGE: &str = concat!(
    "AAEAAhARERERERERERERERERERERAAAAAAAAAAMBABxpuB/EdlBzWkvsCkOHt3gnmtxS6lRHn9JkfP87QFUH",
    "Io+frDF7Oa/wtLH3jTkfwEGhQZI8zgcVeSrMF8Aas53q2DXYMERMkQ9Gx5luumSD3AICIHjhmrkkgVtpqF7r",
    "ZJFb9a7MwlGfY7NINjKuPTBRhwRj",
);

#[test]
fn openmls_messages_are_told_apart_by_their_clear_header() {
    use base64::Engine as _;
    let kind = |message: &str| {
        kind(
            base64::engine::general_purpose::STANDARD
                .decode(message)
                .unwrap(),
        )
    };

    assert_eq!(kind(OPENMLS_MEMBER_COMMIT), Some(CommitKind::Member));
    assert_eq!(kind(OPENMLS_EXTERNAL_COMMIT), Some(CommitKind::External));
    assert_eq!(kind(OPENMLS_JOIN_PROPOSAL), None);
    assert_eq!(kind(OPENMLS_APPLICATION_MESSAGE), None);
}

/// A device of `owner` with root key `[root; 32]`.
fn device(owner: UserId, root: u8) -> Device {
    let at = OffsetDateTime::from_unix_timestamp(1_788_000_000).unwrap();
    Device {
        id: DeviceId::generate(),
        owner,
        label: DeviceLabel::unknown(),
        paired_at: at,
        last_seen_at: at,
        revoked_at: None,
        attestation: Some(Attestation {
            root_key: DeviceRootKey::parse(&[root; 32]).unwrap(),
            signature: vec![7; 64],
            kid: "key-1".into(),
            issued_at: at,
            expires_at: at + ATTESTATION_LIFETIME,
        }),
        hpke_key: None,
        history_generation: None,
    }
}

#[test]
fn a_device_commits_itself_in_only_from_a_session_naming_it_approved() {
    let alice = UserId::generate();
    let (laptop, fresh) = (device(alice, 1), device(alice, 2));
    let first = HistoryGeneration::parse(1).unwrap();
    let trust = DeviceTrust {
        approvals: vec![Approval {
            device: laptop.id,
            root_key: DeviceRootKey::parse(&[1; 32]).unwrap(),
            approver: Approver::Passphrase(first),
            signature: Ed25519Signature::parse("signature", &[9; 64]).unwrap(),
            created_at: laptop.paired_at,
        }],
        devices: vec![laptop.clone(), fresh.clone()],
        current: Some(first),
    };

    let from_the_laptop = may_commit_externally(Some(laptop.id), &trust);
    let from_the_fresh_one = may_commit_externally(Some(fresh.id), &trust);
    let from_no_device = may_commit_externally(None, &trust);
    let with_no_history_key = may_commit_externally(Some(fresh.id), &DeviceTrust::default());
    let unnamed_with_no_history_key = may_commit_externally(None, &DeviceTrust::default());

    assert!(from_the_laptop.is_ok(), "{from_the_laptop:?}");
    assert!(
        matches!(
            from_the_fresh_one,
            Err(DeliveryError::ApprovalRequired(ApprovalRequired))
        ),
        "{from_the_fresh_one:?}"
    );
    assert!(with_no_history_key.is_ok(), "no device is approved yet");
    for unnamed in [from_no_device, unnamed_with_no_history_key] {
        assert!(
            matches!(unnamed, Err(DeliveryError::DeviceRequired(DeviceRequired))),
            "{unnamed:?}"
        );
    }
}

#[test]
fn only_an_active_member_commits() {
    let (alice, carol) = (account("alice"), remote_actor("carol_k2m9x@idp.carol.test"));
    let members = [member(&alice.actor_uri)];

    assert!(may_commit(&members, &alice.actor_uri));
    assert!(!may_commit(&members, &carol.actor_uri));
    assert!(!may_commit(&[], &alice.actor_uri));
}

#[test]
fn a_welcome_goes_from_a_member_to_a_member() {
    let (alice, bob, dave) = (account("alice"), account("bob"), account("dave"));
    let members = [member(&alice.actor_uri), member(&bob.actor_uri)];

    let admitted = check_welcome(&members, &alice.actor_uri, &bob.actor_uri);
    let own_device = check_welcome(&members, &alice.actor_uri, &alice.actor_uri);
    let outsider_in = check_welcome(&members, &alice.actor_uri, &dave.actor_uri);
    let from_outside = check_welcome(&members, &dave.actor_uri, &bob.actor_uri);

    assert!(admitted.is_ok() && own_device.is_ok());
    assert!(
        matches!(outsider_in, Err(DeliveryError::RecipientNotAMember)),
        "{outsider_in:?}"
    );
    assert!(
        matches!(from_outside, Err(DeliveryError::NotAMember)),
        "{from_outside:?}"
    );
}
