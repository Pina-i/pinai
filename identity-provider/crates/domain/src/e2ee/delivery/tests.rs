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
fn an_mls_message_is_never_empty() {
    assert_eq!(CommitBlob::parse(vec![1, 2]).unwrap().as_bytes(), &[1, 2]);
    assert_eq!(WelcomeBlob::parse(vec![3]).unwrap().as_bytes(), &[3]);
    assert!(CommitBlob::parse(Vec::new()).is_err());
    assert!(WelcomeBlob::parse(Vec::new()).is_err());
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
