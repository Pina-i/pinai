use time::OffsetDateTime;

use crate::identity::testing::{account, remote_actor};
use crate::messaging::Role;
use crate::presence::{PresenceEvent, PresenceState, TypingEvent};

use super::*;

fn member(actor: &ActorUri) -> Member {
    Member {
        actor_uri: actor.clone(),
        role: Role::Member,
    }
}

#[test]
fn a_conversations_remote_members_are_grouped_by_instance() {
    let origin = InstanceOrigin::parse("http://localhost:8080").unwrap();
    let alice = account("alice").actor_uri;
    let (carol, dave, erin) = (
        remote_actor("carol_k2m9x@idp.carol.test").actor_uri,
        remote_actor("dave_k2m9x@idp.carol.test").actor_uri,
        remote_actor("erin_k2m9x@idp.erin.test").actor_uri,
    );

    let grouped = remote_members_by_domain(
        &[member(&alice), member(&carol), member(&dave), member(&erin)],
        &origin,
    );

    assert_eq!(grouped.len(), 2);
    assert_eq!(grouped[carol.domain()], vec![carol.clone(), dave]);
    assert_eq!(grouped[erin.domain()], vec![erin.clone()]);
    assert!(remote_members_by_domain(&[member(&alice)], &origin).is_empty());
}

#[test]
fn a_peers_stream_carries_only_what_its_filter_names() {
    let (alice, bob) = (account("alice").actor_uri, account("bob").actor_uri);
    let (followed, other) = (ConversationId::generate(), ConversationId::generate());
    let filter = PeerFilter {
        actors: [alice.clone()].into(),
        conversations: [followed].into(),
    };
    let at = OffsetDateTime::UNIX_EPOCH;
    let presence = |actor: &ActorUri| {
        Signal::Presence(PresenceEvent {
            actor: actor.clone(),
            state: PresenceState::Online,
            at,
        })
    };
    let typing = |actor: &ActorUri, conversation| {
        Signal::Typing(TypingEvent {
            actor: actor.clone(),
            conversation,
            at,
        })
    };

    assert!(filter.admits(&presence(&alice)));
    assert!(!filter.admits(&presence(&bob)));
    assert!(filter.admits(&typing(&alice, followed)));
    assert!(!filter.admits(&typing(&alice, other)));
    assert!(!filter.admits(&typing(&bob, followed)));
}

#[test]
fn a_peer_speaks_only_for_the_accounts_on_its_instance() {
    let carol = remote_actor("carol_k2m9x@idp.carol.test").actor_uri;
    let dave = remote_actor("dave_k2m9x@idp.dave.test").actor_uri;
    let at = OffsetDateTime::UNIX_EPOCH;
    let presence = |actor: &ActorUri| {
        Signal::Presence(PresenceEvent {
            actor: actor.clone(),
            state: PresenceState::Online,
            at,
        })
    };
    let typing = Signal::Typing(TypingEvent {
        actor: dave.clone(),
        conversation: ConversationId::generate(),
        at,
    });

    assert!(speaks_for(carol.domain(), &presence(&carol)));
    assert!(!speaks_for(carol.domain(), &presence(&dave)));
    assert!(!speaks_for(
        carol.domain(),
        &presence(&account("alice").actor_uri)
    ));
    assert!(!speaks_for(carol.domain(), &typing));
}
