use std::sync::Arc;

use domain::ConversationId;
use domain::identity::testing::{InMemoryAccounts, InMemoryRemoteActors, account, remote_actor};
use domain::social::testing::{
    InMemorySocialGraph, Notice, RecordingFriendPresence, RecordingSocialNotifier,
};
use domain::social::{FriendshipStatus, SocialGraph};

use super::*;

#[tokio::test]
async fn an_accept_befriends_the_owner_and_opens_the_advertised_dm_once() {
    let alice = account("alice");
    let carol = remote_actor("carol_k2m9x@idp.carol.test");
    let graph = Arc::new(InMemorySocialGraph::default());
    let notifier = Arc::new(RecordingSocialNotifier::default());
    let presence = Arc::new(RecordingFriendPresence::default());
    let receive = ReceiveAccept::new(
        Arc::new(InMemoryAccounts::with([alice.clone()])),
        Arc::new(InMemoryRemoteActors::with([carol.clone()])),
        graph.clone(),
        notifier.clone(),
        presence.clone(),
    );
    let request = graph
        .record_outgoing(alice.id, &carol.actor_uri, None)
        .await
        .unwrap();
    let advertised = ConversationId::generate();

    receive
        .execute(alice.id, carol.actor_uri.clone(), Some(advertised))
        .await
        .unwrap();
    receive
        .execute(alice.id, carol.actor_uri.clone(), Some(advertised))
        .await
        .unwrap();

    let side = graph
        .between(alice.id, &carol.actor_uri)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(side.status, FriendshipStatus::Accepted);
    let sent = notifier.sent();
    let [(Notice::FriendAccepted, to, event)] = sent.as_slice() else {
        panic!("one friend_accepted expected, got {sent:?}");
    };
    assert_eq!(
        (*to, event.friendship, event.conversation),
        (alice.id, request.id, Some(advertised))
    );
    assert_eq!(presence.watched(), vec![carol.actor_uri.clone()]);
}
