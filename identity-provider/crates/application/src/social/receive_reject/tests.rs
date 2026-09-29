use std::sync::Arc;

use domain::identity::testing::{account, remote_actor};
use domain::social::SocialGraph;
use domain::social::testing::InMemorySocialGraph;

use super::*;

#[tokio::test]
async fn a_reject_drops_the_request_and_a_redelivery_changes_nothing() {
    let alice = account("alice");
    let carol = remote_actor("carol_k2m9x@idp.carol.test");
    let graph = Arc::new(InMemorySocialGraph::default());
    graph
        .record_outgoing(alice.id, &carol.actor_uri, None)
        .await
        .unwrap();
    let receive = ReceiveReject::new(graph.clone());

    receive
        .execute(alice.id, carol.actor_uri.clone())
        .await
        .unwrap();
    receive
        .execute(alice.id, carol.actor_uri.clone())
        .await
        .unwrap();

    assert_eq!(
        graph.between(alice.id, &carol.actor_uri).await.unwrap(),
        None
    );
}
