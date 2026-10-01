use super::*;
use crate::identity::testing::account;

#[tokio::test]
async fn a_local_request_records_both_sides_pending() {
    contract::a_local_request_records_both_sides_pending(
        &InMemorySocialGraph::default(),
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn an_outgoing_request_records_a_pending_outgoing_side() {
    contract::an_outgoing_request_records_a_pending_outgoing_side(
        &InMemorySocialGraph::default(),
        &account("alice"),
    )
    .await;
}

#[tokio::test]
async fn a_new_request_takes_over_a_pending_side() {
    contract::a_new_request_takes_over_a_pending_side(
        &InMemorySocialGraph::default(),
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn accepting_makes_both_local_sides_friends_once() {
    contract::accepting_makes_both_local_sides_friends_once(
        &InMemorySocialGraph::default(),
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn declining_removes_both_local_sides() {
    contract::declining_removes_both_local_sides(
        &InMemorySocialGraph::default(),
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn unfriending_removes_both_local_sides() {
    contract::unfriending_removes_both_local_sides(
        &InMemorySocialGraph::default(),
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn the_dm_outlives_an_unfriend_and_is_reused() {
    contract::the_dm_outlives_an_unfriend_and_is_reused(
        &InMemorySocialGraph::default(),
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn incoming_requests_are_the_pending_ones_received() {
    contract::incoming_requests_are_the_pending_ones_received(
        &InMemorySocialGraph::default(),
        &account("alice"),
        &account("bob"),
        &account("pierre"),
    )
    .await;
}

#[tokio::test]
async fn a_local_friend_is_listed_as_it_now_is() {
    let graph = InMemorySocialGraph::default();
    contract::a_local_friend_is_listed_as_it_now_is(
        &graph,
        &graph,
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn a_remote_friend_is_listed_with_the_avatar_it_was_met_with() {
    contract::a_remote_friend_is_listed_with_the_avatar_it_was_met_with(
        &InMemorySocialGraph::default(),
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn the_friends_list_holds_accepted_friends_with_their_names() {
    contract::the_friends_list_holds_accepted_friends_with_their_names(
        &InMemorySocialGraph::default(),
        &account("alice"),
        &account("bob"),
        &account("pierre"),
    )
    .await;
}

#[tokio::test]
async fn an_incoming_request_is_recorded_once_and_never_reopens_a_friendship() {
    contract::an_incoming_request_is_recorded_once_and_never_reopens_a_friendship(
        &InMemorySocialGraph::default(),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn an_accepted_outgoing_request_opens_the_advertised_dm_once() {
    contract::an_accepted_outgoing_request_opens_the_advertised_dm_once(
        &InMemorySocialGraph::default(),
        &account("alice"),
    )
    .await;
}

#[tokio::test]
async fn a_rejected_outgoing_request_is_dropped_once() {
    contract::a_rejected_outgoing_request_is_dropped_once(
        &InMemorySocialGraph::default(),
        &account("alice"),
    )
    .await;
}

#[tokio::test]
async fn an_advertised_id_naming_another_pairs_dm_opens_a_separate_one() {
    contract::an_advertised_id_naming_another_pairs_dm_opens_a_separate_one(
        &InMemorySocialGraph::default(),
        &account("alice"),
        &account("bob"),
        &account("carol"),
    )
    .await;
}

#[tokio::test]
async fn a_block_ends_both_local_sides_of_a_friendship_at_once() {
    contract::a_block_ends_both_local_sides_of_a_friendship_at_once(
        &InMemorySocialGraph::default(),
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn a_request_the_blocked_account_sent_ends_with_the_block() {
    contract::a_request_the_blocked_account_sent_ends_with_the_block(
        &InMemorySocialGraph::default(),
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn a_block_is_kept_once_and_lifted_once() {
    contract::a_block_is_kept_once_and_lifted_once(
        &InMemorySocialGraph::default(),
        &account("alice"),
    )
    .await;
}

#[tokio::test]
async fn blocks_are_listed_newest_first() {
    let graph = InMemorySocialGraph::default();
    let (alice, bob) = (account("alice"), account("bob"));
    // The fake knows an account's name once it met it in a request.
    graph.record_local_request(&alice, &bob).await.unwrap();
    graph.unfriend(&alice, &bob.actor_uri).await.unwrap();
    contract::blocks_are_listed_newest_first(&graph, &alice, &bob).await;
}

#[tokio::test]
async fn a_block_leaves_the_owners_other_friendships_alone() {
    contract::a_block_leaves_the_owners_other_friendships_alone(
        &InMemorySocialGraph::default(),
        &account("alice"),
        &account("bob"),
        &account("pierre"),
    )
    .await;
}

#[tokio::test]
async fn an_account_takes_messages_from_friends_and_groups_until_it_says_otherwise() {
    contract::an_account_takes_messages_from_friends_and_groups_until_it_says_otherwise(
        &InMemoryContactPolicies::default(),
        UserId::generate(),
    )
    .await;
}

#[tokio::test]
async fn a_contact_policy_is_its_owners() {
    contract::a_contact_policy_is_its_owners(
        &InMemoryContactPolicies::default(),
        UserId::generate(),
        UserId::generate(),
    )
    .await;
}
