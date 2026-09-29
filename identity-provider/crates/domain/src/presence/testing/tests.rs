use crate::identity::testing::account;

use super::*;

#[tokio::test]
async fn an_actor_is_heard_by_the_accounts_that_befriended_it() {
    let audience = InMemoryAudience::default();
    contract::an_actor_is_heard_by_the_accounts_that_befriended_it(
        &audience,
        &audience,
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn a_viewer_knows_its_friends_and_the_members_of_its_conversations() {
    let audience = InMemoryAudience::default();
    contract::a_viewer_knows_its_friends_and_the_members_of_its_conversations(
        &audience,
        &audience,
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn every_accepted_friend_of_a_local_account_is_befriended() {
    let audience = InMemoryAudience::default();
    contract::every_accepted_friend_of_a_local_account_is_befriended(
        &audience,
        &audience,
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn a_peer_knows_the_accounts_its_users_befriended_or_share_a_conversation_with() {
    let audience = InMemoryAudience::default();
    contract::a_peer_knows_the_accounts_its_users_befriended_or_share_a_conversation_with(
        &audience,
        &audience,
        &account("alice"),
        &account("bob"),
    )
    .await;
}

#[tokio::test]
async fn a_peer_follows_the_conversations_it_has_a_member_in() {
    let audience = InMemoryAudience::default();
    contract::a_peer_follows_the_conversations_it_has_a_member_in(
        &audience,
        &audience,
        &account("alice"),
        &account("bob"),
    )
    .await;
}
