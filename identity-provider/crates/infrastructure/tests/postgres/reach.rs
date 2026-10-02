use domain::identity::{Account, ActorUri};
use domain::messaging::{Conversations, initial_roster};
use domain::social::testing::contract;
use domain::social::{ContactPolicies, ContactPolicy, Reachability, Relation, SocialGraph};
use infrastructure::postgres::{PgContactPolicies, PgConversations, PgReachability, PgSocialGraph};
use sqlx::PgPool;

use crate::{a_user, an_account};

fn remote_dave() -> ActorUri {
    ActorUri::parse("https://idp.dave.test/users/dave_k2m9x").unwrap()
}

async fn befriend(pool: &PgPool, requester: &Account, target: &Account) {
    let graph = PgSocialGraph::new(pool.clone());
    let request = graph
        .record_local_request(requester, target)
        .await
        .unwrap()
        .target_side;
    graph.accept(&request, target).await.unwrap();
}

async fn relation(pool: &PgPool, owner: &Account, other: &ActorUri) -> Relation {
    PgReachability::new(pool.clone())
        .relation(owner.id, other)
        .await
        .unwrap()
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_stranger_has_no_tie_under_the_default_setting(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;

    assert_eq!(
        relation(&pool, &alice, &remote_dave()).await,
        Relation {
            policy: ContactPolicy::FriendsAndGroups,
            blocked: false,
            friends: false,
            share_a_group: false,
        }
    );
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_accepted_friendship_is_a_tie_and_a_pending_one_is_not(pool: PgPool) {
    let (alice, bob, carol) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
        an_account(&pool, "carol").await,
    );
    befriend(&pool, &bob, &alice).await;
    PgSocialGraph::new(pool.clone())
        .record_local_request(&carol, &alice)
        .await
        .unwrap();

    assert!(relation(&pool, &alice, &bob.actor_uri).await.friends);
    assert!(relation(&pool, &bob, &alice.actor_uri).await.friends);
    assert!(!relation(&pool, &alice, &carol.actor_uri).await.friends);
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_group_both_are_in_is_a_tie_and_one_left_or_a_dm_is_not(pool: PgPool) {
    let (alice, bob, carol) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
        an_account(&pool, "carol").await,
    );
    let conversations = PgConversations::new(pool.clone());
    conversations
        .create_group(
            None,
            &initial_roster(&alice.actor_uri, &[remote_dave(), carol.actor_uri.clone()]).unwrap(),
        )
        .await
        .unwrap();
    let left = conversations
        .create_group(
            None,
            &initial_roster(&alice.actor_uri, std::slice::from_ref(&bob.actor_uri)).unwrap(),
        )
        .await
        .unwrap();
    conversations
        .remove_member(left.id, &bob.actor_uri, None, None)
        .await
        .unwrap();
    // The DM an unfriend keeps.
    befriend(&pool, &carol, &bob).await;
    PgSocialGraph::new(pool.clone())
        .unfriend(&bob, &carol.actor_uri)
        .await
        .unwrap();

    assert!(relation(&pool, &alice, &remote_dave()).await.share_a_group);
    assert!(
        relation(&pool, &carol, &alice.actor_uri)
            .await
            .share_a_group
    );
    assert!(!relation(&pool, &alice, &bob.actor_uri).await.share_a_group);
    assert!(
        !relation(&pool, &bob, &alice.actor_uri).await.share_a_group,
        "nor for the one who left"
    );
    assert!(!relation(&pool, &bob, &carol.actor_uri).await.share_a_group);
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_block_is_read_with_the_rest(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );
    befriend(&pool, &bob, &alice).await;
    let graph = PgSocialGraph::new(pool.clone());
    graph.block(&alice, &remote_dave()).await.unwrap();

    assert!(relation(&pool, &alice, &remote_dave()).await.blocked);
    assert!(!relation(&pool, &alice, &bob.actor_uri).await.blocked);
    assert!(
        !relation(&pool, &bob, &remote_dave()).await.blocked,
        "a block is its owner's"
    );
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_roster_holding_someone_the_owner_blocked_is_told_apart(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );
    PgSocialGraph::new(pool.clone())
        .block(&alice, &remote_dave())
        .await
        .unwrap();
    let reach = PgReachability::new(pool.clone());

    assert!(
        reach
            .blocks_any(alice.id, &[bob.actor_uri.clone(), remote_dave()])
            .await
            .unwrap()
    );
    assert!(
        !reach
            .blocks_any(alice.id, std::slice::from_ref(&bob.actor_uri))
            .await
            .unwrap()
    );
    assert!(
        !reach.blocks_any(bob.id, &[remote_dave()]).await.unwrap(),
        "a block is its owner's"
    );
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_owners_setting_is_read_with_the_rest(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    PgContactPolicies::new(pool.clone())
        .set(alice.id, ContactPolicy::Friends)
        .await
        .unwrap();

    assert_eq!(
        relation(&pool, &alice, &remote_dave()).await.policy,
        ContactPolicy::Friends
    );
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_account_takes_messages_from_friends_and_groups_until_it_says_otherwise(pool: PgPool) {
    let alice = a_user(&pool).await;

    contract::an_account_takes_messages_from_friends_and_groups_until_it_says_otherwise(
        &PgContactPolicies::new(pool),
        alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_contact_policy_is_its_owners(pool: PgPool) {
    let (alice, bob) = (a_user(&pool).await, a_user(&pool).await);

    contract::a_contact_policy_is_its_owners(&PgContactPolicies::new(pool), alice, bob).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_value_outside_the_three_is_refused_by_the_table(pool: PgPool) {
    let alice = a_user(&pool).await;

    let refused = sqlx::query("UPDATE users SET contact_policy = 'nobody' WHERE id = $1")
        .bind(alice.as_uuid())
        .execute(&pool)
        .await;

    assert!(refused.is_err());
}
