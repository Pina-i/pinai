use domain::ConversationId;
use domain::identity::{Account, ActorUri};
use domain::social::SocialGraph;
use domain::social::testing::{AccountEdits, contract};
use infrastructure::postgres::PgSocialGraph;
use sqlx::PgPool;

use crate::an_account;

struct PgAccountEdits(PgPool);

#[async_trait::async_trait]
impl AccountEdits for PgAccountEdits {
    async fn save(&self, account: &Account) {
        sqlx::query("UPDATE users SET display_name = $2, avatar_url = $3 WHERE id = $1")
            .bind(account.id.as_uuid())
            .bind(&account.display_name)
            .bind(&account.avatar_url)
            .execute(&self.0)
            .await
            .expect("edit an account");
    }
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_remote_friend_is_listed_with_the_avatar_it_was_met_with(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );

    contract::a_remote_friend_is_listed_with_the_avatar_it_was_met_with(
        &PgSocialGraph::new(pool),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_local_friend_is_listed_as_it_now_is(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );

    contract::a_local_friend_is_listed_as_it_now_is(
        &PgSocialGraph::new(pool.clone()),
        &PgAccountEdits(pool),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_local_request_records_both_sides_pending(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );

    contract::a_local_request_records_both_sides_pending(&PgSocialGraph::new(pool), &alice, &bob)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_outgoing_request_records_a_pending_outgoing_side(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;

    contract::an_outgoing_request_records_a_pending_outgoing_side(
        &PgSocialGraph::new(pool),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_new_request_takes_over_a_pending_side(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );

    contract::a_new_request_takes_over_a_pending_side(&PgSocialGraph::new(pool), &alice, &bob)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn accepting_makes_both_local_sides_friends_once(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );

    contract::accepting_makes_both_local_sides_friends_once(
        &PgSocialGraph::new(pool),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn declining_removes_both_local_sides(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );

    contract::declining_removes_both_local_sides(&PgSocialGraph::new(pool), &alice, &bob).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn unfriending_removes_both_local_sides(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );

    contract::unfriending_removes_both_local_sides(&PgSocialGraph::new(pool), &alice, &bob).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_dm_outlives_an_unfriend_and_is_reused(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );

    contract::the_dm_outlives_an_unfriend_and_is_reused(&PgSocialGraph::new(pool), &alice, &bob)
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn incoming_requests_are_the_pending_ones_received(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );
    let pierre = an_account(&pool, "pierre").await;

    contract::incoming_requests_are_the_pending_ones_received(
        &PgSocialGraph::new(pool),
        &alice,
        &bob,
        &pierre,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_friendship_is_dated_from_its_acceptance_on_both_sides_once(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );

    contract::a_friendship_is_dated_from_its_acceptance_on_both_sides_once(
        &PgSocialGraph::new(pool),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_accepted_outgoing_request_is_dated_once(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;

    contract::an_accepted_outgoing_request_is_dated_once(&PgSocialGraph::new(pool), &alice).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_friends_list_holds_accepted_friends_with_their_names(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );
    let pierre = an_account(&pool, "pierre").await;

    contract::the_friends_list_holds_accepted_friends_with_their_names(
        &PgSocialGraph::new(pool),
        &alice,
        &bob,
        &pierre,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_incoming_request_is_recorded_once_and_never_reopens_a_friendship(pool: PgPool) {
    let bob = an_account(&pool, "bob").await;

    contract::an_incoming_request_is_recorded_once_and_never_reopens_a_friendship(
        &PgSocialGraph::new(pool),
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_accepted_outgoing_request_opens_the_advertised_dm_once(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;

    contract::an_accepted_outgoing_request_opens_the_advertised_dm_once(
        &PgSocialGraph::new(pool),
        &alice,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_rejected_outgoing_request_is_dropped_once(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;

    contract::a_rejected_outgoing_request_is_dropped_once(&PgSocialGraph::new(pool), &alice).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_advertised_id_that_names_a_group_opens_a_separate_dm(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let group = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO conversations (id, kind, name) VALUES ($1, 'group', 'Trip')")
        .bind(group)
        .execute(&pool)
        .await
        .unwrap();
    let graph = PgSocialGraph::new(pool.clone());
    graph
        .record_outgoing(alice.id, &contract::remote_bob(), None)
        .await
        .unwrap();

    let (_, dm) = graph
        .accept_outgoing(
            &alice,
            &contract::remote_bob(),
            Some(ConversationId::from(group)),
        )
        .await
        .unwrap()
        .unwrap();

    assert_ne!(dm.as_uuid(), group);
    let group_members: i64 =
        sqlx::query_scalar("SELECT count(*) FROM conversation_members WHERE conversation_id = $1")
            .bind(group)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        group_members, 0,
        "the DM's members were not filed into the group"
    );
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_advertised_id_naming_another_pairs_dm_opens_a_separate_one(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let bob = an_account(&pool, "bob").await;
    let carol = an_account(&pool, "carol").await;
    contract::an_advertised_id_naming_another_pairs_dm_opens_a_separate_one(
        &PgSocialGraph::new(pool),
        &alice,
        &bob,
        &carol,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_block_ends_both_local_sides_of_a_friendship_at_once(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );

    contract::a_block_ends_both_local_sides_of_a_friendship_at_once(
        &PgSocialGraph::new(pool),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_request_the_blocked_account_sent_ends_with_the_block(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );

    contract::a_request_the_blocked_account_sent_ends_with_the_block(
        &PgSocialGraph::new(pool),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_block_is_kept_once_and_lifted_once(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;

    contract::a_block_is_kept_once_and_lifted_once(&PgSocialGraph::new(pool), &alice).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn blocks_are_listed_newest_first(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );

    contract::blocks_are_listed_newest_first(&PgSocialGraph::new(pool), &alice, &bob).await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_block_leaves_the_owners_other_friendships_alone(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let bob = an_account(&pool, "bob").await;
    let pierre = an_account(&pool, "pierre").await;

    contract::a_block_leaves_the_owners_other_friendships_alone(
        &PgSocialGraph::new(pool),
        &alice,
        &bob,
        &pierre,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_block_goes_with_its_owners_account(pool: PgPool) {
    let alice = an_account(&pool, "alice").await;
    let graph = PgSocialGraph::new(pool.clone());
    graph
        .block(
            &alice,
            &ActorUri::parse("https://idp.bob.test/users/bob_zz9yy").unwrap(),
        )
        .await
        .unwrap();

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(alice.id.as_uuid())
        .execute(&pool)
        .await
        .unwrap();

    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM user_blocks")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
}
