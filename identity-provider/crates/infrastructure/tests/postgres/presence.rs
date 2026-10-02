use domain::ConversationId;
use domain::identity::{Account, ActorUri};
use domain::presence::testing::{Relationships, contract};
use infrastructure::postgres::PgPresenceAudience;
use sqlx::PgPool;

use super::an_account;

struct PgRelationships(PgPool);

#[async_trait::async_trait]
impl Relationships for PgRelationships {
    async fn befriend(&self, owner: &Account, friend: &ActorUri, accepted: bool) {
        sqlx::query(
            "INSERT INTO friendships (owner_user_id, friend_actor_uri, status, direction, \
                                      accepted_at) \
             VALUES ($1, $2, $3, 'outgoing', CASE WHEN $3 = 'accepted' THEN now() END)",
        )
        .bind(owner.id.as_uuid())
        .bind(friend.as_str())
        .bind(if accepted { "accepted" } else { "pending" })
        .execute(&self.0)
        .await
        .expect("seed a friendship");
    }

    async fn converse(&self, members: &[&ActorUri]) -> ConversationId {
        let id = ConversationId::generate();
        sqlx::query("INSERT INTO conversations (id, kind) VALUES ($1, 'group')")
            .bind(id.as_uuid())
            .execute(&self.0)
            .await
            .expect("seed a conversation");
        for member in members {
            sqlx::query(
                "INSERT INTO conversation_members (conversation_id, actor_uri) VALUES ($1, $2)",
            )
            .bind(id.as_uuid())
            .bind(member.as_str())
            .execute(&self.0)
            .await
            .expect("seed a member");
        }
        id
    }

    async fn leave(&self, conversation: ConversationId, member: &ActorUri) {
        sqlx::query(
            "UPDATE conversation_members SET left_at = now() \
             WHERE conversation_id = $1 AND actor_uri = $2",
        )
        .bind(conversation.as_uuid())
        .bind(member.as_str())
        .execute(&self.0)
        .await
        .expect("seed a departure");
    }
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_actor_is_heard_by_the_accounts_that_befriended_it(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );
    contract::an_actor_is_heard_by_the_accounts_that_befriended_it(
        &PgPresenceAudience::new(pool.clone()),
        &PgRelationships(pool),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_viewer_knows_its_friends_and_the_members_of_its_conversations(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );
    contract::a_viewer_knows_its_friends_and_the_members_of_its_conversations(
        &PgPresenceAudience::new(pool.clone()),
        &PgRelationships(pool),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn every_accepted_friend_of_a_local_account_is_befriended(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );
    contract::every_accepted_friend_of_a_local_account_is_befriended(
        &PgPresenceAudience::new(pool.clone()),
        &PgRelationships(pool),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_peer_knows_the_accounts_its_users_befriended_or_share_a_conversation_with(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );
    contract::a_peer_knows_the_accounts_its_users_befriended_or_share_a_conversation_with(
        &PgPresenceAudience::new(pool.clone()),
        &PgRelationships(pool),
        &alice,
        &bob,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_peer_follows_the_conversations_it_has_a_member_in(pool: PgPool) {
    let (alice, bob) = (
        an_account(&pool, "alice").await,
        an_account(&pool, "bob").await,
    );
    contract::a_peer_follows_the_conversations_it_has_a_member_in(
        &PgPresenceAudience::new(pool.clone()),
        &PgRelationships(pool),
        &alice,
        &bob,
    )
    .await;
}
