use domain::identity::{Account, ActorUri, RemoteActor};
use domain::messaging::ConversationKind;
use domain::social::testing::people::{Admission, PeopleSeeds, contract};
use domain::social::{Direction, FriendshipStatus};
use domain::{ConversationId, FriendshipId, UserId};
use infrastructure::postgres::PgPeopleSearch;
use sqlx::PgPool;
use time::OffsetDateTime;

struct PgPeopleSeeds(PgPool);

#[async_trait::async_trait]
impl PeopleSeeds for PgPeopleSeeds {
    async fn sign_up(&self, account: &Account, admission: Admission) {
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, display_name, actor_uri, \
                                avatar_url, email_verified_at, admitted_at) \
             VALUES ($1, $2, $3, 'x', $4, $5, $6, \
                     CASE WHEN $7 THEN now() END, CASE WHEN $8 THEN now() END)",
        )
        .bind(account.id.as_uuid())
        .bind(&account.username)
        .bind(format!("{}@idp.test", account.username))
        .bind(&account.display_name)
        .bind(account.actor_uri.as_str())
        .bind(&account.avatar_url)
        .bind(admission == Admission::Confirmed)
        .bind(admission == Admission::Admitted)
        .execute(&self.0)
        .await
        .expect("seed an account");
    }

    async fn remember(&self, actor: &RemoteActor) {
        sqlx::query(
            "INSERT INTO remote_actors (actor_uri, inbox_url, instance, display_name, avatar_url) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(actor.actor_uri.as_str())
        .bind(actor.inbox.as_str())
        .bind(actor.actor_uri.domain().to_string())
        .bind(&actor.display_name)
        .bind(&actor.avatar_url)
        .execute(&self.0)
        .await
        .expect("seed a remote actor");
    }

    async fn befriend(
        &self,
        owner: UserId,
        friend: &ActorUri,
        status: FriendshipStatus,
        direction: Direction,
    ) -> FriendshipId {
        let id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO friendships (owner_user_id, friend_actor_uri, status, direction, \
                                      accepted_at) \
             VALUES ($1, $2, $3, $4, CASE WHEN $3 = 'accepted' THEN now() END) RETURNING id",
        )
        .bind(owner.as_uuid())
        .bind(friend.as_str())
        .bind(status.as_str())
        .bind(direction.as_str())
        .fetch_one(&self.0)
        .await
        .expect("seed a friendship");
        id.into()
    }

    async fn block(&self, owner: UserId, actor: &ActorUri) {
        sqlx::query("INSERT INTO user_blocks (owner_user_id, blocked_actor_uri) VALUES ($1, $2)")
            .bind(owner.as_uuid())
            .bind(actor.as_str())
            .execute(&self.0)
            .await
            .expect("seed a block");
    }

    async fn converse(
        &self,
        kind: ConversationKind,
        name: Option<&str>,
        created_at: OffsetDateTime,
        members: &[&ActorUri],
    ) -> ConversationId {
        let id = ConversationId::generate();
        sqlx::query(
            "INSERT INTO conversations (id, kind, name, created_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(id.as_uuid())
        .bind(kind.as_str())
        .bind(name)
        .bind(created_at)
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
        .expect("leave a conversation");
    }
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn names_are_found_in_three_tiers_then_by_name(pool: PgPool) {
    contract::names_are_found_in_three_tiers_then_by_name(
        &PgPeopleSearch::new(pool.clone()),
        &PgPeopleSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn accents_and_case_never_matter_either_way(pool: PgPool) {
    contract::accents_and_case_never_matter_either_way(
        &PgPeopleSearch::new(pool.clone()),
        &PgPeopleSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_query_is_taken_literally(pool: PgPool) {
    contract::a_query_is_taken_literally(&PgPeopleSearch::new(pool.clone()), &PgPeopleSeeds(pool))
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_caller_and_sign_ups_still_to_confirm_are_never_listed(pool: PgPool) {
    contract::the_caller_and_sign_ups_still_to_confirm_are_never_listed(
        &PgPeopleSearch::new(pool.clone()),
        &PgPeopleSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn groups_hold_the_remote_active_members_of_the_callers_groups_only(pool: PgPool) {
    contract::groups_hold_the_remote_active_members_of_the_callers_groups_only(
        &PgPeopleSearch::new(pool.clone()),
        &PgPeopleSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_group_person_comes_with_the_latest_group_shared(pool: PgPool) {
    contract::a_group_person_comes_with_the_latest_group_shared(
        &PgPeopleSearch::new(pool.clone()),
        &PgPeopleSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn each_person_comes_with_the_callers_standing(pool: PgPool) {
    contract::each_person_comes_with_the_callers_standing(
        &PgPeopleSearch::new(pool.clone()),
        &PgPeopleSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn each_section_holds_at_most_the_limit(pool: PgPool) {
    contract::each_section_holds_at_most_the_limit(
        &PgPeopleSearch::new(pool.clone()),
        &PgPeopleSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn someone_without_an_address_is_left_out(pool: PgPool) {
    contract::someone_without_an_address_is_left_out(
        &PgPeopleSearch::new(pool.clone()),
        &PgPeopleSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_account_here_is_found_by_its_handle_with_the_callers_ties(pool: PgPool) {
    contract::an_account_here_is_found_by_its_handle_with_the_callers_ties(
        &PgPeopleSearch::new(pool.clone()),
        &PgPeopleSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_callers_ties_to_anyone_are_read_alone(pool: PgPool) {
    contract::the_callers_ties_to_anyone_are_read_alone(
        &PgPeopleSearch::new(pool.clone()),
        &PgPeopleSeeds(pool),
    )
    .await;
}
