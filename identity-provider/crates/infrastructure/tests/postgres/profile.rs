use domain::identity::{ActorUri, RemoteActor};
use domain::profile::testing::{ProfileSeeds, contract};
use domain::profile::{OwnProfile, Pronouns, PublicProfile};
use domain::{ConversationId, UserId};
use infrastructure::postgres::{PgPeerProfiles, PgProfileAudience, PgProfileCards, PgProfiles};
use sqlx::PgPool;

struct PgProfileSeeds(PgPool);

#[async_trait::async_trait]
impl ProfileSeeds for PgProfileSeeds {
    async fn sign_up(&self, profile: &OwnProfile) {
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, email_verified_at, \
                                totp_enabled, actor_uri, display_name, avatar_url, pronouns, bio, \
                                is_admin) \
             VALUES ($1, $2, $3, 'x', CASE WHEN $4 THEN now() END, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(profile.id.as_uuid())
        .bind(&profile.username)
        .bind(&profile.email)
        .bind(profile.email_verified)
        .bind(profile.totp_enabled)
        .bind(profile.actor_uri.as_ref().map(ActorUri::as_str))
        .bind(&profile.display_name)
        .bind(&profile.avatar_url)
        .bind(profile.pronouns.map(|p| p.as_str()))
        .bind(&profile.bio)
        .bind(profile.admin)
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
        accepted: bool,
        avatar_url: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO friendships (owner_user_id, friend_actor_uri, friend_avatar_url, status, \
                                      direction, accepted_at) \
             VALUES ($1, $2, $3, $4, 'outgoing', CASE WHEN $4 = 'accepted' THEN now() END)",
        )
        .bind(owner.as_uuid())
        .bind(friend.as_str())
        .bind(avatar_url)
        .bind(if accepted { "accepted" } else { "pending" })
        .execute(&self.0)
        .await
        .expect("seed a friendship");
    }

    async fn shown(&self, actor: &ActorUri) -> (Option<PublicProfile>, Vec<Option<String>>) {
        let cached: Option<(
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT display_name, avatar_url, pronouns, bio FROM remote_actors \
                 WHERE actor_uri = $1",
        )
        .bind(actor.as_str())
        .fetch_optional(&self.0)
        .await
        .unwrap();
        let kept = sqlx::query_scalar(
            "SELECT friend_avatar_url FROM friendships WHERE friend_actor_uri = $1 \
             ORDER BY created_at",
        )
        .bind(actor.as_str())
        .fetch_all(&self.0)
        .await
        .unwrap();
        let cached = cached.map(|(display_name, avatar_url, pronouns, bio)| PublicProfile {
            actor: actor.clone(),
            display_name,
            avatar_url,
            pronouns: pronouns.map(|p| Pronouns::parse(&p).unwrap()),
            bio,
        });
        (cached, kept)
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
        .expect("leave a conversation");
    }
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_account_is_found_with_its_profile(pool: PgPool) {
    contract::an_account_is_found_with_its_profile(
        &PgProfiles::new(pool.clone()),
        &PgProfileSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_edit_writes_every_field(pool: PgPool) {
    contract::an_edit_writes_every_field(&PgProfiles::new(pool.clone()), &PgProfileSeeds(pool))
        .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_avatar_is_shown_until_cleared(pool: PgPool) {
    contract::an_avatar_is_shown_until_cleared(
        &PgProfiles::new(pool.clone()),
        &PgProfileSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_peers_profile_is_cached_and_kept_by_every_friendship_with_it(pool: PgPool) {
    contract::a_peers_profile_is_cached_and_kept_by_every_friendship_with_it(
        &PgPeerProfiles::new(pool.clone()),
        &PgProfileSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_actor_is_heard_of_by_the_accounts_that_befriended_it(pool: PgPool) {
    contract::an_actor_is_heard_of_by_the_accounts_that_befriended_it(
        &PgProfileAudience::new(pool.clone()),
        &PgProfileSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_account_reaches_its_accepted_friends_on_other_instances(pool: PgPool) {
    contract::an_account_reaches_its_accepted_friends_on_other_instances(
        &PgProfileAudience::new(pool.clone()),
        &PgProfileSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_card_holds_what_an_account_here_shows_and_dates_a_friendship(pool: PgPool) {
    contract::a_card_holds_what_an_account_here_shows_and_dates_a_friendship(
        &PgProfileCards::new(pool.clone()),
        &PgProfileSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_card_knows_another_instances_account_by_a_friendship_or_a_conversation(pool: PgPool) {
    contract::a_card_knows_another_instances_account_by_a_friendship_or_a_conversation(
        &PgProfileCards::new(pool.clone()),
        &PgPeerProfiles::new(pool.clone()),
        &PgProfileSeeds(pool),
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn no_card_for_an_account_this_instance_does_not_hold(pool: PgPool) {
    contract::no_card_for_an_account_this_instance_does_not_hold(
        &PgProfileCards::new(pool.clone()),
        &PgProfileSeeds(pool),
    )
    .await;
}
