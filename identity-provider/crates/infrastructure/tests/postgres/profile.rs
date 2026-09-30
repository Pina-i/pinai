use domain::UserId;
use domain::identity::{ActorUri, RemoteActor};
use domain::profile::testing::{ProfileSeeds, contract};
use domain::profile::{OwnProfile, PublicProfile};
use infrastructure::postgres::{PgPeerProfiles, PgProfileAudience, PgProfiles};
use sqlx::PgPool;

struct PgProfileSeeds(PgPool);

#[async_trait::async_trait]
impl ProfileSeeds for PgProfileSeeds {
    async fn sign_up(&self, profile: &OwnProfile) {
        sqlx::query(
            "INSERT INTO users (id, username, email, password_hash, email_verified_at, \
                                totp_enabled, actor_uri, display_name, avatar_url, pronouns, bio) \
             VALUES ($1, $2, $3, 'x', CASE WHEN $4 THEN now() END, $5, $6, $7, $8, $9, $10)",
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
                                      direction) \
             VALUES ($1, $2, $3, $4, 'outgoing')",
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
        let cached: Option<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT display_name, avatar_url FROM remote_actors WHERE actor_uri = $1",
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
        let cached = cached.map(|(display_name, avatar_url)| PublicProfile {
            actor: actor.clone(),
            display_name,
            avatar_url,
        });
        (cached, kept)
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
