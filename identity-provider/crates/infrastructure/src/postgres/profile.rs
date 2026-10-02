use anyhow::Context;
use domain::UserId;
use domain::identity::{Account, ActorUri, RemoteActor};
use domain::profile::{
    CardFacts, OwnProfile, PeerProfiles, ProfileAudience, ProfileCards, ProfileEdit, ProfileError,
    Profiles, Pronouns, PublicProfile,
};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::federation::RemoteActorRow;

/// `users`, as its owner edits it.
pub struct PgProfiles {
    pool: PgPool,
}

impl PgProfiles {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

const PROFILE_COLUMNS: &str = "id, username, email, email_verified_at IS NOT NULL AS email_verified, \
     totp_enabled, actor_uri, display_name, avatar_url, pronouns, bio";

#[derive(sqlx::FromRow)]
struct ProfileRow {
    id: uuid::Uuid,
    username: String,
    email: String,
    email_verified: bool,
    totp_enabled: bool,
    actor_uri: Option<String>,
    display_name: Option<String>,
    avatar_url: Option<String>,
    pronouns: Option<String>,
    bio: Option<String>,
}

impl TryFrom<ProfileRow> for OwnProfile {
    type Error = anyhow::Error;

    fn try_from(row: ProfileRow) -> Result<Self, Self::Error> {
        Ok(OwnProfile {
            id: row.id.into(),
            username: row.username,
            email: row.email,
            email_verified: row.email_verified,
            totp_enabled: row.totp_enabled,
            actor_uri: row
                .actor_uri
                .as_deref()
                .map(ActorUri::parse)
                .transpose()
                .context("users.actor_uri")?,
            display_name: row.display_name,
            avatar_url: row.avatar_url,
            pronouns: row
                .pronouns
                .as_deref()
                .map(Pronouns::parse)
                .transpose()
                .context("users.pronouns")?,
            bio: row.bio,
        })
    }
}

fn profile(row: Option<ProfileRow>) -> Result<Option<OwnProfile>, ProfileError> {
    Ok(row.map(OwnProfile::try_from).transpose()?)
}

#[async_trait::async_trait]
impl Profiles for PgProfiles {
    async fn find(&self, user: UserId) -> Result<Option<OwnProfile>, ProfileError> {
        let row = sqlx::query_as(&format!(
            "SELECT {PROFILE_COLUMNS} FROM users WHERE id = $1"
        ))
        .bind(user.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .context("find a profile")?;
        profile(row)
    }

    async fn edit(
        &self,
        user: UserId,
        edit: &ProfileEdit,
    ) -> Result<Option<OwnProfile>, ProfileError> {
        let row = sqlx::query_as(&format!(
            "UPDATE users SET display_name = $2, pronouns = $3, bio = $4, updated_at = now() \
             WHERE id = $1 RETURNING {PROFILE_COLUMNS}"
        ))
        .bind(user.as_uuid())
        .bind(edit.display_name.as_str())
        .bind(edit.pronouns.map(Pronouns::as_str))
        .bind(edit.bio.as_ref().map(|bio| bio.as_str()))
        .fetch_optional(&self.pool)
        .await
        .context("edit a profile")?;
        profile(row)
    }

    async fn set_avatar(&self, user: UserId, url: Option<&str>) -> Result<(), ProfileError> {
        sqlx::query("UPDATE users SET avatar_url = $2, updated_at = now() WHERE id = $1")
            .bind(user.as_uuid())
            .bind(url)
            .execute(&self.pool)
            .await
            .context("set an avatar")?;
        Ok(())
    }
}

/// `remote_actors` and the avatar `friendships` keep of each friend.
pub struct PgPeerProfiles {
    pool: PgPool,
}

impl PgPeerProfiles {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl PeerProfiles for PgPeerProfiles {
    async fn record(&self, profile: &PublicProfile) -> Result<(), ProfileError> {
        let mut tx = self.pool.begin().await.context("begin a peer profile")?;
        sqlx::query(
            "UPDATE remote_actors \
             SET display_name = $2, avatar_url = $3, pronouns = $4, bio = $5, updated_at = now() \
             WHERE actor_uri = $1",
        )
        .bind(profile.actor.as_str())
        .bind(profile.display_name.as_deref())
        .bind(profile.avatar_url.as_deref())
        .bind(profile.pronouns.map(Pronouns::as_str))
        .bind(profile.bio.as_deref())
        .execute(&mut *tx)
        .await
        .context("cache a peer's profile")?;
        sqlx::query(
            "UPDATE friendships SET friend_avatar_url = $2, updated_at = now() \
             WHERE friend_actor_uri = $1",
        )
        .bind(profile.actor.as_str())
        .bind(profile.avatar_url.as_deref())
        .execute(&mut *tx)
        .await
        .context("keep a peer's avatar on its friendships")?;
        tx.commit().await.context("commit a peer profile")?;
        Ok(())
    }
}

/// Who hears of a profile, from `friendships`.
pub struct PgProfileAudience {
    pool: PgPool,
}

impl PgProfileAudience {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl ProfileAudience for PgProfileAudience {
    async fn friends_here(&self, actor: &ActorUri) -> Result<Vec<UserId>, ProfileError> {
        let owners: Vec<uuid::Uuid> = sqlx::query_scalar(
            "SELECT owner_user_id FROM friendships \
             WHERE friend_actor_uri = $1 AND status = 'accepted'",
        )
        .bind(actor.as_str())
        .fetch_all(&self.pool)
        .await
        .context("list an actor's friends here")?;
        Ok(owners.into_iter().map(UserId::from).collect())
    }

    async fn friends_elsewhere(&self, user: UserId) -> Result<Vec<RemoteActor>, ProfileError> {
        let rows: Vec<RemoteActorRow> = sqlx::query_as(
            "SELECT ra.actor_uri, ra.inbox_url, ra.display_name, ra.avatar_url \
             FROM friendships f JOIN remote_actors ra ON ra.actor_uri = f.friend_actor_uri \
             WHERE f.owner_user_id = $1 AND f.status = 'accepted'",
        )
        .bind(user.as_uuid())
        .fetch_all(&self.pool)
        .await
        .context("list an account's friends elsewhere")?;
        rows.into_iter()
            .map(|row| RemoteActor::try_from(row).map_err(ProfileError::from))
            .collect()
    }
}

/// A profile card's facts, from `users` or `remote_actors`, with the viewer's friendship and
/// conversations.
pub struct PgProfileCards {
    pool: PgPool,
}

impl PgProfileCards {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct CardRow {
    display_name: Option<String>,
    avatar_url: Option<String>,
    pronouns: Option<String>,
    bio: Option<String>,
    local: bool,
    known: bool,
    friends_since: Option<OffsetDateTime>,
    fetched_at: Option<OffsetDateTime>,
}

#[async_trait::async_trait]
impl ProfileCards for PgProfileCards {
    async fn facts(
        &self,
        viewer: &Account,
        actor: &ActorUri,
    ) -> Result<Option<CardFacts>, ProfileError> {
        let row: Option<CardRow> = sqlx::query_as(
            "SELECT COALESCE(u.display_name, ra.display_name) AS display_name, \
                    COALESCE(u.avatar_url, ra.avatar_url) AS avatar_url, \
                    COALESCE(u.pronouns, ra.pronouns) AS pronouns, \
                    COALESCE(u.bio, ra.bio) AS bio, \
                    u.id IS NOT NULL AS local, \
                    ra.fetched_at, \
                    f.accepted_at AS friends_since, \
                    (f.accepted_at IS NOT NULL OR EXISTS ( \
                        SELECT 1 FROM conversation_members mine \
                        JOIN conversation_members theirs \
                          ON theirs.conversation_id = mine.conversation_id \
                        WHERE mine.actor_uri = $2 AND mine.left_at IS NULL \
                          AND theirs.actor_uri = $3 AND theirs.left_at IS NULL \
                    )) AS known \
             FROM (SELECT $3::text AS actor_uri) target \
             LEFT JOIN users u ON u.actor_uri = target.actor_uri \
             LEFT JOIN remote_actors ra ON ra.actor_uri = target.actor_uri \
             LEFT JOIN friendships f ON f.owner_user_id = $1 \
                  AND f.friend_actor_uri = target.actor_uri AND f.status = 'accepted' \
             WHERE u.id IS NOT NULL OR ra.actor_uri IS NOT NULL",
        )
        .bind(viewer.id.as_uuid())
        .bind(viewer.actor_uri.as_str())
        .bind(actor.as_str())
        .fetch_optional(&self.pool)
        .await
        .context("read a profile card")?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some(CardFacts {
            profile: PublicProfile {
                actor: actor.clone(),
                display_name: row.display_name,
                avatar_url: row.avatar_url,
                pronouns: row
                    .pronouns
                    .as_deref()
                    .map(Pronouns::parse)
                    .transpose()
                    .context("a card's pronouns")?,
                bio: row.bio,
            },
            local: row.local,
            known: row.known,
            friends_since: row.friends_since,
            fetched_at: row.fetched_at,
        }))
    }
}
