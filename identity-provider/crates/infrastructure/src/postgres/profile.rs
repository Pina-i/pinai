use anyhow::Context;
use domain::UserId;
use domain::identity::{ActorUri, RemoteActor};
use domain::profile::{
    OwnProfile, PeerProfiles, ProfileAudience, ProfileEdit, ProfileError, Profiles, Pronouns,
    PublicProfile,
};
use sqlx::PgPool;

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
            "UPDATE remote_actors SET display_name = $2, avatar_url = $3, updated_at = now() \
             WHERE actor_uri = $1",
        )
        .bind(profile.actor.as_str())
        .bind(profile.display_name.as_deref())
        .bind(profile.avatar_url.as_deref())
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
