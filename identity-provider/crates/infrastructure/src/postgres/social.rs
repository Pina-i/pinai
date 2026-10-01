use anyhow::Context;
use domain::identity::{Account, ActorUri};
use domain::social::{
    BlockedActor, Direction, FriendView, Friendship, LocalRequest, SocialGraph, SocialStoreError,
    Unfriended,
};
use domain::{ConversationId, UserId};
use sqlx::{PgConnection, PgPool};

use super::dm;

/// `friendships`: one row per side, `UNIQUE (owner_user_id, friend_actor_uri)`; `user_blocks`.
pub struct PgSocialGraph {
    pool: PgPool,
}

impl PgSocialGraph {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct FriendshipRow {
    id: uuid::Uuid,
    owner_user_id: uuid::Uuid,
    friend_actor_uri: String,
    status: String,
    direction: String,
}

impl TryFrom<FriendshipRow> for Friendship {
    type Error = anyhow::Error;

    fn try_from(row: FriendshipRow) -> Result<Self, Self::Error> {
        Ok(Friendship {
            id: row.id.into(),
            owner: row.owner_user_id.into(),
            friend: ActorUri::parse(&row.friend_actor_uri)
                .context("friendships.friend_actor_uri")?,
            status: row.status.parse().context("friendships.status")?,
            direction: row.direction.parse().context("friendships.direction")?,
        })
    }
}

const COLUMNS: &str = "id, owner_user_id, friend_actor_uri, status, direction";

/// The pending-request upsert: a pending side is taken over by the new request (the latest
/// request decides who answers); an accepted side is returned untouched.
async fn request_side(
    c: &mut PgConnection,
    owner: UserId,
    friend: &ActorUri,
    avatar_url: Option<&str>,
    direction: Direction,
) -> Result<Friendship, SocialStoreError> {
    let upserted: Option<FriendshipRow> = sqlx::query_as(&format!(
        "INSERT INTO friendships (owner_user_id, friend_actor_uri, friend_avatar_url, direction) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (owner_user_id, friend_actor_uri) \
         DO UPDATE SET status = 'pending', direction = EXCLUDED.direction, updated_at = now() \
         WHERE friendships.status = 'pending' \
         RETURNING {COLUMNS}"
    ))
    .bind(owner.as_uuid())
    .bind(friend.as_str())
    .bind(avatar_url)
    .bind(direction.as_str())
    .fetch_optional(&mut *c)
    .await
    .context("upsert a request side")?;
    let row = match upserted {
        Some(row) => row,
        // The conflict hit an accepted side, which the WHERE left alone.
        None => side_between(c, owner, friend)
            .await?
            .context("the accepted side the upsert skipped")?,
    };
    Ok(row.try_into()?)
}

async fn side_between(
    c: &mut PgConnection,
    owner: UserId,
    friend: &ActorUri,
) -> Result<Option<FriendshipRow>, SocialStoreError> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM friendships WHERE owner_user_id = $1 AND friend_actor_uri = $2"
    ))
    .bind(owner.as_uuid())
    .bind(friend.as_str())
    .fetch_optional(c)
    .await
    .context("find a friendship side")?)
}

#[derive(sqlx::FromRow)]
struct FriendViewRow {
    username: Option<String>,
    display_name: Option<String>,
    avatar_url: Option<String>,
    friend_actor_uri: String,
    instance: String,
}

impl TryFrom<FriendViewRow> for FriendView {
    type Error = anyhow::Error;

    fn try_from(row: FriendViewRow) -> Result<Self, Self::Error> {
        Ok(FriendView {
            username: row.username,
            display_name: row.display_name,
            avatar_url: row.avatar_url,
            actor_uri: ActorUri::parse(&row.friend_actor_uri)
                .context("friendships.friend_actor_uri")?,
            instance: row.instance,
        })
    }
}

#[async_trait::async_trait]
impl SocialGraph for PgSocialGraph {
    async fn record_local_request(
        &self,
        requester: &Account,
        target: &Account,
    ) -> Result<LocalRequest, SocialStoreError> {
        let mut tx = self.pool.begin().await.context("begin local request")?;
        let requester_side = request_side(
            &mut tx,
            requester.id,
            &target.actor_uri,
            target.avatar_url.as_deref(),
            Direction::Outgoing,
        )
        .await?;
        let target_side = request_side(
            &mut tx,
            target.id,
            &requester.actor_uri,
            requester.avatar_url.as_deref(),
            Direction::Incoming,
        )
        .await?;
        tx.commit().await.context("commit local request")?;
        Ok(LocalRequest {
            requester_side,
            target_side,
        })
    }

    async fn record_outgoing(
        &self,
        owner: UserId,
        friend: &ActorUri,
        friend_avatar_url: Option<&str>,
    ) -> Result<Friendship, SocialStoreError> {
        let mut c = self.pool.acquire().await.context("acquire a connection")?;
        request_side(
            &mut c,
            owner,
            friend,
            friend_avatar_url,
            Direction::Outgoing,
        )
        .await
    }

    async fn accept(
        &self,
        request: &Friendship,
        accepter: &Account,
    ) -> Result<ConversationId, SocialStoreError> {
        let mut tx = self.pool.begin().await.context("begin accept")?;
        let claimed: Option<uuid::Uuid> = sqlx::query_scalar(
            "UPDATE friendships SET status = 'accepted', updated_at = now() \
             WHERE id = $1 AND status = 'pending' AND direction = 'incoming' RETURNING id",
        )
        .bind(request.id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .context("claim the pending request")?;
        if claimed.is_none() {
            return Err(SocialStoreError::Conflict);
        }
        // The requester's side, when they are local; a remote requester's IdP holds theirs.
        sqlx::query(
            "UPDATE friendships SET status = 'accepted', updated_at = now() \
             WHERE friend_actor_uri = $1 \
               AND owner_user_id = (SELECT id FROM users WHERE actor_uri = $2)",
        )
        .bind(accepter.actor_uri.as_str())
        .bind(request.friend.as_str())
        .execute(&mut *tx)
        .await
        .context("accept the requester's side")?;
        let conversation = dm::open_dm(&mut tx, &accepter.actor_uri, &request.friend, None).await?;
        tx.commit().await.context("commit accept")?;
        Ok(conversation)
    }

    async fn decline(
        &self,
        request: &Friendship,
        decliner: &Account,
    ) -> Result<(), SocialStoreError> {
        let mut tx = self.pool.begin().await.context("begin decline")?;
        let removed = sqlx::query(
            "DELETE FROM friendships \
             WHERE id = $1 AND status = 'pending' AND direction = 'incoming'",
        )
        .bind(request.id.as_uuid())
        .execute(&mut *tx)
        .await
        .context("remove the declined request")?;
        if removed.rows_affected() == 0 {
            return Err(SocialStoreError::Conflict);
        }
        // The requester's side, when they are local.
        sqlx::query(
            "DELETE FROM friendships WHERE friend_actor_uri = $1 \
               AND owner_user_id = (SELECT id FROM users WHERE actor_uri = $2)",
        )
        .bind(decliner.actor_uri.as_str())
        .bind(request.friend.as_str())
        .execute(&mut *tx)
        .await
        .context("remove the requester's side")?;
        tx.commit().await.context("commit decline")?;
        Ok(())
    }

    async fn unfriend(
        &self,
        owner: &Account,
        friend: &ActorUri,
    ) -> Result<Option<Unfriended>, SocialStoreError> {
        let mut tx = self.pool.begin().await.context("begin unfriend")?;
        let unfriended = end_sides(&mut tx, owner, friend).await?;
        tx.commit().await.context("commit unfriend")?;
        Ok(unfriended)
    }

    async fn block(
        &self,
        owner: &Account,
        actor: &ActorUri,
    ) -> Result<Option<Unfriended>, SocialStoreError> {
        let mut tx = self.pool.begin().await.context("begin block")?;
        sqlx::query(
            "INSERT INTO user_blocks (owner_user_id, blocked_actor_uri) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(owner.id.as_uuid())
        .bind(actor.as_str())
        .execute(&mut *tx)
        .await
        .context("record a block")?;
        let ended = end_sides(&mut tx, owner, actor).await?;
        tx.commit().await.context("commit block")?;
        Ok(ended)
    }

    async fn unblock(&self, owner: UserId, actor: &ActorUri) -> Result<bool, SocialStoreError> {
        let lifted = sqlx::query(
            "DELETE FROM user_blocks WHERE owner_user_id = $1 AND blocked_actor_uri = $2",
        )
        .bind(owner.as_uuid())
        .bind(actor.as_str())
        .execute(&self.pool)
        .await
        .context("lift a block")?;
        Ok(lifted.rows_affected() > 0)
    }

    async fn blocked(&self, owner: UserId) -> Result<Vec<BlockedActor>, SocialStoreError> {
        let rows: Vec<BlockedRow> = sqlx::query_as(
            "SELECT b.blocked_actor_uri, \
                    COALESCE(u.display_name, ra.display_name) AS display_name, \
                    COALESCE(u.avatar_url, ra.avatar_url) AS avatar_url, \
                    b.created_at \
             FROM user_blocks b \
             LEFT JOIN users u ON u.actor_uri = b.blocked_actor_uri \
             LEFT JOIN remote_actors ra ON ra.actor_uri = b.blocked_actor_uri \
             WHERE b.owner_user_id = $1 \
             ORDER BY b.created_at DESC",
        )
        .bind(owner.as_uuid())
        .fetch_all(&self.pool)
        .await
        .context("list blocks")?;
        rows.into_iter()
            .map(|row| {
                Ok(BlockedActor {
                    actor: ActorUri::parse(&row.blocked_actor_uri)
                        .context("user_blocks.blocked_actor_uri")?,
                    display_name: row.display_name,
                    avatar_url: row.avatar_url,
                    blocked_at: row.created_at,
                })
            })
            .collect()
    }

    async fn befriended_by_anyone(&self, friend: &ActorUri) -> Result<bool, SocialStoreError> {
        Ok(sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM friendships \
             WHERE friend_actor_uri = $1 AND status = 'accepted')",
        )
        .bind(friend.as_str())
        .fetch_one(&self.pool)
        .await
        .context("look for a remaining friend")?)
    }

    async fn incoming_requests(&self, owner: UserId) -> Result<Vec<Friendship>, SocialStoreError> {
        let rows: Vec<FriendshipRow> = sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM friendships \
             WHERE owner_user_id = $1 AND status = 'pending' AND direction = 'incoming' \
             ORDER BY created_at DESC"
        ))
        .bind(owner.as_uuid())
        .fetch_all(&self.pool)
        .await
        .context("list incoming requests")?;
        rows.into_iter()
            .map(|row| Friendship::try_from(row).map_err(SocialStoreError::from))
            .collect()
    }

    async fn friends(&self, owner: UserId) -> Result<Vec<FriendView>, SocialStoreError> {
        // A local friend is read from `users`, the avatar as the name: the friendship's copy is
        // kept up to date for remote friends only. Not `COALESCE`: a cleared avatar stays cleared.
        let rows: Vec<FriendViewRow> = sqlx::query_as(
            "SELECT u.username AS username, \
                    COALESCE(u.display_name, ra.display_name) AS display_name, \
                    CASE WHEN u.id IS NULL THEN f.friend_avatar_url ELSE u.avatar_url END \
                        AS avatar_url, \
                    f.friend_actor_uri, \
                    COALESCE(ra.instance, 'local') AS instance \
             FROM friendships f \
             LEFT JOIN users u ON f.friend_actor_uri = u.actor_uri \
             LEFT JOIN remote_actors ra ON f.friend_actor_uri = ra.actor_uri \
             WHERE f.owner_user_id = $1 AND f.status = 'accepted'",
        )
        .bind(owner.as_uuid())
        .fetch_all(&self.pool)
        .await
        .context("list friends")?;
        rows.into_iter()
            .map(|row| FriendView::try_from(row).map_err(SocialStoreError::from))
            .collect()
    }

    async fn record_incoming(
        &self,
        owner: UserId,
        friend: &ActorUri,
        friend_avatar_url: Option<&str>,
    ) -> Result<Friendship, SocialStoreError> {
        let mut c = self.pool.acquire().await.context("acquire a connection")?;
        request_side(
            &mut c,
            owner,
            friend,
            friend_avatar_url,
            Direction::Incoming,
        )
        .await
    }

    async fn accept_outgoing(
        &self,
        owner: &Account,
        accepter: &ActorUri,
        advertised: Option<ConversationId>,
    ) -> Result<Option<(Friendship, ConversationId)>, SocialStoreError> {
        let mut tx = self.pool.begin().await.context("begin accept_outgoing")?;
        let accepted: Option<FriendshipRow> = sqlx::query_as(&format!(
            "UPDATE friendships SET status = 'accepted', updated_at = now() \
             WHERE owner_user_id = $1 AND friend_actor_uri = $2 \
               AND status = 'pending' AND direction = 'outgoing' \
             RETURNING {COLUMNS}"
        ))
        .bind(owner.id.as_uuid())
        .bind(accepter.as_str())
        .fetch_optional(&mut *tx)
        .await
        .context("accept the outgoing request")?;
        let Some(accepted) = accepted else {
            return Ok(None);
        };
        let dm = dm::open_dm(&mut tx, &owner.actor_uri, accepter, advertised).await?;
        tx.commit().await.context("commit accept_outgoing")?;
        Ok(Some((accepted.try_into()?, dm)))
    }

    async fn drop_outgoing(
        &self,
        owner: UserId,
        friend: &ActorUri,
    ) -> Result<bool, SocialStoreError> {
        let dropped = sqlx::query(
            "DELETE FROM friendships WHERE owner_user_id = $1 AND friend_actor_uri = $2 \
               AND status = 'pending' AND direction = 'outgoing'",
        )
        .bind(owner.as_uuid())
        .bind(friend.as_str())
        .execute(&self.pool)
        .await
        .context("drop the outgoing request")?;
        Ok(dropped.rows_affected() > 0)
    }

    async fn dm_between(
        &self,
        a: &ActorUri,
        b: &ActorUri,
    ) -> Result<Option<ConversationId>, SocialStoreError> {
        let mut c = self.pool.acquire().await.context("acquire a connection")?;
        Ok(dm::dm_between(&mut c, a, b).await?)
    }

    async fn find(&self, id: domain::FriendshipId) -> Result<Option<Friendship>, SocialStoreError> {
        let row: Option<FriendshipRow> =
            sqlx::query_as(&format!("SELECT {COLUMNS} FROM friendships WHERE id = $1"))
                .bind(id.as_uuid())
                .fetch_optional(&self.pool)
                .await
                .context("find a friendship")?;
        row.map(Friendship::try_from)
            .transpose()
            .map_err(SocialStoreError::from)
    }

    async fn between(
        &self,
        owner: UserId,
        friend: &ActorUri,
    ) -> Result<Option<Friendship>, SocialStoreError> {
        let mut c = self.pool.acquire().await.context("acquire a connection")?;
        side_between(&mut c, owner, friend)
            .await?
            .map(Friendship::try_from)
            .transpose()
            .map_err(SocialStoreError::from)
    }
}

/// The owner's side with `friend` and, when the friend is local, theirs: removed within `tx`.
async fn end_sides(
    tx: &mut PgConnection,
    owner: &Account,
    friend: &ActorUri,
) -> Result<Option<Unfriended>, SocialStoreError> {
    let removed: Option<FriendshipRow> = sqlx::query_as(&format!(
        "DELETE FROM friendships WHERE owner_user_id = $1 AND friend_actor_uri = $2 \
         RETURNING {COLUMNS}"
    ))
    .bind(owner.id.as_uuid())
    .bind(friend.as_str())
    .fetch_optional(&mut *tx)
    .await
    .context("remove the owner's side")?;
    let Some(removed) = removed else {
        return Ok(None);
    };
    let reverse: Option<FriendshipRow> = sqlx::query_as(&format!(
        "DELETE FROM friendships WHERE friend_actor_uri = $1 \
           AND owner_user_id = (SELECT id FROM users WHERE actor_uri = $2) \
         RETURNING {COLUMNS}"
    ))
    .bind(owner.actor_uri.as_str())
    .bind(friend.as_str())
    .fetch_optional(&mut *tx)
    .await
    .context("remove the local friend's side")?;
    Ok(Some(Unfriended {
        removed: removed.try_into()?,
        reverse: reverse.map(Friendship::try_from).transpose()?,
    }))
}

#[derive(sqlx::FromRow)]
struct BlockedRow {
    blocked_actor_uri: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    created_at: time::OffsetDateTime,
}
