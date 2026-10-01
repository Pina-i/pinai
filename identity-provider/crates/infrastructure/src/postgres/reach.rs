use anyhow::Context;
use domain::UserId;
use domain::identity::ActorUri;
use domain::social::{ContactPolicies, ContactPolicy, Reachability, Relation, SocialStoreError};
use sqlx::PgPool;

/// Whether an actor may reach a local account: `users.contact_policy`, `user_blocks`,
/// `friendships` and the groups both are in, read in one query.
pub struct PgReachability {
    pool: PgPool,
}

impl PgReachability {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct RelationRow {
    contact_policy: String,
    blocked: bool,
    friends: bool,
    share_a_group: bool,
}

#[async_trait::async_trait]
impl Reachability for PgReachability {
    async fn relation(
        &self,
        owner: UserId,
        other: &ActorUri,
    ) -> Result<Relation, SocialStoreError> {
        let row: RelationRow = sqlx::query_as(
            "SELECT u.contact_policy, \
                    EXISTS (SELECT 1 FROM user_blocks b \
                            WHERE b.owner_user_id = u.id AND b.blocked_actor_uri = $2) AS blocked, \
                    EXISTS (SELECT 1 FROM friendships f \
                            WHERE f.owner_user_id = u.id AND f.friend_actor_uri = $2 \
                              AND f.status = 'accepted') AS friends, \
                    EXISTS (SELECT 1 FROM conversation_members me \
                            JOIN conversations c ON c.id = me.conversation_id AND c.kind = 'group' \
                            JOIN conversation_members them \
                              ON them.conversation_id = me.conversation_id \
                            WHERE me.actor_uri = u.actor_uri AND me.left_at IS NULL \
                              AND them.actor_uri = $2 AND them.left_at IS NULL) AS share_a_group \
             FROM users u WHERE u.id = $1",
        )
        .bind(owner.as_uuid())
        .bind(other.as_str())
        .fetch_one(&self.pool)
        .await
        .context("read an account's relation to an actor")?;
        Ok(Relation {
            policy: row.contact_policy.parse().context("users.contact_policy")?,
            blocked: row.blocked,
            friends: row.friends,
            share_a_group: row.share_a_group,
        })
    }

    async fn blocks_any(
        &self,
        owner: UserId,
        among: &[ActorUri],
    ) -> Result<bool, SocialStoreError> {
        let among: Vec<&str> = among.iter().map(ActorUri::as_str).collect();
        Ok(sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM user_blocks \
             WHERE owner_user_id = $1 AND blocked_actor_uri = ANY($2))",
        )
        .bind(owner.as_uuid())
        .bind(&among)
        .fetch_one(&self.pool)
        .await
        .context("look for a blocked actor among a roster")?)
    }
}

/// `users.contact_policy`.
pub struct PgContactPolicies {
    pool: PgPool,
}

impl PgContactPolicies {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl ContactPolicies for PgContactPolicies {
    async fn get(&self, owner: UserId) -> Result<ContactPolicy, SocialStoreError> {
        let policy: String = sqlx::query_scalar("SELECT contact_policy FROM users WHERE id = $1")
            .bind(owner.as_uuid())
            .fetch_one(&self.pool)
            .await
            .context("read a contact policy")?;
        Ok(policy.parse().context("users.contact_policy")?)
    }

    async fn set(&self, owner: UserId, policy: ContactPolicy) -> Result<(), SocialStoreError> {
        let set = sqlx::query("UPDATE users SET contact_policy = $2 WHERE id = $1")
            .bind(owner.as_uuid())
            .bind(policy.as_str())
            .execute(&self.pool)
            .await
            .context("set a contact policy")?;
        if set.rows_affected() == 0 {
            return Err(anyhow::anyhow!("no account to set a contact policy for").into());
        }
        Ok(())
    }
}
