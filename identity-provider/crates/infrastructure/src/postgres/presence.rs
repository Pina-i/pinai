use anyhow::Context;
use domain::identity::{ActorUri, Domain};
use domain::presence::{PresenceAudience, PresenceError};
use domain::{ConversationId, UserId};
use sqlx::PgPool;

/// Reads `friendships` and `conversation_members`: who hears of whom.
pub struct PgPresenceAudience {
    pool: PgPool,
}

impl PgPresenceAudience {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl PresenceAudience for PgPresenceAudience {
    async fn befriended_by(&self, actor: &ActorUri) -> Result<Vec<UserId>, PresenceError> {
        let owners: Vec<uuid::Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT owner_user_id FROM friendships \
             WHERE friend_actor_uri = $1 AND status = 'accepted'",
        )
        .bind(actor.as_str())
        .fetch_all(&self.pool)
        .await
        .context("find who befriended an actor")?;
        Ok(owners.into_iter().map(Into::into).collect())
    }

    async fn known_to(
        &self,
        viewer: UserId,
        viewer_actor: &ActorUri,
        among: &[ActorUri],
    ) -> Result<Vec<ActorUri>, PresenceError> {
        let among: Vec<&str> = among.iter().map(ActorUri::as_str).collect();
        let known: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT actor FROM unnest($3::text[]) AS a(actor) \
             WHERE EXISTS (SELECT 1 FROM friendships f \
                           WHERE f.owner_user_id = $1 AND f.friend_actor_uri = actor \
                             AND f.status = 'accepted') \
                OR EXISTS (SELECT 1 FROM conversation_members me \
                           JOIN conversation_members them \
                             ON them.conversation_id = me.conversation_id \
                           WHERE me.actor_uri = $2 AND me.left_at IS NULL \
                             AND them.actor_uri = actor AND them.left_at IS NULL)",
        )
        .bind(viewer.as_uuid())
        .bind(viewer_actor.as_str())
        .bind(&among)
        .fetch_all(&self.pool)
        .await
        .context("find the actors a viewer knows")?;
        known
            .iter()
            .map(|actor| {
                ActorUri::parse(actor)
                    .context("a known actor's URI")
                    .map_err(PresenceError::from)
            })
            .collect()
    }

    async fn befriended(&self) -> Result<Vec<ActorUri>, PresenceError> {
        let friends: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT friend_actor_uri FROM friendships WHERE status = 'accepted'",
        )
        .fetch_all(&self.pool)
        .await
        .context("list every befriended actor")?;
        friends
            .iter()
            .map(|actor| {
                ActorUri::parse(actor)
                    .context("a befriended actor's URI")
                    .map_err(PresenceError::from)
            })
            .collect()
    }

    async fn known_on(
        &self,
        peer: &Domain,
        among: &[ActorUri],
    ) -> Result<Vec<ActorUri>, PresenceError> {
        let among: Vec<&str> = among.iter().map(ActorUri::as_str).collect();
        // Every friend and co-member of theirs: which live on `peer` needs the URIs parsed.
        let pairs: Vec<(String, String)> = sqlx::query_as(
            "SELECT u.actor_uri, f.friend_actor_uri FROM friendships f \
             JOIN users u ON u.id = f.owner_user_id \
             WHERE u.actor_uri = ANY($1) AND f.status = 'accepted' \
             UNION \
             SELECT me.actor_uri, them.actor_uri FROM conversation_members me \
             JOIN conversation_members them ON them.conversation_id = me.conversation_id \
             WHERE me.actor_uri = ANY($1) AND me.left_at IS NULL AND them.left_at IS NULL",
        )
        .bind(&among)
        .fetch_all(&self.pool)
        .await
        .context("find the actors a peer's accounts know")?;
        let mut known = Vec::new();
        for (actor, other) in pairs {
            if on(peer, &other)? {
                let actor = ActorUri::parse(&actor).context("a known actor's URI")?;
                if !known.contains(&actor) {
                    known.push(actor);
                }
            }
        }
        Ok(known)
    }

    async fn conversations_with(
        &self,
        peer: &Domain,
        among: &[ActorUri],
    ) -> Result<Vec<ConversationId>, PresenceError> {
        let among: Vec<&str> = among.iter().map(ActorUri::as_str).collect();
        let members: Vec<(uuid::Uuid, String)> = sqlx::query_as(
            "SELECT DISTINCT me.conversation_id, them.actor_uri FROM conversation_members me \
             JOIN conversation_members them ON them.conversation_id = me.conversation_id \
             WHERE me.actor_uri = ANY($1) AND me.left_at IS NULL AND them.left_at IS NULL",
        )
        .bind(&among)
        .fetch_all(&self.pool)
        .await
        .context("find the conversations shared with a peer")?;
        let mut shared: Vec<ConversationId> = Vec::new();
        for (conversation, member) in members {
            if on(peer, &member)? && !shared.contains(&conversation.into()) {
                shared.push(conversation.into());
            }
        }
        Ok(shared)
    }
}

fn on(peer: &Domain, actor: &str) -> Result<bool, PresenceError> {
    Ok(ActorUri::parse(actor).context("a member's URI")?.domain() == peer)
}
