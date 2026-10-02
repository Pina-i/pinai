use anyhow::Context;
use domain::identity::ActorUri;
use domain::messaging::{
    AttachmentView, Conversation, ConversationSummary, Conversations, DeliveryStatus, Departure,
    GroupChanges, GroupName, HistoryCursor, Member, MemberView, Membership, Message,
    MessageStoreError, Messages, Mirrored, MlsCiphertext, NewMessage, RemoteAttachment, Role,
};
use domain::{ConversationId, MessageId, UserId};
use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;

use super::dm;

/// `conversations` + `conversation_members` (+ `conversation_reads` for the list).
pub struct PgConversations {
    pool: PgPool,
}

/// `direct_messages` + the `message_attachments` linked to them.
pub struct PgMessages {
    pool: PgPool,
}

impl PgConversations {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl PgMessages {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct ConversationRow {
    id: uuid::Uuid,
    kind: String,
    name: Option<String>,
    name_at: OffsetDateTime,
    created_at: OffsetDateTime,
}

impl TryFrom<ConversationRow> for Conversation {
    type Error = anyhow::Error;

    fn try_from(row: ConversationRow) -> Result<Self, Self::Error> {
        Ok(Conversation {
            id: row.id.into(),
            kind: row.kind.parse().context("conversations.kind")?,
            name: row.name,
            name_at: row.name_at,
            created_at: row.created_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct MemberRow {
    actor_uri: String,
    role: String,
}

#[derive(sqlx::FromRow)]
struct MembershipRow {
    actor_uri: String,
    role: String,
    joined_at: OffsetDateTime,
    role_at: OffsetDateTime,
    left_at: Option<OffsetDateTime>,
}

#[derive(sqlx::FromRow)]
struct SummaryRow {
    conversation_id: uuid::Uuid,
    kind: String,
    name: Option<String>,
    last_message_at: Option<OffsetDateTime>,
    last_message_sender: Option<String>,
    unread_count: i64,
    members: serde_json::Value,
    removed_at: Option<OffsetDateTime>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MemberJson {
    actor_uri: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
}

impl TryFrom<SummaryRow> for ConversationSummary {
    type Error = anyhow::Error;

    fn try_from(row: SummaryRow) -> Result<Self, Self::Error> {
        let members: Vec<MemberJson> = serde_json::from_value(row.members).unwrap_or_default();
        Ok(ConversationSummary {
            id: row.conversation_id.into(),
            kind: row.kind.parse().context("conversations.kind")?,
            name: row.name,
            // Group rosters may hold URIs stored before they were validated: they are skipped
            // rather than failing the whole list.
            members: members
                .into_iter()
                .filter_map(|m| {
                    Some(MemberView {
                        actor_uri: ActorUri::parse(&m.actor_uri).ok()?,
                        display_name: m.display_name,
                        avatar_url: m.avatar_url,
                    })
                })
                .collect(),
            last_message_sender: row
                .last_message_sender
                .and_then(|uri| ActorUri::parse(&uri).ok()),
            unread_count: row.unread_count,
            last_message_at: row.last_message_at,
            removed_at: row.removed_at,
        })
    }
}

/// Joins, rejoins after leaving, or takes the role, stamped now: a change made here.
async fn hold_member(
    c: &mut PgConnection,
    id: uuid::Uuid,
    member: &Member,
) -> Result<(), MessageStoreError> {
    sqlx::query(
        "INSERT INTO conversation_members (conversation_id, actor_uri, role) VALUES ($1, $2, $3) \
         ON CONFLICT (conversation_id, actor_uri) DO UPDATE SET \
             joined_at = CASE WHEN conversation_members.left_at IS NULL \
                 THEN conversation_members.joined_at ELSE now() END, \
             left_at = NULL, role = EXCLUDED.role, role_at = now()",
    )
    .bind(id)
    .bind(member.actor_uri.as_str())
    .bind(member.role.as_str())
    .execute(c)
    .await
    .context("hold a conversation member")?;
    Ok(())
}

/// Holds a membership exactly as another instance stamped it.
/// Whether holding `membership` brought the member in: a new row, or one back from a departure.
/// Each statement waits for a concurrent mirror's row and then sees it, so of two mirrors taking
/// the same member at once, one brings them in.
async fn hold_membership(
    c: &mut PgConnection,
    id: uuid::Uuid,
    membership: &Membership,
) -> Result<bool, MessageStoreError> {
    let bind = |sql: &'static str| {
        sqlx::query(sql)
            .bind(id)
            .bind(membership.member.actor_uri.as_str())
            .bind(membership.member.role.as_str())
            .bind(membership.joined_at)
            .bind(membership.role_at)
    };
    let added = bind(
        "INSERT INTO conversation_members (conversation_id, actor_uri, role, joined_at, role_at) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (conversation_id, actor_uri) DO NOTHING",
    )
    .execute(&mut *c)
    .await
    .context("add a mirrored member")?;
    if added.rows_affected() == 1 {
        return Ok(true);
    }
    let back = bind(
        "UPDATE conversation_members SET left_at = NULL, role = $3, joined_at = $4, role_at = $5 \
         WHERE conversation_id = $1 AND actor_uri = $2 AND left_at IS NOT NULL",
    )
    .execute(&mut *c)
    .await
    .context("bring a mirrored member back")?;
    if back.rows_affected() == 1 {
        return Ok(true);
    }
    bind(
        "UPDATE conversation_members SET role = $3, joined_at = $4, role_at = $5 \
         WHERE conversation_id = $1 AND actor_uri = $2",
    )
    .execute(&mut *c)
    .await
    .context("hold a mirrored membership")?;
    Ok(false)
}

async fn find_conversation(
    c: &mut PgConnection,
    id: uuid::Uuid,
) -> Result<Option<Conversation>, MessageStoreError> {
    let row: Option<ConversationRow> = sqlx::query_as(
        "SELECT id, kind, name, name_at, created_at FROM conversations WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(c)
    .await
    .context("find a conversation")?;
    Ok(row.map(Conversation::try_from).transpose()?)
}

/// `name_at` is now unless another instance stamped the name.
async fn create_conversation(
    c: &mut PgConnection,
    id: Option<uuid::Uuid>,
    kind: &str,
    name: Option<&str>,
    name_at: Option<OffsetDateTime>,
) -> Result<uuid::Uuid, MessageStoreError> {
    Ok(sqlx::query_scalar(
        "INSERT INTO conversations (id, kind, name, name_at) \
         VALUES (COALESCE($1, gen_random_uuid()), $2, $3, COALESCE($4, now())) RETURNING id",
    )
    .bind(id)
    .bind(kind)
    .bind(name)
    .bind(name_at)
    .fetch_one(c)
    .await
    .context("create a conversation")?)
}

#[async_trait::async_trait]
impl Conversations for PgConversations {
    async fn open_dm(
        &self,
        a: &ActorUri,
        b: &ActorUri,
        pinned: Option<ConversationId>,
    ) -> Result<ConversationId, MessageStoreError> {
        let mut tx = self.pool.begin().await.context("begin open_dm")?;
        let id = dm::open_dm(&mut tx, a, b, pinned).await?;
        tx.commit().await.context("commit open_dm")?;
        Ok(id)
    }

    async fn find(&self, id: ConversationId) -> Result<Option<Conversation>, MessageStoreError> {
        let mut c = self.pool.acquire().await.context("acquire")?;
        find_conversation(&mut c, id.as_uuid()).await
    }

    async fn members(&self, id: ConversationId) -> Result<Vec<Member>, MessageStoreError> {
        let rows: Vec<MemberRow> = sqlx::query_as(
            "SELECT actor_uri, role FROM conversation_members \
             WHERE conversation_id = $1 AND left_at IS NULL",
        )
        .bind(id.as_uuid())
        .fetch_all(&self.pool)
        .await
        .context("list conversation members")?;
        let mut members = Vec::with_capacity(rows.len());
        for row in rows {
            let Ok(actor_uri) = ActorUri::parse(&row.actor_uri) else {
                tracing::warn!(conversation = %id, actor_uri = %row.actor_uri, "member with an invalid actor URI skipped");
                continue;
            };
            members.push(Member {
                actor_uri,
                role: row.role.parse().context("conversation_members.role")?,
            });
        }
        Ok(members)
    }

    async fn memberships(&self, id: ConversationId) -> Result<Vec<Membership>, MessageStoreError> {
        let rows: Vec<MembershipRow> = sqlx::query_as(
            "SELECT actor_uri, role, joined_at, role_at, left_at FROM conversation_members \
             WHERE conversation_id = $1",
        )
        .bind(id.as_uuid())
        .fetch_all(&self.pool)
        .await
        .context("list conversation memberships")?;
        let mut held = Vec::with_capacity(rows.len());
        for row in rows {
            let Ok(actor_uri) = ActorUri::parse(&row.actor_uri) else {
                tracing::warn!(conversation = %id, actor_uri = %row.actor_uri, "member with an invalid actor URI skipped");
                continue;
            };
            held.push(Membership {
                member: Member {
                    actor_uri,
                    role: row.role.parse().context("conversation_members.role")?,
                },
                joined_at: row.joined_at,
                role_at: row.role_at,
                left_at: row.left_at,
            });
        }
        Ok(held)
    }

    async fn ever_held(
        &self,
        actor: &ActorUri,
        ids: &[ConversationId],
    ) -> Result<Vec<ConversationId>, MessageStoreError> {
        let ids: Vec<uuid::Uuid> = ids.iter().map(|id| id.as_uuid()).collect();
        let held: Vec<uuid::Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT conversation_id FROM conversation_members \
             WHERE actor_uri = $1 AND conversation_id = ANY($2)",
        )
        .bind(actor.as_str())
        .bind(&ids)
        .fetch_all(&self.pool)
        .await
        .context("find the conversations an actor held")?;
        Ok(held.into_iter().map(Into::into).collect())
    }

    async fn mirror_group(
        &self,
        id: ConversationId,
        changes: &GroupChanges,
    ) -> Result<Mirrored, MessageStoreError> {
        let mut tx = self.pool.begin().await.context("begin mirror_group")?;
        if find_conversation(&mut tx, id.as_uuid()).await?.is_none() {
            // Two Notes can bring a group new here at the same moment: the one that loses the
            // race takes the other's row, and the newer name, as a snapshot would.
            sqlx::query(
                "INSERT INTO conversations (id, kind, name, name_at) \
                 VALUES ($1, 'group', $2, COALESCE($3, now())) \
                 ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, name_at = EXCLUDED.name_at \
                 WHERE conversations.kind = 'group' AND conversations.name_at < EXCLUDED.name_at",
            )
            .bind(id.as_uuid())
            .bind(changes.name.as_ref().and_then(|n| n.name.as_deref()))
            .bind(changes.name.as_ref().map(|n| n.at))
            .execute(&mut *tx)
            .await
            .context("create a mirrored group")?;
        } else if let Some(named) = &changes.name {
            sqlx::query(
                "UPDATE conversations SET name = $2, name_at = $3 WHERE id = $1 AND kind = 'group'",
            )
            .bind(id.as_uuid())
            .bind(named.name.as_deref())
            .bind(named.at)
            .execute(&mut *tx)
            .await
            .context("rename a mirrored group")?;
        }
        let mut brought_in = Vec::new();
        for membership in &changes.members {
            if hold_membership(&mut tx, id.as_uuid(), membership).await? {
                brought_in.push(membership.member.actor_uri.clone());
            }
        }
        let group = find_conversation(&mut tx, id.as_uuid())
            .await?
            .context("the mirrored group is gone")?;
        tx.commit().await.context("commit mirror_group")?;
        Ok(Mirrored { group, brought_in })
    }

    async fn list_for(
        &self,
        user: UserId,
        actor: &ActorUri,
    ) -> Result<Vec<ConversationSummary>, MessageStoreError> {
        let rows: Vec<SummaryRow> = sqlx::query_as(
            r#"
            WITH ranked_messages AS (
                SELECT dm.conversation_id, dm.sender_actor_uri, dm.created_at,
                       ROW_NUMBER() OVER (
                           PARTITION BY dm.conversation_id
                           ORDER BY dm.created_at DESC, dm.id DESC
                       ) AS rn
                FROM direct_messages dm
                WHERE dm.deleted_at IS NULL
            )
            SELECT
                c.id AS conversation_id,
                c.kind,
                c.name,
                MAX(rm.created_at) AS last_message_at,
                (SELECT rm2.sender_actor_uri FROM ranked_messages rm2
                 WHERE rm2.conversation_id = c.id AND rm2.rn = 1) AS last_message_sender,
                COUNT(CASE
                    WHEN rm.sender_actor_uri != $1
                         AND (r.last_read_at IS NULL OR rm.created_at > r.last_read_at)
                         AND NOT EXISTS (SELECT 1 FROM user_blocks b
                                         WHERE b.owner_user_id = $2
                                           AND b.blocked_actor_uri = rm.sender_actor_uri)
                    THEN 1 ELSE NULL
                END) AS unread_count,
                COALESCE(
                    (SELECT JSON_AGG(JSON_BUILD_OBJECT(
                        'actorUri',    cm_other.actor_uri,
                        'displayName', COALESCE(u.display_name, ra.display_name),
                        'avatarUrl',   COALESCE(u.avatar_url, ra.avatar_url)
                     ))
                     FROM conversation_members cm_other
                     LEFT JOIN users u ON u.actor_uri = cm_other.actor_uri
                     LEFT JOIN remote_actors ra ON ra.actor_uri = cm_other.actor_uri
                     WHERE cm_other.conversation_id = c.id
                       AND cm_other.left_at IS NULL
                       AND cm_other.actor_uri != $1),
                    '[]'
                ) AS members,
                NULL::timestamptz AS removed_at
            FROM conversation_members cm_self
            JOIN conversations c ON c.id = cm_self.conversation_id
            LEFT JOIN ranked_messages rm ON rm.conversation_id = c.id
            LEFT JOIN conversation_reads r ON r.user_id = $2 AND r.conversation_id = c.id
            WHERE cm_self.actor_uri = $1 AND cm_self.left_at IS NULL
            GROUP BY c.id, c.kind, c.name, cm_self.conversation_id
            ORDER BY last_message_at DESC NULLS LAST
            "#,
        )
        .bind(actor.as_str())
        .bind(user.as_uuid())
        .fetch_all(&self.pool)
        .await
        .context("list conversations")?;
        // The groups the account was removed from, as they stood then.
        let removed_from: Vec<SummaryRow> = sqlx::query_as(
            r#"
            SELECT
                c.id AS conversation_id,
                c.kind,
                cm.departure_view->>'name' AS name,
                (SELECT MAX(dm.created_at) FROM direct_messages dm
                 WHERE dm.conversation_id = c.id AND dm.deleted_at IS NULL
                   AND dm.created_at <= cm.left_at) AS last_message_at,
                (SELECT dm.sender_actor_uri FROM direct_messages dm
                 WHERE dm.conversation_id = c.id AND dm.deleted_at IS NULL
                   AND dm.created_at <= cm.left_at
                 ORDER BY dm.created_at DESC, dm.id DESC LIMIT 1) AS last_message_sender,
                0::BIGINT AS unread_count,
                COALESCE(cm.departure_view->'members', '[]') AS members,
                cm.left_at AS removed_at
            FROM conversation_members cm
            JOIN conversations c ON c.id = cm.conversation_id
            WHERE cm.actor_uri = $1 AND cm.left_at IS NOT NULL
              AND cm.removed_by IS NOT NULL AND cm.dismissed_at IS NULL
            "#,
        )
        .bind(actor.as_str())
        .fetch_all(&self.pool)
        .await
        .context("list the groups an account was removed from")?;
        let mut listed = rows
            .into_iter()
            .chain(removed_from)
            .map(|row| ConversationSummary::try_from(row).map_err(MessageStoreError::from))
            .collect::<Result<Vec<_>, _>>()?;
        listed.sort_by_key(|s| std::cmp::Reverse(s.last_message_at));
        Ok(listed)
    }

    async fn mark_read(&self, user: UserId, id: ConversationId) -> Result<(), MessageStoreError> {
        sqlx::query(
            "INSERT INTO conversation_reads (user_id, conversation_id, last_read_at) \
             VALUES ($1, $2, NOW()) \
             ON CONFLICT (user_id, conversation_id) DO UPDATE SET last_read_at = NOW()",
        )
        .bind(user.as_uuid())
        .bind(id.as_uuid())
        .execute(&self.pool)
        .await
        .context("mark a conversation read")?;
        Ok(())
    }

    async fn create_group(
        &self,
        name: Option<&GroupName>,
        roster: &[Member],
    ) -> Result<Conversation, MessageStoreError> {
        let mut tx = self.pool.begin().await.context("begin create_group")?;
        let id =
            create_conversation(&mut tx, None, "group", name.map(GroupName::as_str), None).await?;
        for member in roster {
            hold_member(&mut tx, id, member).await?;
        }
        let group = find_conversation(&mut tx, id)
            .await?
            .context("the new group is gone")?;
        tx.commit().await.context("commit create_group")?;
        Ok(group)
    }

    async fn add_member(
        &self,
        id: ConversationId,
        member: &Member,
    ) -> Result<(), MessageStoreError> {
        let mut c = self.pool.acquire().await.context("acquire")?;
        hold_member(&mut c, id.as_uuid(), member).await
    }

    async fn remove_member(
        &self,
        id: ConversationId,
        actor: &ActorUri,
        removed_by: Option<&ActorUri>,
        at: Option<OffsetDateTime>,
    ) -> Result<bool, MessageStoreError> {
        // The view is read before the update applies: the group as the removed member saw it,
        // everyone named as their list names them.
        let left = sqlx::query(
            r#"
            UPDATE conversation_members SET left_at = COALESCE($4, now()), removed_by = $3,
                dismissed_at = NULL,
                departure_view = CASE WHEN $3::text IS NULL THEN NULL ELSE (
                    SELECT JSON_BUILD_OBJECT(
                        'name', c.name,
                        'members', COALESCE((
                            SELECT JSON_AGG(JSON_BUILD_OBJECT(
                                'actorUri',    o.actor_uri,
                                'displayName', COALESCE(u.display_name, ra.display_name),
                                'avatarUrl',   COALESCE(u.avatar_url, ra.avatar_url)
                            ))
                            FROM conversation_members o
                            LEFT JOIN users u ON u.actor_uri = o.actor_uri
                            LEFT JOIN remote_actors ra ON ra.actor_uri = o.actor_uri
                            WHERE o.conversation_id = $1 AND o.left_at IS NULL
                              AND o.actor_uri != $2
                        ), '[]'::json)
                    )::jsonb
                    FROM conversations c WHERE c.id = $1
                ) END
            WHERE conversation_id = $1 AND actor_uri = $2 AND left_at IS NULL
            "#,
        )
        .bind(id.as_uuid())
        .bind(actor.as_str())
        .bind(removed_by.map(ActorUri::as_str))
        .bind(at)
        .execute(&self.pool)
        .await
        .context("remove a member")?;
        Ok(left.rows_affected() > 0)
    }

    async fn departure(
        &self,
        id: ConversationId,
        actor: &ActorUri,
    ) -> Result<Option<Departure>, MessageStoreError> {
        let row: Option<(OffsetDateTime, Option<String>, Option<OffsetDateTime>)> = sqlx::query_as(
            "SELECT left_at, removed_by, dismissed_at FROM conversation_members \
                 WHERE conversation_id = $1 AND actor_uri = $2 AND left_at IS NOT NULL",
        )
        .bind(id.as_uuid())
        .bind(actor.as_str())
        .fetch_optional(&self.pool)
        .await
        .context("find how a member left")?;
        let Some((left_at, removed_by, dismissed_at)) = row else {
            return Ok(None);
        };
        Ok(Some(Departure {
            left_at,
            removed_by: removed_by
                .map(|uri| ActorUri::parse(&uri))
                .transpose()
                .context("conversation_members.removed_by")?,
            dismissed: dismissed_at.is_some(),
        }))
    }

    async fn dismiss(
        &self,
        id: ConversationId,
        actor: &ActorUri,
    ) -> Result<bool, MessageStoreError> {
        let dismissed = sqlx::query(
            "UPDATE conversation_members SET dismissed_at = now() \
             WHERE conversation_id = $1 AND actor_uri = $2 AND left_at IS NOT NULL \
               AND removed_by IS NOT NULL AND dismissed_at IS NULL",
        )
        .bind(id.as_uuid())
        .bind(actor.as_str())
        .execute(&self.pool)
        .await
        .context("dismiss a group")?;
        Ok(dismissed.rows_affected() > 0)
    }

    async fn set_role(
        &self,
        id: ConversationId,
        actor: &ActorUri,
        role: Role,
    ) -> Result<Option<Member>, MessageStoreError> {
        let changed: Option<String> = sqlx::query_scalar(
            "UPDATE conversation_members SET role = $3, role_at = now() \
             WHERE conversation_id = $1 AND actor_uri = $2 AND left_at IS NULL \
             RETURNING role",
        )
        .bind(id.as_uuid())
        .bind(actor.as_str())
        .bind(role.as_str())
        .fetch_optional(&self.pool)
        .await
        .context("set a member's role")?;
        Ok(changed
            .map(|role| -> anyhow::Result<Member> {
                Ok(Member {
                    actor_uri: actor.clone(),
                    role: role.parse().context("conversation_members.role")?,
                })
            })
            .transpose()?)
    }

    async fn rename_group(
        &self,
        id: ConversationId,
        name: &GroupName,
    ) -> Result<Option<Conversation>, MessageStoreError> {
        let row: Option<ConversationRow> = sqlx::query_as(
            "UPDATE conversations SET name = $2, name_at = now() WHERE id = $1 AND kind = 'group' \
             RETURNING id, kind, name, name_at, created_at",
        )
        .bind(id.as_uuid())
        .bind(name.as_str())
        .fetch_optional(&self.pool)
        .await
        .context("rename a group")?;
        Ok(row.map(Conversation::try_from).transpose()?)
    }
}

#[derive(sqlx::FromRow)]
struct MessageRow {
    id: uuid::Uuid,
    conversation_id: uuid::Uuid,
    sender_actor_uri: String,
    mls_ciphertext: Vec<u8>,
    activity_uri: String,
    federation_status: String,
    created_at: OffsetDateTime,
    edited_at: Option<OffsetDateTime>,
    reply_to_id: Option<uuid::Uuid>,
}

const MESSAGE_COLUMNS: &str = "id, conversation_id, sender_actor_uri, mls_ciphertext, \
     activity_uri, federation_status, created_at, edited_at, reply_to_id";

#[derive(sqlx::FromRow)]
struct AttachmentRow {
    id: uuid::Uuid,
    message_id: Option<uuid::Uuid>,
    mime_type: String,
    byte_size: i64,
    original_filename: String,
}

impl MessageRow {
    fn into_message(self, attachments: &[AttachmentRow]) -> anyhow::Result<Message> {
        Ok(Message {
            id: self.id.into(),
            conversation: self.conversation_id.into(),
            sender: ActorUri::parse(&self.sender_actor_uri)
                .context("direct_messages.sender_actor_uri")?,
            ciphertext: MlsCiphertext::parse(self.mls_ciphertext)
                .context("direct_messages.mls_ciphertext")?,
            activity_uri: self.activity_uri,
            delivery: self
                .federation_status
                .parse::<DeliveryStatus>()
                .context("direct_messages.federation_status")?,
            created_at: self.created_at,
            edited_at: self.edited_at,
            reply_to: self.reply_to_id.map(MessageId::from),
            attachments: attachments
                .iter()
                .filter(|a| a.message_id == Some(self.id))
                .map(|a| AttachmentView {
                    id: a.id.into(),
                    mime_type: a.mime_type.clone(),
                    byte_size: a.byte_size,
                    original_filename: a.original_filename.clone(),
                })
                .collect(),
        })
    }
}

/// The messages of `rows` with their attachments, in `rows`' order.
async fn with_attachments(
    c: &mut PgConnection,
    rows: Vec<MessageRow>,
) -> Result<Vec<Message>, MessageStoreError> {
    let ids: Vec<uuid::Uuid> = rows.iter().map(|r| r.id).collect();
    let attachments: Vec<AttachmentRow> = sqlx::query_as(
        "SELECT id, message_id, mime_type, byte_size, original_filename \
         FROM message_attachments WHERE message_id = ANY($1) \
         ORDER BY message_id, created_at ASC",
    )
    .bind(&ids)
    .fetch_all(c)
    .await
    .context("load message attachments")?;
    rows.into_iter()
        .map(|row| {
            row.into_message(&attachments)
                .map_err(MessageStoreError::from)
        })
        .collect()
}

async fn one(
    c: &mut PgConnection,
    row: Option<MessageRow>,
) -> Result<Option<Message>, MessageStoreError> {
    match row {
        Some(row) => Ok(with_attachments(c, vec![row]).await?.pop()),
        None => Ok(None),
    }
}

/// `None` when a message with that id or activity is already stored.
async fn insert_message(
    c: &mut PgConnection,
    message: &NewMessage,
) -> Result<Option<MessageRow>, MessageStoreError> {
    Ok(sqlx::query_as(&format!(
        "INSERT INTO direct_messages \
            (id, conversation_id, sender_actor_uri, mls_ciphertext, activity_uri, reply_to_id) \
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING RETURNING {MESSAGE_COLUMNS}"
    ))
    .bind(message.id.as_uuid())
    .bind(message.conversation.as_uuid())
    .bind(message.sender.as_str())
    .bind(message.ciphertext.as_bytes())
    .bind(&message.activity_uri)
    .bind(message.reply_to.map(|id| id.as_uuid()))
    .fetch_optional(c)
    .await
    .context("insert a message")?)
}

#[async_trait::async_trait]
impl Messages for PgMessages {
    async fn record(&self, message: &NewMessage) -> Result<Message, MessageStoreError> {
        let mut tx = self.pool.begin().await.context("begin record")?;
        // Ids are minted here: a clash is a bug, not a redelivery.
        let row = insert_message(&mut tx, message)
            .await?
            .with_context(|| format!("message {} already stored", message.id))?;
        if !message.attachments.is_empty() {
            let ids: Vec<uuid::Uuid> = message.attachments.iter().map(|a| a.as_uuid()).collect();
            // Linkable: the sender's own upload, unlinked, or linked to one of its messages
            // whose delivery failed — sending that message again carries its uploads over.
            let linked = sqlx::query(
                "UPDATE message_attachments SET message_id = $1 \
                 WHERE id = ANY($2) AND uploaded_by_actor_uri = $3 \
                   AND (message_id IS NULL OR message_id IN ( \
                       SELECT id FROM direct_messages \
                       WHERE sender_actor_uri = $3 AND federation_status = 'failed'))",
            )
            .bind(message.id.as_uuid())
            .bind(&ids)
            .bind(message.sender.as_str())
            .execute(&mut *tx)
            .await
            .context("link attachments")?
            .rows_affected();
            if linked != ids.len() as u64 {
                return Err(MessageStoreError::AttachmentsUnavailable);
            }
        }
        let recorded = one(&mut tx, Some(row)).await?.expect("just recorded");
        tx.commit().await.context("commit record")?;
        Ok(recorded)
    }

    async fn record_received(
        &self,
        message: &NewMessage,
        attachments: &[RemoteAttachment],
    ) -> Result<Option<Message>, MessageStoreError> {
        let mut tx = self.pool.begin().await.context("begin record_received")?;
        let Some(row) = insert_message(&mut tx, message).await? else {
            return Ok(None);
        };
        for file in attachments {
            // The bytes stay on the sender's instance: `remote_origin_url` is where they live.
            sqlx::query(
                "INSERT INTO message_attachments \
                    (id, message_id, uploaded_by_actor_uri, storage_key, mime_type, byte_size, \
                     original_filename, remote_origin_url) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
            )
            .bind(file.id.as_uuid())
            .bind(message.id.as_uuid())
            .bind(message.sender.as_str())
            .bind(file.id.to_string())
            .bind(&file.mime_type)
            .bind(file.byte_size)
            .bind(&file.original_filename)
            .bind(&file.url)
            .execute(&mut *tx)
            .await
            .context("record a received attachment")?;
        }
        let recorded = one(&mut tx, Some(row)).await?.expect("just recorded");
        tx.commit().await.context("commit record_received")?;
        Ok(Some(recorded))
    }

    async fn find(&self, id: MessageId) -> Result<Option<Message>, MessageStoreError> {
        let mut c = self.pool.acquire().await.context("acquire")?;
        let row = sqlx::query_as(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM direct_messages WHERE id = $1"
        ))
        .bind(id.as_uuid())
        .fetch_optional(&mut *c)
        .await
        .context("find a message")?;
        one(&mut c, row).await
    }

    async fn find_by_activity(&self, uri: &str) -> Result<Option<Message>, MessageStoreError> {
        let mut c = self.pool.acquire().await.context("acquire")?;
        let row = sqlx::query_as(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM direct_messages WHERE activity_uri = $1"
        ))
        .bind(uri)
        .fetch_optional(&mut *c)
        .await
        .context("find a message by activity")?;
        one(&mut c, row).await
    }

    async fn edit(
        &self,
        id: MessageId,
        sender: &ActorUri,
        ciphertext: &MlsCiphertext,
    ) -> Result<Option<Message>, MessageStoreError> {
        let mut c = self.pool.acquire().await.context("acquire")?;
        let row = sqlx::query_as(&format!(
            "UPDATE direct_messages SET mls_ciphertext = $3, edited_at = now() \
             WHERE id = $1 AND sender_actor_uri = $2 AND deleted_at IS NULL \
             RETURNING {MESSAGE_COLUMNS}"
        ))
        .bind(id.as_uuid())
        .bind(sender.as_str())
        .bind(ciphertext.as_bytes())
        .fetch_optional(&mut *c)
        .await
        .context("edit a message")?;
        one(&mut c, row).await
    }

    async fn edit_by_activity(
        &self,
        uri: &str,
        sender: &ActorUri,
        ciphertext: &MlsCiphertext,
    ) -> Result<Option<Message>, MessageStoreError> {
        let mut c = self.pool.acquire().await.context("acquire")?;
        let row = sqlx::query_as(&format!(
            "UPDATE direct_messages SET mls_ciphertext = $3, edited_at = now() \
             WHERE activity_uri = $1 AND sender_actor_uri = $2 AND deleted_at IS NULL \
             RETURNING {MESSAGE_COLUMNS}"
        ))
        .bind(uri)
        .bind(sender.as_str())
        .bind(ciphertext.as_bytes())
        .fetch_optional(&mut *c)
        .await
        .context("edit a message by activity")?;
        one(&mut c, row).await
    }

    async fn history(
        &self,
        conversation: ConversationId,
        before: Option<HistoryCursor>,
        until: Option<OffsetDateTime>,
        limit: i64,
    ) -> Result<Vec<Message>, MessageStoreError> {
        let mut c = self.pool.acquire().await.context("acquire")?;
        let rows: Vec<MessageRow> = sqlx::query_as(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM direct_messages \
             WHERE conversation_id = $1 AND deleted_at IS NULL \
               AND ($2::timestamptz IS NULL OR (created_at, id) < ($2, $3)) \
               AND ($5::timestamptz IS NULL OR created_at <= $5) \
             ORDER BY created_at DESC, id DESC LIMIT $4"
        ))
        .bind(conversation.as_uuid())
        .bind(before.map(|c| c.created_at))
        .bind(before.map(|c| c.id))
        .bind(limit)
        .bind(until)
        .fetch_all(&mut *c)
        .await
        .context("load conversation history")?;
        with_attachments(&mut c, rows).await
    }

    async fn set_delivery(
        &self,
        id: MessageId,
        status: DeliveryStatus,
    ) -> Result<(), MessageStoreError> {
        sqlx::query("UPDATE direct_messages SET federation_status = $2 WHERE id = $1")
            .bind(id.as_uuid())
            .bind(status.as_str())
            .execute(&self.pool)
            .await
            .context("record a delivery outcome")?;
        Ok(())
    }

    async fn fail_stale_deliveries(
        &self,
        sent_before: OffsetDateTime,
    ) -> Result<Vec<Message>, MessageStoreError> {
        let mut c = self.pool.acquire().await.context("acquire")?;
        // Sent here (a local sender) to another instance (a member no local account is).
        let rows: Vec<MessageRow> = sqlx::query_as(
            "UPDATE direct_messages m SET federation_status = 'failed' \
             FROM conversations c \
             WHERE c.id = m.conversation_id AND c.kind = 'dm' \
               AND m.federation_status = 'pending' AND m.created_at < $1 \
               AND EXISTS (SELECT 1 FROM users u WHERE u.actor_uri = m.sender_actor_uri) \
               AND EXISTS ( \
                   SELECT 1 FROM conversation_members cm \
                   WHERE cm.conversation_id = m.conversation_id \
                     AND cm.actor_uri <> m.sender_actor_uri \
                     AND NOT EXISTS (SELECT 1 FROM users u WHERE u.actor_uri = cm.actor_uri)) \
             RETURNING m.id, m.conversation_id, m.sender_actor_uri, m.mls_ciphertext, \
                       m.activity_uri, m.federation_status, m.created_at, m.edited_at, \
                       m.reply_to_id",
        )
        .bind(sent_before)
        .fetch_all(&mut *c)
        .await
        .context("fail stale deliveries")?;
        with_attachments(&mut c, rows).await
    }
}
