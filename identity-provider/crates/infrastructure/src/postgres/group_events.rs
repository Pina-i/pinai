use anyhow::Context;
use domain::identity::ActorUri;
use domain::messaging::{
    EventWindow, GroupChangeKind, GroupEvent, GroupEventKind, GroupEvents, GroupName,
    HistoryCursor, MessageStoreError,
};
use domain::{ConversationId, GroupEventId};
use sqlx::PgPool;
use time::OffsetDateTime;

/// `conversation_events`.
pub struct PgGroupEvents {
    pool: PgPool,
}

impl PgGroupEvents {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct EventRow {
    id: uuid::Uuid,
    conversation_id: uuid::Uuid,
    kind: String,
    actor_uri: String,
    subject_uri: Option<String>,
    detail: Option<String>,
    created_at: OffsetDateTime,
}

impl TryFrom<EventRow> for GroupEvent {
    type Error = anyhow::Error;

    fn try_from(row: EventRow) -> Result<Self, Self::Error> {
        let subject = || -> anyhow::Result<ActorUri> {
            let uri = row
                .subject_uri
                .as_deref()
                .context("conversation_events.subject_uri")?;
            Ok(ActorUri::parse(uri)?)
        };
        let detail = || row.detail.as_deref().context("conversation_events.detail");
        let change = match row.kind.as_str() {
            "created" => None,
            "added" => Some(GroupChangeKind::Added(subject()?)),
            "removed" => Some(GroupChangeKind::Removed(subject()?)),
            "left" => Some(GroupChangeKind::Left),
            "renamed" => Some(GroupChangeKind::Renamed(GroupName::parse(detail()?)?)),
            "role_changed" => Some(GroupChangeKind::RoleChanged(
                subject()?,
                detail()?.parse().context("conversation_events.detail")?,
            )),
            other => anyhow::bail!("conversation_events.kind {other:?}"),
        };
        Ok(GroupEvent {
            id: GroupEventId::from(row.id),
            group: ConversationId::from(row.conversation_id),
            by: ActorUri::parse(&row.actor_uri).context("conversation_events.actor_uri")?,
            at: row.created_at,
            kind: change.map_or(GroupEventKind::Created, GroupEventKind::Changed),
        })
    }
}

#[async_trait::async_trait]
impl GroupEvents for PgGroupEvents {
    async fn record(&self, event: &GroupEvent) -> Result<(), MessageStoreError> {
        let detail = event.name().or(event.role().map(|role| role.as_str()));
        // A leave's subject is its maker, which the row holds already.
        let subject = match &event.kind {
            GroupEventKind::Changed(GroupChangeKind::Left) => None,
            _ => event.subject(),
        };
        sqlx::query(
            "INSERT INTO conversation_events \
                 (id, conversation_id, kind, actor_uri, subject_uri, detail, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(event.id.as_uuid())
        .bind(event.group.as_uuid())
        .bind(event.kind_name())
        .bind(event.by.as_str())
        .bind(subject.map(ActorUri::as_str))
        .bind(detail)
        .bind(event.at)
        .execute(&self.pool)
        .await
        .context("record a group event")?;
        Ok(())
    }

    async fn page(
        &self,
        conversation: ConversationId,
        before: Option<HistoryCursor>,
        window: EventWindow,
        limit: i64,
    ) -> Result<Vec<GroupEvent>, MessageStoreError> {
        let rows: Vec<EventRow> = sqlx::query_as(
            "SELECT id, conversation_id, kind, actor_uri, subject_uri, detail, created_at \
             FROM conversation_events \
             WHERE conversation_id = $1 AND created_at >= $2 \
               AND ($3::timestamptz IS NULL OR created_at <= $3) \
               AND ($4::timestamptz IS NULL OR (created_at, id) < ($4, $5)) \
             ORDER BY created_at DESC, id DESC LIMIT $6",
        )
        .bind(conversation.as_uuid())
        .bind(window.since)
        .bind(window.until)
        .bind(before.map(|c| c.created_at))
        .bind(before.map(|c| c.id))
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("page a group's events")?;
        rows.into_iter()
            .map(|row| GroupEvent::try_from(row).map_err(MessageStoreError::from))
            .collect()
    }
}
