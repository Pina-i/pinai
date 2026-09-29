//! Opening a DM, shared by the two adapters that do: messaging (a send) and social (an accept).

use anyhow::Context;
use domain::ConversationId;
use domain::identity::ActorUri;
use domain::messaging::{ConversationKind, may_hold_dm};
use sqlx::{Connection, PgConnection};

/// The pair of a DM as stored: the smaller actor URI first, so either order finds it.
fn pair<'a>(a: &'a ActorUri, b: &'a ActorUri) -> (&'a str, &'a str) {
    if a.as_str() <= b.as_str() {
        (a.as_str(), b.as_str())
    } else {
        (b.as_str(), a.as_str())
    }
}

/// The pair's DM: the one conversation its unique key names.
pub(super) async fn dm_between(
    c: &mut PgConnection,
    a: &ActorUri,
    b: &ActorUri,
) -> anyhow::Result<Option<ConversationId>> {
    let (low, high) = pair(a, b);
    let id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM conversations WHERE dm_low = $1 AND dm_high = $2")
            .bind(low)
            .bind(high)
            .fetch_optional(c)
            .await
            .context("find the DM between two actors")?;
    Ok(id.map(ConversationId::from))
}

/// The pair's DM, opened when there is none — under `chosen`, the id a client or a peer picked,
/// unless that id already names a conversation that may not hold it. Members are (re)added
/// either way, which heals a half-created DM.
pub(super) async fn open_dm(
    c: &mut PgConnection,
    a: &ActorUri,
    b: &ActorUri,
    chosen: Option<ConversationId>,
) -> anyhow::Result<ConversationId> {
    let id = match dm_between(c, a, b).await? {
        Some(existing) => existing,
        None => claim(c, a, b, chosen).await?,
    };
    for member in [a, b] {
        sqlx::query(
            "INSERT INTO conversation_members (conversation_id, actor_uri) VALUES ($1, $2) \
             ON CONFLICT (conversation_id, actor_uri) DO UPDATE SET left_at = NULL",
        )
        .bind(id.as_uuid())
        .bind(member.as_str())
        .execute(&mut *c)
        .await
        .context("add a DM member")?;
    }
    Ok(id)
}

/// Give the pair a DM. A concurrent open of the same pair may win the unique key first: this
/// one then takes the winner's.
async fn claim(
    c: &mut PgConnection,
    a: &ActorUri,
    b: &ActorUri,
    chosen: Option<ConversationId>,
) -> anyhow::Result<ConversationId> {
    if let Some(chosen) = chosen
        && let Some(id) = under_chosen(c, chosen, a, b).await?
    {
        return Ok(id);
    }
    if let Some(id) = insert(c, None, a, b).await? {
        return Ok(id);
    }
    dm_between(c, a, b)
        .await?
        .context("the pair's DM was taken, then vanished")
}

/// The DM under `chosen`: a new conversation, or an existing one the domain says may hold it.
async fn under_chosen(
    c: &mut PgConnection,
    chosen: ConversationId,
    a: &ActorUri,
    b: &ActorUri,
) -> anyhow::Result<Option<ConversationId>> {
    let existing: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT kind, dm_low FROM conversations WHERE id = $1 FOR UPDATE")
            .bind(chosen.as_uuid())
            .fetch_optional(&mut *c)
            .await
            .context("find the chosen conversation")?;
    let Some((kind, keyed)) = existing else {
        return insert(c, Some(chosen), a, b).await;
    };
    // Keyed already: another pair's DM, as this pair has none.
    if keyed.is_some() {
        return Ok(None);
    }
    let members: Vec<String> =
        sqlx::query_scalar("SELECT actor_uri FROM conversation_members WHERE conversation_id = $1")
            .bind(chosen.as_uuid())
            .fetch_all(&mut *c)
            .await
            .context("list the chosen conversation's members")?;
    // A member this instance cannot parse is someone else: the conversation is not the pair's.
    let Ok(members) = members
        .iter()
        .map(|m| ActorUri::parse(m))
        .collect::<Result<Vec<_>, _>>()
    else {
        return Ok(None);
    };
    let kind: ConversationKind = kind.parse().context("conversations.kind")?;
    if !may_hold_dm(kind, &members, a, b) {
        return Ok(None);
    }
    let (low, high) = pair(a, b);
    // A savepoint: losing the key to a concurrent open must not abort the whole transaction.
    let mut savepoint = c.begin().await.context("savepoint")?;
    let keyed = sqlx::query("UPDATE conversations SET dm_low = $2, dm_high = $3 WHERE id = $1")
        .bind(chosen.as_uuid())
        .bind(low)
        .bind(high)
        .execute(&mut *savepoint)
        .await;
    match keyed {
        Ok(_) => {
            savepoint.commit().await.context("release savepoint")?;
            Ok(Some(chosen))
        }
        Err(e) if is_unique_violation(&e) => {
            savepoint.rollback().await.context("roll back savepoint")?;
            Ok(None)
        }
        Err(e) => Err(anyhow::Error::from(e).context("key the chosen DM")),
    }
}

/// A new DM for the pair; `None` when the id or the pair's key is already taken.
async fn insert(
    c: &mut PgConnection,
    id: Option<ConversationId>,
    a: &ActorUri,
    b: &ActorUri,
) -> anyhow::Result<Option<ConversationId>> {
    let (low, high) = pair(a, b);
    let id: Option<uuid::Uuid> = sqlx::query_scalar(
        "INSERT INTO conversations (id, kind, dm_low, dm_high) \
         VALUES (COALESCE($1, gen_random_uuid()), 'dm', $2, $3) \
         ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind(id.map(|id| id.as_uuid()))
    .bind(low)
    .bind(high)
    .fetch_optional(c)
    .await
    .context("create a DM")?;
    Ok(id.map(ConversationId::from))
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|d| d.code())
        .is_some_and(|code| code == "23505")
}
