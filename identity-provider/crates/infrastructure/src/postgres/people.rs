use anyhow::Context;
use domain::UserId;
use domain::identity::{ActorUri, Handle};
use domain::social::{
    FoundPerson, Friendship, GroupPerson, PeopleFound, PeopleSearch, SearchQuery, SocialStoreError,
    Ties,
};
use sqlx::PgPool;

/// Finding people: by name in `users` and the `remote_actors` of the caller's groups, one query a
/// section, names folded by `unaccent`, then lower case; or an account by handle. Each comes with
/// the caller's `user_blocks` and `friendships` row.
pub struct PgPeopleSearch {
    pool: PgPool,
}

impl PgPeopleSearch {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

// MATERIALIZED: `unaccent` is STABLE, so an inlined `q` would be folded again for every row.
const QUERY: &str = "q AS MATERIALIZED (SELECT lower(unaccent($2)) AS q)";
/// The caller's ties to each person `p`.
const TIES: &str = "EXISTS (SELECT 1 FROM user_blocks b \
                            WHERE b.owner_user_id = $1 AND b.blocked_actor_uri = p.actor_uri) \
                        AS blocked, \
                    f.id AS side_id, f.status AS side_status, f.direction AS side_direction";
const SIDE: &str =
    "LEFT JOIN friendships f ON f.owner_user_id = $1 AND f.friend_actor_uri = p.actor_uri";
// Byte order, as the in-memory search sorts: the database's collation would skip punctuation.
const ORDER: &str = "ORDER BY p.tier, p.folded COLLATE \"C\", p.actor_uri COLLATE \"C\"";

#[derive(sqlx::FromRow)]
struct TiesRow {
    blocked: bool,
    side_id: Option<uuid::Uuid>,
    side_status: Option<String>,
    side_direction: Option<String>,
}

impl TiesRow {
    fn ties(self, caller: UserId, actor: &ActorUri) -> anyhow::Result<Ties> {
        let side = match (self.side_id, self.side_status, self.side_direction) {
            (Some(id), Some(status), Some(direction)) => Some(Friendship {
                id: id.into(),
                owner: caller,
                friend: actor.clone(),
                status: status.parse().context("friendships.status")?,
                direction: direction.parse().context("friendships.direction")?,
            }),
            _ => None,
        };
        Ok(Ties {
            blocked: self.blocked,
            side,
        })
    }
}

#[derive(sqlx::FromRow)]
struct PersonRow {
    actor_uri: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    #[sqlx(flatten)]
    ties: TiesRow,
}

#[derive(sqlx::FromRow)]
struct GroupPersonRow {
    #[sqlx(flatten)]
    person: PersonRow,
    group_name: Option<String>,
}

impl PersonRow {
    /// `None` for someone without an address.
    fn found(self, caller: UserId) -> anyhow::Result<Option<FoundPerson>> {
        let actor = ActorUri::parse(&self.actor_uri).context("a person's actor URI")?;
        let Some(address) = actor.federated_address() else {
            return Ok(None);
        };
        Ok(Some(FoundPerson {
            ties: self.ties.ties(caller, &actor)?,
            actor,
            address,
            display_name: self.display_name,
            avatar_url: self.avatar_url,
        }))
    }
}

#[async_trait::async_trait]
impl PeopleSearch for PgPeopleSearch {
    async fn search(
        &self,
        caller: UserId,
        query: &SearchQuery,
        limit: i64,
    ) -> Result<PeopleFound, SocialStoreError> {
        let joined = super::has_joined("u");
        let server: Vec<PersonRow> = sqlx::query_as(&format!(
            "WITH {QUERY}, \
             p AS ( \
               SELECT u.actor_uri, u.display_name, u.avatar_url, n.folded, \
                      CASE WHEN starts_with(n.folded, q.q) THEN 0 \
                           WHEN strpos(n.folded, q.q) > 0 THEN 1 \
                           WHEN strpos(u.username, q.q) > 0 THEN 2 END AS tier \
               FROM users u CROSS JOIN q \
               CROSS JOIN LATERAL (SELECT lower(unaccent(u.display_name)) AS folded) n \
               WHERE u.id <> $1 AND u.actor_uri IS NOT NULL \
                 AND {joined}) \
             SELECT p.actor_uri, p.display_name, p.avatar_url, {TIES} \
             FROM p {SIDE} WHERE p.tier IS NOT NULL {ORDER} LIMIT $3"
        ))
        .bind(caller.as_uuid())
        .bind(query.as_str())
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("search the instance's accounts")?;
        // No LIMIT: someone without an address is left out before the limit counts.
        let groups: Vec<GroupPersonRow> = sqlx::query_as(&format!(
            "WITH {QUERY}, \
             shared AS ( \
               SELECT DISTINCT ON (them.actor_uri) them.actor_uri, c.name AS group_name \
               FROM users me \
               JOIN conversation_members mine \
                 ON mine.actor_uri = me.actor_uri AND mine.left_at IS NULL \
               JOIN conversations c ON c.id = mine.conversation_id AND c.kind = 'group' \
               JOIN conversation_members them \
                 ON them.conversation_id = c.id AND them.left_at IS NULL \
               WHERE me.id = $1 \
                 AND NOT EXISTS (SELECT 1 FROM users u WHERE u.actor_uri = them.actor_uri) \
               ORDER BY them.actor_uri, c.created_at DESC, c.id DESC), \
             p AS ( \
               SELECT ra.actor_uri, ra.display_name, ra.avatar_url, s.group_name, n.folded, \
                      CASE WHEN starts_with(n.folded, q.q) THEN 0 \
                           WHEN strpos(n.folded, q.q) > 0 THEN 1 END AS tier \
               FROM shared s JOIN remote_actors ra ON ra.actor_uri = s.actor_uri CROSS JOIN q \
               CROSS JOIN LATERAL (SELECT lower(unaccent(ra.display_name)) AS folded) n) \
             SELECT p.actor_uri, p.display_name, p.avatar_url, p.group_name, {TIES} \
             FROM p {SIDE} WHERE p.tier IS NOT NULL {ORDER}"
        ))
        .bind(caller.as_uuid())
        .bind(query.as_str())
        .fetch_all(&self.pool)
        .await
        .context("search the people of the caller's groups")?;
        let limit = usize::try_from(limit).unwrap_or(0);
        Ok(PeopleFound {
            server: server
                .into_iter()
                .filter_map(|row| row.found(caller).transpose())
                .take(limit)
                .collect::<anyhow::Result<_>>()?,
            groups: groups
                .into_iter()
                .filter_map(|row| {
                    let group = row.group_name;
                    let found = row.person.found(caller).transpose()?;
                    Some(found.map(|person| GroupPerson { person, group }))
                })
                .take(limit)
                .collect::<anyhow::Result<_>>()?,
        })
    }

    async fn local(
        &self,
        caller: UserId,
        handle: &Handle,
    ) -> Result<Option<FoundPerson>, SocialStoreError> {
        let row: Option<PersonRow> = sqlx::query_as(&format!(
            "SELECT p.actor_uri, p.display_name, p.avatar_url, {TIES} \
             FROM users p {SIDE} \
             WHERE p.username = $2 AND p.actor_uri IS NOT NULL AND {}",
            super::has_joined("p")
        ))
        .bind(caller.as_uuid())
        .bind(handle.as_str())
        .fetch_optional(&self.pool)
        .await
        .context("find an account by handle")?;
        Ok(row.map(|row| row.found(caller)).transpose()?.flatten())
    }

    async fn ties(&self, caller: UserId, actor: &ActorUri) -> Result<Ties, SocialStoreError> {
        let row: TiesRow = sqlx::query_as(&format!(
            "SELECT {TIES} FROM (SELECT $2::text AS actor_uri) p {SIDE}"
        ))
        .bind(caller.as_uuid())
        .bind(actor.as_str())
        .fetch_one(&self.pool)
        .await
        .context("read the caller's ties to an actor")?;
        Ok(row.ties(caller, actor)?)
    }
}
