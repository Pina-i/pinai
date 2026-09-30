use anyhow::Context;
use domain::UserId;
use domain::identity::{Account, Accounts, AccountsError, ActorUri, Handle};
use sqlx::PgPool;

/// Local accounts, from `users`.
pub struct PgAccounts {
    pool: PgPool,
}

impl PgAccounts {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct AccountRow {
    id: uuid::Uuid,
    actor_uri: Option<String>,
    username: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
}

impl TryFrom<AccountRow> for Account {
    type Error = anyhow::Error;

    fn try_from(row: AccountRow) -> Result<Self, Self::Error> {
        let actor_uri = row.actor_uri.context("users.actor_uri is not set")?;
        Ok(Account {
            id: row.id.into(),
            actor_uri: ActorUri::parse(&actor_uri).context("users.actor_uri")?,
            username: row.username,
            display_name: row.display_name,
            avatar_url: row.avatar_url,
        })
    }
}

const COLUMNS: &str = "id, actor_uri, username, display_name, avatar_url";

fn account(row: Option<AccountRow>) -> Result<Option<Account>, AccountsError> {
    Ok(row.map(Account::try_from).transpose()?)
}

#[async_trait::async_trait]
impl Accounts for PgAccounts {
    async fn find(&self, id: UserId) -> Result<Option<Account>, AccountsError> {
        let row = sqlx::query_as(&format!("SELECT {COLUMNS} FROM users WHERE id = $1"))
            .bind(id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .context("find an account by id")?;
        account(row)
    }

    async fn find_by_handle(&self, handle: &Handle) -> Result<Option<Account>, AccountsError> {
        let row = sqlx::query_as(&format!("SELECT {COLUMNS} FROM users WHERE username = $1"))
            .bind(handle.as_str())
            .fetch_optional(&self.pool)
            .await
            .context("find an account by handle")?;
        account(row)
    }

    async fn find_by_uri(&self, uri: &ActorUri) -> Result<Option<Account>, AccountsError> {
        let row = sqlx::query_as(&format!("SELECT {COLUMNS} FROM users WHERE actor_uri = $1"))
            .bind(uri.as_str())
            .fetch_optional(&self.pool)
            .await
            .context("find an account by actor URI")?;
        account(row)
    }

    async fn search(&self, fragment: &str, limit: i64) -> Result<Vec<Account>, AccountsError> {
        let rows: Vec<AccountRow> = sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM users \
             WHERE username ILIKE $1 ESCAPE '\\' AND actor_uri IS NOT NULL \
             ORDER BY username LIMIT $2"
        ))
        .bind(format!("%{}%", literal(fragment)))
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .context("search accounts")?;
        Ok(rows
            .into_iter()
            .map(Account::try_from)
            .collect::<Result<_, _>>()?)
    }
}

/// `fragment` as a `LIKE` pattern that matches only itself.
fn literal(fragment: &str) -> String {
    fragment
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}
