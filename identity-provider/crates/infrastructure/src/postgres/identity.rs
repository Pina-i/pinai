use anyhow::Context;
use domain::UserId;
use domain::identity::{
    Account, Accounts, AccountsError, ActorUri, Handle, IntroText, SavedIntro, SavedIntroError,
};
use sqlx::PgPool;
use time::OffsetDateTime;

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

    async fn count(&self) -> Result<u64, AccountsError> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE actor_uri IS NOT NULL")
                .fetch_one(&self.pool)
                .await
                .context("count the accounts")?;
        Ok(u64::try_from(count).unwrap_or(0))
    }
}

/// The intro an admin saved, from `instance_intro`'s one row.
pub struct PgSavedIntro {
    pool: PgPool,
}

impl PgSavedIntro {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl SavedIntro for PgSavedIntro {
    async fn get(&self) -> Result<Option<IntroText>, SavedIntroError> {
        let row: Option<(Option<String>, Option<String>)> =
            sqlx::query_as("SELECT name, description FROM instance_intro")
                .fetch_optional(&self.pool)
                .await
                .context("read the saved intro")?;
        let Some((name, description)) = row else {
            return Ok(None);
        };
        let text = IntroText::parse(name.as_deref(), description.as_deref())
            .context("instance_intro breaks the intro's rule")?;
        Ok(Some(text))
    }

    async fn save(
        &self,
        text: &IntroText,
        by: UserId,
        at: OffsetDateTime,
    ) -> Result<(), SavedIntroError> {
        sqlx::query(
            "INSERT INTO instance_intro (name, description, updated_by, updated_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (only_row) DO UPDATE SET name = EXCLUDED.name, \
             description = EXCLUDED.description, updated_by = EXCLUDED.updated_by, \
             updated_at = EXCLUDED.updated_at",
        )
        .bind(text.name())
        .bind(text.description())
        .bind(by.as_uuid())
        .bind(at)
        .execute(&self.pool)
        .await
        .context("save the intro")?;
        Ok(())
    }
}

/// `fragment` as a `LIKE` pattern that matches only itself.
fn literal(fragment: &str) -> String {
    fragment
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}
