use anyhow::Context;
use domain::UserId;
use domain::settings::{SettingsDocument, SettingsPatch, SettingsStore, SettingsStoreError};
use sqlx::PgPool;

/// `user_settings`: one `jsonb` document per user, merged section by section in SQL.
pub struct PgSettingsStore {
    pool: PgPool,
}

impl PgSettingsStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl SettingsStore for PgSettingsStore {
    async fn load(&self, user: UserId) -> Result<Option<SettingsDocument>, SettingsStoreError> {
        let stored: Option<String> =
            sqlx::query_scalar("SELECT settings::text FROM user_settings WHERE user_id = $1")
                .bind(user.as_uuid())
                .fetch_optional(&self.pool)
                .await
                .context("load settings")?;
        match stored {
            Some(text) => {
                let document = serde_json::from_str(&text).context("parse stored settings")?;
                Ok(Some(SettingsDocument::from_value(document)))
            }
            None => Ok(None),
        }
    }

    async fn merge(
        &self,
        user: UserId,
        patch: &SettingsPatch,
    ) -> Result<SettingsDocument, SettingsStoreError> {
        let merged: String = sqlx::query_scalar(
            r#"
            INSERT INTO user_settings (user_id, settings)
            VALUES ($1, $2::jsonb)
            ON CONFLICT (user_id) DO UPDATE
            SET settings = user_settings.settings || EXCLUDED.settings, updated_at = now()
            RETURNING settings::text
            "#,
        )
        .bind(user.as_uuid())
        .bind(patch.as_value().to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_check_violation(&e) {
                SettingsStoreError::TooLarge
            } else {
                anyhow::Error::new(e)
                    .context("merge settings sections")
                    .into()
            }
        })?;
        let document = serde_json::from_str(&merged).context("parse stored settings")?;
        Ok(SettingsDocument::from_value(document))
    }
}

/// The table's `CHECK (octet_length(settings::text) <= 16384)` — the size cap.
fn is_check_violation(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23514"))
}
