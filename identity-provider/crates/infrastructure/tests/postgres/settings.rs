use domain::settings::testing::contract;
use infrastructure::postgres::PgSettingsStore;
use sqlx::PgPool;

use crate::a_user;

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_merge_replaces_the_sections_it_names_and_keeps_the_others(pool: PgPool) {
    let user = a_user(&pool).await;

    contract::a_merge_replaces_the_sections_it_names_and_keeps_the_others(
        &PgSettingsStore::new(pool),
        user,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn an_account_that_never_saved_settings_has_no_document(pool: PgPool) {
    let user = a_user(&pool).await;

    contract::an_account_that_never_saved_settings_has_no_document(
        &PgSettingsStore::new(pool),
        user,
    )
    .await;
}

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn a_document_grown_past_16_kib_is_refused(pool: PgPool) {
    let user = a_user(&pool).await;

    contract::a_document_grown_past_16_kib_is_refused(&PgSettingsStore::new(pool), user).await;
}
