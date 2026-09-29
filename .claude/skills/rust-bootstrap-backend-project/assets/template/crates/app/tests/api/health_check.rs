use sqlx::PgPool;

use crate::helpers::spawn_app;

#[sqlx::test(migrator = "infrastructure::MIGRATOR")]
async fn the_health_endpoint_answers_200(pool: PgPool) {
    let app = spawn_app(pool).await;

    let response = app.get_health().await;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
}
