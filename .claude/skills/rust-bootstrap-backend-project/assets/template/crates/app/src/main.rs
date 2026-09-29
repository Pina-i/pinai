use anyhow::Context;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    app::telemetry::init_tracing(std::io::stdout);
    let config = app::Config::from_env()?;
    let pool = infrastructure::postgres::connect(&config.database_url).await?;
    infrastructure::MIGRATOR
        .run(&pool)
        .await
        .context("run migrations")?;
    let application = app::Application::build(config, pool).await?;
    tracing::info!(port = application.port(), "__SERVICE__ listening");
    application.run_until_stopped().await?;
    Ok(())
}
