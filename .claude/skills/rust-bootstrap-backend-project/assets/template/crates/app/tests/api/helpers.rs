use std::sync::LazyLock;

use sqlx::PgPool;

// Logs to stdout with `TEST_LOG=1 cargo test …`, silent otherwise; installed once per binary.
static TRACING: LazyLock<()> = LazyLock::new(|| {
    if std::env::var("TEST_LOG").is_ok() {
        app::telemetry::init_tracing(std::io::stdout);
    } else {
        app::telemetry::init_tracing(std::io::sink);
    }
});

pub struct TestApp {
    pub address: String,
    pub client: reqwest::Client,
}

impl TestApp {
    pub async fn get_health(&self) -> reqwest::Response {
        self.client
            .get(format!("{}/health", self.address))
            .send()
            .await
            .expect("request /health")
    }
}

/// Starts the application on a free port over `pool` (a fresh database from `#[sqlx::test]`).
pub async fn spawn_app(pool: PgPool) -> TestApp {
    LazyLock::force(&TRACING);
    let config = app::Config {
        host: "127.0.0.1".to_owned(),
        port: 0,
        database_url: String::new(),
    };
    let application = app::Application::build(config, pool)
        .await
        .expect("build the application");
    let address = format!("http://127.0.0.1:{}", application.port());
    tokio::spawn(application.run_until_stopped());
    TestApp {
        address,
        client: reqwest::Client::new(),
    }
}
