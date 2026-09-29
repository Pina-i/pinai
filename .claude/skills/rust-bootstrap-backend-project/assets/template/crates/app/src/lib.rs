pub mod telemetry;

use anyhow::Context;
use sqlx::PgPool;
use tokio::net::TcpListener;

pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let port = match std::env::var("PORT") {
            Ok(raw) => raw.parse().context("PORT must be a port number")?,
            Err(_) => 8080,
        };
        Ok(Self {
            host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_owned()),
            port,
            database_url: std::env::var("DATABASE_URL").context("DATABASE_URL is required")?,
        })
    }
}

pub struct Application {
    listener: TcpListener,
    router: axum::Router,
}

impl Application {
    /// Wires every layer over `pool` and binds the listener; port 0 picks a free one.
    pub async fn build(config: Config, pool: PgPool) -> anyhow::Result<Self> {
        let router = api::router(state(pool));
        let listener = TcpListener::bind((config.host.as_str(), config.port))
            .await
            .with_context(|| format!("bind {}:{}", config.host, config.port))?;
        Ok(Self { listener, router })
    }

    pub fn port(&self) -> u16 {
        self.listener
            .local_addr()
            .map(|a| a.port())
            .unwrap_or_default()
    }

    pub async fn run_until_stopped(self) -> std::io::Result<()> {
        axum::serve(self.listener, self.router).await
    }
}

/// Adapters over the pool, then use cases, then the state handlers see.
fn state(_pool: PgPool) -> api::AppState {
    api::AppState::default()
}
