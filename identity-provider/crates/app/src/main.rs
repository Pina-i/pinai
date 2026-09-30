use app::Application;
use app::configuration::Config;
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // A `.env` is for development; production sets the variables themselves.
    dotenvy::dotenv().ok();
    observability::init_tracing("identity-provider");

    let config = Config::from_env().map_err(|e| anyhow::anyhow!("Config error: {e}"))?;
    info!(domain = %config.domain, port = config.port, "starting identity-provider");
    let listener = TcpListener::bind(("0.0.0.0", config.port)).await?;
    info!(addr = %listener.local_addr()?, "listening");

    let application = Application::build(config, listener).await?;
    let stop = application.stop_token();
    tokio::spawn(async move {
        stop_requested().await;
        info!("stopping");
        stop.cancel();
    });
    application.run_until_stopped().await
}

/// Ctrl-C, or the `SIGTERM` a container is stopped with.
async fn stop_requested() {
    let interrupted = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let terminated = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                terminate.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminated = std::future::pending::<()>();
    tokio::select! {
        _ = interrupted => {}
        () = terminated => {}
    }
}
