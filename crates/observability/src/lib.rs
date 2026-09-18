use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize the global tracing subscriber for a Pina-i service.
///
/// Must be called once at the very start of `main`, before any async runtime is started.
///
/// # Environment variables
///
/// | Variable     | Default | Description                                                    |
/// |---|---|---|
/// | `RUST_LOG`   | `info`  | Log filter. E.g. `debug`, `info,sqlx=warn`, `idp_oidc=debug`  |
/// | `LOG_FORMAT` | (unset) | Set to `json` for machine-readable production logs             |
pub fn init_tracing(service_name: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let use_json = std::env::var("LOG_FORMAT").ok().as_deref() == Some("json");

    if use_json {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    tracing::info!(service = service_name, "tracing initialized");
}
