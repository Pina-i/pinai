use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

/// Installs the global subscriber. Call it once per process: it panics on a second call.
pub fn init_tracing<W>(writer: W)
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .init();
}
