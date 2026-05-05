use std::path::PathBuf;

/// Deployment environment. Controls scheme selection (http vs https) for the
/// local issuer URL **and** for outbound calls to peer IdPs (federation
/// delivery, presence batch poll, presence SSE). Also drives the `Secure`
/// cookie flag.
///
/// Set via `IDP_ENV=development|production`. Defaults to `Production` so
/// forgetting to set it can't accidentally weaken security in a real deploy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Production,
}

impl Environment {
    pub fn is_dev(self) -> bool {
        matches!(self, Self::Development)
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    /// The domain this IdP is hosted on, e.g. "localhost:8080" or "idp.alice.com".
    pub domain: String,
    pub environment: Environment,
    pub jwt_private_key_path: PathBuf,
    pub jwt_key_id: String,
    pub port: u16,
    /// Secret used to sign session cookies. Must be at least 32 bytes.
    /// If not set, a fixed dev-only default is used (sessions invalidated on restart in prod).
    pub session_secret: String,
    /// Base URL of the web-client, e.g. "http://localhost:5173".
    /// Used to redirect to the hosted login/register page instead of serving HTML.
    pub frontend_url: String,
    /// Allowed CORS origins, parsed from the `CORS_ORIGINS` env var
    /// (comma-separated, e.g. "https://app.example.com,https://admin.example.com").
    /// Defaults to localhost dev origins when unset.
    pub cors_origins: Vec<String>,

    // ── Redis (Message Broker) ───────────────────────────────────────────
    /// Redis connection URL for the event broker (Streams + pub-sub).
    pub redis_url: String,

    // ── Object Storage (S3-compatible) ──────────────────────────────────
    /// Internal S3 endpoint (e.g. "http://rustfs:9000" inside Docker).
    pub storage_endpoint: Option<String>,
    pub storage_access_key: Option<String>,
    pub storage_secret_key: Option<String>,
    pub storage_bucket_avatars: String,
    pub storage_bucket_attachments: String,
    /// Externally-reachable base URL for building public avatar URLs.
    pub storage_public_url: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingVar(&'static str),
    #[error("Invalid port: {0}")]
    InvalidPort(String),
    #[error("Invalid IDP_ENV value '{0}' (expected 'development' or 'production')")]
    InvalidEnvironment(String),
}

impl Config {
    /// Load configuration from environment variables.
    /// Call `dotenvy::dotenv().ok()` before this in main.rs.
    pub fn from_env() -> Result<Self, ConfigError> {
        let environment = match std::env::var("IDP_ENV").as_deref() {
            Ok("development") | Ok("dev") => Environment::Development,
            Ok("production") | Ok("prod") | Err(_) => Environment::Production,
            Ok(other) => return Err(ConfigError::InvalidEnvironment(other.to_string())),
        };

        Ok(Self {
            database_url: require_env("DATABASE_URL")?,
            domain: require_env("DOMAIN")?,
            environment,
            jwt_private_key_path: PathBuf::from(require_env("JWT_PRIVATE_KEY_PATH")?),
            jwt_key_id: require_env("JWT_KEY_ID")?,
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8080".into())
                .parse::<u16>()
                .map_err(|e| ConfigError::InvalidPort(e.to_string()))?,
            session_secret: std::env::var("SESSION_SECRET")
                .unwrap_or_else(|_| "dev-only-insecure-session-secret-change-in-production-00000000".into()),
            frontend_url: std::env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "http://localhost:5173".into()),
            cors_origins: std::env::var("CORS_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:5173,http://localhost:3000".into())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),
            storage_endpoint: std::env::var("STORAGE_ENDPOINT").ok(),
            storage_access_key: std::env::var("STORAGE_ACCESS_KEY").ok(),
            storage_secret_key: std::env::var("STORAGE_SECRET_KEY").ok(),
            storage_bucket_avatars: std::env::var("STORAGE_BUCKET_AVATARS")
                .unwrap_or_else(|_| "avatars".into()),
            storage_bucket_attachments: std::env::var("STORAGE_BUCKET_ATTACHMENTS")
                .unwrap_or_else(|_| "attachments".into()),
            storage_public_url: std::env::var("STORAGE_PUBLIC_URL").ok(),
        })
    }

    /// Returns true when all required storage env vars are set.
    pub fn storage_enabled(&self) -> bool {
        self.storage_endpoint.is_some()
            && self.storage_access_key.is_some()
            && self.storage_secret_key.is_some()
    }

    /// The OIDC issuer URL. Built from `domain` + the environment-derived scheme.
    pub fn issuer(&self) -> String {
        format!("{}://{}", self.scheme(), self.domain)
    }

    /// Wire scheme used by this IdP — `http` in development, `https` in
    /// production. Single source of truth: used for the local issuer URL and
    /// for every outbound inter-IdP call (federation delivery, presence batch
    /// poll, presence SSE). Peers in the same network are assumed to use the
    /// same scheme as us — there's no mixed-mode federation.
    pub fn scheme(&self) -> &'static str {
        match self.environment {
            Environment::Development => "http",
            Environment::Production => "https",
        }
    }

    /// Whether the cookie `Secure` attribute should be set. False in
    /// development so the cookie works over plain HTTP, true in production.
    pub fn secure_cookies(&self) -> bool {
        self.environment == Environment::Production
    }
}

fn require_env(key: &'static str) -> Result<String, ConfigError> {
    std::env::var(key).map_err(|_| ConfigError::MissingVar(key))
}
