use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    /// The domain this IdP is hosted on, e.g. "localhost:8080" or "idp.alice.com".
    pub domain: String,
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
}

impl Config {
    /// Load configuration from environment variables.
    /// Call `dotenvy::dotenv().ok()` before this in main.rs.
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            database_url: require_env("DATABASE_URL")?,
            domain: require_env("DOMAIN")?,
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

    /// The OIDC issuer URL. Uses http:// for localhost (dev), https:// otherwise.
    pub fn issuer(&self) -> String {
        if self.domain.starts_with("localhost") || self.domain.starts_with("127.") {
            format!("http://{}", self.domain)
        } else {
            format!("https://{}", self.domain)
        }
    }
}

fn require_env(key: &'static str) -> Result<String, ConfigError> {
    std::env::var(key).map_err(|_| ConfigError::MissingVar(key))
}
