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
        })
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
