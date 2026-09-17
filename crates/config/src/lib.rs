use std::path::PathBuf;
use std::time::Duration;

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

    // ── DM attachments ────────────────────────────────────────────────────
    /// Maximum number of attachments allowed in a single message.
    pub attachment_max_files_per_message: usize,
    /// Maximum byte size for a single attachment.
    pub attachment_max_byte_size: u64,
    /// TTL for the HMAC-signed `/blob` token returned by the metadata endpoint.
    pub attachment_url_ttl: Duration,
    /// How long an unlinked (orphan) attachment lives before the sweep deletes it.
    pub attachment_orphan_ttl: Duration,
    /// File extensions that may not be uploaded. The user-provided env var
    /// *extends* the built-in list — env values cannot remove built-in entries.
    /// Comparisons are case-insensitive against the lowercased extension.
    pub attachment_blocked_extensions: Vec<String>,
    /// MIME types that may not be uploaded. The env var extends the built-in list.
    pub attachment_blocked_mimes: Vec<String>,

    // ── E2EE: MLS key directory ───────────────────────────────────────────
    /// Maximum unconsumed KeyPackages a single device may hold on the server.
    /// Uploads that would push the count past this are rejected.
    pub e2ee_keypackage_cap_per_device: usize,
    /// `GET /api/keys/packages/status` flags `needs_refill = true` when a
    /// device's available count drops to this threshold or below.
    pub e2ee_keypackage_refill_threshold: usize,
    /// Maximum lifetime accepted on a freshly uploaded KeyPackage. Server
    /// validates `expires_at - created_at ≤ this` on `POST /api/keys/packages`.
    pub e2ee_keypackage_lifetime: Duration,

    // ── Outbound email (SMTP — Mailpit in dev, real relay in prod) ───────
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    /// RFC 5322 `From` header (e.g. `Pīna'i <no-reply@idp.alice.com>`).
    pub smtp_from: String,
    pub smtp_starttls: bool,
    /// HMAC pepper for email OTP code hashes. Required — startup fails if unset.
    /// Same value also peppers TOTP recovery codes (one secret to manage).
    pub email_otp_pepper: Vec<u8>,
}

/// Built-in extension blocklist. Extended (never replaced) by
/// `ATTACHMENT_BLOCKED_EXTENSIONS`. Stored lowercased; comparison is
/// lowercase-vs-lowercase.
const BUILTIN_BLOCKED_EXTENSIONS: &[&str] = &[
    "exe", "sh", "bat", "cmd", "com", "ps1", "vbs", "js", "wsf", "hta", "scr", "pif", "lnk", "app",
    "dmg", "pkg", "msi", "msix", "deb", "rpm", "appimage", "jar", "war", "dll", "so", "dylib",
];

/// Built-in MIME blocklist. Extended (never replaced) by `ATTACHMENT_BLOCKED_MIMES`.
const BUILTIN_BLOCKED_MIMES: &[&str] = &[
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-executable",
    "application/x-sh",
    "application/x-mach-binary",
    "application/vnd.microsoft.portable-executable",
];

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingVar(&'static str),
    #[error("Invalid port: {0}")]
    InvalidPort(String),
    #[error("Invalid IDP_ENV value '{0}' (expected 'development' or 'production')")]
    InvalidEnvironment(String),
    #[error("Invalid attachment numeric value for {0}: {1}")]
    InvalidAttachmentValue(&'static str, String),
    #[error("Invalid {0}: {1}")]
    InvalidValue(&'static str, String),
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
            session_secret: std::env::var("SESSION_SECRET").unwrap_or_else(|_| {
                "dev-only-insecure-session-secret-change-in-production-00000000".into()
            }),
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

            attachment_max_files_per_message: parse_env_usize(
                "ATTACHMENT_MAX_FILES_PER_MESSAGE",
                5,
            )?,
            attachment_max_byte_size: parse_env_u64("ATTACHMENT_MAX_BYTE_SIZE", 50 * 1024 * 1024)?,
            attachment_url_ttl: Duration::from_secs(parse_env_u64(
                "ATTACHMENT_URL_TTL_SECS",
                3600,
            )?),
            attachment_orphan_ttl: Duration::from_secs(parse_env_u64(
                "ATTACHMENT_ORPHAN_TTL_SECS",
                1800,
            )?),
            attachment_blocked_extensions: merge_blocklist(
                BUILTIN_BLOCKED_EXTENSIONS,
                std::env::var("ATTACHMENT_BLOCKED_EXTENSIONS")
                    .ok()
                    .as_deref(),
            ),
            attachment_blocked_mimes: merge_blocklist(
                BUILTIN_BLOCKED_MIMES,
                std::env::var("ATTACHMENT_BLOCKED_MIMES").ok().as_deref(),
            ),

            e2ee_keypackage_cap_per_device: parse_env_usize("E2EE_KEYPACKAGE_CAP_PER_DEVICE", 100)?,
            e2ee_keypackage_refill_threshold: parse_env_usize(
                "E2EE_KEYPACKAGE_REFILL_THRESHOLD",
                20,
            )?,
            e2ee_keypackage_lifetime: Duration::from_secs(parse_env_u64(
                "E2EE_KEYPACKAGE_LIFETIME_SECS",
                30 * 24 * 60 * 60,
            )?),

            smtp_host: std::env::var("SMTP_HOST").unwrap_or_else(|_| "mailpit".into()),
            smtp_port: std::env::var("SMTP_PORT")
                .unwrap_or_else(|_| "1025".into())
                .parse::<u16>()
                .map_err(|e| ConfigError::InvalidPort(e.to_string()))?,
            smtp_username: std::env::var("SMTP_USERNAME").unwrap_or_default(),
            smtp_password: std::env::var("SMTP_PASSWORD").unwrap_or_default(),
            smtp_from: std::env::var("SMTP_FROM")
                .unwrap_or_else(|_| "Pīna'i <no-reply@localhost>".into()),
            smtp_starttls: std::env::var("SMTP_STARTTLS")
                .ok()
                .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
                .unwrap_or(false),
            email_otp_pepper: parse_email_otp_pepper()?,
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

fn parse_env_usize(key: &'static str, default: usize) -> Result<usize, ConfigError> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => raw
            .parse()
            .map_err(|_| ConfigError::InvalidAttachmentValue(key, raw)),
    }
}

fn parse_env_u64(key: &'static str, default: u64) -> Result<u64, ConfigError> {
    match std::env::var(key) {
        Err(_) => Ok(default),
        Ok(raw) => raw
            .parse()
            .map_err(|_| ConfigError::InvalidAttachmentValue(key, raw)),
    }
}

/// Hex-decoded ≥ 32-byte HMAC pepper. Required at startup so an operator can't
/// silently run with a missing or weak value.
fn parse_email_otp_pepper() -> Result<Vec<u8>, ConfigError> {
    let raw = std::env::var("EMAIL_OTP_PEPPER")
        .map_err(|_| ConfigError::MissingVar("EMAIL_OTP_PEPPER"))?;
    let bytes = hex::decode(raw.trim())
        .map_err(|e| ConfigError::InvalidValue("EMAIL_OTP_PEPPER", e.to_string()))?;
    if bytes.len() < 32 {
        return Err(ConfigError::InvalidValue(
            "EMAIL_OTP_PEPPER",
            format!("must be at least 32 bytes; got {}", bytes.len()),
        ));
    }
    Ok(bytes)
}

/// Merge a built-in blocklist with an optional user-supplied comma-separated
/// list. Entries are lower-cased and deduplicated. The built-in list is always
/// included — env values can only *add* to it.
fn merge_blocklist(builtins: &[&str], env_value: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = builtins.iter().map(|s| s.to_lowercase()).collect();
    if let Some(raw) = env_value {
        for item in raw.split(',') {
            let trimmed = item.trim().to_lowercase();
            if !trimmed.is_empty() && !out.contains(&trimmed) {
                out.push(trimmed);
            }
        }
    }
    out
}
