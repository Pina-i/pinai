use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use domain::auth::{OFFICIAL_WEB_APP_ORIGIN, Registrations, WebApp};
use domain::identity::host_of;
use infrastructure::email::SmtpTls;

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
    /// `DATABASE_PASSWORD`: set on the connection over any password `database_url` holds.
    pub database_password: Option<String>,
    /// The domain this IdP is hosted on, e.g. "localhost:8080" or "idp.alice.com".
    pub domain: String,
    pub environment: Environment,
    pub jwt_private_key_path: PathBuf,
    /// `JWT_KEY_ID`; unset, the key is named by its RFC 7638 thumbprint.
    pub jwt_key_id: Option<String>,
    pub port: u16,
    /// What the session-cookie and attachment-link keys are derived from. Falls back
    /// to [`DEV_SESSION_SECRET`] in development; production requires a real one.
    pub session_secret: String,
    /// The name the sign-in pages and NodeInfo give the instance; its domain when unset.
    pub instance_name: Option<String>,
    /// A line about the instance, shown under its name on the sign-in pages.
    pub instance_description: Option<String>,

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
    /// Empty when the instance has no relay.
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    /// RFC 5322 `From` header (e.g. `Pīna'i <no-reply@idp.alice.com>`).
    pub smtp_from: String,
    /// `SMTP_TLS`: `none`, `starttls` or `tls`; plain in development, in production TLS on
    /// port 465 and STARTTLS otherwise.
    pub smtp_tls: SmtpTls,
    /// HMAC pepper for email OTP code hashes. Required — startup fails if unset.
    /// Same value also peppers TOTP recovery codes (one secret to manage).
    pub email_otp_pepper: Vec<u8>,

    // ── Who can join ─────────────────────────────────────────────────────
    /// `REGISTRATIONS`: `open`, anyone signs up, or `invite`, the default, only the invited.
    pub registrations: Registrations,

    // ── The first admin ──────────────────────────────────────────────────
    /// `ADMIN_EMAIL`: the admin account is created with it at startup when no account has it.
    pub admin_email: Option<String>,
    /// `ADMIN_PASSWORD`: read only to create that account, never to change it.
    pub admin_password: Option<String>,

    // ── The official web app ─────────────────────────────────────────────
    /// Where someone who joins by invitation lands signed in: the official web app, or
    /// `WEB_APP_ORIGIN` in its stead — `http://localhost:5173` in development. `None`: the
    /// joining ends on a page saying to sign in from the app.
    pub web_app: Option<WebApp>,
}

/// The web client of a development checkout, `pnpm dev`'s.
pub const DEV_WEB_APP_ORIGIN: &str = "http://localhost:5173";

/// `SESSION_SECRET` used when development leaves it unset. Public, so production refuses it.
pub const DEV_SESSION_SECRET: &str =
    "dev-only-insecure-session-secret-change-in-production-00000000";

const MIN_SESSION_SECRET_LEN: usize = 32;

/// The most a `_FILE` is read: a secret is a line, and a device such as /dev/zero never ends.
const MAX_FILE_LEN: u64 = 64 * 1024;

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
    #[error("Missing or empty environment variable: {0} (or {0}_FILE, a file holding it)")]
    MissingVar(&'static str),
    #[error("{0} and {0}_FILE are both set: keep one")]
    ValueAndFile(&'static str),
    #[error("{var}_FILE: cannot read {}: {source}", path.display())]
    UnreadableFile {
        var: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{var}_FILE names {}, which is empty", path.display())]
    EmptyFile { var: &'static str, path: PathBuf },
    #[error("{var}_FILE names {}, which is larger than {kib} KiB", path.display(), kib = MAX_FILE_LEN / 1024)]
    FileTooLarge { var: &'static str, path: PathBuf },
    #[error("Invalid port: {0}")]
    InvalidPort(String),
    #[error("Invalid IDP_ENV value '{0}' (expected 'development' or 'production')")]
    InvalidEnvironment(String),
    #[error("Invalid attachment numeric value for {0}: {1}")]
    InvalidAttachmentValue(&'static str, String),
    #[error("Invalid {0}: {1}")]
    InvalidValue(&'static str, String),
    #[error("REGISTRATIONS=open needs an SMTP relay: set SMTP_HOST, or REGISTRATIONS=invite")]
    OpenWithoutRelay,
}

impl Config {
    /// Load configuration from environment variables.
    /// Call `dotenvy::dotenv().ok()` before this in main.rs.
    pub fn from_env() -> Result<Self, ConfigError> {
        let environment = match env_var("IDP_ENV")?.as_deref() {
            Some("development") | Some("dev") => Environment::Development,
            Some("production") | Some("prod") | None => Environment::Production,
            Some(other) => return Err(ConfigError::InvalidEnvironment(other.to_string())),
        };
        let database_url = require_env("DATABASE_URL")?;
        let domain = require_env("DOMAIN")?;
        let smtp_port = smtp_port(environment, env_var("SMTP_PORT")?)?;

        let config = Self {
            database_password: unless_empty(env_var("DATABASE_PASSWORD")?),
            database_url,
            environment,
            jwt_private_key_path: PathBuf::from(require_env("JWT_PRIVATE_KEY_PATH")?),
            jwt_key_id: unless_empty(env_var("JWT_KEY_ID")?),
            port: env_var("PORT")?
                .unwrap_or_else(|| "8080".into())
                .parse::<u16>()
                .map_err(|e| ConfigError::InvalidPort(e.to_string()))?,
            session_secret: session_secret(environment, env_var("SESSION_SECRET")?)?,
            instance_name: env_var("INSTANCE_NAME")?,
            instance_description: env_var("INSTANCE_DESCRIPTION")?,
            redis_url: env_var("REDIS_URL")?.unwrap_or_else(|| "redis://127.0.0.1:6379".into()),
            storage_endpoint: env_var("STORAGE_ENDPOINT")?,
            storage_access_key: env_var("STORAGE_ACCESS_KEY")?,
            storage_secret_key: env_var("STORAGE_SECRET_KEY")?,
            storage_bucket_avatars: env_var("STORAGE_BUCKET_AVATARS")?
                .unwrap_or_else(|| "avatars".into()),
            storage_bucket_attachments: env_var("STORAGE_BUCKET_ATTACHMENTS")?
                .unwrap_or_else(|| "attachments".into()),
            storage_public_url: env_var("STORAGE_PUBLIC_URL")?,

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
                env_var("ATTACHMENT_BLOCKED_EXTENSIONS")?.as_deref(),
            ),
            attachment_blocked_mimes: merge_blocklist(
                BUILTIN_BLOCKED_MIMES,
                env_var("ATTACHMENT_BLOCKED_MIMES")?.as_deref(),
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

            smtp_host: smtp_host(env_var("SMTP_HOST")?),
            smtp_port,
            smtp_username: env_var("SMTP_USERNAME")?.unwrap_or_default(),
            smtp_password: env_var("SMTP_PASSWORD")?.unwrap_or_default(),
            smtp_from: smtp_from(env_var("SMTP_FROM")?, &domain),
            smtp_tls: smtp_tls(environment, smtp_port, env_var("SMTP_TLS")?)?,
            email_otp_pepper: email_otp_pepper(env_var("EMAIL_OTP_PEPPER")?)?,
            registrations: registrations(env_var("REGISTRATIONS")?)?,
            admin_email: unless_empty(env_var("ADMIN_EMAIL")?),
            admin_password: unless_empty(env_var("ADMIN_PASSWORD")?),
            web_app: web_app(environment, env_var("WEB_APP_ORIGIN")?)?,
            domain,
        };
        require_relay(config.registrations, &config.smtp_host)?;
        Ok(config)
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

/// Read an environment variable with surrounding whitespace removed.
///
/// A `.env` saved with CRLF endings leaves a trailing `\r` on every value when a
/// shell sources it, while Docker Compose strips it — so the same file yields
/// different values depending on how the process was started. Unnoticed, a `\r`
/// in `DOMAIN` reaches `issuer()` and is baked into `actor_uri`, where remote
/// instances resolve a URL the origin no longer recognises.
fn env_var(key: &'static str) -> Result<Option<String>, ConfigError> {
    value_or_file(
        key,
        std::env::var(key).ok(),
        std::env::var(format!("{key}_FILE")).ok(),
        read_bounded,
    )
}

/// A regular file only, read a byte past the limit at most: a FIFO or a device would block, or
/// never end.
fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut content = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_FILE_LEN + 1)
        .read_to_end(&mut content)?;
    Ok(content)
}

/// The variable's value, or else the content of the file its `_FILE` twin names, as Docker
/// secrets hand them over. The content is never put in an error.
fn value_or_file(
    key: &'static str,
    value: Option<String>,
    file: Option<String>,
    read: impl FnOnce(&Path) -> std::io::Result<Vec<u8>>,
) -> Result<Option<String>, ConfigError> {
    let value = value.map(|v| v.trim().to_string());
    let path = match (value, unless_empty(file.map(|f| f.trim().to_string()))) {
        (Some(value), Some(_)) if !value.is_empty() => return Err(ConfigError::ValueAndFile(key)),
        (_, Some(path)) => PathBuf::from(path),
        (value, None) => return Ok(value),
    };
    let unreadable = |source| ConfigError::UnreadableFile {
        var: key,
        path: path.clone(),
        source,
    };
    let content = read(&path).map_err(unreadable)?;
    if content.len() as u64 > MAX_FILE_LEN {
        return Err(ConfigError::FileTooLarge { var: key, path });
    }
    let content = String::from_utf8(content).map_err(|_| {
        unreadable(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not UTF-8",
        ))
    })?;
    // Whoever named a file meant a value: an empty one is a mistake, not an unset variable.
    match content.trim() {
        "" => Err(ConfigError::EmptyFile { var: key, path }),
        content => Ok(Some(content.to_owned())),
    }
}

fn require_env(key: &'static str) -> Result<String, ConfigError> {
    required(key, env_var(key)?)
}

/// Empty is missing too: an instance never runs on an empty `DOMAIN` or `DATABASE_URL`.
fn required(key: &'static str, raw: Option<String>) -> Result<String, ConfigError> {
    unless_empty(raw).ok_or(ConfigError::MissingVar(key))
}

fn parse_env_usize(key: &'static str, default: usize) -> Result<usize, ConfigError> {
    match env_var(key)? {
        None => Ok(default),
        Some(raw) => raw
            .parse()
            .map_err(|_| ConfigError::InvalidAttachmentValue(key, raw)),
    }
}

fn parse_env_u64(key: &'static str, default: u64) -> Result<u64, ConfigError> {
    match env_var(key)? {
        None => Ok(default),
        Some(raw) => raw
            .parse()
            .map_err(|_| ConfigError::InvalidAttachmentValue(key, raw)),
    }
}

/// Empty counts as unset: the submission port in production, Mailpit's in development.
fn smtp_port(environment: Environment, raw: Option<String>) -> Result<u16, ConfigError> {
    match unless_empty(raw) {
        None if environment.is_dev() => Ok(1025),
        None => Ok(587),
        Some(v) => v
            .parse()
            .map_err(|e: std::num::ParseIntError| ConfigError::InvalidPort(e.to_string())),
    }
}

/// A `.env` keeps `ADMIN_PASSWORD=` once the admin exists: empty is unset.
fn unless_empty(raw: Option<String>) -> Option<String> {
    raw.filter(|v| !v.is_empty())
}

/// `WEB_APP_ORIGIN` stands in for the official web app; unset, development has its own and
/// production the official one, when it has one.
fn web_app(environment: Environment, raw: Option<String>) -> Result<Option<WebApp>, ConfigError> {
    let origin = match unless_empty(raw) {
        Some(raw) => {
            return WebApp::parse(&raw)
                .map(Some)
                .map_err(|e| ConfigError::InvalidValue("WEB_APP_ORIGIN", e.reason));
        }
        None if environment.is_dev() => Some(DEV_WEB_APP_ORIGIN),
        None => OFFICIAL_WEB_APP_ORIGIN,
    };
    Ok(origin.map(|origin| WebApp::parse(origin).expect("a built-in origin")))
}

/// Unset or empty, no-reply at the instance's own host: a `.env` without a relay leaves
/// `SMTP_FROM=` empty.
fn smtp_from(raw: Option<String>, domain: &str) -> String {
    unless_empty(raw).unwrap_or_else(|| format!("Pīna'i <no-reply@{}>", host_of(domain)))
}

/// Unset or empty, the instance has no relay: never a host it wasn't given.
fn smtp_host(raw: Option<String>) -> String {
    raw.unwrap_or_default()
}

/// Unset or empty, an instance lets in only the people its admins invite.
fn registrations(raw: Option<String>) -> Result<Registrations, ConfigError> {
    match raw.map(|v| v.to_lowercase()).as_deref() {
        None | Some("") | Some("invite") => Ok(Registrations::Invite),
        Some("open") => Ok(Registrations::Open),
        Some(other) => Err(ConfigError::InvalidValue(
            "REGISTRATIONS",
            format!("'{other}' (expected open or invite)"),
        )),
    }
}

/// An open instance mails every sign-up a code: without a relay — `SMTP_HOST` unset or empty —
/// nobody could finish signing up.
fn require_relay(registrations: Registrations, smtp_host: &str) -> Result<(), ConfigError> {
    if registrations.are_open() && smtp_host.is_empty() {
        return Err(ConfigError::OpenWithoutRelay);
    }
    Ok(())
}

fn smtp_tls(
    environment: Environment,
    port: u16,
    raw: Option<String>,
) -> Result<SmtpTls, ConfigError> {
    match raw.map(|v| v.to_lowercase()).as_deref() {
        None | Some("") if environment.is_dev() => Ok(SmtpTls::None),
        None | Some("") if port == 465 => Ok(SmtpTls::Tls),
        None | Some("") => Ok(SmtpTls::StartTls),
        Some("none") => Ok(SmtpTls::None),
        Some("starttls") => Ok(SmtpTls::StartTls),
        Some("tls") => Ok(SmtpTls::Tls),
        Some(other) => Err(ConfigError::InvalidValue(
            "SMTP_TLS",
            format!("'{other}' (expected none, starttls or tls)"),
        )),
    }
}

fn session_secret(environment: Environment, raw: Option<String>) -> Result<String, ConfigError> {
    let secret = match raw.filter(|v| !v.is_empty()) {
        Some(secret) => secret,
        None if environment.is_dev() => return Ok(DEV_SESSION_SECRET.into()),
        None => return Err(ConfigError::MissingVar("SESSION_SECRET")),
    };
    if environment.is_dev() {
        return Ok(secret);
    }
    // Both are published — the fallback above and the `.env.example` placeholder.
    if secret == DEV_SESSION_SECRET || secret.starts_with("change-me") {
        return Err(ConfigError::InvalidValue(
            "SESSION_SECRET",
            "still a published placeholder — generate one with `openssl rand -hex 32`".into(),
        ));
    }
    if secret.len() < MIN_SESSION_SECRET_LEN {
        return Err(ConfigError::InvalidValue(
            "SESSION_SECRET",
            format!(
                "must be at least {MIN_SESSION_SECRET_LEN} bytes; got {}",
                secret.len()
            ),
        ));
    }
    Ok(secret)
}

/// Hex-decoded ≥ 32-byte HMAC pepper. Required at startup so an operator can't
/// silently run with a missing or weak value.
fn email_otp_pepper(raw: Option<String>) -> Result<Vec<u8>, ConfigError> {
    let raw = unless_empty(raw).ok_or(ConfigError::MissingVar("EMAIL_OTP_PEPPER"))?;
    // hex's error quotes the offending character: a secret's, here.
    let bytes = hex::decode(raw).map_err(|_| {
        ConfigError::InvalidValue(
            "EMAIL_OTP_PEPPER",
            "must be hex, as `openssl rand -hex 32` makes it".into(),
        )
    })?;
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

#[cfg(test)]
mod tests;
