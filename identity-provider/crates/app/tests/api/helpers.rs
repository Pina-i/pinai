//! Spawns the whole application on a loopback port — its own database on the test Postgres, the
//! test Redis, a fresh instance key, an SMTP sink for its mail — and drives it over HTTP.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use app::Application;
use app::configuration::{Config, Environment};
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use serde_json::Value;
use sqlx::{Connection, Executor, PgConnection};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// RFC 7636 appendix B.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
pub const PASSWORD: &str = "journey-password-1";

/// `TEST_LOG=1` shows the applications' logs.
static TRACING: LazyLock<()> = LazyLock::new(|| {
    if std::env::var("TEST_LOG").is_ok() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("info")
            .with_test_writer()
            .try_init();
    }
});

pub struct TestApp {
    /// `http://127.0.0.1:{port}`
    pub address: String,
    /// `127.0.0.1:{port}`, which its addresses and actor URIs name.
    pub domain: String,
    pub mail: MailSink,
    pub http: reqwest::Client,
    /// The web client the journeys sign in through: its document, served on a port of its own.
    pub client_id: String,
    pub redirect_uri: String,
    _client: MockServer,
    database: String,
    stop: CancellationToken,
    running: JoinHandle<anyhow::Result<()>>,
}

/// An account signed up and signed in over the real flows.
#[derive(Debug, Clone)]
pub struct Account {
    pub email: String,
    pub handle: String,
    pub actor_uri: String,
    pub token: String,
}

impl Account {
    /// How accounts on other instances name it.
    pub fn address(&self, on: &TestApp) -> String {
        format!("{}@{}", self.handle, on.domain)
    }
}

pub async fn spawn_app() -> TestApp {
    LazyLock::force(&TRACING);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let domain = format!("127.0.0.1:{port}");
    let (database_url, database) = fresh_database().await;
    let mail = MailSink::start().await;
    let client = MockServer::start().await;
    let (client_id, redirect_uri) = (
        format!("{}/oauth-client.json", client.uri()),
        format!("{}/callback", client.uri()),
    );
    Mock::given(method("GET"))
        .and(path("/oauth-client.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "client_id": client_id,
            "client_name": "Pīna'i",
            "redirect_uris": [redirect_uri],
        })))
        .mount(&client)
        .await;
    let key = std::env::temp_dir().join(format!("pinai-journey-{}.pem", Uuid::new_v4()));
    let pem = SigningKey::from_bytes(&rand::random())
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap();
    std::fs::write(&key, pem.as_bytes()).unwrap();
    let config = Config {
        database_url,
        domain: domain.clone(),
        environment: Environment::Development,
        jwt_private_key_path: key.clone(),
        jwt_key_id: format!("journey-{port}"),
        port,
        session_secret: hex::encode(rand::random::<[u8; 32]>()),
        instance_name: None,
        instance_description: None,
        redis_url: std::env::var("TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://localhost:56479".into()),
        storage_endpoint: None,
        storage_access_key: None,
        storage_secret_key: None,
        storage_bucket_avatars: "avatars".into(),
        storage_bucket_attachments: "attachments".into(),
        storage_public_url: None,
        attachment_max_files_per_message: 5,
        attachment_max_byte_size: 10 * 1024 * 1024,
        attachment_url_ttl: Duration::from_secs(3600),
        attachment_orphan_ttl: Duration::from_secs(1800),
        attachment_blocked_extensions: vec!["exe".into()],
        attachment_blocked_mimes: vec![],
        e2ee_keypackage_cap_per_device: 100,
        e2ee_keypackage_refill_threshold: 20,
        e2ee_keypackage_lifetime: Duration::from_secs(30 * 24 * 3600),
        smtp_host: "127.0.0.1".into(),
        smtp_port: mail.port,
        smtp_username: String::new(),
        smtp_password: String::new(),
        smtp_from: "Pīna'i <no-reply@journey.test>".into(),
        smtp_starttls: false,
        email_otp_pepper: rand::random::<[u8; 32]>().to_vec(),
    };
    let application = Application::build(config, listener)
        .await
        .expect("the application builds");
    std::fs::remove_file(&key).unwrap();
    let stop = application.stop_token();
    let running = tokio::spawn(application.run_until_stopped());
    TestApp {
        address: format!("http://{domain}"),
        domain,
        mail,
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        client_id,
        redirect_uri,
        _client: client,
        database,
        stop,
        running,
    }
}

/// A database of its own, on the server `DATABASE_URL` names; the application migrates it.
async fn fresh_database() -> (String, String) {
    let server = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://test:test@localhost:55432/test".into());
    let name = format!("journey_{}", Uuid::new_v4().simple());
    let mut connection = PgConnection::connect(&server)
        .await
        .expect("the test Postgres — `make test-integration` starts it");
    connection
        .execute(format!(r#"CREATE DATABASE "{name}""#).as_str())
        .await
        .unwrap();
    let base = &server[..server.rfind('/').unwrap()];
    (format!("{base}/{name}"), name)
}

/// The query of a `Location`: absolute when it goes to the client, relative within this
/// instance's own pages.
pub fn query_of(location: &str) -> HashMap<String, String> {
    let url = reqwest::Url::parse("http://instance.test")
        .unwrap()
        .join(location)
        .unwrap();
    url.query_pairs().into_owned().collect()
}

pub fn location(response: &reqwest::Response) -> String {
    response.headers()["location"].to_str().unwrap().to_owned()
}

impl TestApp {
    /// The OIDC request the web client makes, as form pairs.
    pub fn the_request(&self) -> Vec<(&'static str, String)> {
        [
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("scope", "openid profile email"),
            ("state", "journey-state"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("nonce", "journey-nonce"),
        ]
        .into_iter()
        .map(|(name, value)| (name, value.to_owned()))
        .collect()
    }

    pub async fn form(&self, path: &str, pairs: &[(&str, &str)]) -> reqwest::Response {
        let mut pairs: Vec<(&str, String)> = pairs
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned()))
            .collect();
        pairs.extend(self.the_request());
        self.http
            .post(format!("{}{path}", self.address))
            .form(&pairs)
            .send()
            .await
            .unwrap()
    }

    pub async fn get(&self, who: &Account, path: &str) -> (reqwest::StatusCode, Value) {
        let response = self
            .http
            .get(format!("{}{path}", self.address))
            .bearer_auth(&who.token)
            .send()
            .await
            .unwrap();
        (
            response.status(),
            response.json().await.unwrap_or(Value::Null),
        )
    }

    pub async fn send(
        &self,
        method: reqwest::Method,
        who: &Account,
        path: &str,
        body: Value,
    ) -> (reqwest::StatusCode, Value) {
        let response = self
            .http
            .request(method, format!("{}{path}", self.address))
            .bearer_auth(&who.token)
            .json(&body)
            .send()
            .await
            .unwrap();
        (
            response.status(),
            response.json().await.unwrap_or(Value::Null),
        )
    }

    /// Signs up through the instance's pages — the form, the mailed code — then exchanges the
    /// code the flow ends in for tokens.
    pub async fn sign_up(&self, name: &str) -> Account {
        let email = format!("{name}@journey.test");
        let signed_up = self
            .form(
                "/register-and-login",
                &[
                    ("display_name", name),
                    ("email", &email),
                    ("password", PASSWORD),
                ],
            )
            .await;
        assert_eq!(signed_up.status(), 303);
        let pending = query_of(&location(&signed_up));
        let code = self.mail.code_for(&email).await;
        let verified = self
            .form(
                "/verify-email-and-login",
                &[
                    ("pending_user_id", &pending["pending_user_id"]),
                    ("pending_email", &email),
                    ("code", &code),
                ],
            )
            .await;
        assert_eq!(verified.status(), 303);
        let landed = location(&verified);
        assert!(landed.starts_with(&self.redirect_uri), "{landed}");
        let token = self.exchange(&query_of(&landed)["code"]).await;
        let mut account = Account {
            email,
            handle: String::new(),
            actor_uri: String::new(),
            token,
        };
        let (_, userinfo) = self.get(&account, "/userinfo").await;
        account.handle = userinfo["preferred_username"].as_str().unwrap().to_owned();
        account.actor_uri = userinfo["actor_uri"].as_str().unwrap().to_owned();
        account
    }

    pub async fn exchange(&self, code: &str) -> String {
        let tokens: Value = self
            .http
            .post(format!("{}/token", self.address))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("client_id", self.client_id.as_str()),
                ("code_verifier", VERIFIER),
            ])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        tokens["access_token"].as_str().unwrap().to_owned()
    }

    /// A count straight from the instance's database, for what no route shows.
    pub async fn count(&self, query: &str) -> i64 {
        let server = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://test:test@localhost:55432/test".into());
        let base = &server[..server.rfind('/').unwrap()];
        let mut connection = PgConnection::connect(&format!("{base}/{}", self.database))
            .await
            .unwrap();
        sqlx::query_scalar(query)
            .fetch_one(&mut connection)
            .await
            .unwrap()
    }

    /// Stops the application and waits for it, then drops its database.
    pub async fn stop(self) -> anyhow::Result<()> {
        self.stop.cancel();
        let stopped = self.running.await.unwrap();
        let server = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://test:test@localhost:55432/test".into());
        if let Ok(mut connection) = PgConnection::connect(&server).await {
            let drop = format!(
                r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
                self.database
            );
            let _ = connection.execute(drop.as_str()).await;
        }
        stopped
    }
}

/// Retries `check` for up to 10 s, until it answers `Some`.
pub async fn eventually<T, F, Fut>(what: &str, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    for _ in 0..100 {
        if let Some(found) = check().await {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{what}: not within 10 s");
}

/// An SMTP server on the loopback interface keeping every mail it is given, by recipient.
#[derive(Clone)]
pub struct MailSink {
    pub port: u16,
    mails: Arc<Mutex<Vec<(String, String)>>>,
}

impl MailSink {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sink = Self {
            port: listener.local_addr().unwrap().port(),
            mails: Arc::default(),
        };
        let mails = sink.mails.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(converse(socket, mails.clone()));
            }
        });
        sink
    }

    /// The confirmation code in the latest mail to `to`, once one has come.
    pub async fn code_for(&self, to: &str) -> String {
        eventually(&format!("a mail to {to}"), || async {
            let mails = self.mails.lock().unwrap();
            let (_, data) = mails.iter().rev().find(|(rcpt, _)| rcpt == to)?;
            confirmation_code(data)
        })
        .await
    }

    pub fn count_for(&self, to: &str) -> usize {
        self.mails
            .lock()
            .unwrap()
            .iter()
            .filter(|(rcpt, _)| rcpt == to)
            .count()
    }
}

/// Just enough of RFC 5321 for one client and no authentication.
async fn converse(socket: tokio::net::TcpStream, mails: Arc<Mutex<Vec<(String, String)>>>) {
    let (read, mut write) = socket.into_split();
    let mut lines = BufReader::new(read).lines();
    let _ = write.write_all(b"220 sink ESMTP\r\n").await;
    let mut recipient = String::new();
    while let Ok(Some(line)) = lines.next_line().await {
        let verb = line.to_ascii_uppercase();
        let answer: &[u8] = if verb.starts_with("EHLO") {
            b"250-sink\r\n250-8BITMIME\r\n250 SMTPUTF8\r\n"
        } else if verb.starts_with("RCPT TO:") {
            recipient = line[8..]
                .trim()
                .trim_start_matches('<')
                .split('>')
                .next()
                .unwrap_or_default()
                .to_owned();
            b"250 OK\r\n"
        } else if verb.starts_with("DATA") {
            let _ = write.write_all(b"354 go on\r\n").await;
            let mut data = String::new();
            while let Ok(Some(line)) = lines.next_line().await {
                if line == "." {
                    break;
                }
                data.push_str(&line);
                data.push('\n');
            }
            mails.lock().unwrap().push((recipient.clone(), data));
            b"250 OK\r\n"
        } else if verb.starts_with("QUIT") {
            let _ = write.write_all(b"221 bye\r\n").await;
            return;
        } else {
            b"250 OK\r\n"
        };
        let _ = write.write_all(answer).await;
    }
}

/// The code in a mail's text part, whatever its transfer encoding.
fn confirmation_code(data: &str) -> Option<String> {
    let part_start = data.find("Content-Type: text/plain")?;
    let part = &data[part_start..];
    let (headers, body) = part.split_once("\n\n")?;
    let body = body.split("\n--").next()?;
    let text = if headers.contains("Content-Transfer-Encoding: base64") {
        let joined: String = body.split_whitespace().collect();
        String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(joined)
                .ok()?,
        )
        .ok()?
    } else {
        body.replace("=\n", "")
    };
    let after = text.split("confirmation code is: ").nth(1)?;
    Some(after.chars().take_while(char::is_ascii_digit).collect())
        .filter(|code: &String| code.len() == 6)
}
