//! Outbound mail over SMTP: the confirmation codes of sign-up.

mod template;

use domain::auth::{AuthError, OtpCode, SignupMailer};
use lettre::message::header::ContentType;
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use template::{SignupOtpView, signup_otp_html, signup_otp_plaintext, signup_otp_subject};

/// Where mail goes out, and the host named in its footer.
#[derive(Debug, Clone)]
pub struct SmtpSettings {
    /// Empty when the instance has no relay.
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    /// RFC 5322 `From`, e.g. `Pīna'i <no-reply@idp.alice.com>`.
    pub from: String,
    pub tls: SmtpTls,
    pub issuer_host: String,
}

/// How the connection to the relay is secured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTls {
    /// Plain SMTP, for a local catcher such as Mailpit.
    None,
    /// Upgraded with STARTTLS, which must succeed: the submission port, 587.
    StartTls,
    /// TLS from the first byte: port 465.
    Tls,
}

/// Connects on the first send: the instance starts even when the relay is not up yet, or
/// when it has none — every send is then refused.
pub struct SmtpSignupMailer {
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    from: Mailbox,
    issuer_host: String,
}

impl SmtpSignupMailer {
    pub fn new(settings: SmtpSettings) -> anyhow::Result<Self> {
        let from = settings
            .from
            .parse::<Mailbox>()
            .map_err(|e| anyhow::anyhow!("SMTP_FROM `{}`: {e}", settings.from))?;
        let transport = if settings.host.is_empty() {
            None
        } else {
            Some(transport(&settings)?)
        };
        Ok(Self {
            transport,
            from,
            issuer_host: settings.issuer_host,
        })
    }

    /// Connects, signs in when there are credentials, and quits: whether a code could be
    /// mailed now.
    pub async fn check(&self) -> anyhow::Result<()> {
        match self.relay()?.test_connection().await {
            Ok(true) => Ok(()),
            Ok(false) => Err(anyhow::anyhow!("the relay stopped answering")),
            Err(e) => Err(anyhow::anyhow!("reach the relay: {e}")),
        }
    }

    fn relay(&self) -> anyhow::Result<&AsyncSmtpTransport<Tokio1Executor>> {
        self.transport
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no SMTP relay is configured"))
    }

    fn message(&self, to: &str, name: &str, code: &OtpCode) -> anyhow::Result<Message> {
        let to: Mailbox = to
            .parse()
            .map_err(|e| anyhow::anyhow!("a signup code's address: {e}"))?;
        let view = SignupOtpView {
            display_name: name,
            code: code.as_str(),
            issuer_host: &self.issuer_host,
        };
        Ok(Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(signup_otp_subject(&view))
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(signup_otp_plaintext(&view)),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(signup_otp_html(&view)),
                    ),
            )?)
    }
}

#[async_trait::async_trait]
impl SignupMailer for SmtpSignupMailer {
    async fn send_code(&self, to: &str, name: &str, code: &OtpCode) -> Result<(), AuthError> {
        let message = self.message(to, name, code)?;
        self.relay()?
            .send(message)
            .await
            .map_err(|e| anyhow::anyhow!("send a signup code: {e}"))?;
        Ok(())
    }
}

fn transport(settings: &SmtpSettings) -> anyhow::Result<AsyncSmtpTransport<Tokio1Executor>> {
    let builder = match settings.tls {
        SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&settings.host),
        SmtpTls::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.host)?,
        SmtpTls::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&settings.host)?,
    }
    .port(settings.port);
    let builder = if settings.username.is_empty() {
        builder
    } else {
        builder.credentials(Credentials::new(
            settings.username.clone(),
            settings.password.clone(),
        ))
    };
    Ok(builder.build())
}

#[cfg(test)]
mod tests;
