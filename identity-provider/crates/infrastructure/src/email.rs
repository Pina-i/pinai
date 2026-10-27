//! Outbound mail over SMTP: the confirmation codes of sign-up, and the reset links asked for.

mod budget;
mod template;

use std::time::Duration;

use domain::auth::{AuthError, OtpCode, ResetMail, ResetMailer, SignupMailer};
use lettre::message::header::ContentType;
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use template::{
    ResetLinkView, SignupOtpView, reset_link_html, reset_link_plaintext, reset_link_subject,
    signup_otp_html, signup_otp_plaintext, signup_otp_subject,
};

pub use budget::ResetMailBudget;

/// How long a relay may take over each step of a send: a stalled one holds no request up long.
const RELAY_TIMEOUT: Duration = Duration::from_secs(15);

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
pub struct SmtpMailer {
    transport: Option<AsyncSmtpTransport<Tokio1Executor>>,
    from: Mailbox,
    issuer_host: String,
}

impl SmtpMailer {
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
        self.alternative(
            to,
            signup_otp_subject(&view),
            signup_otp_plaintext(&view),
            signup_otp_html(&view),
        )
    }

    fn reset_message(&self, mail: &ResetMail) -> anyhow::Result<Message> {
        let to: Mailbox = mail
            .to
            .parse()
            .map_err(|e| anyhow::anyhow!("a reset link's address: {e}"))?;
        let view = ResetLinkView {
            display_name: &mail.name,
            instance: &mail.instance,
            link: &mail.link,
            minutes: mail.valid_for.whole_minutes(),
            issuer_host: &self.issuer_host,
        };
        self.alternative(
            to,
            reset_link_subject(&view),
            reset_link_plaintext(&view),
            reset_link_html(&view),
        )
    }

    /// A mail in plain text and HTML, the client showing the one it can.
    fn alternative(
        &self,
        to: Mailbox,
        subject: String,
        plain: String,
        html: String,
    ) -> anyhow::Result<Message> {
        Ok(Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(plain),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html),
                    ),
            )?)
    }
}

#[async_trait::async_trait]
impl SignupMailer for SmtpMailer {
    async fn send_code(&self, to: &str, name: &str, code: &OtpCode) -> Result<(), AuthError> {
        let message = self.message(to, name, code)?;
        self.relay()?
            .send(message)
            .await
            .map_err(|e| anyhow::anyhow!("send a signup code: {}", failure(&e)))?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl ResetMailer for SmtpMailer {
    async fn send_reset_link(&self, mail: &ResetMail) -> Result<(), AuthError> {
        let message = self.reset_message(mail)?;
        self.relay()?
            .send(message)
            .await
            .map_err(|e| anyhow::anyhow!("send a reset link: {}", failure(&e)))?;
        Ok(())
    }
}

/// What went wrong with a send, without the relay's reply: it often repeats the recipient's
/// address, which a log line must never tell.
fn failure(error: &lettre::transport::smtp::Error) -> String {
    if let Some(code) = error.status() {
        let lasting = if error.is_permanent() {
            "permanently"
        } else {
            "for now"
        };
        return format!("the relay refused it {lasting} ({code})");
    }
    let kind = if error.is_timeout() {
        "the relay took too long"
    } else if error.is_tls() {
        "TLS with the relay failed"
    } else if error.is_response() {
        "the relay's answer couldn't be read"
    } else if error.is_client() {
        "the message couldn't be sent as built"
    } else {
        "the relay couldn't be reached"
    };
    kind.to_owned()
}

fn transport(settings: &SmtpSettings) -> anyhow::Result<AsyncSmtpTransport<Tokio1Executor>> {
    let builder = match settings.tls {
        SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&settings.host),
        SmtpTls::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.host)?,
        SmtpTls::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&settings.host)?,
    }
    .port(settings.port)
    .timeout(Some(RELAY_TIMEOUT));
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
