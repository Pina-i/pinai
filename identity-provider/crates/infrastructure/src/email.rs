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
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    /// RFC 5322 `From`, e.g. `Pīna'i <no-reply@idp.alice.com>`.
    pub from: String,
    pub starttls: bool,
    pub issuer_host: String,
}

/// Connects on the first send: the instance starts even when the relay is not up yet.
pub struct SmtpSignupMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    issuer_host: String,
}

impl SmtpSignupMailer {
    pub fn new(settings: SmtpSettings) -> anyhow::Result<Self> {
        let from = settings
            .from
            .parse::<Mailbox>()
            .map_err(|e| anyhow::anyhow!("SMTP_FROM `{}`: {e}", settings.from))?;
        // Mailpit and most dev relays speak plain SMTP; STARTTLS is for production relays.
        let builder = if settings.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.host)?
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&settings.host)
        }
        .port(settings.port);
        let builder = if settings.username.is_empty() {
            builder
        } else {
            builder.credentials(Credentials::new(settings.username, settings.password))
        };
        Ok(Self {
            transport: builder.build(),
            from,
            issuer_host: settings.issuer_host,
        })
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
        self.transport
            .send(message)
            .await
            .map_err(|e| anyhow::anyhow!("send a signup code: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
