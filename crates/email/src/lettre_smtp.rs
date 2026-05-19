//! SMTP transport built on `lettre`. Single instance lives in `AppState`.

use async_trait::async_trait;
use lettre::{
    message::{header::ContentType, Mailbox, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use tracing::instrument;

use crate::{
    template::{signup_otp_html, signup_otp_plaintext, signup_otp_subject, SignupOtpView},
    EmailError, EmailSender,
};

/// Resolved SMTP settings + per-instance branding (the IdP host shown in the
/// "if you didn't start signup at X" footer).
#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    /// RFC 5322 `From`. E.g. `Pīna'i <no-reply@idp.alice.com>`.
    pub from: String,
    pub starttls: bool,
    /// Bare host used in plaintext template footers.
    pub issuer_host: String,
}

pub struct LettreSmtpSender {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    issuer_host: String,
}

impl LettreSmtpSender {
    pub fn from_config(cfg: EmailConfig) -> Result<Self, EmailError> {
        let from = cfg
            .from
            .parse::<Mailbox>()
            .map_err(|e| EmailError::Address(format!("SMTP_FROM `{}`: {e}", cfg.from)))?;

        // Mailpit + most dev relays speak plaintext SMTP on 1025. STARTTLS is
        // opt-in via env so production can flip it without code changes.
        let builder = if cfg.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
                .map_err(|e| EmailError::Smtp(e.to_string()))?
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host)
        }
        .port(cfg.port);

        let builder = if !cfg.username.is_empty() {
            builder.credentials(Credentials::new(cfg.username.clone(), cfg.password.clone()))
        } else {
            builder
        };

        Ok(Self {
            transport: builder.build(),
            from,
            issuer_host: cfg.issuer_host,
        })
    }

    fn build_signup_message(
        &self,
        to: &str,
        display_name: &str,
        code: &str,
    ) -> Result<Message, EmailError> {
        let to_mailbox: Mailbox = to
            .parse()
            .map_err(|e: lettre::address::AddressError| EmailError::Address(e.to_string()))?;

        let view = SignupOtpView {
            display_name,
            code,
            issuer_host: &self.issuer_host,
        };

        Message::builder()
            .from(self.from.clone())
            .to(to_mailbox)
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
            )
            .map_err(|e| EmailError::Template(e.to_string()))
    }
}

#[async_trait]
impl EmailSender for LettreSmtpSender {
    #[instrument(skip_all, fields(to = %to))]
    async fn send_signup_otp(
        &self,
        to: &str,
        display_name: &str,
        code: &str,
    ) -> Result<(), EmailError> {
        let message = self.build_signup_message(to, display_name, code)?;
        self.transport
            .send(message)
            .await
            .map_err(|e| EmailError::Smtp(e.to_string()))?;
        tracing::info!("signup OTP email dispatched");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> EmailConfig {
        EmailConfig {
            host: "mailpit".into(),
            port: 1025,
            username: String::new(),
            password: String::new(),
            from: "Pīna'i <no-reply@localhost>".into(),
            starttls: false,
            issuer_host: "localhost:8080".into(),
        }
    }

    #[test]
    fn build_message_has_expected_subject_and_body() {
        let sender = LettreSmtpSender::from_config(cfg()).unwrap();
        let msg = sender
            .build_signup_message("alice@example.com", "Alice", "123456")
            .unwrap();
        let formatted = std::str::from_utf8(&msg.formatted()).unwrap().to_string();
        let headers = formatted
            .split("\r\n\r\n")
            .next()
            .expect("message has headers");
        // Subject is RFC2047-encoded by lettre because of the non-ASCII "ī",
        // so we just check for stable substrings. The display name lives in
        // the rendered body, not the To header — the To header carries the
        // email address only.
        assert!(headers.contains("Confirm"));
        assert!(headers.contains("123456"));
        assert!(headers.contains("alice@example.com"));
        assert!(formatted.contains("123456"));
        assert!(formatted.contains("Alice"));
    }

    #[test]
    fn rejects_invalid_to_address() {
        let sender = LettreSmtpSender::from_config(cfg()).unwrap();
        let err = sender
            .build_signup_message("not-an-email", "Alice", "123456")
            .unwrap_err();
        assert!(matches!(err, EmailError::Address(_)));
    }
}
