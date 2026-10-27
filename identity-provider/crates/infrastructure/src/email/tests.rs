use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

fn settings() -> SmtpSettings {
    SmtpSettings {
        host: "mailpit".into(),
        port: 1025,
        username: String::new(),
        password: String::new(),
        from: "Pīna'i <no-reply@localhost>".into(),
        tls: SmtpTls::None,
        issuer_host: "localhost:8080".into(),
    }
}

fn mailer() -> SmtpMailer {
    SmtpMailer::new(settings()).unwrap()
}

fn mailer_on(port: u16) -> SmtpMailer {
    SmtpMailer::new(SmtpSettings {
        host: "127.0.0.1".into(),
        port,
        ..settings()
    })
    .unwrap()
}

fn code() -> OtpCode {
    OtpCode::parse("123456").unwrap()
}

/// Answers one session the way a relay that refuses the recipient does, repeating the address in
/// its reply.
async fn refusing_relay() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (read, mut write) = socket.into_split();
        let mut lines = BufReader::new(read).lines();
        write.write_all(b"220 relay ESMTP\r\n").await.unwrap();
        while let Ok(Some(line)) = lines.next_line().await {
            let answer = if line.starts_with("RCPT") {
                let to = line.split_once(':').map_or("", |(_, to)| to.trim());
                format!("550 5.1.1 {to}: Recipient address rejected\r\n")
            } else if line.starts_with("QUIT") {
                "221 bye\r\n".to_owned()
            } else {
                "250 OK\r\n".to_owned()
            };
            if write.write_all(answer.as_bytes()).await.is_err() || line.starts_with("QUIT") {
                break;
            }
        }
    });
    port
}

/// Answers one session the way a relay that takes us would: 250 to everything until QUIT.
async fn answering_relay() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (read, mut write) = socket.into_split();
        let mut lines = BufReader::new(read).lines();
        write.write_all(b"220 relay ESMTP\r\n").await.unwrap();
        while let Ok(Some(line)) = lines.next_line().await {
            let quit = line.starts_with("QUIT");
            let answer: &[u8] = if quit { b"221 bye\r\n" } else { b"250 OK\r\n" };
            write.write_all(answer).await.unwrap();
            if quit {
                break;
            }
        }
    });
    port
}

#[test]
fn a_signup_mail_carries_the_code_in_its_subject_and_body() {
    let message = mailer()
        .message("alice@example.com", "Alice", &code())
        .unwrap();

    let formatted = String::from_utf8(message.formatted()).unwrap();
    let headers = formatted.split("\r\n\r\n").next().unwrap();
    // The subject is RFC 2047-encoded for its "ī": only stable parts are checked.
    assert!(headers.contains("Confirm"), "{headers}");
    assert!(headers.contains("123456"), "{headers}");
    assert!(headers.contains("alice@example.com"), "{headers}");
    assert!(formatted.contains("Alice"));
}

fn reset_mail() -> ResetMail {
    ResetMail {
        to: "alice@example.com".to_owned(),
        name: "Alice <3".to_owned(),
        instance: "Aotearoa".to_owned(),
        link: "http://localhost:8080/r/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        valid_for: time::Duration::minutes(30),
    }
}

/// The text of the message's `content_type` part, its transfer encoding undone.
fn part(message: &Message, content_type: &str) -> String {
    use base64::Engine as _;
    let formatted = String::from_utf8(message.formatted()).unwrap();
    let start = formatted
        .find(&format!("Content-Type: {content_type}"))
        .unwrap_or_else(|| panic!("{content_type}: {formatted}"));
    let (headers, body) = formatted[start..].split_once("\r\n\r\n").unwrap();
    let body = body.split("\r\n--").next().unwrap();
    if headers.contains("Content-Transfer-Encoding: base64") {
        let joined: String = body.split_whitespace().collect();
        String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(joined)
                .unwrap(),
        )
        .unwrap()
    } else {
        body.replace("=\r\n", "").replace("=3D", "=")
    }
}

#[test]
fn a_reset_mail_names_the_instance_and_carries_the_link_working_once_for_thirty_minutes() {
    let message = mailer().reset_message(&reset_mail()).unwrap();

    let formatted = String::from_utf8(message.formatted()).unwrap();
    let headers = formatted.split("\r\n\r\n").next().unwrap();
    assert!(
        headers.contains("Subject: Reset your password on Aotearoa"),
        "{headers}"
    );
    assert!(headers.contains("To: alice@example.com"), "{headers}");
    let plain = part(&message, "text/plain");
    let html = part(&message, "text/html");
    for text in [&plain, &html] {
        assert!(text.contains(&reset_mail().link), "{text}");
        assert!(text.contains("It works once, for 30 minutes."), "{text}");
        assert!(
            text.contains(
                "If you didn't ask for it, ignore this email: your password stays as it is."
            ),
            "{text}"
        );
    }
    assert!(plain.contains("Hi Alice <3,"), "{plain}");
    assert!(html.contains("Hi Alice &lt;3,"), "{html}");
}

#[test]
fn a_mail_to_something_else_than_an_address_is_refused() {
    assert!(mailer().message("not-an-email", "Alice", &code()).is_err());
    let elsewhere = ResetMail {
        to: "not-an-email".to_owned(),
        ..reset_mail()
    };
    assert!(mailer().reset_message(&elsewhere).is_err());
}

#[test]
fn every_tls_mode_builds_for_a_relay_host() {
    for tls in [SmtpTls::None, SmtpTls::StartTls, SmtpTls::Tls] {
        let built = SmtpMailer::new(SmtpSettings {
            host: "smtp.example.com".into(),
            port: 587,
            tls,
            ..settings()
        });
        assert!(built.is_ok(), "{tls:?}");
    }
}

#[tokio::test]
async fn without_a_relay_the_mailer_builds_and_refuses_every_send() {
    for tls in [SmtpTls::None, SmtpTls::StartTls, SmtpTls::Tls] {
        let mailer = SmtpMailer::new(SmtpSettings {
            host: String::new(),
            tls,
            ..settings()
        })
        .unwrap_or_else(|e| panic!("{tls:?}: the instance must start without a relay: {e:#}"));

        assert!(mailer.check().await.is_err(), "{tls:?}");
        assert!(
            mailer
                .send_code("alice@example.com", "Alice", &code())
                .await
                .is_err(),
            "{tls:?}"
        );
        assert!(
            mailer.send_reset_link(&reset_mail()).await.is_err(),
            "{tls:?}"
        );
    }
}

#[tokio::test]
async fn the_check_passes_when_the_relay_answers() {
    let port = answering_relay().await;

    mailer_on(port).check().await.unwrap();
}

#[tokio::test]
async fn the_check_fails_when_nothing_listens() {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };

    assert!(mailer_on(port).check().await.is_err());
}

#[tokio::test]
async fn a_refused_send_never_tells_the_recipients_address() {
    let mailer = mailer_on(refusing_relay().await);
    let reset = mailer
        .send_reset_link(&reset_mail())
        .await
        .expect_err("refused");
    let mailer = mailer_on(refusing_relay().await);
    let code = mailer
        .send_code("alice@example.com", "Alice", &code())
        .await
        .expect_err("refused");

    for refused in [reset, code] {
        for told in [format!("{refused}"), format!("{refused:?}")] {
            assert!(!told.contains("alice@example.com"), "{told}");
            assert!(
                told.contains("the relay refused it permanently (550)"),
                "{told}"
            );
        }
    }
}
