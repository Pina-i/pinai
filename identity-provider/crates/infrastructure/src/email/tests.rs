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

fn mailer() -> SmtpSignupMailer {
    SmtpSignupMailer::new(settings()).unwrap()
}

fn mailer_on(port: u16) -> SmtpSignupMailer {
    SmtpSignupMailer::new(SmtpSettings {
        host: "127.0.0.1".into(),
        port,
        ..settings()
    })
    .unwrap()
}

fn code() -> OtpCode {
    OtpCode::parse("123456").unwrap()
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

#[test]
fn a_mail_to_something_else_than_an_address_is_refused() {
    assert!(mailer().message("not-an-email", "Alice", &code()).is_err());
}

#[test]
fn every_tls_mode_builds_for_a_relay_host() {
    for tls in [SmtpTls::None, SmtpTls::StartTls, SmtpTls::Tls] {
        let built = SmtpSignupMailer::new(SmtpSettings {
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
        let mailer = SmtpSignupMailer::new(SmtpSettings {
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
