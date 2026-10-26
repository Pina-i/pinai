use super::*;

/// A production config; each test changes only the field it is about.
fn config() -> Config {
    Config {
        database_url: "postgres://localhost/idp".into(),
        domain: "idp.alice.com".into(),
        environment: Environment::Production,
        jwt_private_key_path: PathBuf::from("./keys/ed25519.pem"),
        jwt_key_id: "key-2026-01".into(),
        port: 8080,
        session_secret: "x".repeat(64),
        instance_name: None,
        instance_description: None,
        redis_url: "redis://127.0.0.1:6379".into(),
        storage_endpoint: None,
        storage_access_key: None,
        storage_secret_key: None,
        storage_bucket_avatars: "avatars".into(),
        storage_bucket_attachments: "attachments".into(),
        storage_public_url: None,
        attachment_max_files_per_message: 4,
        attachment_max_byte_size: 10 * 1024 * 1024,
        attachment_url_ttl: Duration::from_secs(300),
        attachment_orphan_ttl: Duration::from_secs(3600),
        attachment_blocked_extensions: vec!["exe".into()],
        attachment_blocked_mimes: vec!["application/x-msdownload".into()],
        smtp_host: "mailpit".into(),
        smtp_port: 1025,
        smtp_username: String::new(),
        smtp_password: String::new(),
        smtp_from: "no-reply@alice.com".into(),
        smtp_tls: SmtpTls::StartTls,
        email_otp_pepper: vec![0u8; 32],
        e2ee_keypackage_cap_per_device: 100,
        e2ee_keypackage_refill_threshold: 20,
        e2ee_keypackage_lifetime: Duration::from_secs(90 * 24 * 3600),
        admin_email: None,
        admin_password: None,
    }
}

// ─── Scheme ──────────────────────────────────────────────────────────────────

#[test]
fn production_speaks_https() {
    assert_eq!(config().scheme(), "https");
}

#[test]
fn development_speaks_http() {
    let cfg = Config {
        environment: Environment::Development,
        ..config()
    };
    assert_eq!(cfg.scheme(), "http");
}

// ─── Issuer ──────────────────────────────────────────────────────────────────

#[test]
fn the_issuer_is_the_domain_under_the_environments_scheme() {
    assert_eq!(config().issuer(), "https://idp.alice.com");
}

#[test]
fn a_development_issuer_keeps_the_port_in_the_domain() {
    let cfg = Config {
        environment: Environment::Development,
        domain: "localhost:8080".into(),
        ..config()
    };
    assert_eq!(cfg.issuer(), "http://localhost:8080");
}

/// `UrlPolicy::from_issuer` decides whether peer URLs must be https and whether
/// private address space is reachable, purely from this string. A production
/// issuer that came back as http would silently disable the SSRF screen.
#[test]
fn a_production_issuer_is_recognisable_as_https() {
    assert!(config().issuer().starts_with("https"));
}

#[test]
fn a_development_issuer_is_not_mistaken_for_production() {
    let cfg = Config {
        environment: Environment::Development,
        ..config()
    };
    assert!(!cfg.issuer().starts_with("https"));
}

// ─── Cookies ─────────────────────────────────────────────────────────────────

#[test]
fn production_marks_cookies_secure() {
    assert!(config().secure_cookies());
}

/// Development runs over plain HTTP, where a Secure cookie would never be sent.
#[test]
fn development_does_not_mark_cookies_secure() {
    let cfg = Config {
        environment: Environment::Development,
        ..config()
    };
    assert!(!cfg.secure_cookies());
}

// ─── Environment ─────────────────────────────────────────────────────────────

#[test]
fn only_development_reports_itself_as_dev() {
    assert!(Environment::Development.is_dev());
    assert!(!Environment::Production.is_dev());
}

// ─── Object storage ──────────────────────────────────────────────────────────

#[test]
fn storage_is_enabled_only_when_fully_configured() {
    let cfg = Config {
        storage_endpoint: Some("http://localhost:9000".into()),
        storage_access_key: Some("key".into()),
        storage_secret_key: Some("secret".into()),
        ..config()
    };
    assert!(cfg.storage_enabled());
}

#[test]
fn storage_is_disabled_when_nothing_is_configured() {
    assert!(!config().storage_enabled());
}

/// A half-configured bucket is the dangerous case: the avatar and attachment
/// endpoints would accept uploads and then fail at the storage call.
#[test]
fn storage_is_disabled_when_any_credential_is_missing() {
    let full = (
        Some("http://localhost:9000".to_string()),
        Some("key".to_string()),
        Some("secret".to_string()),
    );

    for (endpoint, access, secret) in [
        (None, full.1.clone(), full.2.clone()),
        (full.0.clone(), None, full.2.clone()),
        (full.0.clone(), full.1.clone(), None),
    ] {
        let cfg = Config {
            storage_endpoint: endpoint,
            storage_access_key: access,
            storage_secret_key: secret,
            ..config()
        };
        assert!(
            !cfg.storage_enabled(),
            "a partial storage configuration must not count as enabled"
        );
    }
}

// ─── Session secret ──────────────────────────────────────────────────────────

const REAL_SECRET: &str = "4f1c9a7e2b6d8035e1a4c7f9b2d6e8a01c3f5b7d9e2a4c6f8b0d2e4a6c8f0b2d";

#[test]
fn production_accepts_a_generated_session_secret() {
    let secret = session_secret(Environment::Production, Some(REAL_SECRET.into())).unwrap();
    assert_eq!(secret, REAL_SECRET);
}

#[test]
fn production_refuses_to_start_without_a_session_secret() {
    assert!(matches!(
        session_secret(Environment::Production, None),
        Err(ConfigError::MissingVar("SESSION_SECRET"))
    ));
}

/// `SESSION_SECRET=` left blank would otherwise reach the server's 64-byte
/// stretch and panic on a remainder by zero.
#[test]
fn an_empty_session_secret_counts_as_unset() {
    assert!(matches!(
        session_secret(Environment::Production, Some(String::new())),
        Err(ConfigError::MissingVar("SESSION_SECRET"))
    ));
    assert_eq!(
        session_secret(Environment::Development, Some(String::new())).unwrap(),
        DEV_SESSION_SECRET
    );
}

/// Anyone can read these values in the repository and forge session cookies
/// with them.
#[test]
fn production_refuses_a_published_placeholder() {
    for placeholder in [
        DEV_SESSION_SECRET,
        "change-me-to-a-random-64-char-secret-in-production-000000000000",
    ] {
        assert!(
            matches!(
                session_secret(Environment::Production, Some(placeholder.into())),
                Err(ConfigError::InvalidValue("SESSION_SECRET", _))
            ),
            "production accepted the placeholder {placeholder:?}"
        );
    }
}

#[test]
fn production_refuses_a_short_session_secret() {
    assert!(matches!(
        session_secret(Environment::Production, Some("x".repeat(31))),
        Err(ConfigError::InvalidValue("SESSION_SECRET", _))
    ));
}

#[test]
fn development_falls_back_to_the_dev_secret() {
    assert_eq!(
        session_secret(Environment::Development, None).unwrap(),
        DEV_SESSION_SECRET
    );
}

#[test]
fn development_accepts_any_session_secret() {
    assert_eq!(
        session_secret(Environment::Development, Some("alice-secret".into())).unwrap(),
        "alice-secret"
    );
}

// ─── The first admin ─────────────────────────────────────────────────────────

#[test]
fn an_empty_admin_variable_counts_as_unset() {
    assert_eq!(unless_empty(None), None);
    assert_eq!(unless_empty(Some(String::new())), None);
    assert_eq!(
        unless_empty(Some("root@idp.alice.com".into())).as_deref(),
        Some("root@idp.alice.com")
    );
}

// ─── SMTP TLS ────────────────────────────────────────────────────────────────

#[test]
fn production_mails_over_starttls_unless_told_otherwise() {
    for raw in [None, Some(String::new())] {
        assert_eq!(
            smtp_tls(Environment::Production, raw).unwrap(),
            SmtpTls::StartTls
        );
    }
}

#[test]
fn development_mails_in_plain_smtp_unless_told_otherwise() {
    assert_eq!(
        smtp_tls(Environment::Development, None).unwrap(),
        SmtpTls::None
    );
}

#[test]
fn each_tls_mode_is_read_by_its_name_in_any_case() {
    for (raw, mode) in [
        ("none", SmtpTls::None),
        ("starttls", SmtpTls::StartTls),
        ("tls", SmtpTls::Tls),
        ("TLS", SmtpTls::Tls),
    ] {
        assert_eq!(
            smtp_tls(Environment::Production, Some(raw.into())).unwrap(),
            mode,
            "{raw}"
        );
    }
}

#[test]
fn an_unset_or_empty_smtp_port_is_mailpits() {
    for raw in [None, Some(String::new())] {
        assert_eq!(smtp_port(raw).unwrap(), 1025);
    }
}

#[test]
fn an_smtp_port_is_read_and_a_bad_one_refused() {
    assert_eq!(smtp_port(Some("465".into())).unwrap(), 465);
    assert!(matches!(
        smtp_port(Some("submission".into())),
        Err(ConfigError::InvalidPort(_))
    ));
}

#[test]
fn an_unknown_tls_mode_is_refused() {
    assert!(matches!(
        smtp_tls(Environment::Production, Some("ssl".into())),
        Err(ConfigError::InvalidValue("SMTP_TLS", _))
    ));
}

// ─── Environment reading ─────────────────────────────────────────────────────

/// A `.env` saved with CRLF endings leaves a trailing `\r` on every value a
/// shell sources, while Docker Compose strips it. Left in, a `\r` in `DOMAIN`
/// reaches `issuer()` and is written into `actor_uri`, and remote instances then
/// resolve a URL the origin's own actor endpoint does not recognise.
#[test]
fn a_value_from_a_crlf_env_file_is_read_without_its_carriage_return() {
    let key = "PINAI_TEST_CRLF_DOMAIN";
    // SAFETY: no other test reads or writes this variable.
    unsafe { std::env::set_var(key, "localhost:8081\r") };

    assert_eq!(env_var(key).unwrap(), "localhost:8081");

    unsafe { std::env::remove_var(key) };
}

#[test]
fn surrounding_whitespace_is_stripped_from_env_values() {
    let key = "PINAI_TEST_PADDED_VALUE";
    // SAFETY: no other test reads or writes this variable.
    unsafe { std::env::set_var(key, "  idp.alice.com \t\n") };

    assert_eq!(env_var(key).unwrap(), "idp.alice.com");

    unsafe { std::env::remove_var(key) };
}

#[test]
fn a_missing_variable_is_still_reported_missing() {
    assert!(env_var("PINAI_TEST_DEFINITELY_UNSET").is_err());
}

/// The whole point of trimming: a domain read from a CRLF file must still build
/// an issuer a peer can resolve.
#[test]
fn an_issuer_built_from_a_trimmed_domain_has_no_control_characters() {
    let key = "PINAI_TEST_CRLF_ISSUER_DOMAIN";
    // SAFETY: no other test reads or writes this variable.
    unsafe { std::env::set_var(key, "idp.bob.com\r") };

    let cfg = Config {
        domain: env_var(key).unwrap(),
        ..config()
    };
    assert_eq!(cfg.issuer(), "https://idp.bob.com");
    assert!(!cfg.issuer().chars().any(|c| c.is_control()));

    unsafe { std::env::remove_var(key) };
}
