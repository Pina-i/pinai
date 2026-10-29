use super::*;

/// A production config; each test changes only the field it is about.
fn config() -> Config {
    Config {
        database_url: "postgres://localhost/idp".into(),
        database_password: None,
        domain: "idp.alice.com".into(),
        environment: Environment::Production,
        jwt_private_key_path: PathBuf::from("./keys/ed25519.pem"),
        jwt_key_id: Some("key-2026-01".into()),
        port: 8080,
        session_secret: "x".repeat(64),
        instance_name: None,
        instance_description: None,
        source_url: SourceUrl::parse(PINAI_SOURCE_URL).unwrap(),
        redis_url: "redis://127.0.0.1:6379".into(),
        storage_endpoint: None,
        storage_access_key: None,
        storage_secret_key: None,
        storage_bucket_avatars: "avatars".into(),
        storage_bucket_attachments: "attachments".into(),
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
        registrations: Registrations::Invite,
        e2ee_keypackage_cap_per_device: 100,
        e2ee_keypackage_refill_threshold: 20,
        e2ee_keypackage_lifetime: Duration::from_secs(90 * 24 * 3600),
        admin_email: None,
        admin_password: None,
        web_app: None,
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

// ─── Who can join ────────────────────────────────────────────────────────────

#[test]
fn an_instance_is_invite_only_unless_told_otherwise() {
    for raw in [None, Some(String::new())] {
        assert_eq!(registrations(raw).unwrap(), Registrations::Invite);
    }
}

#[test]
fn each_registrations_setting_is_read_by_its_name_in_any_case() {
    for (raw, setting) in [
        ("open", Registrations::Open),
        ("invite", Registrations::Invite),
        ("Open", Registrations::Open),
        ("INVITE", Registrations::Invite),
    ] {
        assert_eq!(registrations(Some(raw.into())).unwrap(), setting, "{raw}");
    }
}

#[test]
fn an_unknown_registrations_setting_is_refused_naming_the_two() {
    let refused = registrations(Some("closed".into())).unwrap_err();

    assert_eq!(
        refused.to_string(),
        "Invalid REGISTRATIONS: 'closed' (expected open or invite)"
    );
}

#[test]
fn an_unset_or_empty_smtp_host_means_no_relay() {
    for raw in [None, Some(String::new())] {
        assert_eq!(smtp_host(raw), "");
    }
    assert_eq!(
        smtp_host(Some("smtp.example.com".into())),
        "smtp.example.com"
    );
}

#[test]
fn an_open_instance_with_smtp_host_unset_or_empty_is_refused() {
    for raw in [None, Some(String::new())] {
        let refused = require_relay(Registrations::Open, &smtp_host(raw)).unwrap_err();

        assert!(matches!(refused, ConfigError::OpenWithoutRelay));
        assert_eq!(
            refused.to_string(),
            "REGISTRATIONS=open needs an SMTP relay: set SMTP_HOST, or REGISTRATIONS=invite"
        );
    }
}

#[test]
fn an_invite_only_instance_needs_no_relay_and_an_open_one_with_a_relay_starts() {
    assert!(require_relay(Registrations::Invite, &smtp_host(None)).is_ok());
    assert!(require_relay(Registrations::Invite, "").is_ok());
    assert!(require_relay(Registrations::Invite, "smtp.example.com").is_ok());
    assert!(require_relay(Registrations::Open, "smtp.example.com").is_ok());
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

// ─── The official web app ────────────────────────────────────────────────────

#[test]
fn development_lands_invited_people_in_its_own_web_client() {
    for raw in [None, Some(String::new())] {
        assert_eq!(
            web_app(Environment::Development, raw).unwrap(),
            Some(WebApp::parse("http://localhost:5173").unwrap())
        );
    }
}

#[test]
fn production_has_no_web_app_but_the_official_one() {
    let official = OFFICIAL_WEB_APP_ORIGIN.map(|origin| WebApp::parse(origin).unwrap());

    assert_eq!(web_app(Environment::Production, None).unwrap(), official);
    assert_ne!(
        web_app(Environment::Production, None).unwrap(),
        Some(WebApp::parse(DEV_WEB_APP_ORIGIN).unwrap()),
        "never the development client"
    );
}

#[test]
fn a_web_app_origin_given_stands_in_for_the_official_one() {
    for environment in [Environment::Development, Environment::Production] {
        assert_eq!(
            web_app(environment, Some("https://App.Example.org/".into())).unwrap(),
            Some(WebApp::parse("https://app.example.org").unwrap())
        );
    }
}

#[test]
fn a_web_app_origin_that_is_not_one_is_refused() {
    for raw in [
        "app.example.org",
        "https://app.example.org/app",
        "ftp://x.test",
    ] {
        assert!(
            matches!(
                web_app(Environment::Development, Some(raw.into())),
                Err(ConfigError::InvalidValue("WEB_APP_ORIGIN", _))
            ),
            "{raw}"
        );
    }
}

// ─── Where the source is ─────────────────────────────────────────────────────

#[test]
fn an_unset_or_empty_source_url_is_pinais_own_repository() {
    for raw in [None, Some(String::new())] {
        assert_eq!(
            source_url(raw).unwrap().as_str(),
            "https://github.com/Pina-i/pinai"
        );
    }
}

#[test]
fn a_source_url_given_stands_in_for_pinais_own() {
    assert_eq!(
        source_url(Some("https://codeberg.org/aotearoa/pinai".into()))
            .unwrap()
            .as_str(),
        "https://codeberg.org/aotearoa/pinai"
    );
}

#[test]
fn a_source_url_that_is_no_http_url_is_refused_quoting_it() {
    for raw in ["codeberg.org/aotearoa/pinai", "ftp://git.example.org/pinai"] {
        let refused = source_url(Some(raw.into())).unwrap_err();

        assert!(
            matches!(refused, ConfigError::InvalidValue("SOURCE_URL", _)),
            "{raw}"
        );
        assert!(refused.to_string().contains(raw), "{refused}");
    }
}

// ─── SMTP TLS ────────────────────────────────────────────────────────────────

#[test]
fn production_mails_over_starttls_unless_told_otherwise() {
    for raw in [None, Some(String::new())] {
        for port in [587, 25, 2525] {
            assert_eq!(
                smtp_tls(Environment::Production, port, raw.clone()).unwrap(),
                SmtpTls::StartTls,
                "{port}"
            );
        }
    }
}

/// Port 465 is SMTP submission over TLS from the first byte: STARTTLS there never connects.
#[test]
fn production_mails_over_tls_on_port_465_unless_told_otherwise() {
    for raw in [None, Some(String::new())] {
        assert_eq!(
            smtp_tls(Environment::Production, 465, raw).unwrap(),
            SmtpTls::Tls
        );
    }
    assert_eq!(
        smtp_tls(Environment::Production, 465, Some("starttls".into())).unwrap(),
        SmtpTls::StartTls
    );
}

#[test]
fn development_mails_in_plain_smtp_unless_told_otherwise() {
    for port in [1025, 465] {
        assert_eq!(
            smtp_tls(Environment::Development, port, None).unwrap(),
            SmtpTls::None
        );
    }
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
            smtp_tls(Environment::Production, 587, Some(raw.into())).unwrap(),
            mode,
            "{raw}"
        );
    }
}

#[test]
fn an_unset_or_empty_smtp_port_is_submission_in_production_and_mailpits_in_development() {
    for raw in [None, Some(String::new())] {
        assert_eq!(
            smtp_port(Environment::Production, raw.clone()).unwrap(),
            587
        );
        assert_eq!(smtp_port(Environment::Development, raw).unwrap(), 1025);
    }
}

#[test]
fn an_smtp_port_is_read_and_a_bad_one_refused() {
    for environment in [Environment::Production, Environment::Development] {
        assert_eq!(smtp_port(environment, Some("465".into())).unwrap(), 465);
        assert!(matches!(
            smtp_port(environment, Some("submission".into())),
            Err(ConfigError::InvalidPort(_))
        ));
    }
}

#[test]
fn an_unset_or_empty_smtp_from_is_no_reply_at_the_instances_host() {
    for raw in [None, Some(String::new())] {
        assert_eq!(
            smtp_from(raw.clone(), "idp.alice.com"),
            "Pīna'i <no-reply@idp.alice.com>"
        );
        assert_eq!(
            smtp_from(raw, "localhost:8088"),
            "Pīna'i <no-reply@localhost>"
        );
    }
    assert_eq!(
        smtp_from(
            Some("Aotearoa <no-reply@idp.alice.com>".into()),
            "idp.bob.com"
        ),
        "Aotearoa <no-reply@idp.alice.com>"
    );
}

#[test]
fn an_unknown_tls_mode_is_refused() {
    assert!(matches!(
        smtp_tls(Environment::Production, 587, Some("ssl".into())),
        Err(ConfigError::InvalidValue("SMTP_TLS", _))
    ));
}

// ─── A value or a file holding it ────────────────────────────────────────────

const SECRET_FILE: &str = "/run/secrets/session_secret";

fn no_file(path: &Path) -> std::io::Result<Vec<u8>> {
    panic!("no file should be read, yet {} was", path.display())
}

fn holding(content: &'static str) -> impl FnOnce(&Path) -> std::io::Result<Vec<u8>> {
    move |path| {
        assert_eq!(path, Path::new(SECRET_FILE));
        Ok(content.as_bytes().to_vec())
    }
}

/// A `.env` saved with CRLF endings leaves a `\r` on every value a shell sources, while Docker
/// Compose strips it: kept, a `\r` in `DOMAIN` would be written into every `actor_uri`.
#[test]
fn a_value_given_is_read_trimmed_and_no_file_is_opened() {
    for raw in ["localhost:8081\r", "  idp.alice.com \t\n"] {
        let read = value_or_file("DOMAIN", Some(raw.into()), None, no_file).unwrap();
        assert_eq!(read.as_deref(), Some(raw.trim()), "{raw:?}");
    }
}

#[test]
fn an_issuer_built_from_a_trimmed_domain_has_no_control_characters() {
    let domain = value_or_file("DOMAIN", Some("idp.bob.com\r".into()), None, no_file)
        .unwrap()
        .unwrap();
    let cfg = Config { domain, ..config() };

    assert_eq!(cfg.issuer(), "https://idp.bob.com");
    assert!(!cfg.issuer().chars().any(|c| c.is_control()));
}

#[test]
fn an_unset_value_without_a_file_is_unset_and_an_empty_one_empty() {
    assert_eq!(
        value_or_file("SMTP_FROM", None, None, no_file).unwrap(),
        None
    );
    assert_eq!(
        value_or_file("SMTP_FROM", Some(String::new()), None, no_file).unwrap(),
        Some(String::new())
    );
}

#[test]
fn a_required_variable_unset_or_left_empty_is_missing() {
    for raw in [None, Some(String::new())] {
        assert!(
            matches!(
                required("DOMAIN", raw.clone()),
                Err(ConfigError::MissingVar("DOMAIN"))
            ),
            "{raw:?}"
        );
    }
    let blank = value_or_file("DOMAIN", Some("  \r".into()), None, no_file).unwrap();
    assert!(matches!(
        required("DOMAIN", blank),
        Err(ConfigError::MissingVar("DOMAIN"))
    ));
    assert_eq!(
        required("DOMAIN", Some("idp.alice.com".into())).unwrap(),
        "idp.alice.com"
    );
}

#[test]
fn without_a_value_the_file_named_by_its_file_twin_is_read_trimmed() {
    for value in [None, Some(String::new()), Some(" \r".into())] {
        assert_eq!(
            value_or_file(
                "SESSION_SECRET",
                value.clone(),
                Some(SECRET_FILE.into()),
                holding("4f1c9a7e2b6d\n")
            )
            .unwrap(),
            Some("4f1c9a7e2b6d".into()),
            "{value:?}"
        );
    }
}

#[test]
fn a_value_and_a_file_both_given_are_refused_naming_both() {
    let refused = value_or_file(
        "SESSION_SECRET",
        Some(REAL_SECRET.into()),
        Some(SECRET_FILE.into()),
        no_file,
    )
    .unwrap_err();

    assert!(matches!(
        refused,
        ConfigError::ValueAndFile("SESSION_SECRET")
    ));
    assert_eq!(
        refused.to_string(),
        "SESSION_SECRET and SESSION_SECRET_FILE are both set: keep one"
    );
    assert!(!refused.to_string().contains(REAL_SECRET));
}

#[test]
fn a_file_that_cannot_be_read_is_refused_naming_the_variable_and_the_path() {
    let refused = value_or_file("SESSION_SECRET", None, Some(SECRET_FILE.into()), |_| {
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    })
    .unwrap_err();

    assert!(matches!(
        &refused,
        ConfigError::UnreadableFile { var: "SESSION_SECRET", path, .. } if path == Path::new(SECRET_FILE)
    ));
    assert!(
        refused
            .to_string()
            .starts_with("SESSION_SECRET_FILE: cannot read /run/secrets/session_secret: "),
        "{refused}"
    );
}

/// Whoever set `<VAR>_FILE` meant a value; read as unset, an empty file would quietly fall back.
#[test]
fn a_file_empty_once_trimmed_is_refused_naming_it() {
    for content in ["", " \n", "\r\n"] {
        let refused = value_or_file(
            "SESSION_SECRET",
            None,
            Some(SECRET_FILE.into()),
            holding(content),
        )
        .unwrap_err();

        assert!(
            matches!(
                &refused,
                ConfigError::EmptyFile { var: "SESSION_SECRET", path } if path == Path::new(SECRET_FILE)
            ),
            "{content:?}"
        );
        assert_eq!(
            refused.to_string(),
            "SESSION_SECRET_FILE names /run/secrets/session_secret, which is empty"
        );
    }
}

#[test]
fn a_file_larger_than_64_kib_is_refused_and_one_at_the_limit_read() {
    let at_limit = "a".repeat(MAX_FILE_LEN as usize);
    let read = value_or_file("SESSION_SECRET", None, Some(SECRET_FILE.into()), |_| {
        Ok(at_limit.clone().into_bytes())
    })
    .unwrap();
    assert_eq!(read.map(|v| v.len()), Some(at_limit.len()));

    let refused = value_or_file("SESSION_SECRET", None, Some(SECRET_FILE.into()), |_| {
        Ok(vec![b'a'; MAX_FILE_LEN as usize + 1])
    })
    .unwrap_err();
    assert!(matches!(
        refused,
        ConfigError::FileTooLarge {
            var: "SESSION_SECRET",
            ..
        }
    ));
}

#[test]
fn a_file_that_is_not_utf8_is_refused_without_quoting_it() {
    let refused = value_or_file("SESSION_SECRET", None, Some(SECRET_FILE.into()), |_| {
        Ok(vec![0x73, 0x65, 0xff, 0xfe])
    })
    .unwrap_err();

    assert!(matches!(refused, ConfigError::UnreadableFile { .. }));
    assert_eq!(
        refused.to_string(),
        "SESSION_SECRET_FILE: cannot read /run/secrets/session_secret: not UTF-8"
    );
}

/// The reader behind `env_var`: a device or a FIFO would block or never end.
#[test]
fn only_a_regular_file_is_read() {
    let refused = read_bounded(Path::new("/dev/zero")).unwrap_err();

    assert_eq!(refused.kind(), std::io::ErrorKind::InvalidInput);
}

/// Docker and Kubernetes hand secrets over as symlinks: the link is followed.
#[test]
fn a_regular_file_reached_through_a_symlink_is_read() {
    let dir = std::env::temp_dir().join(format!("idp-config-symlink-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("secret");
    let link = dir.join("link");
    std::fs::write(&target, "s3cret").unwrap();
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let read = read_bounded(&link);
    std::fs::remove_dir_all(&dir).unwrap();

    assert_eq!(read.unwrap(), b"s3cret");
}

#[test]
fn an_empty_file_twin_counts_as_unset() {
    for file in [Some(String::new()), Some("  ".into())] {
        assert_eq!(
            value_or_file(
                "SMTP_HOST",
                Some("smtp.example.com".into()),
                file.clone(),
                no_file
            )
            .unwrap(),
            Some("smtp.example.com".into())
        );
        assert_eq!(
            value_or_file("SMTP_HOST", None, file, no_file).unwrap(),
            None
        );
    }
}

#[test]
fn a_missing_variable_names_its_file_twin_too() {
    assert_eq!(
        ConfigError::MissingVar("DOMAIN").to_string(),
        "Missing or empty environment variable: DOMAIN (or DOMAIN_FILE, a file holding it)"
    );
}

// ─── The email pepper ────────────────────────────────────────────────────────

#[test]
fn a_pepper_that_is_not_hex_is_refused_without_quoting_it() {
    let pepper = format!("{}zq", "ab".repeat(32));
    let refused = email_otp_pepper(Some(pepper)).unwrap_err();

    assert!(matches!(
        refused,
        ConfigError::InvalidValue("EMAIL_OTP_PEPPER", _)
    ));
    assert!(!refused.to_string().contains('z'), "{refused}");
}

#[test]
fn a_generated_pepper_is_read_as_its_bytes() {
    assert_eq!(
        email_otp_pepper(Some("ab".repeat(32))).unwrap(),
        vec![0xab; 32]
    );
}

#[test]
fn an_unset_or_empty_pepper_is_missing() {
    for raw in [None, Some(String::new())] {
        assert!(
            matches!(
                email_otp_pepper(raw.clone()),
                Err(ConfigError::MissingVar("EMAIL_OTP_PEPPER"))
            ),
            "{raw:?}"
        );
    }
}
