use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use domain::UserId;
use domain::auth::testing::signed_up;
use domain::identity::{TokenError, TokenVerifier};
use jwt_utils::{EdKeyPair, issue_access_token, load_ed_keypair_from_pem};

use super::*;

const ISSUER: &str = "http://localhost:8080";
// Minted for these tests only.
const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIF1VRwFuAo+gfSZtIUeF2VmNnVy0VePE+L7/D1UTTV6/
-----END PRIVATE KEY-----
";

fn keypair() -> Arc<EdKeyPair> {
    let path =
        std::env::temp_dir().join(format!("pinai-token-verifier-{}.pem", uuid::Uuid::new_v4()));
    std::fs::write(&path, TEST_KEY).unwrap();
    let keypair = load_ed_keypair_from_pem(&path, "test-key").unwrap();
    std::fs::remove_file(&path).unwrap();
    Arc::new(keypair)
}

fn token(keypair: &EdKeyPair, issuer: &str, subject: &str, ttl: i64) -> String {
    issue_access_token(
        keypair,
        issuer,
        subject,
        "web-client",
        "a@idp.test",
        "a",
        ttl,
    )
    .unwrap()
}

#[test]
fn a_token_this_instance_issued_names_its_user() {
    let keypair = keypair();
    let user = UserId::generate();
    let verifier = JwtTokenVerifier::new(keypair.clone(), ISSUER.to_owned());

    let verified = verifier.verify(&token(&keypair, ISSUER, &user.to_string(), 60));

    assert_eq!(verified.unwrap(), user);
}

#[test]
fn an_expired_or_foreign_token_is_refused() {
    let keypair = keypair();
    let verifier = JwtTokenVerifier::new(keypair.clone(), ISSUER.to_owned());
    let user = UserId::generate().to_string();

    for token in [
        token(&keypair, ISSUER, &user, -120),
        token(&keypair, "https://idp.other.test", &user, 60),
        "not-a-jwt".to_owned(),
    ] {
        assert!(matches!(verifier.verify(&token), Err(TokenError::Invalid)));
    }
    assert!(matches!(
        verifier.verify(&token(&keypair, ISSUER, "not-a-uuid", 60)),
        Err(TokenError::BadSubject)
    ));
}

#[test]
fn the_tokens_a_code_is_exchanged_for_name_the_account_and_carry_the_nonce() {
    let keypair = keypair();
    let alice = signed_up("alice");
    let client = ClientId::parse("web-client").unwrap();

    let tokens = JwtTokenIssuer::new(keypair.clone(), ISSUER.to_owned())
        .issue(&alice, &client, Some("the-nonce"), Duration::hours(1))
        .unwrap();

    let verified = JwtTokenVerifier::new(keypair, ISSUER.to_owned()).verify(&tokens.access_token);
    let payload = tokens.id_token.split('.').nth(1).unwrap();
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert_eq!(verified.unwrap(), alice.id);
    assert_eq!(tokens.expires_in, Duration::hours(1));
    assert_eq!(
        (
            &claims["sub"],
            &claims["aud"],
            &claims["email"],
            &claims["nonce"]
        ),
        (
            &serde_json::json!(alice.id.to_string()),
            &serde_json::json!("web-client"),
            &serde_json::json!(alice.email),
            &serde_json::json!("the-nonce"),
        )
    );
}

#[test]
fn a_password_matches_only_its_argon2_hash() {
    let hasher = Argon2Hasher::new();
    let hash = hasher.hash("correct horse").unwrap();

    assert!(hasher.verify("correct horse", &hash));
    assert!(!hasher.verify("correct horse ", &hash));
    assert!(!hasher.verify("correct horse", &PasswordHash::new("x".to_owned())));
}

#[test]
fn the_decoy_costs_what_a_registered_password_costs_and_matches_none() {
    let hasher = Argon2Hasher::new();

    let decoy = argon2::PasswordHash::new(hasher.decoy().as_str()).unwrap();

    assert_eq!(decoy.algorithm.as_str(), "argon2id");
    assert_eq!(
        (
            decoy.params.get_decimal("m"),
            decoy.params.get_decimal("t"),
            decoy.params.get_decimal("p"),
        ),
        (Some(65536), Some(3), Some(4))
    );
    assert!(!hasher.verify("", hasher.decoy()));
}

#[test]
fn a_suffix_is_drawn_from_the_handle_alphabet() {
    let drawn: std::collections::HashSet<String> = (0..100)
        .map(|_| {
            let suffix = RandomSuffixes.fresh();
            format!("{suffix:?}")
        })
        .collect();

    assert!(drawn.len() > 95, "{}", drawn.len());
}

fn a_secret() -> TotpSecret {
    TotpAuthenticator.new_secret()
}

#[test]
fn an_authenticator_accepts_the_code_an_app_shows_now_and_a_step_either_side() {
    let secret = a_secret();
    let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
    let at = |t: OffsetDateTime| {
        totp(&secret, "", "")
            .unwrap()
            .generate(u64::try_from(t.unix_timestamp()).unwrap())
    };
    let step = Duration::seconds(30);
    let matches = |code: &str| {
        TotpAuthenticator
            .matching_step(&secret, code, now)
            .is_some()
    };

    assert!(matches(&at(now)));
    assert!(matches(&format!(" {} ", at(now))));
    assert!(matches(&at(now - step)));
    assert!(matches(&at(now + step)));
    assert!(!matches(&at(now - step * 3)));
    assert!(!matches("12345"));
    assert!(!matches("abcdef"));
}

#[test]
fn an_authenticator_app_is_given_the_secret_by_a_url_naming_the_issuer_and_account() {
    let secret = a_secret();

    let url = TotpAuthenticator
        .provisioning_url(&secret, "Pina'i (idp.alice.test)", "alice@idp.test")
        .unwrap();

    assert!(url.starts_with("otpauth://totp/"), "{url}");
    assert!(url.contains("issuer="), "{url}");
    assert!(url.contains("alice"), "{url}");
    assert!(url.contains(&TotpAuthenticator.base32(&secret)), "{url}");
    assert_ne!(a_secret(), secret);
}

#[test]
fn a_code_is_matched_to_the_step_it_was_shown_at() {
    let secret = a_secret();
    let now = OffsetDateTime::from_unix_timestamp(1_790_000_010).unwrap();
    let step = now.unix_timestamp() / 30;
    let at = |t: OffsetDateTime| {
        totp(&secret, "", "")
            .unwrap()
            .generate(u64::try_from(t.unix_timestamp()).unwrap())
    };
    let thirty = Duration::seconds(30);

    assert_eq!(
        TotpAuthenticator.matching_step(&secret, &at(now), now),
        Some(step)
    );
    assert_eq!(
        TotpAuthenticator.matching_step(&secret, &at(now - thirty), now),
        Some(step - 1)
    );
    assert_eq!(
        TotpAuthenticator.matching_step(&secret, &at(now + thirty), now),
        Some(step + 1)
    );
    assert_eq!(
        TotpAuthenticator.matching_step(&secret, &at(now - thirty * 3), now),
        None
    );
}

#[test]
fn an_issuer_or_account_holding_a_colon_is_written_the_way_the_format_allows() {
    let secret = a_secret();

    let url = TotpAuthenticator
        .provisioning_url(&secret, "Pina'i (localhost:8080)", "a:lice@idp.test")
        .unwrap();

    let parsed = url::Url::parse(&url).unwrap();
    let issuer: Vec<String> = parsed
        .query_pairs()
        .filter(|(key, _)| key == "issuer")
        .map(|(_, value)| value.into_owned())
        .collect();
    let label = decoded(parsed.path());
    assert_eq!(issuer, vec!["Pina'i (localhost 8080)".to_owned()]);
    assert_eq!(label, "/Pina'i (localhost 8080):a lice@idp.test");
}

/// A percent-encoded path, as read.
fn decoded(path: &str) -> String {
    url::form_urlencoded::parse(format!("p={}", path.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default()
}
