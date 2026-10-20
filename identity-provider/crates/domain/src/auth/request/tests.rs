use crate::auth::testing::{a_request, web_client};
use crate::auth::{DESKTOP_REDIRECT_URI, desktop_client};
use crate::identity::InstanceOrigin;

use super::*;

// RFC 7636 appendix B.
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

#[test]
fn only_an_s256_challenge_is_accepted() {
    assert!(CodeChallenge::parse(CHALLENGE, "S256").is_ok());
    for method in ["plain", "s256", "", "S512"] {
        assert!(
            matches!(
                CodeChallenge::parse(CHALLENGE, method),
                Err(AuthError::BadChallengeMethod)
            ),
            "{method}"
        );
    }
}

#[test]
fn a_challenge_is_met_by_its_verifier_only() {
    let challenge = CodeChallenge::parse(CHALLENGE, "S256").unwrap();

    assert!(challenge.is_met_by(VERIFIER));
    assert!(!challenge.is_met_by(&VERIFIER[1..]));
    assert!(!challenge.is_met_by(CHALLENGE));
    assert!(!challenge.is_met_by(""));
}

#[test]
fn a_signup_code_is_six_digits() {
    assert!(OtpCode::parse("012345").is_ok());
    for refused in ["12345", "1234567", "12345a", "", "١٢٣٤٥٦"] {
        assert!(OtpCode::parse(refused).is_err(), "{refused}");
    }
}

#[test]
fn only_a_client_allowed_to_stay_signed_in_that_asked_to_opens_an_app_session() {
    let desktop = desktop_client(&InstanceOrigin::parse("http://localhost:8080").unwrap());
    let request = |scope: &str| AuthorizationRequest {
        client: desktop.id.clone(),
        redirect_uri: DESKTOP_REDIRECT_URI.to_owned(),
        scope: scope.to_owned(),
        ..a_request()
    };
    let grant =
        |scope: &str| Grant::answering(UserId::generate(), SessionId::generate(), &request(scope));
    let staying = "openid profile email offline_access";

    assert!(grant(staying).opens_app_session(&desktop));
    assert!(
        !grant("openid profile email").opens_app_session(&desktop),
        "it did not ask"
    );
    assert!(
        !grant(staying).opens_app_session(&Client {
            offline_access: false,
            ..desktop.clone()
        }),
        "its document does not allow it"
    );
    assert!(
        !grant(staying).opens_app_session(&web_client()),
        "a web client never may"
    );
}

#[test]
fn login_among_the_prompt_values_asks_the_password_again() {
    assert!(prompts_login(Some("login")));
    assert!(prompts_login(Some("consent login")));
    assert!(!prompts_login(Some("none")));
    assert!(!prompts_login(Some("loginx")));
    assert!(!prompts_login(None));
}
