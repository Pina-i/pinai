#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("unknown client")]
    UnknownClient,
    #[error("redirect_uri is not registered for this client")]
    UnregisteredRedirect,
    #[error("only the code response type is supported")]
    UnsupportedResponseType,
    #[error("code_challenge_method must be S256")]
    BadChallengeMethod,
    #[error("only the authorization_code grant is supported")]
    UnsupportedGrantType,
    #[error("the code was issued for another redirect_uri")]
    RedirectMismatch,
    #[error("the code is invalid, expired, or already used")]
    CodeUnusable,
    #[error("the code was issued to another client")]
    ClientMismatch,
    #[error("the code_verifier does not match the code_challenge")]
    VerifierMismatch,
    #[error("display_name, email, and password are required")]
    MissingField,
    #[error(transparent)]
    BadDisplayName(crate::ValidationError),
    #[error(transparent)]
    BadEmail(crate::ValidationError),
    #[error("password must be at least 8 characters")]
    PasswordTooShort,
    #[error("the email is registered already")]
    EmailTaken,
    #[error("no such account")]
    UnknownUser,
    #[error("the address is confirmed already")]
    AlreadyVerified,
    #[error("too many codes mailed lately")]
    TooManyCodes,
    #[error("TOTP already enabled — disable it first to re-enroll")]
    TotpEnabled,
    #[error("TOTP is not enabled")]
    TotpNotEnabled,
    #[error("no pending enrollment")]
    NoEnrollment,
    #[error("incorrect code")]
    WrongCode,
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}
