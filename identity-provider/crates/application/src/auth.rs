//! Signing in over OpenID Connect: a client's request, the credentials, the code it ends in and
//! the tokens that code is exchanged for.

mod authorize;
mod exchange_code;
mod log_in;
mod log_out;
mod pass_second_factor;
mod register;
mod resend_code;
mod send_test_mail;
mod sweep_signups;
mod totp_enrollment;
mod totp_settings;
mod verify_email;
#[cfg(test)]
mod world;

pub use authorize::{Authorize, AuthorizeCommand, Authorized};
pub use exchange_code::{ExchangeCode, TokenCommand};
pub use log_in::{LogIn, LoginOutcome};
pub use log_out::LogOut;
pub use pass_second_factor::{PassSecondFactor, SecondFactorOutcome};
pub use register::{Register, RegisterCommand, Registered};
pub use resend_code::ResendCode;
pub use send_test_mail::SendTestMail;
pub use sweep_signups::{SweepSignups, Swept};
pub use totp_enrollment::{ConfirmTotpEnrollment, StartTotpEnrollment};
pub use totp_settings::{DisableTotp, RegenerateRecoveryCodes};
pub use verify_email::{Verification, VerifyEmail};

use domain::auth::{
    AuthError, RESEND_LIMIT, RESEND_WINDOW, SIGNUP_CODE_TTL, SignInAccount, SignupCodes,
    SignupMailer,
};
use time::OffsetDateTime;

/// A fresh code to confirm the account's address, by mail; its earlier codes stop working.
/// Within the resend limit, whoever asks: past it, `TooManyCodes` — each code is more mail to
/// the address, and more guesses at it.
pub(crate) async fn mail_signup_code(
    codes: &dyn SignupCodes,
    mailer: &dyn SignupMailer,
    account: &SignInAccount,
    now: OffsetDateTime,
) -> Result<(), AuthError> {
    if codes.issued_since(account.id, now - RESEND_WINDOW).await? >= RESEND_LIMIT {
        return Err(AuthError::TooManyCodes);
    }
    let code = codes.issue(account.id, now + SIGNUP_CODE_TTL).await?;
    let name = account
        .display_name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or(&account.username);
    mailer.send_code(&account.email, name, &code).await
}
