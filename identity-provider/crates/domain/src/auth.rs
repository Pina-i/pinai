//! Signing in to this instance over OpenID Connect: the clients, the authorization codes a
//! sign-in ends in and the tokens they are exchanged for — see
//! identity-provider/specs/auth.md § 1.

/// The secret a link carries: 256 random bits, URL-safe base64 without padding, which `Debug`
/// never prints. `$what` names the link in the refusal of anything else. Every link's token is
/// declared with it, so the macro stays private to this module.
macro_rules! link_token {
    ($(#[$meta:meta])* $name:ident, $what:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// 32 bytes, base64url without padding.
            pub const LEN: usize = 43;

            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                use ::base64::Engine as _;
                Self(::base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
            }

            /// A token as a link brings it back. Anything else names no link.
            pub fn parse(raw: &str) -> Result<Self, $crate::ValidationError> {
                use ::base64::Engine as _;
                let refuse =
                    || $crate::ValidationError::new($what, "43 characters of URL-safe base64");
                if raw.len() != Self::LEN {
                    return Err(refuse());
                }
                match ::base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw) {
                    Ok(bytes) if bytes.len() == 32 => Ok(Self(raw.to_owned())),
                    _ => Err(refuse()),
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

mod account;
mod admin;
mod client;
mod client_sign_in;
mod error;
mod invitation;
mod members;
mod password_reset;
mod ports;
mod refresh;
mod registrations;
mod request;
mod second_factor;
mod session;
mod signup;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;
mod web_app;

pub use account::{PasswordHash, SignInAccount};
pub use admin::{
    AddressHolder, AdminBootstrap, AdminFacts, AdminPassword, AdminRefusal, NewAdmin,
    admin_bootstrap, admin_display_name,
};
pub use client::{
    Client, ClientDocument, ClientId, ClientKind, ClientPolicy, DESKTOP_DOCUMENT_PATH,
    DESKTOP_REDIRECT_URI, desktop_client,
};
pub use client_sign_in::ClientSignIn;
pub use error::AuthError;
pub use invitation::{
    INVITATION_RETENTION, INVITATION_TTL, Invitation, InvitationToken, OpenInvitation,
};
pub use members::InstanceMember;
pub use password_reset::{
    NewPassword, OpenReset, PasswordChange, PasswordReset, RESET_RETENTION, RESET_TTL, ResetToken,
    reset_target,
};
pub use ports::{
    Authenticator, AuthorizationCodes, ClientSignIns, Clients, HandleSuffixes, InstanceMembers,
    Invitations, LoginTickets, PasswordHasher, PasswordResets, RefreshTokens, SecondFactors,
    SessionNotifier, Sessions, SignInAccounts, SignUps, SignupCodes, SignupMailer, TokenIssuer,
};
pub use refresh::{
    Presentation, REFRESH_GRACE, REFRESH_GRANT_TYPE, RefreshLink, RefreshToken, Rotation,
};
pub use registrations::{Joining, Registrations};
pub use request::{
    ACCESS_TOKEN_TTL, AuthorizationCode, AuthorizationRequest, CODE_TTL, CodeChallenge, GRANT_TYPE,
    Grant, LOGIN_TICKET_TTL, OtpCode, RESPONSE_TYPE, SIGNUP_CODE_TTL, Tokens, prompts_login,
};
pub use second_factor::{
    Enrollment, RECOVERY_CODES, TICKET_ATTEMPTS, Ticket, TicketAttempt, TotpSecret,
};
pub use session::{
    RevokedReason, SESSION_IDLE, SESSION_RETENTION, Session, SessionKind, last_active,
};
pub use signup::{
    CODE_ATTEMPTS, CodeAttempt, Email, NewAccount, RESEND_LIMIT, RESEND_WINDOW, Registration,
    SPENT_RETENTION, UNVERIFIED_TTL, check_password,
};
pub use web_app::{OFFICIAL_WEB_APP_ORIGIN, WebApp};

#[cfg(test)]
mod tests;
