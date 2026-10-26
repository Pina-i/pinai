//! Signing in to this instance over OpenID Connect: the clients, the authorization codes a
//! sign-in ends in and the tokens they are exchanged for — see
//! identity-provider/specs/auth.md § 1.

mod account;
mod admin;
mod client;
mod client_sign_in;
mod error;
mod invitation;
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
pub use ports::{
    Authenticator, AuthorizationCodes, ClientSignIns, Clients, HandleSuffixes, Invitations,
    LoginTickets, PasswordHasher, RefreshTokens, SecondFactors, SessionNotifier, Sessions,
    SignInAccounts, SignUps, SignupCodes, SignupMailer, TokenIssuer,
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
