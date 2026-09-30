use time::{Duration, OffsetDateTime};

use crate::identity::HandleSuffix;
use crate::{TicketId, UserId};

use super::{
    AuthError, AuthorizationCode, AuthorizationRequest, Client, ClientId, CodeAttempt, Email,
    Grant, NewAccount, OtpCode, PasswordHash, Registration, SignInAccount, Ticket, TicketAttempt,
    Tokens, TotpSecret,
};

#[async_trait::async_trait]
pub trait Clients: Send + Sync {
    async fn find(&self, id: &ClientId) -> Result<Option<Client>, AuthError>;
    async fn all(&self) -> Result<Vec<Client>, AuthError>;
}

/// Each code is handed out once, and good only until it expires.
#[async_trait::async_trait]
pub trait AuthorizationCodes: Send + Sync {
    async fn issue(
        &self,
        grant: &Grant,
        expires_at: OffsetDateTime,
    ) -> Result<AuthorizationCode, AuthError>;
    /// The grant, the first time the code is presented before it expires; `None` after.
    async fn consume(
        &self,
        code: &AuthorizationCode,
        now: OffsetDateTime,
    ) -> Result<Option<Grant>, AuthError>;
}

#[async_trait::async_trait]
pub trait SignInAccounts: Send + Sync {
    /// Whatever case the stored address is in.
    async fn by_email(&self, email: &Email) -> Result<Option<SignInAccount>, AuthError>;
    async fn by_id(&self, id: UserId) -> Result<Option<SignInAccount>, AuthError>;
}

pub trait PasswordHasher: Send + Sync {
    fn hash(&self, password: &str) -> Result<PasswordHash, AuthError>;
    fn verify(&self, password: &str, hash: &PasswordHash) -> bool;
    /// A hash no password matches, as costly to check as a real one.
    fn decoy(&self) -> &PasswordHash;
}

/// Signs the tokens a code is exchanged for, as this instance.
pub trait TokenIssuer: Send + Sync {
    fn issue(
        &self,
        account: &SignInAccount,
        client: &ClientId,
        nonce: Option<&str>,
        ttl: Duration,
    ) -> Result<Tokens, AuthError>;
}

/// The second step of a sign-in with an authenticator: the request waits here for the code.
#[async_trait::async_trait]
pub trait LoginTickets: Send + Sync {
    /// Replaces any ticket the account still had open.
    async fn open(
        &self,
        user: UserId,
        request: &AuthorizationRequest,
        expires_at: OffsetDateTime,
    ) -> Result<TicketId, AuthError>;
    /// The ticket, while open: not spent and not expired by `now`.
    async fn find(
        &self,
        ticket: TicketId,
        now: OffsetDateTime,
    ) -> Result<Option<Ticket>, AuthError>;
    /// Counts an attempt on the ticket before its code is checked, all in one step: parallel
    /// guesses cannot pass its five.
    async fn reserve_attempt(
        &self,
        ticket: TicketId,
        now: OffsetDateTime,
    ) -> Result<TicketAttempt, AuthError>;
    /// Spends the ticket; `false` if it was spent already.
    async fn consume(&self, ticket: TicketId) -> Result<bool, AuthError>;
    /// The tickets spent or expired by `now` and opened before `opened_before`. How many went.
    async fn delete_spent(
        &self,
        now: OffsetDateTime,
        opened_before: OffsetDateTime,
    ) -> Result<usize, AuthError>;
}

/// The codes that confirm an account's email address.
#[async_trait::async_trait]
pub trait SignupCodes: Send + Sync {
    /// A fresh code; the account's earlier ones stop working.
    async fn issue(&self, user: UserId, expires_at: OffsetDateTime) -> Result<OtpCode, AuthError>;
    /// How many were issued to the account after `since`.
    async fn issued_since(&self, user: UserId, since: OffsetDateTime) -> Result<usize, AuthError>;
    /// Tries `code` against the account's live code; the right one spends it and confirms the
    /// account's address.
    async fn attempt(
        &self,
        user: UserId,
        code: &OtpCode,
        now: OffsetDateTime,
    ) -> Result<CodeAttempt, AuthError>;
    /// The codes spent or expired by `now` and issued before `issued_before`. How many went.
    async fn delete_spent(
        &self,
        now: OffsetDateTime,
        issued_before: OffsetDateTime,
    ) -> Result<usize, AuthError>;
}

/// The accounts registering creates.
#[async_trait::async_trait]
pub trait SignUps: Send + Sync {
    /// Refused — nothing written — when the address or the handle is another account's already.
    async fn create(&self, account: &NewAccount) -> Result<Registration, AuthError>;
    /// The accounts still unconfirmed and created before `created_before`. How many went.
    async fn delete_unverified(&self, created_before: OffsetDateTime) -> Result<usize, AuthError>;
}

/// The random part appended to a chosen name.
pub trait HandleSuffixes: Send + Sync {
    fn fresh(&self) -> HandleSuffix;
}

#[async_trait::async_trait]
pub trait SignupMailer: Send + Sync {
    async fn send_code(&self, to: &str, name: &str, code: &OtpCode) -> Result<(), AuthError>;
}

/// The time-based one-time passwords of RFC 6238: SHA-1, six digits, 30 s steps, one step of
/// drift either way.
pub trait Authenticator: Send + Sync {
    fn new_secret(&self) -> TotpSecret;
    fn base32(&self, secret: &TotpSecret) -> String;
    /// The `otpauth://totp/…` URL an authenticator app scans.
    fn provisioning_url(
        &self,
        secret: &TotpSecret,
        issuer: &str,
        account: &str,
    ) -> Result<String, AuthError>;
    /// The time step `code` belongs to, if it is the secret's code for a step within the drift.
    fn matching_step(&self, secret: &TotpSecret, code: &str, now: OffsetDateTime) -> Option<i64>;
}

/// Each account's second factor: its authenticator's secret, an enrollment in progress, and its
/// single-use recovery codes, of which only a peppered hash is kept.
#[async_trait::async_trait]
pub trait SecondFactors: Send + Sync {
    /// The secret of an account whose second factor is on.
    async fn secret(&self, user: UserId) -> Result<Option<TotpSecret>, AuthError>;
    /// Keeps the secret being enrolled, replacing an earlier one.
    async fn start_enrollment(&self, user: UserId, secret: &TotpSecret) -> Result<(), AuthError>;
    async fn pending(&self, user: UserId) -> Result<Option<TotpSecret>, AuthError>;
    /// Turns the second factor on with `secret`, its code of `step` used, the enrollment
    /// forgotten and a fresh set of recovery codes minted — all or nothing, so it is never on
    /// without codes to recover it. The codes' plaintexts, shown once.
    async fn enable(
        &self,
        user: UserId,
        secret: &TotpSecret,
        step: i64,
    ) -> Result<Vec<String>, AuthError>;
    /// Turns it off, forgetting its secret, its last step, its recovery codes and any enrollment
    /// — all or nothing.
    async fn disable(&self, user: UserId) -> Result<(), AuthError>;
    /// A fresh set of recovery codes in place of the old: the plaintexts, shown once.
    async fn replace_recovery_codes(&self, user: UserId) -> Result<Vec<String>, AuthError>;

    /// Records that the code of `step` was used: `false` — and nothing recorded — unless `step`
    /// comes after the last one used, so a code is never accepted twice.
    async fn use_step(&self, user: UserId, step: i64) -> Result<bool, AuthError>;
    /// Spends the recovery code matching `submitted` — dashes, spaces and case aside.
    async fn use_recovery_code(&self, user: UserId, submitted: &str) -> Result<bool, AuthError>;
}
