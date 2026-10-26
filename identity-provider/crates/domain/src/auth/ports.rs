use time::{Duration, OffsetDateTime};

use crate::identity::HandleSuffix;
use crate::{DeviceId, SessionId, TicketId, UserId};

use super::{
    AdminFacts, AuthError, AuthorizationCode, AuthorizationRequest, Client, ClientId, ClientSignIn,
    CodeAttempt, Email, Grant, NewAccount, OtpCode, PasswordHash, RefreshToken, Registration,
    RevokedReason, Rotation, Session, SessionKind, SignInAccount, Ticket, TicketAttempt,
    TotpSecret,
};

#[async_trait::async_trait]
pub trait Clients: Send + Sync {
    /// The client its document describes; `None` when the document can't be had or breaks a
    /// rule, so its redirect URIs are never trusted.
    async fn find(&self, id: &ClientId) -> Result<Option<Client>, AuthError>;
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

/// Signs the tokens a sign-in leads to, as this instance.
pub trait TokenIssuer: Send + Sync {
    /// Names `session`, so it stops working when the session ends, and when the password was
    /// last typed on it.
    fn access_token(
        &self,
        account: &SignInAccount,
        session: &Session,
        client: &ClientId,
        ttl: Duration,
    ) -> Result<String, AuthError>;
    fn id_token(
        &self,
        account: &SignInAccount,
        client: &ClientId,
        nonce: Option<&str>,
        ttl: Duration,
    ) -> Result<String, AuthError>;
}

/// The sessions: each a row, so each can end on its own.
#[async_trait::async_trait]
pub trait Sessions: Send + Sync {
    /// A new session for the account, used — and its password typed — `now`.
    async fn open(
        &self,
        user: UserId,
        kind: &SessionKind,
        now: OffsetDateTime,
    ) -> Result<SessionId, AuthError>;
    async fn find(&self, id: SessionId) -> Result<Option<Session>, AuthError>;
    /// Stamps a use of it.
    async fn touch(&self, id: SessionId, now: OffsetDateTime) -> Result<(), AuthError>;
    /// Records the account's password typed on it at `at`.
    async fn authenticate(&self, id: SessionId, at: OffsetDateTime) -> Result<(), AuthError>;
    /// Ends it; `false` when it had ended already.
    async fn revoke(
        &self,
        id: SessionId,
        reason: RevokedReason,
        now: OffsetDateTime,
    ) -> Result<bool, AuthError>;
    /// The sessions over before `before`: revoked then, or idle since `before - SESSION_IDLE`.
    /// How many went.
    async fn delete_ended(&self, before: OffsetDateTime) -> Result<usize, AuthError>;
    /// The account's sessions, ended or not, until swept.
    async fn of_user(&self, user: UserId) -> Result<Vec<Session>, AuthError>;
    /// Links the session to the E2EE device it signed in, and ends the device's other sessions
    /// (`replaced`): a device is signed in once at a time. The sessions it ended.
    async fn link(
        &self,
        id: SessionId,
        device: DeviceId,
        now: OffsetDateTime,
    ) -> Result<Vec<Session>, AuthError>;
    /// Ends the account's sessions linked to `device` (`device_revoked`). The sessions it ended.
    async fn revoke_device(
        &self,
        user: UserId,
        device: DeviceId,
        now: OffsetDateTime,
    ) -> Result<Vec<Session>, AuthError>;
    /// Ends every session of the account but `keep` (`signed_out_elsewhere`). The sessions it
    /// ended.
    async fn revoke_others(
        &self,
        user: UserId,
        keep: SessionId,
        now: OffsetDateTime,
    ) -> Result<Vec<Session>, AuthError>;
}

/// Tells what hangs on a session that it ended: its account's sockets opened under it close.
pub trait SessionNotifier: Send + Sync {
    fn ended(&self, session: &Session);
}

/// The refresh tokens, in chains: each use rotates a token to its successor. Only a hash of each
/// is kept.
#[async_trait::async_trait]
pub trait RefreshTokens: Send + Sync {
    /// The first token of a new chain, for `client` under `session`.
    async fn start(
        &self,
        session: SessionId,
        client: &ClientId,
        now: OffsetDateTime,
    ) -> Result<RefreshToken, AuthError>;
    /// Presents `token` for `client`, and does what [`crate::auth::RefreshLink::presented`] decides — in one
    /// step, so two presentations of one token are judged one after the other.
    async fn rotate(
        &self,
        token: &RefreshToken,
        client: &ClientId,
        now: OffsetDateTime,
    ) -> Result<Rotation, AuthError>;
    /// The tokens last used before `before`: a head since its creation, any other since its
    /// rotation. How many went.
    async fn delete_unused(&self, before: OffsetDateTime) -> Result<usize, AuthError>;
    /// The session `token` belongs to, rotated or not, when it was issued to `client`.
    async fn session_of(
        &self,
        token: &RefreshToken,
        client: &ClientId,
    ) -> Result<Option<SessionId>, AuthError>;
}

/// The apps each account signed in to with its password.
#[async_trait::async_trait]
pub trait ClientSignIns: Send + Sync {
    /// Remembers it, or remembers it again; an `offline_access` once given is kept.
    async fn remember(&self, sign_in: &ClientSignIn, at: OffsetDateTime) -> Result<(), AuthError>;
    async fn find(
        &self,
        user: UserId,
        client: &ClientId,
    ) -> Result<Option<ClientSignIn>, AuthError>;
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

/// The accounts registering creates, and the instance's first admin.
#[async_trait::async_trait]
pub trait SignUps: Send + Sync {
    /// Refused — nothing written — when the address or the handle is another account's already.
    async fn create(&self, account: &NewAccount) -> Result<Registration, AuthError>;
    /// The instance's admin, refused as `create` refuses: its address unconfirmed, but the
    /// account admitted at `admitted_at`.
    async fn create_admin(
        &self,
        account: &NewAccount,
        admitted_at: OffsetDateTime,
    ) -> Result<Registration, AuthError>;
    /// Who has `address`, whatever its case — nobody without one — and whether any account is
    /// an admin.
    async fn admin_facts(&self, address: Option<&Email>) -> Result<AdminFacts, AuthError>;
    /// The accounts still unconfirmed, never admitted, and created before `created_before`. How
    /// many went.
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
