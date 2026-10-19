//! In-memory fakes of the sign-in ports and the contract every store must satisfy.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use time::{Duration, OffsetDateTime};

use crate::identity::{ActorUri, Handle, HandleSuffix};
use crate::{TicketId, UserId};

use super::{
    AuthError, Authenticator, AuthorizationCode, AuthorizationCodes, AuthorizationRequest,
    CODE_ATTEMPTS, Client, ClientDocument, ClientId, ClientKind, ClientPolicy, ClientSignIn,
    ClientSignIns, Clients, CodeAttempt, CodeChallenge, Email, Grant, HandleSuffixes,
    LOGIN_TICKET_TTL, LoginTickets, NewAccount, OtpCode, PasswordHash, PasswordHasher,
    RECOVERY_CODES, Registration, SIGNUP_CODE_TTL, SecondFactors, SignInAccount, SignInAccounts,
    SignUps, SignupCodes, SignupMailer, TICKET_ATTEMPTS, Ticket, TicketAttempt, TokenIssuer,
    Tokens, TotpSecret,
};

pub const CLIENT_ID: &str = "http://localhost:5173/oauth-client.json";
pub const REDIRECT_URI: &str = "http://localhost:5173/callback";
pub const POST_LOGOUT_URI: &str = "http://localhost:5173/";
// RFC 7636 appendix B.
pub const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
pub const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The web client in development, as its `/oauth-client.json` describes it.
pub fn web_client() -> Client {
    Client {
        id: ClientId::parse(CLIENT_ID).unwrap(),
        name: "Pīna'i".to_owned(),
        kind: ClientKind::Web,
        redirect_uris: vec![REDIRECT_URI.to_owned()],
        post_logout_redirect_uris: vec![POST_LOGOUT_URI.to_owned()],
        offline_access: false,
    }
}

/// What the web client asks for, as it does.
pub fn a_request() -> AuthorizationRequest {
    AuthorizationRequest {
        client: web_client().id,
        redirect_uri: REDIRECT_URI.to_owned(),
        scope: "openid profile email".to_owned(),
        state: "the-clients-state".to_owned(),
        challenge: CodeChallenge::parse(CHALLENGE, "S256").unwrap(),
        nonce: Some("the-nonce".to_owned()),
    }
}

/// A verified account without a second factor, whose password is `{name}-password`.
pub fn signed_up(name: &str) -> SignInAccount {
    SignInAccount {
        id: UserId::generate(),
        email: format!("{name}@idp.test"),
        username: format!("{name}_t3st0"),
        display_name: Some(name.to_owned()),
        password_hash: PlainHasher::hash(&format!("{name}-password")),
        email_verified: true,
        totp_enabled: false,
    }
}

#[derive(Default)]
pub struct InMemoryClients {
    clients: Mutex<Vec<Client>>,
}

impl InMemoryClients {
    pub fn with(clients: impl IntoIterator<Item = Client>) -> Self {
        Self {
            clients: Mutex::new(clients.into_iter().collect()),
        }
    }
}

#[async_trait::async_trait]
impl Clients for InMemoryClients {
    async fn find(&self, id: &ClientId) -> Result<Option<Client>, AuthError> {
        Ok(self
            .clients
            .lock()
            .unwrap()
            .iter()
            .find(|client| client.id == *id)
            .cloned())
    }
}

#[derive(Default)]
pub struct InMemoryClientSignIns {
    sign_ins: Mutex<Vec<(ClientSignIn, OffsetDateTime)>>,
}

impl InMemoryClientSignIns {
    /// What is remembered, first remembered first.
    pub fn remembered(&self) -> Vec<ClientSignIn> {
        self.sign_ins
            .lock()
            .unwrap()
            .iter()
            .map(|(sign_in, _)| sign_in.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl ClientSignIns for InMemoryClientSignIns {
    async fn remember(&self, sign_in: &ClientSignIn, at: OffsetDateTime) -> Result<(), AuthError> {
        let mut sign_ins = self.sign_ins.lock().unwrap();
        let known = sign_ins
            .iter_mut()
            .find(|(known, _)| known.user == sign_in.user && known.client == sign_in.client);
        match known {
            Some((known, when)) => {
                known.offline_access |= sign_in.offline_access;
                *when = at;
            }
            None => sign_ins.push((sign_in.clone(), at)),
        }
        Ok(())
    }

    async fn find(
        &self,
        user: UserId,
        client: &ClientId,
    ) -> Result<Option<ClientSignIn>, AuthError> {
        Ok(self
            .sign_ins
            .lock()
            .unwrap()
            .iter()
            .find(|(known, _)| known.user == user && known.client == *client)
            .map(|(known, _)| known.clone()))
    }
}

#[derive(Default)]
pub struct InMemoryCodes {
    issued: AtomicUsize,
    /// `(code, grant, expires_at, used)`.
    codes: Mutex<Vec<(AuthorizationCode, Grant, OffsetDateTime, bool)>>,
}

impl InMemoryCodes {
    /// The grants issued so far, oldest first.
    pub fn issued(&self) -> Vec<(AuthorizationCode, Grant)> {
        self.codes
            .lock()
            .unwrap()
            .iter()
            .map(|(code, grant, _, _)| (code.clone(), grant.clone()))
            .collect()
    }
}

#[async_trait::async_trait]
impl AuthorizationCodes for InMemoryCodes {
    async fn issue(
        &self,
        grant: &Grant,
        expires_at: OffsetDateTime,
    ) -> Result<AuthorizationCode, AuthError> {
        let n = self.issued.fetch_add(1, Ordering::SeqCst) + 1;
        let code = AuthorizationCode::new(format!("code-{n}"));
        self.codes
            .lock()
            .unwrap()
            .push((code.clone(), grant.clone(), expires_at, false));
        Ok(code)
    }

    async fn consume(
        &self,
        code: &AuthorizationCode,
        now: OffsetDateTime,
    ) -> Result<Option<Grant>, AuthError> {
        let mut codes = self.codes.lock().unwrap();
        let Some(held) = codes
            .iter_mut()
            .find(|(held, _, expires_at, used)| held == code && !*used && *expires_at > now)
        else {
            return Ok(None);
        };
        held.3 = true;
        Ok(Some(held.1.clone()))
    }
}

#[derive(Default)]
pub struct InMemorySignInAccounts {
    /// Each with when it was created.
    accounts: Mutex<Vec<(SignInAccount, OffsetDateTime)>>,
    created: Mutex<Vec<NewAccount>>,
}

impl InMemorySignInAccounts {
    pub fn with(accounts: impl IntoIterator<Item = SignInAccount>) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            accounts: Mutex::new(accounts.into_iter().map(|a| (a, now)).collect()),
            created: Mutex::default(),
        }
    }

    /// What registering created, oldest first.
    pub fn created(&self) -> Vec<NewAccount> {
        self.created.lock().unwrap().clone()
    }

    fn set_totp(&self, user: UserId, enabled: bool) {
        let mut accounts = self.accounts.lock().unwrap();
        if let Some((account, _)) = accounts.iter_mut().find(|(a, _)| a.id == user) {
            account.totp_enabled = enabled;
        }
    }

    fn confirm(&self, user: UserId) {
        let mut accounts = self.accounts.lock().unwrap();
        if let Some((account, _)) = accounts.iter_mut().find(|(a, _)| a.id == user) {
            account.email_verified = true;
        }
    }
}

#[async_trait::async_trait]
impl SignInAccounts for InMemorySignInAccounts {
    async fn by_email(&self, email: &Email) -> Result<Option<SignInAccount>, AuthError> {
        Ok(self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .map(|(account, _)| account)
            .find(|account| account.email.to_lowercase() == email.as_str())
            .cloned())
    }

    async fn by_id(&self, id: UserId) -> Result<Option<SignInAccount>, AuthError> {
        Ok(self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .map(|(account, _)| account)
            .find(|account| account.id == id)
            .cloned())
    }
}

#[async_trait::async_trait]
impl SignUps for InMemorySignInAccounts {
    async fn create(&self, account: &NewAccount) -> Result<Registration, AuthError> {
        let mut accounts = self.accounts.lock().unwrap();
        if accounts
            .iter()
            .any(|(held, _)| held.email.to_lowercase() == account.email.as_str())
        {
            return Ok(Registration::EmailTaken);
        }
        if accounts
            .iter()
            .any(|(held, _)| held.username == account.username.as_str())
        {
            return Ok(Registration::HandleTaken);
        }
        self.created.lock().unwrap().push(account.clone());
        accounts.push((
            SignInAccount {
                id: account.id,
                email: account.email.as_str().to_owned(),
                username: account.username.as_str().to_owned(),
                display_name: Some(account.display_name.clone()),
                password_hash: account.password_hash.clone(),
                email_verified: false,
                totp_enabled: false,
            },
            OffsetDateTime::now_utc(),
        ));
        Ok(Registration::Created)
    }

    async fn delete_unverified(&self, created_before: OffsetDateTime) -> Result<usize, AuthError> {
        let mut accounts = self.accounts.lock().unwrap();
        let before = accounts.len();
        accounts.retain(|(account, created)| account.email_verified || *created >= created_before);
        Ok(before - accounts.len())
    }
}

/// `plain:{password}`, and a count of the checks made.
pub struct PlainHasher {
    verifications: AtomicUsize,
    decoy: PasswordHash,
}

impl Default for PlainHasher {
    fn default() -> Self {
        Self {
            verifications: AtomicUsize::default(),
            decoy: PasswordHash::new("decoy".to_owned()),
        }
    }
}

impl PlainHasher {
    pub fn hash(password: &str) -> PasswordHash {
        PasswordHash::new(format!("plain:{password}"))
    }

    pub fn verifications(&self) -> usize {
        self.verifications.load(Ordering::SeqCst)
    }
}

impl PasswordHasher for PlainHasher {
    fn hash(&self, password: &str) -> Result<PasswordHash, AuthError> {
        Ok(Self::hash(password))
    }

    fn verify(&self, password: &str, hash: &PasswordHash) -> bool {
        self.verifications.fetch_add(1, Ordering::SeqCst);
        hash.as_str() == format!("plain:{password}")
    }

    fn decoy(&self) -> &PasswordHash {
        &self.decoy
    }
}

/// Tokens that spell out what they were issued for.
pub struct SpelledTokens;

impl TokenIssuer for SpelledTokens {
    fn issue(
        &self,
        account: &SignInAccount,
        client: &ClientId,
        nonce: Option<&str>,
        ttl: Duration,
    ) -> Result<Tokens, AuthError> {
        Ok(Tokens {
            access_token: format!("access:{}:{}", account.id, client.as_str()),
            id_token: format!(
                "id:{}:{}:{}:{}",
                account.id,
                client.as_str(),
                account.email,
                nonce.unwrap_or("-")
            ),
            expires_in: ttl,
        })
    }
}

struct TicketRow {
    id: TicketId,
    user: UserId,
    request: AuthorizationRequest,
    expires_at: OffsetDateTime,
    attempts: i32,
    spent: bool,
}

/// Tickets as the table keeps them.
#[derive(Default)]
pub struct RecordingTickets {
    rows: Mutex<Vec<TicketRow>>,
}

impl RecordingTickets {
    /// Every ticket opened, oldest first, with its expiry.
    pub fn opened(&self) -> Vec<(TicketId, UserId, AuthorizationRequest, OffsetDateTime)> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .map(|row| (row.id, row.user, row.request.clone(), row.expires_at))
            .collect()
    }
}

#[async_trait::async_trait]
impl LoginTickets for RecordingTickets {
    async fn open(
        &self,
        user: UserId,
        request: &AuthorizationRequest,
        expires_at: OffsetDateTime,
    ) -> Result<TicketId, AuthError> {
        let id = TicketId::generate();
        let mut rows = self.rows.lock().unwrap();
        for row in rows.iter_mut().filter(|row| row.user == user) {
            row.spent = true;
        }
        rows.push(TicketRow {
            id,
            user,
            request: request.clone(),
            expires_at,
            attempts: 0,
            spent: false,
        });
        Ok(id)
    }

    async fn find(
        &self,
        ticket: TicketId,
        now: OffsetDateTime,
    ) -> Result<Option<Ticket>, AuthError> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|row| row.id == ticket && !row.spent && row.expires_at > now)
            .map(|row| Ticket {
                user: row.user,
                request: row.request.clone(),
                attempts: row.attempts,
            }))
    }

    async fn reserve_attempt(
        &self,
        ticket: TicketId,
        now: OffsetDateTime,
    ) -> Result<TicketAttempt, AuthError> {
        let mut rows = self.rows.lock().unwrap();
        let Some(row) = rows
            .iter_mut()
            .find(|row| row.id == ticket && !row.spent && row.expires_at > now)
        else {
            return Ok(TicketAttempt::Gone);
        };
        if row.attempts >= TICKET_ATTEMPTS {
            return Ok(TicketAttempt::Exhausted);
        }
        row.attempts += 1;
        Ok(TicketAttempt::Open(Ticket {
            user: row.user,
            request: row.request.clone(),
            attempts: row.attempts,
        }))
    }

    async fn consume(&self, ticket: TicketId) -> Result<bool, AuthError> {
        let mut rows = self.rows.lock().unwrap();
        let Some(row) = rows.iter_mut().find(|row| row.id == ticket && !row.spent) else {
            return Ok(false);
        };
        row.spent = true;
        Ok(true)
    }

    async fn delete_spent(
        &self,
        now: OffsetDateTime,
        opened_before: OffsetDateTime,
    ) -> Result<usize, AuthError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|row| {
            !(row.spent || row.expires_at < now)
                || row.expires_at - LOGIN_TICKET_TTL >= opened_before
        });
        Ok(before - rows.len())
    }
}

/// Codes of the step they are for: `code_at` says which one an app would show.
#[derive(Default)]
pub struct StepAuthenticator {
    secrets: AtomicUsize,
}

impl StepAuthenticator {
    pub fn code_at(secret: &TotpSecret, at: OffsetDateTime) -> String {
        Self::code_of(secret, at.unix_timestamp().div_euclid(30))
    }

    fn code_of(secret: &TotpSecret, step: i64) -> String {
        format!(
            "{:06}",
            (i64::from(secret.as_bytes()[0]) * 100_000 + step).rem_euclid(1_000_000)
        )
    }
}

impl Authenticator for StepAuthenticator {
    fn new_secret(&self) -> TotpSecret {
        let n = self.secrets.fetch_add(1, Ordering::SeqCst) + 1;
        TotpSecret::parse(vec![u8::try_from(n % 256).unwrap(); TotpSecret::LEN]).unwrap()
    }

    fn base32(&self, secret: &TotpSecret) -> String {
        format!("SECRET{}", secret.as_bytes()[0])
    }

    fn provisioning_url(
        &self,
        secret: &TotpSecret,
        issuer: &str,
        account: &str,
    ) -> Result<String, AuthError> {
        Ok(format!(
            "otpauth://totp/{issuer}:{account}?secret={}",
            self.base32(secret)
        ))
    }

    fn matching_step(&self, secret: &TotpSecret, code: &str, now: OffsetDateTime) -> Option<i64> {
        let step = now.unix_timestamp().div_euclid(30);
        (step - 1..=step + 1).find(|step| Self::code_of(secret, *step) == code)
    }
}

#[derive(Default)]
struct FactorState {
    secret: Option<TotpSecret>,
    last_step: Option<i64>,
    pending: Option<TotpSecret>,
    /// Normalized, with whether each was used.
    codes: Vec<(String, bool)>,
}

/// Second factors in memory; turning one on or off shows on the accounts it is given. It can be
/// made to fail after a number of writes, to see what a half-done change leaves.
#[derive(Default)]
pub struct InMemorySecondFactors {
    states: Mutex<HashMap<UserId, FactorState>>,
    accounts: Option<std::sync::Arc<InMemorySignInAccounts>>,
    minted: AtomicUsize,
    writes_left: Mutex<Option<usize>>,
}

impl InMemorySecondFactors {
    pub fn for_accounts(accounts: std::sync::Arc<InMemorySignInAccounts>) -> Self {
        Self {
            accounts: Some(accounts),
            ..Self::default()
        }
    }

    /// Every write after the next `writes` fails.
    pub fn down_after(&self, writes: usize) {
        *self.writes_left.lock().unwrap() = Some(writes);
    }

    /// Whether the account's second factor is on, its unused recovery codes, and whether an
    /// enrollment is pending.
    pub fn state_of(&self, user: UserId) -> (bool, usize, bool) {
        let states = self.states.lock().unwrap();
        states.get(&user).map_or((false, 0, false), |state| {
            (
                state.secret.is_some(),
                state.codes.iter().filter(|(_, used)| !used).count(),
                state.pending.is_some(),
            )
        })
    }

    fn write(&self) -> Result<(), AuthError> {
        let mut left = self.writes_left.lock().unwrap();
        match left.as_mut() {
            Some(0) => Err(anyhow::anyhow!("the store is down").into()),
            Some(n) => {
                *n -= 1;
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn mint(&self) -> Vec<String> {
        (0..RECOVERY_CODES)
            .map(|_| format!("RCODE-{:05}", self.minted.fetch_add(1, Ordering::SeqCst)))
            .collect()
    }

    fn show(&self, user: UserId, enabled: bool) {
        if let Some(accounts) = &self.accounts {
            accounts.set_totp(user, enabled);
        }
    }
}

fn normalized(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

#[async_trait::async_trait]
impl SecondFactors for InMemorySecondFactors {
    async fn secret(&self, user: UserId) -> Result<Option<TotpSecret>, AuthError> {
        Ok(self
            .states
            .lock()
            .unwrap()
            .get(&user)
            .and_then(|state| state.secret.clone()))
    }

    async fn start_enrollment(&self, user: UserId, secret: &TotpSecret) -> Result<(), AuthError> {
        self.write()?;
        self.states.lock().unwrap().entry(user).or_default().pending = Some(secret.clone());
        Ok(())
    }

    async fn pending(&self, user: UserId) -> Result<Option<TotpSecret>, AuthError> {
        Ok(self
            .states
            .lock()
            .unwrap()
            .get(&user)
            .and_then(|state| state.pending.clone()))
    }

    async fn enable(
        &self,
        user: UserId,
        secret: &TotpSecret,
        step: i64,
    ) -> Result<Vec<String>, AuthError> {
        self.write()?;
        let codes = self.mint();
        let mut states = self.states.lock().unwrap();
        let state = states.entry(user).or_default();
        state.secret = Some(secret.clone());
        state.last_step = Some(step);
        state.pending = None;
        state.codes = codes.iter().map(|code| (normalized(code), false)).collect();
        drop(states);
        self.show(user, true);
        Ok(codes)
    }

    async fn disable(&self, user: UserId) -> Result<(), AuthError> {
        self.write()?;
        self.states
            .lock()
            .unwrap()
            .insert(user, FactorState::default());
        self.show(user, false);
        Ok(())
    }

    async fn replace_recovery_codes(&self, user: UserId) -> Result<Vec<String>, AuthError> {
        self.write()?;
        let codes = self.mint();
        self.states.lock().unwrap().entry(user).or_default().codes =
            codes.iter().map(|code| (normalized(code), false)).collect();
        Ok(codes)
    }

    async fn use_step(&self, user: UserId, step: i64) -> Result<bool, AuthError> {
        let mut states = self.states.lock().unwrap();
        let Some(state) = states.get_mut(&user).filter(|state| state.secret.is_some()) else {
            return Ok(false);
        };
        if state.last_step.is_some_and(|last| last >= step) {
            return Ok(false);
        }
        state.last_step = Some(step);
        Ok(true)
    }

    async fn use_recovery_code(&self, user: UserId, submitted: &str) -> Result<bool, AuthError> {
        let submitted = normalized(submitted);
        let mut states = self.states.lock().unwrap();
        let Some(code) = states.get_mut(&user).and_then(|state| {
            state
                .codes
                .iter_mut()
                .find(|(code, used)| !used && *code == submitted)
        }) else {
            return Ok(false);
        };
        code.1 = true;
        Ok(true)
    }
}

struct CodeRow {
    user: UserId,
    code: OtpCode,
    expires_at: OffsetDateTime,
    spent: bool,
    attempts: i32,
}

/// Codes as the table keeps them; confirming an address shows on the accounts it is given.
#[derive(Default)]
pub struct InMemorySignupCodes {
    rows: Mutex<Vec<CodeRow>>,
    accounts: Option<std::sync::Arc<InMemorySignInAccounts>>,
}

impl InMemorySignupCodes {
    pub fn confirming(accounts: std::sync::Arc<InMemorySignInAccounts>) -> Self {
        Self {
            rows: Mutex::default(),
            accounts: Some(accounts),
        }
    }

    /// Every code issued, oldest first, with its expiry.
    pub fn issued(&self) -> Vec<(UserId, OtpCode, OffsetDateTime)> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .map(|row| (row.user, row.code.clone(), row.expires_at))
            .collect()
    }
}

#[async_trait::async_trait]
impl SignupCodes for InMemorySignupCodes {
    async fn issue(&self, user: UserId, expires_at: OffsetDateTime) -> Result<OtpCode, AuthError> {
        let mut rows = self.rows.lock().unwrap();
        for row in rows.iter_mut().filter(|row| row.user == user) {
            row.spent = true;
        }
        let code = OtpCode::parse(&format!("{:06}", rows.len() + 1)).unwrap();
        rows.push(CodeRow {
            user,
            code: code.clone(),
            expires_at,
            spent: false,
            attempts: 0,
        });
        Ok(code)
    }

    async fn issued_since(&self, user: UserId, since: OffsetDateTime) -> Result<usize, AuthError> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .filter(|row| row.user == user && row.expires_at - SIGNUP_CODE_TTL > since)
            .count())
    }

    async fn attempt(
        &self,
        user: UserId,
        code: &OtpCode,
        now: OffsetDateTime,
    ) -> Result<CodeAttempt, AuthError> {
        let mut rows = self.rows.lock().unwrap();
        let Some(live) = rows
            .iter_mut()
            .rev()
            .find(|row| row.user == user && !row.spent && row.expires_at > now)
        else {
            return Ok(CodeAttempt::NoCode);
        };
        if live.attempts >= CODE_ATTEMPTS {
            return Ok(CodeAttempt::Exhausted);
        }
        if live.code != *code {
            live.attempts += 1;
            return Ok(CodeAttempt::Wrong {
                left: CODE_ATTEMPTS - live.attempts,
            });
        }
        live.spent = true;
        if let Some(accounts) = &self.accounts {
            accounts.confirm(user);
        }
        Ok(CodeAttempt::Confirmed)
    }

    async fn delete_spent(
        &self,
        now: OffsetDateTime,
        issued_before: OffsetDateTime,
    ) -> Result<usize, AuthError> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|row| {
            !(row.spent || row.expires_at < now)
                || row.expires_at - SIGNUP_CODE_TTL >= issued_before
        });
        Ok(before - rows.len())
    }
}

/// `sfx01`, `sfx02`, …
#[derive(Default)]
pub struct CountingSuffixes {
    given: AtomicUsize,
}

impl HandleSuffixes for CountingSuffixes {
    fn fresh(&self) -> HandleSuffix {
        HandleSuffix::parse(&format!(
            "sfx{:02}",
            self.given.fetch_add(1, Ordering::SeqCst) + 1
        ))
        .expect("a–z0–9")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mail {
    pub to: String,
    pub name: String,
    pub code: OtpCode,
}

#[derive(Default)]
pub struct RecordingMailer {
    sent: Mutex<Vec<Mail>>,
    down: Mutex<bool>,
}

impl RecordingMailer {
    pub fn sent(&self) -> Vec<Mail> {
        self.sent.lock().unwrap().clone()
    }

    /// Every send fails from now on.
    pub fn break_down(&self) {
        *self.down.lock().unwrap() = true;
    }
}

#[async_trait::async_trait]
impl SignupMailer for RecordingMailer {
    async fn send_code(&self, to: &str, name: &str, code: &OtpCode) -> Result<(), AuthError> {
        if *self.down.lock().unwrap() {
            return Err(anyhow::anyhow!("the mail server is down").into());
        }
        self.sent.lock().unwrap().push(Mail {
            to: to.to_owned(),
            name: name.to_owned(),
            code: code.clone(),
        });
        Ok(())
    }
}

/// Seeds what the sign-in stores read: accounts are written by other contexts.
#[async_trait::async_trait]
pub trait SignInSeeds: Send + Sync {
    async fn sign_up(&self, account: &SignInAccount);
}

/// Publishes client documents where a [`Clients`] adapter will look for them.
#[async_trait::async_trait]
pub trait ClientSeeds: Send + Sync {
    /// Where documents are published, e.g. `http://127.0.0.1:41234`.
    fn origin(&self) -> String;
    async fn publish(&self, path: &str, document: &ClientDocument);
}

#[async_trait::async_trait]
impl SignInSeeds for InMemorySignInAccounts {
    async fn sign_up(&self, account: &SignInAccount) {
        self.accounts
            .lock()
            .unwrap()
            .push((account.clone(), OffsetDateTime::now_utc()));
    }
}

#[async_trait::async_trait]
impl ClientSeeds for InMemoryClients {
    fn origin(&self) -> String {
        "http://localhost:5173".to_owned()
    }

    async fn publish(&self, path: &str, document: &ClientDocument) {
        let id = ClientId::parse(&format!("{}{path}", self.origin())).unwrap();
        let client =
            Client::from_document(id, document.clone(), ClientPolicy { allow_http: true }).unwrap();
        self.clients.lock().unwrap().push(client);
    }
}

/// What every sign-in store must do.
pub mod contract {
    use super::*;

    pub async fn a_published_client_is_found_by_its_url(
        clients: &dyn Clients,
        seeds: &dyn ClientSeeds,
    ) {
        let origin = seeds.origin();
        let id = format!("{origin}/clients/web.json");
        seeds
            .publish(
                "/clients/web.json",
                &ClientDocument {
                    client_id: id.clone(),
                    client_name: Some("Pīna'i".to_owned()),
                    application_type: None,
                    redirect_uris: vec![format!("{origin}/callback")],
                    post_logout_redirect_uris: vec![format!("{origin}/")],
                    scope: None,
                    token_endpoint_auth_method: None,
                },
            )
            .await;

        let found = clients
            .find(&ClientId::parse(&id).unwrap())
            .await
            .unwrap()
            .expect("the published client");
        assert_eq!(found.name, "Pīna'i");
        assert!(found.allows(&format!("{origin}/callback")));
        assert!(found.may_return_to(&format!("{origin}/")));
        assert_eq!(
            clients
                .find(&ClientId::parse(&format!("{origin}/clients/nobody.json")).unwrap())
                .await
                .unwrap(),
            None
        );
    }

    pub async fn an_account_is_found_by_email_and_id_with_its_sign_in_state(
        accounts: &dyn SignInAccounts,
        seeds: &dyn SignInSeeds,
    ) {
        let alice = signed_up("alice");
        let bob = SignInAccount {
            display_name: None,
            email_verified: false,
            totp_enabled: true,
            ..signed_up("bob")
        };
        seeds.sign_up(&alice).await;
        seeds.sign_up(&bob).await;

        assert_eq!(
            accounts.by_email(&email(&alice.email)).await.unwrap(),
            Some(alice.clone())
        );
        assert_eq!(accounts.by_id(bob.id).await.unwrap(), Some(bob));
        assert_eq!(
            accounts.by_email(&email("carol@idp.test")).await.unwrap(),
            None
        );
        assert_eq!(accounts.by_id(UserId::generate()).await.unwrap(), None);
    }

    pub async fn a_code_is_good_once_and_only_until_it_expires(
        codes: &dyn AuthorizationCodes,
        user: UserId,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let grant = Grant::answering(user, &a_request());
        let fresh = codes
            .issue(&grant, now + Duration::minutes(10))
            .await
            .unwrap();
        let stale = codes
            .issue(&grant, now - Duration::seconds(1))
            .await
            .unwrap();
        let other = codes
            .issue(&grant, now + Duration::minutes(10))
            .await
            .unwrap();

        let first = codes.consume(&fresh, now).await.unwrap();
        let again = codes.consume(&fresh, now).await.unwrap();
        let expired = codes.consume(&stale, now).await.unwrap();
        let unknown = codes
            .consume(&AuthorizationCode::new("no-such-code".to_owned()), now)
            .await
            .unwrap();

        assert_ne!(fresh, other);
        assert_eq!(first, Some(grant.clone()));
        assert_eq!((again, expired, unknown), (None, None, None));
        assert_eq!(codes.consume(&other, now).await.unwrap(), Some(grant));
    }

    fn email(raw: &str) -> Email {
        Email::parse(raw).unwrap()
    }

    pub fn a_new_account(name: &str) -> NewAccount {
        let username = Handle::parse(&format!("{name}_sfx01")).unwrap();
        NewAccount {
            id: UserId::generate(),
            actor_uri: ActorUri::parse(&format!(
                "http://localhost:8080/users/{}",
                username.as_str()
            ))
            .unwrap(),
            username,
            display_name: name.to_owned(),
            email: email(&format!("{name}@idp.test")),
            password_hash: PlainHasher::hash(&format!("{name}-password")),
        }
    }

    pub async fn an_address_or_a_handle_is_one_accounts_whatever_its_case(
        sign_ups: &dyn SignUps,
        accounts: &dyn SignInAccounts,
        seeds: &dyn SignInSeeds,
    ) {
        // Stored before addresses were kept lowercase.
        let carol = SignInAccount {
            email: "Carol@IDP.test".to_owned(),
            ..signed_up("carol")
        };
        seeds.sign_up(&carol).await;
        let bob = a_new_account("bob");
        let dave = a_new_account("dave");

        let created = sign_ups.create(&bob).await.unwrap();
        let bobs_address = sign_ups
            .create(&NewAccount {
                email: bob.email.clone(),
                ..dave.clone()
            })
            .await
            .unwrap();
        let carols_address = sign_ups
            .create(&NewAccount {
                email: email("carol@idp.test"),
                ..dave.clone()
            })
            .await
            .unwrap();
        let bobs_handle = sign_ups
            .create(&NewAccount {
                id: UserId::generate(),
                email: email("robert@idp.test"),
                ..bob.clone()
            })
            .await
            .unwrap();

        assert_eq!(
            (created, bobs_address, carols_address, bobs_handle),
            (
                Registration::Created,
                Registration::EmailTaken,
                Registration::EmailTaken,
                Registration::HandleTaken
            )
        );
        assert_eq!(
            accounts
                .by_email(&email("CAROL@idp.test"))
                .await
                .unwrap()
                .map(|found| found.id),
            Some(carol.id)
        );
        assert_eq!(accounts.by_id(dave.id).await.unwrap(), None);
    }

    pub async fn a_new_account_is_unconfirmed_and_found_by_its_email(
        sign_ups: &dyn SignUps,
        accounts: &dyn SignInAccounts,
    ) {
        let bob = a_new_account("bob");

        sign_ups.create(&bob).await.unwrap();

        let found = accounts.by_email(&bob.email).await.unwrap();
        assert_eq!(
            found,
            Some(SignInAccount {
                id: bob.id,
                email: bob.email.as_str().to_owned(),
                username: bob.username.as_str().to_owned(),
                display_name: Some("bob".to_owned()),
                password_hash: bob.password_hash.clone(),
                email_verified: false,
                totp_enabled: false,
            })
        );
        assert_eq!(accounts.by_id(bob.id).await.unwrap(), found);
    }

    pub async fn accounts_left_unconfirmed_are_deleted_after_their_grace(
        sign_ups: &dyn SignUps,
        accounts: &dyn SignInAccounts,
        seeds: &dyn SignInSeeds,
    ) {
        let now = OffsetDateTime::now_utc();
        let alice = signed_up("alice");
        let bob = a_new_account("bob");
        seeds.sign_up(&alice).await;
        sign_ups.create(&bob).await.unwrap();

        let early = sign_ups
            .delete_unverified(now - Duration::days(1))
            .await
            .unwrap();
        let late = sign_ups
            .delete_unverified(now + Duration::minutes(1))
            .await
            .unwrap();

        assert_eq!((early, late), (0, 1));
        assert_eq!(accounts.by_id(bob.id).await.unwrap(), None);
        assert!(accounts.by_id(alice.id).await.unwrap().is_some());
    }

    fn another_than(code: &OtpCode) -> OtpCode {
        OtpCode::parse(if code.as_str() == "000000" {
            "111111"
        } else {
            "000000"
        })
        .unwrap()
    }

    pub async fn a_signup_code_confirms_its_account_once(
        codes: &dyn SignupCodes,
        accounts: &dyn SignInAccounts,
        user: UserId,
    ) {
        let now = OffsetDateTime::now_utc();
        let code = codes.issue(user, now + SIGNUP_CODE_TTL).await.unwrap();

        let first = codes.attempt(user, &code, now).await.unwrap();
        let again = codes.attempt(user, &code, now).await.unwrap();

        assert_eq!(
            (first, again),
            (CodeAttempt::Confirmed, CodeAttempt::NoCode)
        );
        assert!(accounts.by_id(user).await.unwrap().unwrap().email_verified);
    }

    pub async fn wrong_codes_count_down_to_exhaustion(codes: &dyn SignupCodes, user: UserId) {
        let now = OffsetDateTime::now_utc();
        let code = codes.issue(user, now + SIGNUP_CODE_TTL).await.unwrap();
        let wrong = another_than(&code);

        let mut answers = Vec::new();
        for _ in 0..CODE_ATTEMPTS {
            answers.push(codes.attempt(user, &wrong, now).await.unwrap());
        }
        let right_too_late = codes.attempt(user, &code, now).await.unwrap();

        assert_eq!(
            answers,
            (0..CODE_ATTEMPTS)
                .rev()
                .map(|left| CodeAttempt::Wrong { left })
                .collect::<Vec<_>>()
        );
        assert_eq!(right_too_late, CodeAttempt::Exhausted);
    }

    pub async fn only_the_latest_live_code_counts(codes: &dyn SignupCodes, user: UserId) {
        let now = OffsetDateTime::now_utc();
        let older = codes.issue(user, now + SIGNUP_CODE_TTL).await.unwrap();
        let latest = codes.issue(user, now + SIGNUP_CODE_TTL).await.unwrap();

        let retired = codes.attempt(user, &older, now).await.unwrap();
        let after_expiry = codes
            .attempt(user, &latest, now + SIGNUP_CODE_TTL)
            .await
            .unwrap();

        if older != latest {
            assert_eq!(
                retired,
                CodeAttempt::Wrong {
                    left: CODE_ATTEMPTS - 1
                }
            );
        }
        assert_eq!(after_expiry, CodeAttempt::NoCode);
    }

    pub async fn the_codes_issued_lately_are_counted(codes: &dyn SignupCodes, user: UserId) {
        let now = OffsetDateTime::now_utc();
        for _ in 0..3 {
            codes.issue(user, now + SIGNUP_CODE_TTL).await.unwrap();
        }

        let lately = codes
            .issued_since(user, now - Duration::minutes(10))
            .await
            .unwrap();
        let later = codes
            .issued_since(user, now + Duration::minutes(1))
            .await
            .unwrap();
        let others = codes
            .issued_since(UserId::generate(), now - Duration::minutes(10))
            .await
            .unwrap();

        assert_eq!((lately, later, others), (3, 0, 0));
    }

    pub fn a_secret(n: u8) -> TotpSecret {
        TotpSecret::parse(vec![n; TotpSecret::LEN]).unwrap()
    }

    pub async fn an_enrollment_waits_until_the_second_factor_is_turned_on(
        factors: &dyn SecondFactors,
        user: UserId,
    ) {
        factors.start_enrollment(user, &a_secret(1)).await.unwrap();
        factors.start_enrollment(user, &a_secret(2)).await.unwrap();

        let pending = factors.pending(user).await.unwrap();
        let secret = factors.secret(user).await.unwrap();
        factors.enable(user, &a_secret(2), 1_000).await.unwrap();

        assert_eq!((pending, secret), (Some(a_secret(2)), None));
        assert_eq!(factors.pending(user).await.unwrap(), None);
        assert_eq!(factors.secret(user).await.unwrap(), Some(a_secret(2)));
    }

    pub async fn turning_the_second_factor_on_mints_its_codes_and_off_forgets_everything(
        factors: &dyn SecondFactors,
        accounts: &dyn SignInAccounts,
        user: UserId,
    ) {
        let codes = factors.enable(user, &a_secret(3), 1_000).await.unwrap();
        let on = (
            factors.secret(user).await.unwrap(),
            accounts.by_id(user).await.unwrap().unwrap().totp_enabled,
        );
        let enrollment_step_used = !factors.use_step(user, 1_000).await.unwrap();
        let recovers = factors.use_recovery_code(user, &codes[0]).await.unwrap();
        factors.start_enrollment(user, &a_secret(4)).await.unwrap();
        factors.disable(user).await.unwrap();
        let off = (
            factors.secret(user).await.unwrap(),
            accounts.by_id(user).await.unwrap().unwrap().totp_enabled,
        );

        assert_eq!(codes.len(), RECOVERY_CODES);
        assert_eq!(on, (Some(a_secret(3)), true));
        assert!(enrollment_step_used && recovers);
        assert_eq!(off, (None, false));
        assert!(!factors.use_recovery_code(user, &codes[1]).await.unwrap());
        assert_eq!(factors.pending(user).await.unwrap(), None);
    }

    pub async fn a_recovery_code_is_used_once_and_a_new_set_replaces_the_old(
        factors: &dyn SecondFactors,
        user: UserId,
    ) {
        let codes = factors.enable(user, &a_secret(5), 1_000).await.unwrap();
        let distinct: std::collections::HashSet<&String> = codes.iter().collect();

        let first = factors.use_recovery_code(user, &codes[0]).await.unwrap();
        let again = factors.use_recovery_code(user, &codes[0]).await.unwrap();
        let loose = factors
            .use_recovery_code(
                user,
                &format!(" {} ", codes[1].to_lowercase().replace('-', "")),
            )
            .await
            .unwrap();
        let others = factors
            .use_recovery_code(UserId::generate(), &codes[2])
            .await
            .unwrap();
        let fresh = factors.replace_recovery_codes(user).await.unwrap();
        let replaced = factors.use_recovery_code(user, &codes[2]).await.unwrap();
        let new = factors.use_recovery_code(user, &fresh[0]).await.unwrap();

        assert_eq!(
            (codes.len(), distinct.len()),
            (RECOVERY_CODES, RECOVERY_CODES)
        );
        assert_eq!(
            (first, again, loose, others, replaced, new),
            (true, false, true, false, false, true)
        );
    }

    pub async fn a_time_step_is_used_once_and_only_forward(
        factors: &dyn SecondFactors,
        user: UserId,
    ) {
        factors.enable(user, &a_secret(4), 1).await.unwrap();

        let steps = [
            factors.use_step(user, 1_000).await.unwrap(),
            factors.use_step(user, 1_000).await.unwrap(),
            factors.use_step(user, 999).await.unwrap(),
            factors.use_step(user, 1_001).await.unwrap(),
        ];
        factors.disable(user).await.unwrap();
        factors.enable(user, &a_secret(5), 1).await.unwrap();
        let after_a_new_secret = factors.use_step(user, 1_000).await.unwrap();

        assert_eq!(steps, [true, false, false, true]);
        assert!(after_a_new_secret);
    }

    pub async fn a_ticket_gives_five_attempts_until_spent_or_expired(
        tickets: &dyn LoginTickets,
        user: UserId,
    ) {
        let now = OffsetDateTime::now_utc();
        let open = tickets
            .open(user, &a_request(), now + LOGIN_TICKET_TTL)
            .await
            .unwrap();

        let mut attempts = Vec::new();
        for _ in 0..=TICKET_ATTEMPTS {
            attempts.push(tickets.reserve_attempt(open, now).await.unwrap());
        }
        let other = tickets
            .open(user, &a_request(), now + LOGIN_TICKET_TTL)
            .await
            .unwrap();
        let expired = tickets
            .reserve_attempt(other, now + LOGIN_TICKET_TTL)
            .await
            .unwrap();
        tickets.consume(other).await.unwrap();
        let spent = tickets.reserve_attempt(other, now).await.unwrap();

        let open_ticket = |attempts| {
            TicketAttempt::Open(Ticket {
                user,
                request: a_request(),
                attempts,
            })
        };
        assert_eq!(
            attempts,
            vec![
                open_ticket(1),
                open_ticket(2),
                open_ticket(3),
                open_ticket(4),
                open_ticket(5),
                TicketAttempt::Exhausted
            ]
        );
        assert_eq!((expired, spent), (TicketAttempt::Gone, TicketAttempt::Gone));
    }

    /// `user` and `other` are two accounts.
    pub async fn an_app_signed_in_to_is_remembered_and_staying_signed_in_kept(
        sign_ins: &dyn ClientSignIns,
        user: UserId,
        other: UserId,
    ) {
        let now = OffsetDateTime::now_utc();
        let web = ClientSignIn::of(user, &a_request());
        let staying = ClientSignIn {
            offline_access: true,
            ..web.clone()
        };

        let before = sign_ins.find(user, &web.client).await.unwrap();
        sign_ins.remember(&web, now).await.unwrap();
        let remembered = sign_ins.find(user, &web.client).await.unwrap();
        sign_ins.remember(&staying, now).await.unwrap();
        sign_ins.remember(&web, now).await.unwrap();
        let kept = sign_ins.find(user, &web.client).await.unwrap();
        let another_app = sign_ins
            .find(
                user,
                &ClientId::parse("https://other.test/oauth-client.json").unwrap(),
            )
            .await
            .unwrap();
        let another_account = sign_ins.find(other, &web.client).await.unwrap();

        assert_eq!(before, None);
        assert_eq!(remembered, Some(web));
        assert_eq!(
            kept,
            Some(staying),
            "staying signed in, once given, is kept"
        );
        assert_eq!((another_app, another_account), (None, None));
    }

    pub async fn an_open_ticket_is_found_until_spent_or_expired(
        tickets: &dyn LoginTickets,
        user: UserId,
    ) {
        let now = OffsetDateTime::now_utc();
        let open = tickets
            .open(user, &a_request(), now + LOGIN_TICKET_TTL)
            .await
            .unwrap();
        tickets.reserve_attempt(open, now).await.unwrap();
        tickets.reserve_attempt(open, now).await.unwrap();

        let found = tickets.find(open, now).await.unwrap();
        let expired = tickets.find(open, now + LOGIN_TICKET_TTL).await.unwrap();
        let spent = tickets.consume(open).await.unwrap();
        let again = tickets.consume(open).await.unwrap();
        let gone = tickets.find(open, now).await.unwrap();

        assert_eq!(
            found,
            Some(Ticket {
                user,
                request: a_request(),
                attempts: 2,
            })
        );
        assert_eq!((expired, spent, again, gone), (None, true, false, None));
    }

    pub async fn spent_codes_are_deleted_and_the_live_one_kept(
        codes: &dyn SignupCodes,
        user: UserId,
    ) {
        let now = OffsetDateTime::now_utc();
        codes.issue(user, now + SIGNUP_CODE_TTL).await.unwrap();
        let live = codes.issue(user, now + SIGNUP_CODE_TTL).await.unwrap();

        let kept_young = codes
            .delete_spent(now, now - Duration::hours(1))
            .await
            .unwrap();
        let deleted = codes
            .delete_spent(now, now + Duration::minutes(1))
            .await
            .unwrap();

        assert_eq!((kept_young, deleted), (0, 1));
        assert_eq!(
            codes.attempt(user, &live, now).await.unwrap(),
            CodeAttempt::Confirmed
        );
    }
}

#[cfg(test)]
mod tests;
