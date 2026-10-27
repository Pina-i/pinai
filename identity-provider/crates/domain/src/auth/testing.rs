//! In-memory fakes of the sign-in ports and the contract every store must satisfy.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use time::{Duration, OffsetDateTime};

use crate::identity::{ActorUri, Handle, HandleSuffix};
use crate::{DeviceId, InvitationId, SessionId, TicketId, UserId};

use super::{
    AddressHolder, AdminFacts, AuthError, Authenticator, AuthorizationCode, AuthorizationCodes,
    AuthorizationRequest, CODE_ATTEMPTS, Client, ClientDocument, ClientId, ClientKind,
    ClientPolicy, ClientSignIn, ClientSignIns, Clients, CodeAttempt, CodeChallenge, Email, Grant,
    HandleSuffixes, INVITATION_TTL, InstanceMember, InstanceMembers, Invitation, InvitationToken,
    Invitations, LOGIN_TICKET_TTL, LoginTickets, NewAccount, OpenInvitation, OpenReset, OtpCode,
    PasswordChange, PasswordHash, PasswordHasher, PasswordReset, PasswordResets, Presentation,
    RECOVERY_CODES, REQUESTED_RESET_TTL, RESET_REQUEST_LIMIT, RESET_REQUEST_WINDOW, RESET_TTL,
    RefreshLink, RefreshToken, RefreshTokens, Registration, ResetBy, ResetMail, ResetMailer,
    ResetToken, RevokedReason, Rotation, SESSION_IDLE, SESSION_RETENTION, SIGNUP_CODE_TTL,
    SecondFactors, Session, SessionKind, SessionNotifier, Sessions, SignInAccount, SignInAccounts,
    SignUps, SignupCodes, SignupMailer, TICKET_ATTEMPTS, Ticket, TicketAttempt, TokenIssuer,
    TotpSecret, may_request_reset,
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

/// The actor URI a seeded account has, on the tests' instance: `http://localhost:8080/users/{handle}`.
pub fn seeded_actor(account: &SignInAccount) -> ActorUri {
    ActorUri::parse(&format!("http://localhost:8080/users/{}", account.username))
        .expect("a seeded account's handle")
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
        admitted: false,
        admin: false,
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
pub struct InMemorySessions {
    sessions: Mutex<Vec<(Session, Option<RevokedReason>)>>,
}

impl InMemorySessions {
    /// Every session, ended or not, oldest first.
    pub fn all(&self) -> Vec<Session> {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .map(|(session, _)| session.clone())
            .collect()
    }

    /// A live session of `user`'s, opened now: what a test's bearer token belongs to.
    pub fn live(&self, user: UserId) -> SessionId {
        let id = SessionId::generate();
        let now = OffsetDateTime::now_utc();
        self.sessions.lock().unwrap().push((
            Session {
                id,
                user,
                kind: SessionKind::Browser,
                device: None,
                created_at: now,
                last_used_at: now,
                authenticated_at: now,
                revoked_at: None,
            },
            None,
        ));
        id
    }

    pub fn reason(&self, id: SessionId) -> Option<RevokedReason> {
        self.sessions
            .lock()
            .unwrap()
            .iter()
            .find(|(session, _)| session.id == id)
            .and_then(|(_, reason)| *reason)
    }

    /// Ends the sessions not ended yet that `which` picks, as they are once ended.
    fn end(
        &self,
        which: impl Fn(&Session) -> bool,
        reason: RevokedReason,
        now: OffsetDateTime,
    ) -> Vec<Session> {
        let mut ended = Vec::new();
        for (session, why) in self.sessions.lock().unwrap().iter_mut() {
            if session.revoked_at.is_none() && which(session) {
                session.revoked_at = Some(now);
                *why = Some(reason);
                ended.push(session.clone());
            }
        }
        ended
    }
}

#[async_trait::async_trait]
impl Sessions for InMemorySessions {
    async fn open(
        &self,
        user: UserId,
        kind: &SessionKind,
        now: OffsetDateTime,
    ) -> Result<SessionId, AuthError> {
        let id = SessionId::generate();
        self.sessions.lock().unwrap().push((
            Session {
                id,
                user,
                kind: kind.clone(),
                device: None,
                created_at: now,
                last_used_at: now,
                authenticated_at: now,
                revoked_at: None,
            },
            None,
        ));
        Ok(id)
    }

    async fn find(&self, id: SessionId) -> Result<Option<Session>, AuthError> {
        Ok(self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .find(|(session, _)| session.id == id)
            .map(|(session, _)| session.clone()))
    }

    async fn touch(&self, id: SessionId, now: OffsetDateTime) -> Result<(), AuthError> {
        for (session, _) in self.sessions.lock().unwrap().iter_mut() {
            if session.id == id {
                session.last_used_at = now;
            }
        }
        Ok(())
    }

    async fn authenticate(&self, id: SessionId, at: OffsetDateTime) -> Result<(), AuthError> {
        for (session, _) in self.sessions.lock().unwrap().iter_mut() {
            if session.id == id {
                session.authenticated_at = at;
            }
        }
        Ok(())
    }

    async fn revoke(
        &self,
        id: SessionId,
        reason: RevokedReason,
        now: OffsetDateTime,
    ) -> Result<bool, AuthError> {
        let mut sessions = self.sessions.lock().unwrap();
        let Some((session, why)) = sessions
            .iter_mut()
            .find(|(session, _)| session.id == id && session.revoked_at.is_none())
        else {
            return Ok(false);
        };
        session.revoked_at = Some(now);
        *why = Some(reason);
        Ok(true)
    }

    async fn delete_ended(&self, before: OffsetDateTime) -> Result<usize, AuthError> {
        let mut sessions = self.sessions.lock().unwrap();
        let held = sessions.len();
        sessions.retain(|(session, _)| {
            !(session.revoked_at.is_some_and(|at| at < before)
                || session.last_used_at < before - SESSION_IDLE)
        });
        Ok(held - sessions.len())
    }

    async fn of_user(&self, user: UserId) -> Result<Vec<Session>, AuthError> {
        Ok(self
            .all()
            .into_iter()
            .filter(|session| session.user == user)
            .collect())
    }

    async fn link(
        &self,
        id: SessionId,
        device: DeviceId,
        now: OffsetDateTime,
    ) -> Result<Vec<Session>, AuthError> {
        let replaced = self.end(
            |session| session.device == Some(device) && session.id != id,
            RevokedReason::Replaced,
            now,
        );
        for (session, _) in self.sessions.lock().unwrap().iter_mut() {
            if session.id == id {
                session.device = Some(device);
            }
        }
        Ok(replaced)
    }

    async fn revoke_device(
        &self,
        user: UserId,
        device: DeviceId,
        now: OffsetDateTime,
    ) -> Result<Vec<Session>, AuthError> {
        Ok(self.end(
            |session| session.user == user && session.device == Some(device),
            RevokedReason::DeviceRevoked,
            now,
        ))
    }

    async fn revoke_others(
        &self,
        user: UserId,
        keep: SessionId,
        now: OffsetDateTime,
    ) -> Result<Vec<Session>, AuthError> {
        Ok(self.end(
            |session| session.user == user && session.id != keep,
            RevokedReason::SignedOutElsewhere,
            now,
        ))
    }
}

/// The sessions told ended, in order.
#[derive(Default)]
pub struct RecordingSessionNotifier {
    ended: Mutex<Vec<SessionId>>,
}

impl RecordingSessionNotifier {
    pub fn ended(&self) -> Vec<SessionId> {
        self.ended.lock().unwrap().clone()
    }
}

impl SessionNotifier for RecordingSessionNotifier {
    fn ended(&self, session: &Session) {
        self.ended.lock().unwrap().push(session.id);
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

struct InvitationRow {
    invitation: Invitation,
    token: InvitationToken,
}

/// The accounts and the invitations that let some in, as `users` and `invitations` keep them.
#[derive(Default)]
pub struct InMemorySignInAccounts {
    /// Each with when it was created.
    accounts: Mutex<Vec<(SignInAccount, OffsetDateTime)>>,
    created: Mutex<Vec<NewAccount>>,
    invitations: Mutex<Vec<InvitationRow>>,
    tokens: AtomicUsize,
    /// Who vouched for each account an invitation let in.
    vouched: Mutex<HashMap<UserId, UserId>>,
    actors: Mutex<HashMap<UserId, ActorUri>>,
}

impl InMemorySignInAccounts {
    pub fn with(accounts: impl IntoIterator<Item = SignInAccount>) -> Self {
        let now = OffsetDateTime::now_utc();
        let accounts: Vec<SignInAccount> = accounts.into_iter().collect();
        Self {
            actors: Mutex::new(
                accounts
                    .iter()
                    .map(|account| (account.id, seeded_actor(account)))
                    .collect(),
            ),
            accounts: Mutex::new(accounts.into_iter().map(|a| (a, now)).collect()),
            ..Self::default()
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

    fn set_password(&self, user: UserId, hash: &PasswordHash) {
        let mut accounts = self.accounts.lock().unwrap();
        if let Some((account, _)) = accounts.iter_mut().find(|(a, _)| a.id == user) {
            account.password_hash = hash.clone();
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

type Held = Vec<(SignInAccount, OffsetDateTime)>;

impl InMemorySignInAccounts {
    /// Why the account can't be created beside those held, if it can't.
    fn taken(accounts: &Held, account: &NewAccount) -> Option<Registration> {
        if accounts
            .iter()
            .any(|(held, _)| held.email.to_lowercase() == account.email.as_str())
        {
            return Some(Registration::EmailTaken);
        }
        accounts
            .iter()
            .any(|(held, _)| held.username == account.username.as_str())
            .then_some(Registration::HandleTaken)
    }

    fn add(&self, accounts: &mut Held, account: &NewAccount, admitted: bool, admin: bool) {
        self.created.lock().unwrap().push(account.clone());
        self.actors
            .lock()
            .unwrap()
            .insert(account.id, account.actor_uri.clone());
        accounts.push((
            SignInAccount {
                id: account.id,
                email: account.email.as_str().to_owned(),
                username: account.username.as_str().to_owned(),
                display_name: Some(account.display_name.clone()),
                password_hash: account.password_hash.clone(),
                email_verified: false,
                admitted,
                admin,
                totp_enabled: false,
            },
            OffsetDateTime::now_utc(),
        ));
    }

    fn insert(&self, account: &NewAccount, admitted: bool, admin: bool) -> Registration {
        let mut accounts = self.accounts.lock().unwrap();
        if let Some(taken) = Self::taken(&accounts, account) {
            return taken;
        }
        self.add(&mut accounts, account, admitted, admin);
        Registration::Created
    }

    /// The invitation as it is shown, while its creator is held.
    fn open_one(accounts: &Held, invitation: &Invitation) -> Option<OpenInvitation> {
        let (creator, _) = accounts
            .iter()
            .find(|(held, _)| held.id == invitation.created_by)?;
        Some(OpenInvitation {
            id: invitation.id,
            inviter: creator.display_name.clone(),
            created_at: invitation.created_at,
            expires_at: invitation.expires_at,
        })
    }
}

#[async_trait::async_trait]
impl SignUps for InMemorySignInAccounts {
    async fn create(&self, account: &NewAccount) -> Result<Registration, AuthError> {
        Ok(self.insert(account, false, false))
    }

    async fn create_admin(
        &self,
        account: &NewAccount,
        _admitted_at: OffsetDateTime,
    ) -> Result<Registration, AuthError> {
        Ok(self.insert(account, true, true))
    }

    async fn create_invited(
        &self,
        account: &NewAccount,
        invitation: InvitationId,
        now: OffsetDateTime,
    ) -> Result<Registration, AuthError> {
        let mut accounts = self.accounts.lock().unwrap();
        let mut invitations = self.invitations.lock().unwrap();
        let Some(row) = invitations
            .iter_mut()
            .find(|row| row.invitation.id == invitation && row.invitation.is_open(now))
        else {
            return Ok(Registration::InvitationSpent);
        };
        if let Some(taken) = Self::taken(&accounts, account) {
            return Ok(taken);
        }
        row.invitation.used_at = Some(now);
        self.vouched
            .lock()
            .unwrap()
            .insert(account.id, row.invitation.created_by);
        self.add(&mut accounts, account, true, false);
        Ok(Registration::Created)
    }

    async fn admin_facts(&self, address: Option<&Email>) -> Result<AdminFacts, AuthError> {
        let accounts = self.accounts.lock().unwrap();
        let admin_exists = accounts.iter().any(|(held, _)| held.admin);
        let held = address.and_then(|address| {
            accounts
                .iter()
                .find(|(held, _)| held.email.to_lowercase() == address.as_str())
        });
        let holder = match held {
            None => AddressHolder::Nobody,
            Some((held, _)) if held.admin => AddressHolder::Admin,
            Some(_) => AddressHolder::NotAdmin,
        };
        Ok(AdminFacts {
            holder,
            admin_exists,
        })
    }

    async fn delete_unverified(&self, created_before: OffsetDateTime) -> Result<usize, AuthError> {
        let mut accounts = self.accounts.lock().unwrap();
        let before = accounts.len();
        accounts.retain(|(account, created)| {
            account.email_verified || account.admitted || *created >= created_before
        });
        Ok(before - accounts.len())
    }
}

/// Tokens of known bytes — a fake's tokens are no secret — kept as they are.
#[async_trait::async_trait]
impl Invitations for InMemorySignInAccounts {
    async fn issue(
        &self,
        by: UserId,
        now: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<(InvitationId, InvitationToken), AuthError> {
        let n = self.tokens.fetch_add(1, Ordering::SeqCst) + 1;
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&u64::try_from(n).unwrap_or(u64::MAX).to_le_bytes());
        let token = InvitationToken::from_bytes(bytes);
        let id = InvitationId::generate();
        self.invitations.lock().unwrap().push(InvitationRow {
            invitation: Invitation {
                id,
                created_by: by,
                created_at: now,
                expires_at,
                used_at: None,
                revoked_at: None,
            },
            token: token.clone(),
        });
        Ok((id, token))
    }

    async fn find_open(
        &self,
        token: &InvitationToken,
        now: OffsetDateTime,
    ) -> Result<Option<OpenInvitation>, AuthError> {
        let accounts = self.accounts.lock().unwrap();
        let invitations = self.invitations.lock().unwrap();
        Ok(invitations
            .iter()
            .find(|row| row.token == *token && row.invitation.is_open(now))
            .and_then(|row| Self::open_one(&accounts, &row.invitation)))
    }

    async fn list_open(&self, now: OffsetDateTime) -> Result<Vec<OpenInvitation>, AuthError> {
        let accounts = self.accounts.lock().unwrap();
        let invitations = self.invitations.lock().unwrap();
        let mut open: Vec<OpenInvitation> = invitations
            .iter()
            .filter(|row| row.invitation.is_open(now))
            .filter_map(|row| Self::open_one(&accounts, &row.invitation))
            .collect();
        open.sort_by_key(|open| std::cmp::Reverse((open.created_at, open.id)));
        Ok(open)
    }

    async fn revoke(&self, id: InvitationId, now: OffsetDateTime) -> Result<bool, AuthError> {
        let mut invitations = self.invitations.lock().unwrap();
        let Some(row) = invitations
            .iter_mut()
            .find(|row| row.invitation.id == id && row.invitation.is_open(now))
        else {
            return Ok(false);
        };
        row.invitation.revoked_at = Some(now);
        Ok(true)
    }

    async fn delete_ended(&self, before: OffsetDateTime) -> Result<usize, AuthError> {
        let mut invitations = self.invitations.lock().unwrap();
        let held = invitations.len();
        invitations.retain(|row| row.invitation.ended_at() >= before);
        Ok(held - invitations.len())
    }
}

struct ResetRow {
    reset: PasswordReset,
    token: ResetToken,
    /// The link that replaced it.
    replaced_by: Option<ResetToken>,
}

/// Reset links as `password_resets` keeps them, over the accounts whose password they set and the
/// sessions and second-factor tickets they end.
pub struct InMemoryPasswordResets {
    accounts: std::sync::Arc<InMemorySignInAccounts>,
    sessions: std::sync::Arc<InMemorySessions>,
    tickets: std::sync::Arc<RecordingTickets>,
    rows: Mutex<Vec<ResetRow>>,
    tokens: AtomicUsize,
}

impl InMemoryPasswordResets {
    pub fn over(
        accounts: std::sync::Arc<InMemorySignInAccounts>,
        sessions: std::sync::Arc<InMemorySessions>,
        tickets: std::sync::Arc<RecordingTickets>,
    ) -> Self {
        Self {
            accounts,
            sessions,
            tickets,
            rows: Mutex::default(),
            tokens: AtomicUsize::default(),
        }
    }
}

impl InMemoryPasswordResets {
    /// A new link for `member` among `rows`, the one they had open replaced.
    fn open_link(
        &self,
        rows: &mut Vec<ResetRow>,
        member: UserId,
        by: Option<UserId>,
        now: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> ResetToken {
        let n = self.tokens.fetch_add(1, Ordering::SeqCst) + 1;
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&u64::try_from(n).unwrap_or(u64::MAX).to_le_bytes());
        let token = ResetToken::from_bytes(bytes);
        for row in rows.iter_mut().filter(|row| {
            row.reset.member == member
                && row.reset.used_at.is_none()
                && row.reset.replaced_at.is_none()
        }) {
            row.reset.replaced_at = Some(now);
            row.replaced_by = Some(token.clone());
        }
        rows.push(ResetRow {
            reset: PasswordReset {
                member,
                created_by: by,
                created_at: now,
                expires_at,
                used_at: None,
                replaced_at: None,
            },
            token: token.clone(),
            replaced_by: None,
        });
        token
    }
}

/// Tokens of known bytes — a fake's tokens are no secret — kept as they are.
#[async_trait::async_trait]
impl PasswordResets for InMemoryPasswordResets {
    async fn issue(
        &self,
        member: UserId,
        by: UserId,
        now: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<ResetToken, AuthError> {
        let mut rows = self.rows.lock().unwrap();
        Ok(self.open_link(&mut rows, member, Some(by), now, expires_at))
    }

    async fn request(
        &self,
        member: UserId,
        now: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Option<ResetToken>, AuthError> {
        let mut rows = self.rows.lock().unwrap();
        let since = now - RESET_REQUEST_WINDOW;
        let asked = rows
            .iter()
            .filter(|row| {
                row.reset.member == member
                    && row.reset.by() == ResetBy::Mailbox
                    && row.reset.created_at > since
            })
            .count();
        if !may_request_reset(asked) {
            return Ok(None);
        }
        Ok(Some(
            self.open_link(&mut rows, member, None, now, expires_at),
        ))
    }

    async fn withdraw(&self, token: &ResetToken, now: OffsetDateTime) -> Result<(), AuthError> {
        let mut rows = self.rows.lock().unwrap();
        let Some(at) = rows.iter().position(|row| {
            row.token == *token && row.reset.used_at.is_none() && row.reset.by() == ResetBy::Mailbox
        }) else {
            return Ok(());
        };
        let withdrawn = rows.remove(at);
        if withdrawn.reset.replaced_at.is_some() {
            return Ok(());
        }
        if let Some(replaced) = rows.iter_mut().find(|row| {
            row.replaced_by.as_ref() == Some(&withdrawn.token)
                && row.reset.used_at.is_none()
                && now < row.reset.expires_at
        }) {
            replaced.reset.replaced_at = None;
            replaced.replaced_by = None;
        }
        Ok(())
    }

    async fn find_open(
        &self,
        token: &ResetToken,
        now: OffsetDateTime,
    ) -> Result<Option<OpenReset>, AuthError> {
        let rows = self.rows.lock().unwrap();
        let Some(row) = rows
            .iter()
            .find(|row| row.token == *token && row.reset.is_open(now))
        else {
            return Ok(None);
        };
        let accounts = self.accounts.accounts.lock().unwrap();
        Ok(accounts
            .iter()
            .find(|(account, _)| account.id == row.reset.member)
            .map(|(account, _)| OpenReset {
                member: account.id,
                display_name: account.display_name.clone(),
                email: account.email.to_lowercase(),
                by: row.reset.by(),
                expires_at: row.reset.expires_at,
            }))
    }

    async fn reset(
        &self,
        token: &ResetToken,
        hash: &PasswordHash,
        now: OffsetDateTime,
    ) -> Result<PasswordChange, AuthError> {
        let mut rows = self.rows.lock().unwrap();
        let Some(row) = rows
            .iter_mut()
            .find(|row| row.token == *token && row.reset.is_open(now))
        else {
            return Ok(PasswordChange::LinkUnusable);
        };
        row.reset.used_at = Some(now);
        let member = row.reset.member;
        self.accounts.set_password(member, hash);
        let ended = self.sessions.end(
            |session| session.user == member,
            RevokedReason::PasswordReset,
            now,
        );
        for ticket in self
            .tickets
            .rows
            .lock()
            .unwrap()
            .iter_mut()
            .filter(|ticket| ticket.user == member)
        {
            ticket.spent = true;
        }
        Ok(PasswordChange::Changed { member, ended })
    }

    async fn delete_ended(&self, before: OffsetDateTime) -> Result<usize, AuthError> {
        let mut rows = self.rows.lock().unwrap();
        let held = rows.len();
        rows.retain(|row| row.reset.ended_at() >= before);
        Ok(held - rows.len())
    }
}

/// The members, read from the accounts and their sessions.
pub struct InMemoryInstanceMembers {
    accounts: std::sync::Arc<InMemorySignInAccounts>,
    sessions: std::sync::Arc<InMemorySessions>,
}

impl InMemoryInstanceMembers {
    pub fn over(
        accounts: std::sync::Arc<InMemorySignInAccounts>,
        sessions: std::sync::Arc<InMemorySessions>,
    ) -> Self {
        Self { accounts, sessions }
    }
}

#[async_trait::async_trait]
impl InstanceMembers for InMemoryInstanceMembers {
    async fn list(&self, now: OffsetDateTime) -> Result<Vec<InstanceMember>, AuthError> {
        let sessions = self.sessions.all();
        let actors = self.accounts.actors.lock().unwrap().clone();
        let mut members: Vec<InstanceMember> = self
            .accounts
            .accounts
            .lock()
            .unwrap()
            .iter()
            .map(|(account, _)| account)
            .filter(|account| !account.needs_code())
            .map(|account| InstanceMember {
                id: account.id,
                actor: actors.get(&account.id).cloned(),
                display_name: account.display_name.clone(),
                admin: account.admin,
                last_active_at: sessions
                    .iter()
                    .filter(|session| session.user == account.id && session.is_live(now))
                    .map(|session| session.last_used_at)
                    .max(),
            })
            .collect();
        members.sort_by_key(|member| (std::cmp::Reverse(member.last_active_at), member.id));
        Ok(members)
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
    fn access_token(
        &self,
        account: &SignInAccount,
        session: &Session,
        client: &ClientId,
        _ttl: Duration,
    ) -> Result<String, AuthError> {
        Ok(format!(
            "access:{}:{}:{}",
            account.id,
            session.id,
            client.as_str()
        ))
    }

    fn id_token(
        &self,
        account: &SignInAccount,
        client: &ClientId,
        nonce: Option<&str>,
        _ttl: Duration,
    ) -> Result<String, AuthError> {
        Ok(format!(
            "id:{}:{}:{}:{}",
            account.id,
            client.as_str(),
            account.email,
            nonce.unwrap_or("-")
        ))
    }
}

struct RefreshRow {
    token: RefreshToken,
    session: SessionId,
    client: ClientId,
    created_at: OffsetDateTime,
    rotated_at: Option<OffsetDateTime>,
    successor: Option<RefreshToken>,
}

/// Refresh tokens spelled `refresh-{n}`, kept as they are: a fake's tokens are no secret.
#[derive(Default)]
pub struct InMemoryRefreshTokens {
    issued: AtomicUsize,
    rows: Mutex<Vec<RefreshRow>>,
}

impl InMemoryRefreshTokens {
    fn fresh(&self) -> RefreshToken {
        let n = self.issued.fetch_add(1, Ordering::SeqCst) + 1;
        RefreshToken::new(format!("refresh-{n}"))
    }

    /// The tokens kept for `session`, rotated or not, oldest first.
    pub fn of(&self, session: SessionId) -> Vec<RefreshToken> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .filter(|row| row.session == session)
            .map(|row| row.token.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl RefreshTokens for InMemoryRefreshTokens {
    async fn start(
        &self,
        session: SessionId,
        client: &ClientId,
        now: OffsetDateTime,
    ) -> Result<RefreshToken, AuthError> {
        let token = self.fresh();
        self.rows.lock().unwrap().push(RefreshRow {
            token: token.clone(),
            session,
            client: client.clone(),
            created_at: now,
            rotated_at: None,
            successor: None,
        });
        Ok(token)
    }

    async fn rotate(
        &self,
        token: &RefreshToken,
        client: &ClientId,
        now: OffsetDateTime,
    ) -> Result<Rotation, AuthError> {
        let mut rows = self.rows.lock().unwrap();
        let Some(at) = rows.iter().position(|row| row.token == *token) else {
            return Ok(Rotation::Refused);
        };
        let successor = rows[at]
            .successor
            .as_ref()
            .and_then(|successor| rows.iter().position(|row| row.token == *successor));
        let link = RefreshLink {
            session: rows[at].session,
            client: rows[at].client.clone(),
            rotated_at: rows[at].rotated_at,
            successor_unused: successor.is_some_and(|i| rows[i].rotated_at.is_none()),
        };
        let session = link.session;
        match link.presented(client, now) {
            Presentation::Refused => return Ok(Rotation::Refused),
            Presentation::Reuse => return Ok(Rotation::Reused { session }),
            Presentation::Rotate => rows[at].rotated_at = Some(now),
            Presentation::Retry => {
                let replaced = successor.expect("a retry replaces a successor");
                rows[replaced].rotated_at = Some(now);
                rows[replaced].successor = None;
            }
        }
        let next = self.fresh();
        rows[at].successor = Some(next.clone());
        rows.push(RefreshRow {
            token: next.clone(),
            session,
            client: client.clone(),
            created_at: now,
            rotated_at: None,
            successor: None,
        });
        Ok(Rotation::Rotated {
            session,
            successor: next,
        })
    }

    async fn delete_unused(&self, before: OffsetDateTime) -> Result<usize, AuthError> {
        let mut rows = self.rows.lock().unwrap();
        let held = rows.len();
        rows.retain(|row| row.rotated_at.unwrap_or(row.created_at) >= before);
        Ok(held - rows.len())
    }

    async fn session_of(
        &self,
        token: &RefreshToken,
        client: &ClientId,
    ) -> Result<Option<SessionId>, AuthError> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|row| row.token == *token && row.client == *client)
            .map(|row| row.session))
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

/// Both kinds of mail the instance sends, kept as sent: the sign-up codes and the reset links.
#[derive(Default)]
pub struct RecordingMailer {
    sent: Mutex<Vec<Mail>>,
    resets: Mutex<Vec<ResetMail>>,
    down: Mutex<bool>,
}

impl RecordingMailer {
    /// The sign-up codes.
    pub fn sent(&self) -> Vec<Mail> {
        self.sent.lock().unwrap().clone()
    }

    /// The reset links asked for.
    pub fn reset_mails(&self) -> Vec<ResetMail> {
        self.resets.lock().unwrap().clone()
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

#[async_trait::async_trait]
impl ResetMailer for RecordingMailer {
    async fn send_reset_link(&self, mail: &ResetMail) -> Result<(), AuthError> {
        if *self.down.lock().unwrap() {
            return Err(anyhow::anyhow!("the mail server is down").into());
        }
        self.resets.lock().unwrap().push(mail.clone());
        Ok(())
    }
}

/// Seeds what the sign-in stores read: accounts are written by other contexts.
#[async_trait::async_trait]
pub trait SignInSeeds: Send + Sync {
    async fn sign_up(&self, account: &SignInAccount);
}

/// What the sign-up store keeps that no port reads back.
#[async_trait::async_trait]
pub trait SignUpRecords: Send + Sync {
    /// Who vouched for the account, if anyone did.
    async fn invited_by(&self, user: UserId) -> Option<UserId>;
}

#[async_trait::async_trait]
impl SignUpRecords for InMemorySignInAccounts {
    async fn invited_by(&self, user: UserId) -> Option<UserId> {
        self.vouched.lock().unwrap().get(&user).copied()
    }
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
        self.actors
            .lock()
            .unwrap()
            .insert(account.id, seeded_actor(account));
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
            admitted: true,
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

    /// `session` is one of `user`'s.
    pub async fn a_code_is_good_once_and_only_until_it_expires(
        codes: &dyn AuthorizationCodes,
        user: UserId,
        session: SessionId,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let grant = Grant::answering(user, session, &a_request());
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
                admitted: false,
                admin: false,
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

    pub async fn an_admitted_account_is_never_swept_as_unconfirmed(
        sign_ups: &dyn SignUps,
        accounts: &dyn SignInAccounts,
        seeds: &dyn SignInSeeds,
    ) {
        let now = OffsetDateTime::now_utc();
        let carol = SignInAccount {
            email_verified: false,
            admitted: true,
            ..signed_up("carol")
        };
        seeds.sign_up(&carol).await;
        let admin = a_new_account("admin");
        sign_ups.create_admin(&admin, now).await.unwrap();
        let bob = a_new_account("bob");
        sign_ups.create(&bob).await.unwrap();

        let swept = sign_ups
            .delete_unverified(now + Duration::minutes(1))
            .await
            .unwrap();

        assert_eq!(swept, 1);
        assert_eq!(accounts.by_id(bob.id).await.unwrap(), None);
        assert!(accounts.by_id(carol.id).await.unwrap().is_some());
        assert!(accounts.by_id(admin.id).await.unwrap().is_some());
    }

    pub async fn the_admin_is_created_admitted_unconfirmed_and_never_written_over(
        sign_ups: &dyn SignUps,
        accounts: &dyn SignInAccounts,
    ) {
        let now = OffsetDateTime::now_utc();
        let admin = a_new_account("admin");

        let created = sign_ups.create_admin(&admin, now).await.unwrap();
        let again = sign_ups
            .create_admin(
                &NewAccount {
                    email: admin.email.clone(),
                    password_hash: PlainHasher::hash("another-password"),
                    ..a_new_account("root")
                },
                now,
            )
            .await
            .unwrap();
        let its_handle = sign_ups
            .create_admin(
                &NewAccount {
                    id: UserId::generate(),
                    email: email("root@idp.test"),
                    ..admin.clone()
                },
                now,
            )
            .await
            .unwrap();

        assert_eq!(
            (created, again, its_handle),
            (
                Registration::Created,
                Registration::EmailTaken,
                Registration::HandleTaken
            )
        );
        assert_eq!(
            accounts.by_email(&admin.email).await.unwrap(),
            Some(SignInAccount {
                id: admin.id,
                email: admin.email.as_str().to_owned(),
                username: admin.username.as_str().to_owned(),
                display_name: Some("admin".to_owned()),
                password_hash: admin.password_hash.clone(),
                email_verified: false,
                admitted: true,
                admin: true,
                totp_enabled: false,
            })
        );
        assert_eq!(
            sign_ups.admin_facts(Some(&admin.email)).await.unwrap(),
            AdminFacts {
                holder: AddressHolder::Admin,
                admin_exists: true,
            }
        );
    }

    pub async fn the_admin_facts_tell_who_has_an_address_and_whether_any_admin_exists(
        sign_ups: &dyn SignUps,
        seeds: &dyn SignInSeeds,
    ) {
        let facts = async |address: Option<&str>| {
            sign_ups
                .admin_facts(address.map(email).as_ref())
                .await
                .unwrap()
        };
        let none = facts(None).await;
        let nobody = facts(Some("alice@idp.test")).await;
        // Stored before addresses were kept lowercase.
        seeds
            .sign_up(&SignInAccount {
                email: "Alice@IDP.test".to_owned(),
                ..signed_up("alice")
            })
            .await;
        let alice_alone = facts(Some("alice@idp.test")).await;
        let admin = a_new_account("admin");
        sign_ups
            .create_admin(&admin, OffsetDateTime::now_utc())
            .await
            .unwrap();

        let fact = |holder, admin_exists| AdminFacts {
            holder,
            admin_exists,
        };
        assert_eq!(
            (none, nobody, alice_alone),
            (
                fact(AddressHolder::Nobody, false),
                fact(AddressHolder::Nobody, false),
                fact(AddressHolder::NotAdmin, false)
            )
        );
        assert_eq!(
            (
                facts(None).await,
                facts(Some("alice@idp.test")).await,
                facts(Some("ADMIN@idp.test")).await,
                facts(Some("carol@idp.test")).await,
            ),
            (
                fact(AddressHolder::Nobody, true),
                fact(AddressHolder::NotAdmin, true),
                fact(AddressHolder::Admin, true),
                fact(AddressHolder::Nobody, true)
            )
        );
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

    pub async fn a_session_opens_is_used_and_ends_once(sessions: &dyn Sessions, user: UserId) {
        let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let id = sessions
            .open(user, &SessionKind::Browser, at)
            .await
            .unwrap();
        let app = SessionKind::App(web_client().id);
        let apps = sessions.open(user, &app, at).await.unwrap();

        let opened = sessions.find(id).await.unwrap();
        sessions.touch(id, at + Duration::hours(1)).await.unwrap();
        let used = sessions.find(id).await.unwrap().unwrap();
        sessions
            .authenticate(id, at + Duration::minutes(90))
            .await
            .unwrap();
        let authenticated = sessions.find(id).await.unwrap().unwrap();
        let revoked = sessions
            .revoke(id, RevokedReason::SignOut, at + Duration::hours(2))
            .await
            .unwrap();
        let again = sessions
            .revoke(id, RevokedReason::Replaced, at + Duration::hours(3))
            .await
            .unwrap();
        let reused = sessions
            .revoke(apps, RevokedReason::Reuse, at + Duration::hours(2))
            .await
            .unwrap();
        let ended = sessions.find(id).await.unwrap().unwrap();

        assert_eq!(
            opened,
            Some(Session {
                id,
                user,
                kind: SessionKind::Browser,
                device: None,
                created_at: at,
                last_used_at: at,
                authenticated_at: at,
                revoked_at: None,
            })
        );
        assert_eq!(
            (used.authenticated_at, authenticated.authenticated_at),
            (at, at + Duration::minutes(90)),
            "a use is no password"
        );
        assert_eq!(authenticated.last_used_at, at + Duration::hours(1));
        assert_eq!(sessions.find(apps).await.unwrap().unwrap().kind, app);
        assert_eq!(used.last_used_at, at + Duration::hours(1));
        assert_eq!((revoked, again, reused), (true, false, true), "ended once");
        assert_eq!(ended.revoked_at, Some(at + Duration::hours(2)));
        assert_eq!(sessions.find(SessionId::generate()).await.unwrap(), None);
    }

    pub async fn sessions_ended_are_swept_after_their_retention(
        sessions: &dyn Sessions,
        user: UserId,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let before = now - SESSION_RETENTION;
        let live = sessions
            .open(user, &SessionKind::Browser, now)
            .await
            .unwrap();
        let revoked_long_ago = sessions
            .open(user, &SessionKind::Browser, now - Duration::days(40))
            .await
            .unwrap();
        sessions
            .revoke(
                revoked_long_ago,
                RevokedReason::SignOut,
                before - Duration::days(1),
            )
            .await
            .unwrap();
        let revoked_lately = sessions
            .open(user, &SessionKind::Browser, now - Duration::days(2))
            .await
            .unwrap();
        sessions
            .revoke(
                revoked_lately,
                RevokedReason::SignOut,
                before + Duration::days(1),
            )
            .await
            .unwrap();
        let idle_long_ago = sessions
            .open(
                user,
                &SessionKind::Browser,
                before - SESSION_IDLE - Duration::days(1),
            )
            .await
            .unwrap();
        let idle_lately = sessions
            .open(
                user,
                &SessionKind::Browser,
                before - SESSION_IDLE + Duration::days(1),
            )
            .await
            .unwrap();

        let swept = sessions.delete_ended(before).await.unwrap();

        assert_eq!(swept, 2);
        for kept in [live, revoked_lately, idle_lately] {
            assert!(sessions.find(kept).await.unwrap().is_some());
        }
        for gone in [revoked_long_ago, idle_long_ago] {
            assert_eq!(sessions.find(gone).await.unwrap(), None);
        }
    }

    fn ids(sessions: Vec<Session>) -> Vec<SessionId> {
        sessions.into_iter().map(|session| session.id).collect()
    }

    /// `device` is one of `user`'s.
    pub async fn a_device_holds_one_session_the_latest_linked(
        sessions: &dyn Sessions,
        user: UserId,
        device: DeviceId,
    ) {
        let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let first = sessions
            .open(user, &SessionKind::Browser, at)
            .await
            .unwrap();
        let second = sessions
            .open(user, &SessionKind::Browser, at)
            .await
            .unwrap();
        let unlinked = sessions
            .open(user, &SessionKind::Browser, at)
            .await
            .unwrap();

        let linked = sessions.link(first, device, at).await.unwrap();
        let replaced = sessions
            .link(second, device, at + Duration::hours(1))
            .await
            .unwrap();
        let again = sessions
            .link(second, device, at + Duration::hours(2))
            .await
            .unwrap();
        let mine = sessions.of_user(user).await.unwrap();
        let first = sessions.find(first).await.unwrap().unwrap();

        assert!(linked.is_empty());
        assert_eq!(
            ids(replaced),
            vec![first.id],
            "a new sign-in takes the device over"
        );
        assert!(again.is_empty(), "linking again changes nothing");
        assert_eq!(first.revoked_at, Some(at + Duration::hours(1)));
        assert_eq!(
            sessions.find(second).await.unwrap().unwrap().device,
            Some(device)
        );
        assert_eq!(sessions.find(unlinked).await.unwrap().unwrap().device, None);
        assert_eq!(mine.len(), 3);
    }

    /// `device` is one of `user`'s; `other` is another account.
    pub async fn a_revoked_device_and_signing_out_elsewhere_end_the_right_sessions(
        sessions: &dyn Sessions,
        user: UserId,
        other: UserId,
        device: DeviceId,
    ) {
        let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let on_device = sessions
            .open(user, &SessionKind::Browser, at)
            .await
            .unwrap();
        sessions.link(on_device, device, at).await.unwrap();
        let current = sessions
            .open(user, &SessionKind::Browser, at)
            .await
            .unwrap();
        let elsewhere = sessions
            .open(user, &SessionKind::App(web_client().id), at)
            .await
            .unwrap();
        let someone_elses = sessions
            .open(other, &SessionKind::Browser, at)
            .await
            .unwrap();

        let not_theirs = sessions.revoke_device(other, device, at).await.unwrap();
        let revoked = sessions.revoke_device(user, device, at).await.unwrap();
        let revoked_again = sessions.revoke_device(user, device, at).await.unwrap();
        let signed_out = sessions.revoke_others(user, current, at).await.unwrap();

        assert!(not_theirs.is_empty());
        assert_eq!(ids(revoked), vec![on_device]);
        assert!(revoked_again.is_empty());
        assert_eq!(
            ids(signed_out),
            vec![elsewhere],
            "the ended one is not ended twice"
        );
        assert!(sessions.find(current).await.unwrap().unwrap().is_live(at));
        assert!(
            sessions
                .find(someone_elses)
                .await
                .unwrap()
                .unwrap()
                .is_live(at)
        );
    }

    fn rotated(rotation: Rotation) -> RefreshToken {
        match rotation {
            Rotation::Rotated { successor, .. } => successor,
            other => panic!("not rotated: {other:?}"),
        }
    }

    /// `session` is a live one.
    pub async fn a_refresh_token_rotates_at_each_use_and_a_used_one_is_reused(
        tokens: &dyn RefreshTokens,
        session: SessionId,
    ) {
        let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let client = web_client().id;
        let other = ClientId::parse("http://localhost:5173/other.json").unwrap();
        let first = tokens.start(session, &client, at).await.unwrap();
        let elsewhere = tokens.start(session, &client, at).await.unwrap();

        let second = rotated(
            tokens
                .rotate(&first, &client, at + Duration::hours(1))
                .await
                .unwrap(),
        );
        let third = rotated(
            tokens
                .rotate(&second, &client, at + Duration::hours(2))
                .await
                .unwrap(),
        );
        let first_again = tokens
            .rotate(&first, &client, at + Duration::hours(2))
            .await
            .unwrap();
        let second_later = tokens
            .rotate(
                &second,
                &client,
                at + Duration::hours(2) + Duration::minutes(2),
            )
            .await
            .unwrap();
        let unknown = tokens
            .rotate(
                &RefreshToken::new("no-such-token".to_owned()),
                &client,
                at + Duration::hours(2),
            )
            .await
            .unwrap();
        let by_another = tokens
            .rotate(&third, &other, at + Duration::hours(2))
            .await
            .unwrap();
        let fourth = tokens
            .rotate(&third, &client, at + Duration::hours(3))
            .await
            .unwrap();
        let other_chain = tokens
            .rotate(&elsewhere, &client, at + Duration::hours(3))
            .await
            .unwrap();

        assert_ne!(first, elsewhere);
        assert_ne!(second, third);
        assert_eq!(
            first_again,
            Rotation::Reused { session },
            "its successor was used"
        );
        assert_eq!(second_later, Rotation::Reused { session }, "past the grace");
        assert_eq!(
            (unknown, by_another),
            (Rotation::Refused, Rotation::Refused)
        );
        assert!(
            matches!(fourth, Rotation::Rotated { session: s, .. } if s == session),
            "another client's try changed nothing: {fourth:?}"
        );
        assert!(
            matches!(other_chain, Rotation::Rotated { .. }),
            "each chain on its own: {other_chain:?}"
        );
    }

    /// `session` is a live one.
    pub async fn a_lost_answer_is_answered_again_within_the_grace(
        tokens: &dyn RefreshTokens,
        session: SessionId,
    ) {
        let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let client = web_client().id;
        let first = tokens.start(session, &client, at).await.unwrap();
        let lost = rotated(tokens.rotate(&first, &client, at).await.unwrap());

        let retried = rotated(
            tokens
                .rotate(&first, &client, at + Duration::seconds(30))
                .await
                .unwrap(),
        );
        let lost_after_all = tokens
            .rotate(&lost, &client, at + Duration::seconds(40))
            .await
            .unwrap();
        let next = tokens
            .rotate(&retried, &client, at + Duration::seconds(45))
            .await
            .unwrap();
        let first_once_more = tokens
            .rotate(&first, &client, at + Duration::seconds(50))
            .await
            .unwrap();

        assert_ne!(retried, lost);
        assert_eq!(
            lost_after_all,
            Rotation::Reused { session },
            "replaced: whoever holds it holds a copy"
        );
        assert!(matches!(next, Rotation::Rotated { .. }), "{next:?}");
        assert_eq!(
            first_once_more,
            Rotation::Reused { session },
            "its successor came this time"
        );
    }

    /// `session` is a live one.
    pub async fn a_refresh_token_names_its_session_to_its_own_client_only(
        tokens: &dyn RefreshTokens,
        session: SessionId,
    ) {
        let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let client = web_client().id;
        let other = ClientId::parse("http://localhost:5173/other.json").unwrap();
        let first = tokens.start(session, &client, at).await.unwrap();
        let head = rotated(tokens.rotate(&first, &client, at).await.unwrap());

        assert_eq!(
            tokens.session_of(&head, &client).await.unwrap(),
            Some(session)
        );
        assert_eq!(
            tokens.session_of(&first, &client).await.unwrap(),
            Some(session),
            "a rotated one too"
        );
        assert_eq!(tokens.session_of(&head, &other).await.unwrap(), None);
        assert_eq!(
            tokens
                .session_of(&RefreshToken::new("no-such-token".to_owned()), &client)
                .await
                .unwrap(),
            None
        );
    }

    /// `session` is a live one.
    pub async fn refresh_tokens_unused_since_the_cutoff_are_swept(
        tokens: &dyn RefreshTokens,
        session: SessionId,
    ) {
        let before = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let now = before + Duration::days(2);
        let client = web_client().id;
        let old_head = tokens
            .start(session, &client, before - Duration::days(1))
            .await
            .unwrap();
        let new_head = tokens
            .start(session, &client, before + Duration::days(1))
            .await
            .unwrap();
        let old_link = tokens
            .start(session, &client, before - Duration::days(2))
            .await
            .unwrap();
        let new_link = rotated(
            tokens
                .rotate(&old_link, &client, before - Duration::days(1))
                .await
                .unwrap(),
        );
        let chain_head = rotated(
            tokens
                .rotate(&new_link, &client, before + Duration::days(1))
                .await
                .unwrap(),
        );

        let swept = tokens.delete_unused(before).await.unwrap();

        assert_eq!(swept, 2);
        for kept in [new_head, chain_head] {
            let rotation = tokens.rotate(&kept, &client, now).await.unwrap();
            assert!(matches!(rotation, Rotation::Rotated { .. }), "{rotation:?}");
        }
        assert_eq!(
            tokens.rotate(&new_link, &client, now).await.unwrap(),
            Rotation::Reused { session },
            "kept, to catch a copy"
        );
        for gone in [old_head, old_link] {
            assert_eq!(
                tokens.rotate(&gone, &client, now).await.unwrap(),
                Rotation::Refused
            );
        }
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

    /// The instance's admin, who creates invitations.
    async fn an_admin(sign_ups: &dyn SignUps, now: OffsetDateTime) -> NewAccount {
        let admin = a_new_account("admin");
        sign_ups.create_admin(&admin, now).await.unwrap();
        admin
    }

    pub async fn an_invited_account_is_created_admitted_vouched_for_and_spends_its_invitation(
        sign_ups: &dyn SignUps,
        invitations: &dyn Invitations,
        accounts: &dyn SignInAccounts,
        records: &dyn SignUpRecords,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, now).await;
        let (id, token) = invitations
            .issue(admin.id, now, now + INVITATION_TTL)
            .await
            .unwrap();
        let (_, other) = invitations
            .issue(admin.id, now, now + INVITATION_TTL)
            .await
            .unwrap();
        let joined_at = now + Duration::hours(1);

        let open = invitations.find_open(&token, now).await.unwrap();
        let bob = a_new_account("bob");
        let created = sign_ups.create_invited(&bob, id, joined_at).await.unwrap();
        let carol = a_new_account("carol");
        let again = sign_ups
            .create_invited(&carol, id, joined_at)
            .await
            .unwrap();

        assert_ne!(token, other);
        assert_eq!(
            open,
            Some(OpenInvitation {
                id,
                inviter: Some("admin".to_owned()),
                created_at: now,
                expires_at: now + INVITATION_TTL,
            })
        );
        assert_eq!(
            (created, again),
            (Registration::Created, Registration::InvitationSpent)
        );
        assert_eq!(
            accounts.by_id(bob.id).await.unwrap(),
            Some(SignInAccount {
                id: bob.id,
                email: bob.email.as_str().to_owned(),
                username: bob.username.as_str().to_owned(),
                display_name: Some("bob".to_owned()),
                password_hash: bob.password_hash.clone(),
                email_verified: false,
                admitted: true,
                admin: false,
                totp_enabled: false,
            })
        );
        assert_eq!(records.invited_by(bob.id).await, Some(admin.id));
        assert_eq!(accounts.by_id(carol.id).await.unwrap(), None);
        assert_eq!(
            invitations.find_open(&token, joined_at).await.unwrap(),
            None
        );
        assert!(
            !invitations.revoke(id, joined_at).await.unwrap(),
            "a used invitation is not revoked"
        );
        assert!(
            !invitations
                .list_open(joined_at)
                .await
                .unwrap()
                .iter()
                .any(|open| open.id == id)
        );
    }

    pub async fn a_revoked_expired_or_unknown_invitation_lets_nobody_in(
        sign_ups: &dyn SignUps,
        invitations: &dyn Invitations,
        accounts: &dyn SignInAccounts,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, now).await;
        let expires_at = now + INVITATION_TTL;
        let (revoked, revoked_token) = invitations.issue(admin.id, now, expires_at).await.unwrap();
        let (expired, expired_token) = invitations.issue(admin.id, now, expires_at).await.unwrap();

        let first = invitations.revoke(revoked, now).await.unwrap();
        let twice = invitations.revoke(revoked, now).await.unwrap();
        let past_expiry = invitations.revoke(expired, expires_at).await.unwrap();
        let bob = a_new_account("bob");
        let carol = a_new_account("carol");
        let dave = a_new_account("dave");
        let with_revoked = sign_ups.create_invited(&bob, revoked, now).await.unwrap();
        let with_expired = sign_ups
            .create_invited(&carol, expired, expires_at)
            .await
            .unwrap();
        let with_unknown = sign_ups
            .create_invited(&dave, InvitationId::generate(), now)
            .await
            .unwrap();

        assert_eq!((first, twice, past_expiry), (true, false, false));
        assert_eq!(
            (with_revoked, with_expired, with_unknown),
            (
                Registration::InvitationSpent,
                Registration::InvitationSpent,
                Registration::InvitationSpent
            )
        );
        for nobody in [bob.id, carol.id, dave.id] {
            assert_eq!(accounts.by_id(nobody).await.unwrap(), None);
        }
        assert_eq!(
            invitations.find_open(&revoked_token, now).await.unwrap(),
            None
        );
        assert!(
            invitations
                .find_open(&expired_token, expires_at - Duration::seconds(1))
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            invitations
                .find_open(&expired_token, expires_at)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            invitations
                .find_open(&InvitationToken::from_bytes([9; 32]), now)
                .await
                .unwrap(),
            None
        );
    }

    pub async fn an_address_already_taken_leaves_the_invitation_open(
        sign_ups: &dyn SignUps,
        invitations: &dyn Invitations,
        seeds: &dyn SignInSeeds,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, now).await;
        let alice = signed_up("alice");
        seeds.sign_up(&alice).await;
        let (id, token) = invitations
            .issue(admin.id, now, now + INVITATION_TTL)
            .await
            .unwrap();
        let bob = a_new_account("bob");

        let taken = sign_ups
            .create_invited(
                &NewAccount {
                    email: email(&alice.email),
                    ..bob.clone()
                },
                id,
                now,
            )
            .await
            .unwrap();
        let still_open = invitations.find_open(&token, now).await.unwrap();
        let created = sign_ups.create_invited(&bob, id, now).await.unwrap();

        assert_eq!(
            (taken, created),
            (Registration::EmailTaken, Registration::Created)
        );
        assert!(still_open.is_some());
    }

    pub async fn the_open_invitations_are_listed_newest_first(
        sign_ups: &dyn SignUps,
        invitations: &dyn Invitations,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, now - Duration::days(60)).await;
        let issue = async |at: OffsetDateTime| {
            invitations
                .issue(admin.id, at, at + INVITATION_TTL)
                .await
                .unwrap()
                .0
        };
        let used = issue(now - Duration::days(2)).await;
        sign_ups
            .create_invited(&a_new_account("bob"), used, now - Duration::days(1))
            .await
            .unwrap();
        let expired = issue(now - Duration::days(10)).await;
        let open_older = issue(now - Duration::days(3)).await;
        let revoked = issue(now - Duration::days(1)).await;
        invitations
            .revoke(revoked, now - Duration::hours(2))
            .await
            .unwrap();
        let open_newer = issue(now - Duration::hours(1)).await;

        let listed = invitations.list_open(now).await.unwrap();

        let open = |id, at: OffsetDateTime| OpenInvitation {
            id,
            inviter: Some("admin".to_owned()),
            created_at: at,
            expires_at: at + INVITATION_TTL,
        };
        assert_eq!(
            listed,
            vec![
                open(open_newer, now - Duration::hours(1)),
                open(open_older, now - Duration::days(3)),
            ]
        );
        assert!(
            !listed
                .iter()
                .any(|listed| [used, expired, revoked].contains(&listed.id))
        );
    }

    pub async fn invitations_are_swept_a_while_after_they_ended(
        sign_ups: &dyn SignUps,
        invitations: &dyn Invitations,
    ) {
        let before = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, before - Duration::days(60)).await;
        let issue = async |at: OffsetDateTime| {
            invitations
                .issue(admin.id, at, at + INVITATION_TTL)
                .await
                .unwrap()
        };
        let (used_before, _) = issue(before - Duration::days(2)).await;
        sign_ups
            .create_invited(
                &a_new_account("bob"),
                used_before,
                before - Duration::days(1),
            )
            .await
            .unwrap();
        let (revoked_before, _) = issue(before - Duration::days(2)).await;
        invitations
            .revoke(revoked_before, before - Duration::days(1))
            .await
            .unwrap();
        issue(before - INVITATION_TTL - Duration::days(1)).await;
        let (used_after, _) = issue(before - Duration::days(1)).await;
        sign_ups
            .create_invited(
                &a_new_account("carol"),
                used_after,
                before + Duration::days(1),
            )
            .await
            .unwrap();
        let (_, expiring_after) = issue(before - INVITATION_TTL + Duration::days(2)).await;
        let (_, open) = issue(before + Duration::days(1)).await;

        let swept = invitations.delete_ended(before).await.unwrap();
        let again = invitations.delete_ended(before).await.unwrap();
        let still_open = invitations
            .find_open(&expiring_after, before)
            .await
            .unwrap();
        let used_later = invitations
            .delete_ended(before + Duration::days(1) + Duration::hours(1))
            .await
            .unwrap();
        let expired_later = invitations
            .delete_ended(before + Duration::days(2) + Duration::hours(1))
            .await
            .unwrap();

        assert_eq!(
            (swept, again, used_later, expired_later),
            (3, 0, 1, 1),
            "each a while after it ended, not before"
        );
        assert!(still_open.is_some());
        assert!(
            invitations
                .find_open(&open, before + Duration::days(2))
                .await
                .unwrap()
                .is_some()
        );
    }

    pub async fn issuing_a_link_replaces_the_members_open_one(
        resets: &dyn PasswordResets,
        sign_ups: &dyn SignUps,
        seeds: &dyn SignInSeeds,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, now).await;
        let (alice, bob) = (signed_up("alice"), signed_up("bob"));
        seeds.sign_up(&alice).await;
        seeds.sign_up(&bob).await;
        let later = now + Duration::minutes(5);

        let first = resets
            .issue(alice.id, admin.id, now, now + RESET_TTL)
            .await
            .unwrap();
        let bobs = resets
            .issue(bob.id, admin.id, now, now + RESET_TTL)
            .await
            .unwrap();
        let second = resets
            .issue(alice.id, admin.id, later, later + RESET_TTL)
            .await
            .unwrap();

        assert_ne!(first, second);
        assert_eq!(
            resets.find_open(&first, later).await.unwrap(),
            None,
            "replaced"
        );
        assert_eq!(
            resets.find_open(&second, later).await.unwrap(),
            Some(OpenReset {
                member: alice.id,
                display_name: Some("alice".to_owned()),
                email: alice.email.clone(),
                by: ResetBy::Admin,
                expires_at: later + RESET_TTL,
            })
        );
        assert!(
            resets.find_open(&bobs, later).await.unwrap().is_some(),
            "another member's stays open"
        );
    }

    pub async fn a_reset_sets_the_password_spends_the_link_and_ends_what_the_old_password_opened(
        resets: &dyn PasswordResets,
        accounts: &dyn SignInAccounts,
        sessions: &dyn Sessions,
        tickets: &dyn LoginTickets,
        sign_ups: &dyn SignUps,
        seeds: &dyn SignInSeeds,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, now).await;
        let (alice, bob) = (signed_up("alice"), signed_up("bob"));
        seeds.sign_up(&alice).await;
        seeds.sign_up(&bob).await;
        let open =
            async |user: UserId, kind: SessionKind| sessions.open(user, &kind, now).await.unwrap();
        let browser = open(alice.id, SessionKind::Browser).await;
        let desktop = open(alice.id, SessionKind::App(web_client().id)).await;
        let signed_out = open(alice.id, SessionKind::Browser).await;
        sessions
            .revoke(signed_out, RevokedReason::SignOut, now)
            .await
            .unwrap();
        let bobs = open(bob.id, SessionKind::Browser).await;
        let token = resets
            .issue(alice.id, admin.id, now, now + RESET_TTL)
            .await
            .unwrap();
        let at = now + Duration::hours(1);
        let ticket_of = async |user: UserId| {
            tickets
                .open(user, &a_request(), at + LOGIN_TICKET_TTL)
                .await
                .unwrap()
        };
        let (alices_ticket, bobs_ticket) = (ticket_of(alice.id).await, ticket_of(bob.id).await);
        let hash = PlainHasher::hash("a-new-password");

        let changed = resets.reset(&token, &hash, at).await.unwrap();
        let again = resets
            .reset(&token, &PlainHasher::hash("yet-another-password"), at)
            .await
            .unwrap();

        let PasswordChange::Changed { member, ended } = changed else {
            panic!("not changed: {changed:?}");
        };
        let mut ended_ids = ids(ended.clone());
        ended_ids.sort();
        let mut live = vec![browser, desktop];
        live.sort();
        assert_eq!(member, alice.id);
        assert_eq!(ended_ids, live, "the sessions not ended already");
        assert!(ended.iter().all(|session| session.revoked_at == Some(at)));
        assert_eq!(again, PasswordChange::LinkUnusable, "spent");
        assert_eq!(
            accounts
                .by_id(alice.id)
                .await
                .unwrap()
                .unwrap()
                .password_hash,
            hash
        );
        assert_eq!(
            accounts.by_id(bob.id).await.unwrap().unwrap().password_hash,
            bob.password_hash
        );
        assert_eq!(resets.find_open(&token, at).await.unwrap(), None);
        for gone in [browser, desktop] {
            assert!(!sessions.find(gone).await.unwrap().unwrap().is_live(at));
        }
        assert_eq!(
            sessions.find(signed_out).await.unwrap().unwrap().revoked_at,
            Some(now),
            "ended once"
        );
        assert!(sessions.find(bobs).await.unwrap().unwrap().is_live(at));
        assert_eq!(
            tickets.find(alices_ticket, at).await.unwrap(),
            None,
            "a sign-in half done with the old password ends too"
        );
        assert!(tickets.find(bobs_ticket, at).await.unwrap().is_some());
    }

    pub async fn a_replaced_expired_or_unknown_link_resets_nothing(
        resets: &dyn PasswordResets,
        accounts: &dyn SignInAccounts,
        sessions: &dyn Sessions,
        sign_ups: &dyn SignUps,
        seeds: &dyn SignInSeeds,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, now).await;
        let (alice, carol) = (signed_up("alice"), signed_up("carol"));
        seeds.sign_up(&alice).await;
        seeds.sign_up(&carol).await;
        let alices = sessions
            .open(alice.id, &SessionKind::Browser, now)
            .await
            .unwrap();
        let expires_at = now + RESET_TTL;
        let replaced = resets
            .issue(alice.id, admin.id, now, expires_at)
            .await
            .unwrap();
        resets
            .issue(alice.id, admin.id, now, expires_at)
            .await
            .unwrap();
        let expiring = resets
            .issue(carol.id, admin.id, now, expires_at)
            .await
            .unwrap();
        let hash = PlainHasher::hash("a-new-password");

        let with_replaced = resets.reset(&replaced, &hash, now).await.unwrap();
        let with_expired = resets.reset(&expiring, &hash, expires_at).await.unwrap();
        let with_unknown = resets
            .reset(&ResetToken::from_bytes([9; 32]), &hash, now)
            .await
            .unwrap();

        assert_eq!(
            (with_replaced, with_expired, with_unknown),
            (
                PasswordChange::LinkUnusable,
                PasswordChange::LinkUnusable,
                PasswordChange::LinkUnusable
            )
        );
        for (account, kept) in [
            (&alice, &alice.password_hash),
            (&carol, &carol.password_hash),
        ] {
            assert_eq!(
                &accounts
                    .by_id(account.id)
                    .await
                    .unwrap()
                    .unwrap()
                    .password_hash,
                kept
            );
        }
        assert!(sessions.find(alices).await.unwrap().unwrap().is_live(now));
        assert!(
            resets
                .find_open(&expiring, expires_at - Duration::seconds(1))
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(resets.find_open(&expiring, expires_at).await.unwrap(), None);
    }

    pub async fn reset_links_are_swept_a_while_after_they_ended(
        resets: &dyn PasswordResets,
        sign_ups: &dyn SignUps,
        seeds: &dyn SignInSeeds,
    ) {
        let before = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, before - Duration::days(60)).await;
        let members = [
            signed_up("alice"),
            signed_up("bob"),
            signed_up("carol"),
            signed_up("dave"),
        ];
        for member in &members {
            seeds.sign_up(member).await;
        }
        let [alice, bob, carol, dave] = members.map(|member| member.id);
        let issue = async |member: UserId, at: OffsetDateTime| {
            resets
                .issue(member, admin.id, at, at + RESET_TTL)
                .await
                .unwrap()
        };
        let hash = PlainHasher::hash("a-new-password");
        let used_before = issue(alice, before - Duration::hours(2)).await;
        resets
            .reset(&used_before, &hash, before - Duration::hours(1))
            .await
            .unwrap();
        issue(bob, before - Duration::hours(3)).await;
        let replacing = issue(bob, before - Duration::hours(2)).await;
        issue(carol, before - RESET_TTL - Duration::hours(1)).await;
        let used_after = issue(dave, before - Duration::hours(1)).await;
        resets
            .reset(&used_after, &hash, before + Duration::hours(1))
            .await
            .unwrap();

        let swept = resets.delete_ended(before).await.unwrap();
        let again = resets.delete_ended(before).await.unwrap();
        let still_open = resets.find_open(&replacing, before).await.unwrap();
        let used_later = resets
            .delete_ended(before + Duration::hours(1) + Duration::minutes(1))
            .await
            .unwrap();
        let expired_later = resets
            .delete_ended(before + Duration::hours(22) + Duration::minutes(1))
            .await
            .unwrap();

        assert_eq!(
            (swept, again, used_later, expired_later),
            (3, 0, 1, 1),
            "each a while after it ended — used, replaced or expired — not before"
        );
        assert!(still_open.is_some());
    }

    pub async fn a_link_through_the_mailbox_has_no_maker_and_replaces_the_open_one_an_admins_too(
        resets: &dyn PasswordResets,
        sign_ups: &dyn SignUps,
        seeds: &dyn SignInSeeds,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, now).await;
        let (alice, bob) = (signed_up("alice"), signed_up("bob"));
        seeds.sign_up(&alice).await;
        seeds.sign_up(&bob).await;
        let admins = resets
            .issue(alice.id, admin.id, now, now + RESET_TTL)
            .await
            .unwrap();
        let bobs = resets
            .issue(bob.id, admin.id, now, now + RESET_TTL)
            .await
            .unwrap();
        let later = now + Duration::minutes(5);

        let asked = resets
            .request(alice.id, later, later + REQUESTED_RESET_TTL)
            .await
            .unwrap()
            .expect("within the limit");
        let asked_again = resets
            .request(alice.id, later, later + REQUESTED_RESET_TTL)
            .await
            .unwrap()
            .expect("within the limit");
        let by_an_admin = resets
            .issue(alice.id, admin.id, later, later + RESET_TTL)
            .await
            .unwrap();

        assert_eq!(resets.find_open(&admins, later).await.unwrap(), None);
        assert_eq!(resets.find_open(&asked, later).await.unwrap(), None);
        assert!(
            resets.find_open(&bobs, later).await.unwrap().is_some(),
            "another account's stays open"
        );
        assert!(
            resets
                .find_open(&by_an_admin, later)
                .await
                .unwrap()
                .is_some()
        );
        let again = resets
            .request(alice.id, later, later + REQUESTED_RESET_TTL)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            resets.find_open(&again, later).await.unwrap(),
            Some(OpenReset {
                member: alice.id,
                display_name: Some("alice".to_owned()),
                email: alice.email.clone(),
                by: ResetBy::Mailbox,
                expires_at: later + REQUESTED_RESET_TTL,
            })
        );
        assert_eq!(
            resets.find_open(&by_an_admin, later).await.unwrap(),
            None,
            "an admin's replaced by a request"
        );
        assert_ne!(asked, asked_again);
    }

    pub async fn five_links_asked_for_an_hour_and_the_next_makes_nothing(
        resets: &dyn PasswordResets,
        sign_ups: &dyn SignUps,
        seeds: &dyn SignInSeeds,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, now).await;
        let (alice, bob) = (signed_up("alice"), signed_up("bob"));
        seeds.sign_up(&alice).await;
        seeds.sign_up(&bob).await;
        let request = async |member: UserId, at: OffsetDateTime| {
            resets
                .request(member, at, at + REQUESTED_RESET_TTL)
                .await
                .unwrap()
        };
        let mut asked = Vec::new();
        for minute in 0..i64::try_from(RESET_REQUEST_LIMIT).unwrap() {
            asked.push(request(alice.id, now + Duration::minutes(minute)).await);
        }
        // An admin's links are no request: they count for nothing.
        resets
            .issue(alice.id, admin.id, now, now + RESET_TTL)
            .await
            .unwrap();
        let sixth = request(alice.id, now + Duration::minutes(10)).await;

        let past = request(alice.id, now + Duration::minutes(59)).await;
        let bobs = request(bob.id, now + Duration::minutes(59)).await;
        let once_the_first_is_an_hour_old =
            request(alice.id, now + RESET_REQUEST_WINDOW + Duration::seconds(1)).await;

        assert!(asked[..4].iter().all(Option::is_some), "{asked:?}");
        assert!(asked[4].is_some());
        assert_eq!(sixth, None, "five asked for, the admin's not counted");
        assert_eq!(past, None);
        let open = asked[4].as_ref().unwrap();
        assert!(
            resets
                .find_open(open, now + Duration::minutes(5))
                .await
                .unwrap()
                .is_none(),
            "replaced by the admin's"
        );
        assert!(bobs.is_some(), "counted per account");
        assert!(once_the_first_is_an_hour_old.is_some());
    }

    pub async fn a_link_withdrawn_neither_counts_nor_works(
        resets: &dyn PasswordResets,
        seeds: &dyn SignInSeeds,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let (alice, bob) = (signed_up("alice"), signed_up("bob"));
        seeds.sign_up(&alice).await;
        seeds.sign_up(&bob).await;
        let request = async |member: UserId| {
            resets
                .request(member, now, now + REQUESTED_RESET_TTL)
                .await
                .unwrap()
        };
        let mut asked = Vec::new();
        for _ in 0..RESET_REQUEST_LIMIT {
            asked.push(request(alice.id).await.expect("within the limit"));
        }
        let bobs = request(bob.id).await.unwrap();
        let last = asked.last().unwrap();

        resets.withdraw(last, now).await.unwrap();
        resets
            .withdraw(&ResetToken::from_bytes([9; 32]), now)
            .await
            .unwrap();

        assert_eq!(resets.find_open(last, now).await.unwrap(), None);
        assert!(
            resets.find_open(&asked[3], now).await.unwrap().is_some(),
            "the one it replaced, given back"
        );
        for older in &asked[..3] {
            assert_eq!(
                resets.find_open(older, now).await.unwrap(),
                None,
                "replaced the same instant, by another"
            );
        }
        assert!(
            resets.find_open(&bobs, now).await.unwrap().is_some(),
            "another account's stays"
        );
        assert!(
            request(alice.id).await.is_some(),
            "four asked for: the one withdrawn doesn't count"
        );
        assert_eq!(request(alice.id).await, None);
    }

    pub async fn a_link_used_or_an_admins_is_never_withdrawn(
        resets: &dyn PasswordResets,
        sign_ups: &dyn SignUps,
        seeds: &dyn SignInSeeds,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, now).await;
        let (alice, bob) = (signed_up("alice"), signed_up("bob"));
        seeds.sign_up(&alice).await;
        seeds.sign_up(&bob).await;
        let admins = resets
            .issue(bob.id, admin.id, now, now + RESET_TTL)
            .await
            .unwrap();
        let mut asked = Vec::new();
        for _ in 0..RESET_REQUEST_LIMIT {
            asked.push(
                resets
                    .request(alice.id, now, now + REQUESTED_RESET_TTL)
                    .await
                    .unwrap()
                    .expect("within the limit"),
            );
        }
        let used = asked.last().unwrap();
        resets
            .reset(used, &PlainHasher::hash("a-new-password"), now)
            .await
            .unwrap();

        resets.withdraw(&admins, now).await.unwrap();
        resets.withdraw(used, now).await.unwrap();

        assert!(
            resets.find_open(&admins, now).await.unwrap().is_some(),
            "an admin's link stays"
        );
        assert_eq!(
            resets
                .request(alice.id, now, now + REQUESTED_RESET_TTL)
                .await
                .unwrap(),
            None,
            "the used one still counts"
        );
    }

    pub async fn withdrawing_a_link_gives_back_the_open_one_it_replaced_an_admins_included(
        resets: &dyn PasswordResets,
        sign_ups: &dyn SignUps,
        seeds: &dyn SignInSeeds,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, now).await;
        let (alice, bob) = (signed_up("alice"), signed_up("bob"));
        seeds.sign_up(&alice).await;
        seeds.sign_up(&bob).await;
        let later = now + Duration::minutes(1);
        let request = async |member: UserId, at: OffsetDateTime| {
            resets
                .request(member, at, at + REQUESTED_RESET_TTL)
                .await
                .unwrap()
                .expect("within the limit")
        };
        let admins = resets
            .issue(alice.id, admin.id, now, now + RESET_TTL)
            .await
            .unwrap();
        let instead_of_the_admins = request(alice.id, later).await;
        let mailed = request(bob.id, now).await;
        let instead_of_the_mailed = request(bob.id, later).await;

        resets
            .withdraw(&instead_of_the_admins, later)
            .await
            .unwrap();
        resets
            .withdraw(&instead_of_the_mailed, later)
            .await
            .unwrap();

        for (given_back, withdrawn) in [
            (&admins, &instead_of_the_admins),
            (&mailed, &instead_of_the_mailed),
        ] {
            assert!(
                resets.find_open(given_back, later).await.unwrap().is_some(),
                "given back"
            );
            assert_eq!(resets.find_open(withdrawn, later).await.unwrap(), None);
        }
        assert_eq!(
            resets
                .find_open(&admins, later)
                .await
                .unwrap()
                .map(|open| (open.by, open.expires_at)),
            Some((ResetBy::Admin, now + RESET_TTL)),
            "as it was"
        );
    }

    pub async fn a_replaced_link_expired_or_replaced_again_is_not_given_back(
        resets: &dyn PasswordResets,
        sign_ups: &dyn SignUps,
        seeds: &dyn SignInSeeds,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, now).await;
        let (alice, bob) = (signed_up("alice"), signed_up("bob"));
        seeds.sign_up(&alice).await;
        seeds.sign_up(&bob).await;
        let request = async |member: UserId, at: OffsetDateTime| {
            resets
                .request(member, at, at + REQUESTED_RESET_TTL)
                .await
                .unwrap()
                .expect("within the limit")
        };
        // Alice's first link expires before the one that replaced it is withdrawn.
        let expiring = request(alice.id, now).await;
        let replacing = request(alice.id, now + Duration::minutes(1)).await;
        // Bob's: the withdrawn one was itself replaced by an admin's in between.
        let first = request(bob.id, now).await;
        let second = request(bob.id, now + Duration::minutes(1)).await;
        let admins = resets
            .issue(
                bob.id,
                admin.id,
                now + Duration::minutes(2),
                now + RESET_TTL,
            )
            .await
            .unwrap();
        let after_expiry = now + REQUESTED_RESET_TTL + Duration::minutes(1);

        resets.withdraw(&replacing, after_expiry).await.unwrap();
        resets
            .withdraw(&second, now + Duration::minutes(3))
            .await
            .unwrap();

        assert_eq!(
            resets
                .find_open(&expiring, now + Duration::minutes(2))
                .await
                .unwrap(),
            None,
            "still replaced, even before its expiry"
        );
        assert_eq!(
            resets
                .find_open(&first, now + Duration::minutes(3))
                .await
                .unwrap(),
            None,
            "the newest is the admin's"
        );
        assert!(
            resets
                .find_open(&admins, now + Duration::minutes(3))
                .await
                .unwrap()
                .is_some()
        );
    }

    pub async fn the_members_are_listed_most_recently_active_first(
        members: &dyn InstanceMembers,
        sessions: &dyn Sessions,
        sign_ups: &dyn SignUps,
        seeds: &dyn SignInSeeds,
    ) {
        let now = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let admin = an_admin(sign_ups, now - Duration::days(10)).await;
        let alice = signed_up("alice");
        let carol = SignInAccount {
            email_verified: false,
            admitted: true,
            ..signed_up("carol")
        };
        let dave = SignInAccount {
            display_name: None,
            ..signed_up("dave")
        };
        for account in [&alice, &carol, &dave] {
            seeds.sign_up(account).await;
        }
        let bob = a_new_account("bob");
        sign_ups.create(&bob).await.unwrap();
        let used = async |user: UserId, opened: OffsetDateTime, last_used: OffsetDateTime| {
            let id = sessions
                .open(user, &SessionKind::Browser, opened)
                .await
                .unwrap();
            sessions.touch(id, last_used).await.unwrap();
            id
        };
        let a_month_ago = now - Duration::days(30);
        used(alice.id, a_month_ago, now - Duration::hours(1)).await;
        let ended = used(alice.id, a_month_ago, now - Duration::minutes(1)).await;
        sessions
            .revoke(ended, RevokedReason::SignOut, now - Duration::minutes(1))
            .await
            .unwrap();
        used(admin.id, a_month_ago, now - Duration::hours(2)).await;
        let idle_since = now - SESSION_IDLE - Duration::days(1);
        used(carol.id, idle_since, idle_since).await;
        used(bob.id, now, now).await;

        let listed = members.list(now).await.unwrap();

        let member = |account: &SignInAccount, last_active_at| InstanceMember {
            id: account.id,
            actor: Some(seeded_actor(account)),
            display_name: account.display_name.clone(),
            admin: false,
            last_active_at,
        };
        let mut signed_out = vec![member(&carol, None), member(&dave, None)];
        signed_out.sort_by_key(|member| member.id);
        let expected = [
            vec![
                member(&alice, Some(now - Duration::hours(1))),
                InstanceMember {
                    id: admin.id,
                    actor: Some(admin.actor_uri.clone()),
                    display_name: Some("admin".to_owned()),
                    admin: true,
                    last_active_at: Some(now - Duration::hours(2)),
                },
            ],
            signed_out,
        ]
        .concat();
        assert_eq!(
            listed, expected,
            "live sessions only; bob, unconfirmed, is no member"
        );
    }
}

#[cfg(test)]
mod tests;
