//! The sign-in use cases over fakes, sharing them so tests can look behind each flow.

use std::sync::Arc;

use domain::auth::SignInAccount;
use domain::auth::testing::{
    CountingSuffixes, InMemoryClientSignIns, InMemoryClients, InMemoryCodes,
    InMemoryInstanceMembers, InMemoryPasswordResets, InMemoryRefreshTokens, InMemorySecondFactors,
    InMemorySessions, InMemorySignInAccounts, InMemorySignupCodes, PlainHasher, RecordingMailer,
    RecordingSessionNotifier, RecordingTickets, SignInSeeds, SpelledTokens, StepAuthenticator,
    signed_up, web_client,
};
use domain::auth::{Client, Registrations, SecondFactors, TotpSecret, WebApp, desktop_client};
use domain::e2ee::testing::InMemoryKeyDirectory;
use domain::identity::InstanceOrigin;
use domain::presence::PresenceBoard;
use time::OffsetDateTime;

use super::{
    Authorize, CompleteSignIn, ConfirmTotpEnrollment, CreateInvitation, DisableTotp, EnsureAdmin,
    ExchangeCode, IssuePasswordReset, LinkDevice, ListInvitations, ListMembers, LogIn, LogOut,
    PassSecondFactor, Refresh, RegenerateRecoveryCodes, Register, RegisterInvited, ResendCode,
    ResetPassword, RevokeInvitation, RevokeToken, ShowSignIn, SignOutOthers, StartTotpEnrollment,
    SweepSignups, VerifyEmail,
};

pub struct World {
    pub alice: SignInAccount,
    pub origin: InstanceOrigin,
    /// The official desktop app: native, and allowed to stay signed in.
    pub desktop: Client,
    pub accounts: Arc<InMemorySignInAccounts>,
    pub codes: Arc<InMemoryCodes>,
    pub hasher: Arc<PlainHasher>,
    pub tickets: Arc<RecordingTickets>,
    pub signup_codes: Arc<InMemorySignupCodes>,
    pub mailer: Arc<RecordingMailer>,
    pub sign_ins: Arc<InMemoryClientSignIns>,
    pub sessions: Arc<InMemorySessions>,
    pub ended: Arc<RecordingSessionNotifier>,
    pub refresh_tokens: Arc<InMemoryRefreshTokens>,
    pub devices: Arc<InMemoryKeyDirectory>,
    pub resets: Arc<InMemoryPasswordResets>,
    /// The presence states this instance has heard.
    pub board: Arc<PresenceBoard>,
    pub authorize: Authorize,
    pub log_in: LogIn,
    pub exchange: ExchangeCode,
    pub refresh: Refresh,
    pub link: LinkDevice,
    pub sign_out_others: SignOutOthers,
    pub revoke_token: RevokeToken,
    pub log_out: LogOut,
    pub register: Register,
    pub register_invited: RegisterInvited,
    pub create_invitation: CreateInvitation,
    pub list_invitations: ListInvitations,
    pub revoke_invitation: RevokeInvitation,
    pub issue_reset: IssuePasswordReset,
    pub reset_password: ResetPassword,
    pub list_members: ListMembers,
    pub ensure_admin: EnsureAdmin,
    pub verify: VerifyEmail,
    pub resend: ResendCode,
    pub sweep: SweepSignups,
    pub show: ShowSignIn,
    pub factors: Arc<InMemorySecondFactors>,
    pub pass: PassSecondFactor,
    pub enroll: StartTotpEnrollment,
    pub confirm: ConfirmTotpEnrollment,
    pub disable: DisableTotp,
    pub regenerate: RegenerateRecoveryCodes,
}

pub fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap()
}

/// An open instance.
pub async fn world() -> World {
    world_with(Registrations::Open).await
}

pub async fn invite_only() -> World {
    world_with(Registrations::Invite).await
}

async fn world_with(registrations: Registrations) -> World {
    let alice = signed_up("alice");
    let accounts = Arc::new(InMemorySignInAccounts::with([alice.clone()]));
    let origin = InstanceOrigin::parse("http://localhost:8080").unwrap();
    let desktop = desktop_client(&origin);
    let clients = Arc::new(InMemoryClients::with([web_client(), desktop.clone()]));
    let codes = Arc::new(InMemoryCodes::default());
    let hasher = Arc::new(PlainHasher::default());
    let tickets = Arc::new(RecordingTickets::default());
    let signup_codes = Arc::new(InMemorySignupCodes::confirming(accounts.clone()));
    let mailer = Arc::new(RecordingMailer::default());
    let sign_ins = Arc::new(InMemoryClientSignIns::default());
    let sessions = Arc::new(InMemorySessions::default());
    let ended = Arc::new(RecordingSessionNotifier::default());
    let refresh_tokens = Arc::new(InMemoryRefreshTokens::default());
    let devices = Arc::new(InMemoryKeyDirectory::default());
    let resets = Arc::new(InMemoryPasswordResets::over(
        accounts.clone(),
        sessions.clone(),
        tickets.clone(),
    ));
    let board = Arc::new(PresenceBoard::default());
    let complete = Arc::new(CompleteSignIn::new(
        sign_ins.clone(),
        codes.clone(),
        sessions.clone(),
        ended.clone(),
    ));
    let factors = Arc::new(InMemorySecondFactors::for_accounts(accounts.clone()));
    let authenticator = Arc::new(StepAuthenticator::default());
    World {
        pass: PassSecondFactor::new(
            tickets.clone(),
            factors.clone(),
            authenticator.clone(),
            complete.clone(),
        ),
        enroll: StartTotpEnrollment::new(
            origin.clone(),
            accounts.clone(),
            factors.clone(),
            authenticator.clone(),
        ),
        confirm: ConfirmTotpEnrollment::new(factors.clone(), authenticator.clone()),
        disable: DisableTotp::new(accounts.clone(), factors.clone(), authenticator.clone()),
        regenerate: RegenerateRecoveryCodes::new(
            accounts.clone(),
            factors.clone(),
            authenticator.clone(),
        ),
        factors,
        authorize: Authorize::new(
            clients.clone(),
            accounts.clone(),
            codes.clone(),
            sign_ins.clone(),
            sessions.clone(),
        ),
        log_in: LogIn::new(
            clients.clone(),
            accounts.clone(),
            hasher.clone(),
            tickets.clone(),
            signup_codes.clone(),
            mailer.clone(),
            complete.clone(),
        ),
        exchange: ExchangeCode::new(
            clients.clone(),
            codes.clone(),
            accounts.clone(),
            Arc::new(SpelledTokens),
            sessions.clone(),
            refresh_tokens.clone(),
        ),
        refresh: Refresh::new(
            refresh_tokens.clone(),
            sessions.clone(),
            ended.clone(),
            accounts.clone(),
            Arc::new(SpelledTokens),
        ),
        link: LinkDevice::new(devices.clone(), sessions.clone(), ended.clone()),
        sign_out_others: SignOutOthers::new(sessions.clone(), ended.clone()),
        revoke_token: RevokeToken::new(refresh_tokens.clone(), sessions.clone(), ended.clone()),
        log_out: LogOut::new(clients.clone(), sessions.clone(), ended.clone()),
        register: Register::new(
            origin.clone(),
            registrations,
            clients.clone(),
            accounts.clone(),
            accounts.clone(),
            hasher.clone(),
            Arc::new(CountingSuffixes::default()),
            signup_codes.clone(),
            mailer.clone(),
        ),
        register_invited: RegisterInvited::new(
            origin.clone(),
            registrations,
            Some(WebApp::parse("http://localhost:5173").unwrap()),
            accounts.clone(),
            accounts.clone(),
            accounts.clone(),
            hasher.clone(),
            Arc::new(CountingSuffixes::default()),
            complete.clone(),
        ),
        create_invitation: CreateInvitation::new(registrations, accounts.clone(), accounts.clone()),
        list_invitations: ListInvitations::new(accounts.clone(), accounts.clone()),
        revoke_invitation: RevokeInvitation::new(accounts.clone(), accounts.clone()),
        issue_reset: IssuePasswordReset::new(accounts.clone(), resets.clone()),
        reset_password: ResetPassword::new(
            origin.clone(),
            Some(WebApp::parse("http://localhost:5173").unwrap()),
            hasher.clone(),
            resets.clone(),
            ended.clone(),
        ),
        list_members: ListMembers::new(
            accounts.clone(),
            Arc::new(InMemoryInstanceMembers::over(
                accounts.clone(),
                sessions.clone(),
            )),
            board.clone(),
        ),
        ensure_admin: EnsureAdmin::new(
            origin.clone(),
            accounts.clone(),
            hasher.clone(),
            Arc::new(CountingSuffixes::default()),
        ),
        verify: VerifyEmail::new(
            clients.clone(),
            accounts.clone(),
            signup_codes.clone(),
            complete,
        ),
        resend: ResendCode::new(accounts.clone(), signup_codes.clone(), mailer.clone()),
        sweep: SweepSignups::new(
            signup_codes.clone(),
            tickets.clone(),
            accounts.clone(),
            sessions.clone(),
            refresh_tokens.clone(),
            accounts.clone(),
            resets.clone(),
        ),
        show: ShowSignIn::new(
            clients.clone(),
            tickets.clone(),
            accounts.clone(),
            resets.clone(),
        ),
        alice,
        origin,
        desktop,
        accounts,
        codes,
        hasher,
        tickets,
        signup_codes,
        mailer,
        sign_ins,
        sessions,
        ended,
        refresh_tokens,
        devices,
        resets,
        board,
    }
}

impl World {
    pub async fn sign_up(&self, account: &SignInAccount) {
        self.accounts.sign_up(account).await;
    }

    /// An admin of the instance, signed up.
    pub async fn an_admin(&self) -> SignInAccount {
        let admin = SignInAccount {
            admin: true,
            ..signed_up("root")
        };
        self.sign_up(&admin).await;
        admin
    }

    /// Turns the account's second factor on with a known secret: the codes of its app come from
    /// `StepAuthenticator::code_at`.
    pub async fn with_authenticator(&self, account: &SignInAccount) -> (TotpSecret, Vec<String>) {
        let secret = TotpSecret::parse(vec![7; TotpSecret::LEN]).unwrap();
        let codes = self.factors.enable(account.id, &secret, 0).await.unwrap();
        (secret, codes)
    }
}
