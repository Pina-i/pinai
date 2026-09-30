//! The sign-in use cases over fakes, sharing them so tests can look behind each flow.

use std::sync::Arc;

use domain::auth::SignInAccount;
use domain::auth::testing::{
    CountingSuffixes, InMemoryClients, InMemoryCodes, InMemorySecondFactors,
    InMemorySignInAccounts, InMemorySignupCodes, PlainHasher, RecordingMailer, RecordingTickets,
    SignInSeeds, SpelledTokens, StepAuthenticator, signed_up, web_client,
};
use domain::auth::{SecondFactors, TotpSecret};
use domain::identity::InstanceOrigin;
use time::OffsetDateTime;

use super::{
    Authorize, ConfirmTotpEnrollment, DisableTotp, ExchangeCode, LogIn, LogOut, PassSecondFactor,
    RegenerateRecoveryCodes, Register, ResendCode, StartTotpEnrollment, SweepSignups, VerifyEmail,
};

pub struct World {
    pub alice: SignInAccount,
    pub accounts: Arc<InMemorySignInAccounts>,
    pub codes: Arc<InMemoryCodes>,
    pub hasher: Arc<PlainHasher>,
    pub tickets: Arc<RecordingTickets>,
    pub signup_codes: Arc<InMemorySignupCodes>,
    pub mailer: Arc<RecordingMailer>,
    pub authorize: Authorize,
    pub log_in: LogIn,
    pub exchange: ExchangeCode,
    pub log_out: LogOut,
    pub register: Register,
    pub verify: VerifyEmail,
    pub resend: ResendCode,
    pub sweep: SweepSignups,
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

pub async fn world() -> World {
    let alice = signed_up("alice");
    let accounts = Arc::new(InMemorySignInAccounts::with([alice.clone()]));
    let clients = Arc::new(InMemoryClients::with([web_client()]));
    let codes = Arc::new(InMemoryCodes::default());
    let hasher = Arc::new(PlainHasher::default());
    let tickets = Arc::new(RecordingTickets::default());
    let signup_codes = Arc::new(InMemorySignupCodes::confirming(accounts.clone()));
    let mailer = Arc::new(RecordingMailer::default());
    let factors = Arc::new(InMemorySecondFactors::for_accounts(accounts.clone()));
    let authenticator = Arc::new(StepAuthenticator::default());
    let origin = InstanceOrigin::parse("http://localhost:8080").unwrap();
    World {
        pass: PassSecondFactor::new(
            tickets.clone(),
            factors.clone(),
            authenticator.clone(),
            codes.clone(),
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
        authorize: Authorize::new(clients.clone(), accounts.clone(), codes.clone()),
        log_in: LogIn::new(
            clients.clone(),
            accounts.clone(),
            hasher.clone(),
            codes.clone(),
            tickets.clone(),
            signup_codes.clone(),
            mailer.clone(),
        ),
        exchange: ExchangeCode::new(
            clients.clone(),
            codes.clone(),
            accounts.clone(),
            Arc::new(SpelledTokens),
        ),
        log_out: LogOut::new(clients.clone()),
        register: Register::new(
            origin.clone(),
            clients.clone(),
            accounts.clone(),
            accounts.clone(),
            hasher.clone(),
            Arc::new(CountingSuffixes::default()),
            signup_codes.clone(),
            mailer.clone(),
        ),
        verify: VerifyEmail::new(
            clients.clone(),
            accounts.clone(),
            signup_codes.clone(),
            codes.clone(),
        ),
        resend: ResendCode::new(accounts.clone(), signup_codes.clone(), mailer.clone()),
        sweep: SweepSignups::new(signup_codes.clone(), tickets.clone(), accounts.clone()),
        alice,
        accounts,
        codes,
        hasher,
        tickets,
        signup_codes,
        mailer,
    }
}

impl World {
    pub async fn sign_up(&self, account: &SignInAccount) {
        self.accounts.sign_up(account).await;
    }

    /// Turns the account's second factor on with a known secret: the codes of its app come from
    /// `StepAuthenticator::code_at`.
    pub async fn with_authenticator(&self, account: &SignInAccount) -> (TotpSecret, Vec<String>) {
        let secret = TotpSecret::parse(vec![7; TotpSecret::LEN]).unwrap();
        let codes = self.factors.enable(account.id, &secret, 0).await.unwrap();
        (secret, codes)
    }
}
