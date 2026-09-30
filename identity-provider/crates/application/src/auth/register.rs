use std::sync::Arc;

use domain::UserId;
use domain::auth::{
    AuthError, AuthorizationRequest, Clients, Email, HandleSuffixes, NewAccount, PasswordHasher,
    Registration, SignInAccount, SignInAccounts, SignUps, SignupCodes, SignupMailer,
    check_password,
};
use domain::identity::{Handle, InstanceOrigin, UsernameChoice};
use time::OffsetDateTime;

use super::mail_signup_code;

/// Suffixes drawn for one chosen name before giving up: 36⁵ of them make a second a rarity.
const SUFFIX_DRAWS: usize = 3;

#[derive(Debug, Clone)]
pub struct RegisterCommand {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    pub user: UserId,
    pub username: String,
    pub display_name: String,
    pub email: String,
}

/// `POST /register` and `/register-and-login`: an account, unconfirmed until the code mailed to
/// its address comes back.
pub struct Register {
    origin: InstanceOrigin,
    clients: Arc<dyn Clients>,
    accounts: Arc<dyn SignInAccounts>,
    sign_ups: Arc<dyn SignUps>,
    hasher: Arc<dyn PasswordHasher>,
    suffixes: Arc<dyn HandleSuffixes>,
    codes: Arc<dyn SignupCodes>,
    mailer: Arc<dyn SignupMailer>,
}

impl Register {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        origin: InstanceOrigin,
        clients: Arc<dyn Clients>,
        accounts: Arc<dyn SignInAccounts>,
        sign_ups: Arc<dyn SignUps>,
        hasher: Arc<dyn PasswordHasher>,
        suffixes: Arc<dyn HandleSuffixes>,
        codes: Arc<dyn SignupCodes>,
        mailer: Arc<dyn SignupMailer>,
    ) -> Self {
        Self {
            origin,
            clients,
            accounts,
            sign_ups,
            hasher,
            suffixes,
            codes,
            mailer,
        }
    }

    /// `request` is the sign-in the registration continues into, if any.
    pub async fn execute(
        &self,
        command: RegisterCommand,
        request: Option<&AuthorizationRequest>,
        now: OffsetDateTime,
    ) -> Result<Registered, AuthError> {
        let blank = [&command.username, &command.email, &command.password]
            .iter()
            .any(|field| field.is_empty());
        if request.is_none() && blank {
            return Err(AuthError::MissingField);
        }
        let choice = UsernameChoice::parse(&command.username).map_err(AuthError::BadUsername)?;
        let email = Email::parse(&command.email).map_err(AuthError::BadEmail)?;
        check_password(&command.password)?;
        if self.accounts.by_email(&email).await?.is_some() {
            return Err(AuthError::EmailTaken);
        }
        if let Some(request) = request {
            let client = self
                .clients
                .find(&request.client)
                .await?
                .ok_or(AuthError::UnknownClient)?;
            if !client.allows(&request.redirect_uri) {
                return Err(AuthError::UnregisteredRedirect);
            }
        }
        let password_hash = self.hasher.hash(&command.password)?;
        // The store has the last word on both: an address registered in between is refused,
        // and a handle taken by chance is drawn again.
        for _ in 0..SUFFIX_DRAWS {
            let handle = Handle::compose(&choice, &self.suffixes.fresh());
            let account = NewAccount {
                id: UserId::generate(),
                actor_uri: self.origin.actor_uri(&handle),
                username: handle,
                display_name: command.username.clone(),
                email: email.clone(),
                password_hash: password_hash.clone(),
            };
            match self.sign_ups.create(&account).await? {
                Registration::Created => return self.mail(account, now).await,
                Registration::EmailTaken => return Err(AuthError::EmailTaken),
                Registration::HandleTaken => continue,
            }
        }
        Err(anyhow::anyhow!(
            "no free handle for {} in {SUFFIX_DRAWS} draws",
            choice.as_str()
        )
        .into())
    }

    async fn mail(
        &self,
        account: NewAccount,
        now: OffsetDateTime,
    ) -> Result<Registered, AuthError> {
        let signing_in = SignInAccount {
            id: account.id,
            email: account.email.as_str().to_owned(),
            username: account.username.as_str().to_owned(),
            display_name: Some(account.display_name.clone()),
            password_hash: account.password_hash,
            email_verified: false,
            totp_enabled: false,
        };
        mail_signup_code(&*self.codes, &*self.mailer, &signing_in, now).await?;
        Ok(Registered {
            user: account.id,
            username: signing_in.username,
            display_name: account.display_name,
            email: signing_in.email,
        })
    }
}

#[cfg(test)]
mod tests;
