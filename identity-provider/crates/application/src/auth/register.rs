use std::sync::Arc;

use domain::UserId;
use domain::auth::{
    AuthError, AuthorizationRequest, Clients, Email, HandleSuffixes, NewAccount, PasswordHasher,
    SignInAccount, SignInAccounts, SignUps, SignupCodes, SignupMailer, check_password,
};
use domain::identity::InstanceOrigin;
use domain::profile::DisplayName;
use time::OffsetDateTime;

use super::{Creation, create_account, mail_signup_code};

#[derive(Debug, Clone)]
pub struct RegisterCommand {
    pub display_name: String,
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
        let blank = [&command.display_name, &command.email, &command.password]
            .iter()
            .any(|field| field.is_empty());
        if request.is_none() && blank {
            return Err(AuthError::MissingField);
        }
        let name = DisplayName::parse(&command.display_name).map_err(AuthError::BadDisplayName)?;
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
        let account = create_account(
            &*self.sign_ups,
            &self.origin,
            &*self.suffixes,
            Creation::SignUp,
            &name,
            &email,
            &self.hasher.hash(&command.password)?,
        )
        .await?;
        self.mail(account, now).await
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
            admitted: false,
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
