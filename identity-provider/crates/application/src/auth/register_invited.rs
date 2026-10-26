use std::sync::Arc;

use domain::auth::{
    AuthError, ClientSignIn, HandleSuffixes, InvitationToken, Invitations, PasswordHasher,
    SignInAccounts, SignUps, WebApp,
};
use domain::identity::InstanceOrigin;
use domain::{SessionId, UserId};
use time::OffsetDateTime;

use super::{CompleteSignIn, Creation, RegisterCommand, Registered, create_account};

/// Where someone who joined by invitation goes next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Joined {
    /// Signed in on this browser, the web app remembered as signed in to: off to `entry`, where
    /// the app's own sign-in goes through without the password.
    InWebApp {
        user: UserId,
        session: SessionId,
        entry: String,
    },
    /// No web app to land in, or signing in on joining failed: the person signs in from their app.
    Ready(Registered),
}

/// `POST /i/{token}/sign-up`: an account let in by an invitation — admitted, vouched for by
/// the invitation's creator, the invitation spent with it. No code is mailed. With the official
/// web app known, the browser is signed in and the web app recorded as signed in to, with the
/// password just typed: the person lands there signed in.
pub struct RegisterInvited {
    origin: InstanceOrigin,
    web_app: Option<WebApp>,
    accounts: Arc<dyn SignInAccounts>,
    sign_ups: Arc<dyn SignUps>,
    invitations: Arc<dyn Invitations>,
    hasher: Arc<dyn PasswordHasher>,
    suffixes: Arc<dyn HandleSuffixes>,
    complete: Arc<CompleteSignIn>,
}

impl RegisterInvited {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        origin: InstanceOrigin,
        web_app: Option<WebApp>,
        accounts: Arc<dyn SignInAccounts>,
        sign_ups: Arc<dyn SignUps>,
        invitations: Arc<dyn Invitations>,
        hasher: Arc<dyn PasswordHasher>,
        suffixes: Arc<dyn HandleSuffixes>,
        complete: Arc<CompleteSignIn>,
    ) -> Self {
        Self {
            origin,
            web_app,
            accounts,
            sign_ups,
            invitations,
            hasher,
            suffixes,
            complete,
        }
    }

    /// Where the web app opens on this instance, when one is known: joining ends there, signed
    /// in.
    pub fn web_app_entry(&self) -> Option<String> {
        self.web_app.as_ref().map(|app| app.entry(&self.origin))
    }

    /// `current` is the session the browser holds already, as a sign-in takes it.
    /// `InvitationUnusable` when the invitation is not open, or stops being so before the
    /// account is created.
    pub async fn execute(
        &self,
        token: &InvitationToken,
        command: RegisterCommand,
        current: Option<SessionId>,
        now: OffsetDateTime,
    ) -> Result<Joined, AuthError> {
        let invitation = self
            .invitations
            .find_open(token, now)
            .await?
            .ok_or(AuthError::InvitationUnusable)?;
        let (name, email) = command.parse()?;
        if self.accounts.by_email(&email).await?.is_some() {
            return Err(AuthError::EmailTaken);
        }
        let account = create_account(
            &*self.sign_ups,
            &self.origin,
            &*self.suffixes,
            Creation::Invited {
                invitation: invitation.id,
                at: now,
            },
            &name,
            &email,
            &self.hasher.hash(&command.password)?,
        )
        .await?;
        let Some(web_app) = &self.web_app else {
            return Ok(Joined::Ready(Registered::of(&account)));
        };
        let app = ClientSignIn {
            user: account.id,
            client: web_app.client_id().clone(),
            offline_access: false,
        };
        // The account exists and the invitation is spent: signing in from the app still works.
        match self
            .complete
            .signed_in(account.id, &app, current, now)
            .await
        {
            Ok(session) => Ok(Joined::InWebApp {
                user: account.id,
                session,
                entry: web_app.entry(&self.origin),
            }),
            Err(e) => {
                tracing::warn!(user = %account.id, error = ?e, "an invited account not signed in on joining");
                Ok(Joined::Ready(Registered::of(&account)))
            }
        }
    }
}

#[cfg(test)]
mod tests;
