use std::sync::{Arc, RwLock};

use domain::auth::SignInAccounts;
use domain::identity::{InstanceIntro, InstanceOrigin, IntroError, IntroText, SavedIntro};
use domain::{UserId, ValidationError};
use futures_util::lock::Mutex;
use time::OffsetDateTime;

use crate::auth::require_admin;

/// The text in force, held here so that no visitor's request reads the database for it: loaded
/// at startup, replaced by each save. One process per instance.
pub struct IntroInForce {
    origin: InstanceOrigin,
    text: RwLock<IntroText>,
}

impl IntroInForce {
    pub fn new(origin: InstanceOrigin, in_force: IntroText) -> Self {
        Self {
            origin,
            text: RwLock::new(in_force),
        }
    }

    /// As written: `None` for a default.
    pub fn text(&self) -> IntroText {
        self.text.read().unwrap().clone()
    }

    /// As the pages and NodeInfo show it.
    pub fn shown(&self) -> InstanceIntro {
        self.text.read().unwrap().shown(&self.origin)
    }

    fn replace(&self, text: IntroText) {
        *self.text.write().unwrap() = text;
    }
}

/// `GET /api/admin/intro`: what Settings → Instance edits, a default left `None` rather than
/// shown.
pub struct ShowIntro {
    accounts: Arc<dyn SignInAccounts>,
    in_force: Arc<IntroInForce>,
}

impl ShowIntro {
    pub fn new(accounts: Arc<dyn SignInAccounts>, in_force: Arc<IntroInForce>) -> Self {
        Self { accounts, in_force }
    }

    pub async fn execute(&self, caller: UserId) -> Result<IntroText, IntroError> {
        require_admin(&*self.accounts, caller).await?;
        Ok(self.in_force.text())
    }
}

/// The text an admin asks to save, as typed: `None` for a field left to its default.
#[derive(Debug)]
pub struct IntroDraft {
    pub name: Option<String>,
    pub description: Option<String>,
}

/// `PUT /api/admin/intro`: an admin's text, saved, then in force over `.env` at once.
pub struct EditIntro {
    accounts: Arc<dyn SignInAccounts>,
    saved: Arc<dyn SavedIntro>,
    in_force: Arc<IntroInForce>,
    // Two admins saving at once: the row and memory end on the same text.
    saving: Mutex<()>,
}

impl EditIntro {
    pub fn new(
        accounts: Arc<dyn SignInAccounts>,
        saved: Arc<dyn SavedIntro>,
        in_force: Arc<IntroInForce>,
    ) -> Self {
        Self {
            accounts,
            saved,
            in_force,
            saving: Mutex::new(()),
        }
    }

    /// `draft` is the request's refusal when it carried none, answered only once the caller is an
    /// admin. A refused or failed save leaves the text in force as it was.
    pub async fn execute(
        &self,
        caller: UserId,
        draft: Result<IntroDraft, ValidationError>,
        now: OffsetDateTime,
    ) -> Result<IntroText, IntroError> {
        require_admin(&*self.accounts, caller).await?;
        let draft = draft?;
        let text = IntroText::parse(draft.name.as_deref(), draft.description.as_deref())?;
        let _saving = self.saving.lock().await;
        self.saved.save(&text, caller, now).await?;
        self.in_force.replace(text.clone());
        Ok(text)
    }
}

#[cfg(test)]
mod tests;
