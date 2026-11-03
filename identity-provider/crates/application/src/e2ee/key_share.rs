//! The account's history passphrase shared with its approved devices, sealed for each — see
//! identity-provider/specs/e2ee.md § 3.11.

use std::sync::Arc;

use domain::auth::Sessions;
use domain::e2ee::{
    Audience, Deposit, DeviceApprovals, DeviceTrustNotifier, Devices, Ed25519Verifier,
    HistoryGeneration, HistoryKeys, KeyDirectoryError, KeyShare, KeyShares, SealedShare,
    ShareFacts, may_share,
};
use domain::identity::{Accounts, Bearer};
use domain::{DeviceId, UserId};
use time::OffsetDateTime;

use super::approval::{ATTEMPTS, the_callers_device};

async fn current_generation(
    keys: &dyn HistoryKeys,
    owner: UserId,
) -> Result<Option<HistoryGeneration>, KeyDirectoryError> {
    Ok(keys
        .current(owner)
        .await
        .map_err(|e| KeyDirectoryError::Unexpected(e.into()))?
        .map(|held| held.key.generation))
}

/// `POST /api/history/key-shares`: the calling session's device, holding the current generation,
/// deposits the passphrase sealed for another approved device of the account.
pub struct ShareHistoryKey {
    accounts: Arc<dyn Accounts>,
    sessions: Arc<dyn Sessions>,
    devices: Arc<dyn Devices>,
    keys: Arc<dyn HistoryKeys>,
    approvals: Arc<dyn DeviceApprovals>,
    shares: Arc<dyn KeyShares>,
    verifier: Arc<dyn Ed25519Verifier>,
    notifier: Arc<dyn DeviceTrustNotifier>,
}

impl ShareHistoryKey {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        accounts: Arc<dyn Accounts>,
        sessions: Arc<dyn Sessions>,
        devices: Arc<dyn Devices>,
        keys: Arc<dyn HistoryKeys>,
        approvals: Arc<dyn DeviceApprovals>,
        shares: Arc<dyn KeyShares>,
        verifier: Arc<dyn Ed25519Verifier>,
        notifier: Arc<dyn DeviceTrustNotifier>,
    ) -> Self {
        Self {
            accounts,
            sessions,
            devices,
            keys,
            approvals,
            shares,
            verifier,
            notifier,
        }
    }

    /// A share held already for the recipient and generation is a success: only the first is
    /// kept, and only it is announced.
    pub async fn execute(
        &self,
        bearer: &Bearer,
        recipient: DeviceId,
        generation: HistoryGeneration,
        sealed: SealedShare,
        now: OffsetDateTime,
    ) -> Result<(), KeyDirectoryError> {
        let owner = bearer.user;
        let account = self.accounts.find(owner).await?.ok_or_else(|| {
            KeyDirectoryError::Unexpected(anyhow::anyhow!("the sharing account is gone"))
        })?;
        for _ in 0..ATTEMPTS {
            let sender = the_callers_device(&*self.sessions, &*self.devices, bearer).await?;
            let devices = self.devices.list(owner).await?;
            let approvals = self.approvals.of_owner(owner).await?;
            let current = current_generation(&*self.keys, owner).await?;
            let facts = ShareFacts {
                actor: &account.actor_uri,
                sender: &sender,
                devices: &devices,
                approvals: &approvals,
                current,
            };
            let checked = may_share(
                recipient,
                generation,
                sealed.clone(),
                facts,
                &*self.verifier,
            )?;
            match self.shares.deposit(owner, &checked).await? {
                Deposit::Stored => {
                    let generation = generation.value();
                    tracing::info!(user_id = %owner, sender = %sender.id, recipient = %recipient, generation, "history key shared");
                    // The share is stored: the recipient reads it when it next lacks the passphrase.
                    match self.sessions.of_user(owner).await {
                        Ok(sessions) => {
                            let to = Audience::Devices(vec![recipient]).sessions(&sessions, now);
                            self.notifier.history_key_ready(owner, &to, recipient);
                        }
                        Err(e) => {
                            tracing::warn!(error = ?e, user_id = %owner, "the key share went untold");
                        }
                    }
                    return Ok(());
                }
                Deposit::AlreadyHeld => return Ok(()),
                Deposit::Stale => continue,
            }
        }
        Err(KeyDirectoryError::Unexpected(anyhow::anyhow!(
            "the devices kept changing while sharing with {recipient}"
        )))
    }
}

/// `GET /api/history/key-shares`: the share waiting for the calling session's device under the
/// current generation.
pub struct LoadKeyShare {
    sessions: Arc<dyn Sessions>,
    devices: Arc<dyn Devices>,
    keys: Arc<dyn HistoryKeys>,
    shares: Arc<dyn KeyShares>,
}

impl LoadKeyShare {
    pub fn new(
        sessions: Arc<dyn Sessions>,
        devices: Arc<dyn Devices>,
        keys: Arc<dyn HistoryKeys>,
        shares: Arc<dyn KeyShares>,
    ) -> Self {
        Self {
            sessions,
            devices,
            keys,
            shares,
        }
    }

    /// `NoKeyShare` when none waits, as before the account has a history key.
    pub async fn execute(&self, bearer: &Bearer) -> Result<KeyShare, KeyDirectoryError> {
        let device = the_callers_device(&*self.sessions, &*self.devices, bearer).await?;
        let Some(current) = current_generation(&*self.keys, bearer.user).await? else {
            return Err(KeyDirectoryError::NoKeyShare);
        };
        self.shares
            .of_recipient(bearer.user, device.id, current)
            .await?
            .ok_or(KeyDirectoryError::NoKeyShare)
    }
}

#[cfg(test)]
mod tests;
