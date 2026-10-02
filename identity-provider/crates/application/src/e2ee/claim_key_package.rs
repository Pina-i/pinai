use std::sync::Arc;

use domain::e2ee::{
    Claim, ClaimedKeyPackage, DeviceNotifier, KeyDirectoryError, KeyPackagePolicy, KeyPackages,
    RemoteKeyPackages,
};
use domain::identity::{Accounts, ActorUri, InstanceOrigin, Requester};
use domain::social::Reachability;
use domain::{DeviceId, UserId};

/// `POST /api/keys/packages/claim`: one of `target`'s KeyPackages, to add a device of theirs to
/// a group — of `device`, or of any device with some left. A local user's claim for an account
/// elsewhere is asked of that account's instance. The owner's live sessions are told to refill
/// when a claim leaves a device at the threshold, or finds nothing.
pub struct ClaimKeyPackage {
    origin: InstanceOrigin,
    policy: KeyPackagePolicy,
    accounts: Arc<dyn Accounts>,
    key_packages: Arc<dyn KeyPackages>,
    remote: Arc<dyn RemoteKeyPackages>,
    reach: Arc<dyn Reachability>,
    notifier: Arc<dyn DeviceNotifier>,
}

impl ClaimKeyPackage {
    pub fn new(
        origin: InstanceOrigin,
        policy: KeyPackagePolicy,
        accounts: Arc<dyn Accounts>,
        key_packages: Arc<dyn KeyPackages>,
        remote: Arc<dyn RemoteKeyPackages>,
        reach: Arc<dyn Reachability>,
        notifier: Arc<dyn DeviceNotifier>,
    ) -> Self {
        Self {
            origin,
            policy,
            accounts,
            key_packages,
            remote,
            reach,
            notifier,
        }
    }

    pub async fn execute(
        &self,
        requester: &Requester,
        target: &ActorUri,
        device: Option<DeviceId>,
    ) -> Result<Claim, KeyDirectoryError> {
        if !self.origin.owns(target) {
            let sender = self.local_sender(requester).await?;
            return Ok(self.remote.claim(&sender, target, device).await?);
        }
        let owner = self.admitted_owner(requester, target).await?;
        let Some(package) = self.key_packages.claim(owner, device).await? else {
            self.notifier.key_packages_low(owner);
            return Err(KeyDirectoryError::NoKeyPackage);
        };
        let claim = self.counted(owner, package).await?;
        if claim.needs_refill {
            self.notifier.key_packages_low(owner);
        }
        Ok(claim)
    }

    /// `POST /api/keys/packages/claim/devices`: one KeyPackage of each of `target`'s devices that
    /// has any, for a contact's first add — every device of theirs then reads the group, not only
    /// the one a single claim would pick. Asked and refused as a single claim is.
    pub async fn each_device(
        &self,
        requester: &Requester,
        target: &ActorUri,
    ) -> Result<Vec<Claim>, KeyDirectoryError> {
        if !self.origin.owns(target) {
            let sender = self.local_sender(requester).await?;
            return Ok(self.remote.claim_each_device(&sender, target).await?);
        }
        let owner = self.admitted_owner(requester, target).await?;
        let mut claims = Vec::new();
        for (device, available) in self.key_packages.available_per_device(owner).await? {
            if available == 0 {
                continue;
            }
            // A revoked device's, or one another claimer just emptied, comes back empty.
            if let Some(package) = self.key_packages.claim(owner, Some(device)).await? {
                claims.push(self.counted(owner, package).await?);
            }
        }
        if claims.is_empty() || claims.iter().any(|c| c.needs_refill) {
            self.notifier.key_packages_low(owner);
        }
        if claims.is_empty() {
            return Err(KeyDirectoryError::NoKeyPackage);
        }
        Ok(claims)
    }

    /// A local user asking for an account elsewhere, whose instance is asked in their name.
    async fn local_sender(&self, requester: &Requester) -> Result<ActorUri, KeyDirectoryError> {
        let Requester::User(user) = requester else {
            return Err(KeyDirectoryError::PeerMustTargetLocal);
        };
        let sender = self.accounts.find(*user).await?.ok_or_else(|| {
            KeyDirectoryError::Unexpected(anyhow::anyhow!("the claiming account is gone"))
        })?;
        Ok(sender.actor_uri)
    }

    /// The owner of `target`, here, once they admit whoever asks.
    async fn admitted_owner(
        &self,
        requester: &Requester,
        target: &ActorUri,
    ) -> Result<UserId, KeyDirectoryError> {
        let owner = self
            .accounts
            .find_by_uri(target)
            .await?
            .ok_or(KeyDirectoryError::UserNotFound)?;
        let claimer = match requester {
            Requester::User(user) => {
                self.accounts
                    .find(*user)
                    .await?
                    .ok_or_else(|| {
                        KeyDirectoryError::Unexpected(anyhow::anyhow!(
                            "the claiming account is gone"
                        ))
                    })?
                    .actor_uri
            }
            Requester::Peer(actor) => actor.clone(),
        };
        // Before a package is taken: a refused claim must cost the owner nothing.
        if claimer != owner.actor_uri {
            self.reach.relation(owner.id, &claimer).await?.admits()?;
        }
        Ok(owner.id)
    }

    async fn counted(
        &self,
        owner: UserId,
        package: ClaimedKeyPackage,
    ) -> Result<Claim, KeyDirectoryError> {
        let remaining = self.key_packages.available(owner, package.device).await?;
        Ok(Claim {
            needs_refill: self.policy.needs_refill(remaining),
            package,
            remaining,
        })
    }
}
