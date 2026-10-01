use std::sync::Arc;

use domain::DeviceId;
use domain::e2ee::{Claim, KeyDirectoryError, KeyPackagePolicy, KeyPackages, RemoteKeyPackages};
use domain::identity::{Accounts, ActorUri, InstanceOrigin, Requester};
use domain::social::Reachability;

/// `POST /api/keys/packages/claim`: one of `target`'s KeyPackages, to add a device of theirs to
/// a group — of `device`, or of any device with some left. A local user's claim for an account
/// elsewhere is asked of that account's instance.
pub struct ClaimKeyPackage {
    origin: InstanceOrigin,
    policy: KeyPackagePolicy,
    accounts: Arc<dyn Accounts>,
    key_packages: Arc<dyn KeyPackages>,
    remote: Arc<dyn RemoteKeyPackages>,
    reach: Arc<dyn Reachability>,
}

impl ClaimKeyPackage {
    pub fn new(
        origin: InstanceOrigin,
        policy: KeyPackagePolicy,
        accounts: Arc<dyn Accounts>,
        key_packages: Arc<dyn KeyPackages>,
        remote: Arc<dyn RemoteKeyPackages>,
        reach: Arc<dyn Reachability>,
    ) -> Self {
        Self {
            origin,
            policy,
            accounts,
            key_packages,
            remote,
            reach,
        }
    }

    pub async fn execute(
        &self,
        requester: &Requester,
        target: &ActorUri,
        device: Option<DeviceId>,
    ) -> Result<Claim, KeyDirectoryError> {
        if !self.origin.owns(target) {
            let Requester::User(user) = requester else {
                return Err(KeyDirectoryError::PeerMustTargetLocal);
            };
            let sender = self.accounts.find(*user).await?.ok_or_else(|| {
                KeyDirectoryError::Unexpected(anyhow::anyhow!("the claiming account is gone"))
            })?;
            return Ok(self.remote.claim(&sender.actor_uri, target, device).await?);
        }
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
        let package = self
            .key_packages
            .claim(owner.id, device)
            .await?
            .ok_or(KeyDirectoryError::NoKeyPackage)?;
        let remaining = self
            .key_packages
            .available(owner.id, package.device)
            .await?;
        Ok(Claim {
            package,
            remaining,
            needs_refill: self.policy.needs_refill(remaining),
        })
    }
}
