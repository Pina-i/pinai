use std::sync::Arc;

use domain::auth::{
    AdminBootstrap, AdminRefusal, AuthError, Email, HandleSuffixes, PasswordHasher, SignUps,
    admin_bootstrap, admin_display_name,
};
use domain::identity::InstanceOrigin;
use time::OffsetDateTime;

use super::{Creation, create_account};

/// Starting the instance: its first admin, from the address and password it is configured with.
pub struct EnsureAdmin {
    origin: InstanceOrigin,
    sign_ups: Arc<dyn SignUps>,
    hasher: Arc<dyn PasswordHasher>,
    suffixes: Arc<dyn HandleSuffixes>,
}

impl EnsureAdmin {
    pub fn new(
        origin: InstanceOrigin,
        sign_ups: Arc<dyn SignUps>,
        hasher: Arc<dyn PasswordHasher>,
        suffixes: Arc<dyn HandleSuffixes>,
    ) -> Self {
        Self {
            origin,
            sign_ups,
            hasher,
            suffixes,
        }
    }

    /// What was done about the admin: `Create` with the address of the account created.
    pub async fn execute(
        &self,
        address: Option<&str>,
        password: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<AdminBootstrap<Email>, AuthError> {
        let address = match address.map(Email::parse).transpose() {
            Ok(address) => address,
            Err(bad) => {
                return Ok(AdminBootstrap::Refused(AdminRefusal::BadAddress(
                    bad.reason,
                )));
            }
        };
        let facts = self.sign_ups.admin_facts(address.as_ref()).await?;
        let bootstrap = admin_bootstrap(
            facts.admin_exists,
            address.map(|address| (address, facts.holder)),
            password,
        );
        if let AdminBootstrap::Create(admin) = &bootstrap {
            create_account(
                &*self.sign_ups,
                &self.origin,
                &*self.suffixes,
                Creation::Admin(now),
                &admin_display_name(),
                &admin.address,
                &self.hasher.hash(admin.password.as_str())?,
            )
            .await?;
        }
        Ok(bootstrap.map_create(|admin| admin.address))
    }
}

#[cfg(test)]
mod tests;
