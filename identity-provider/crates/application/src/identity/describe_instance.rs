use std::sync::{Arc, Mutex};

use domain::auth::Registrations;
use domain::identity::{Accounts, AccountsError, InstanceIntro};
use time::{Duration, OffsetDateTime};

/// What this instance tells a visitor about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceFacts {
    pub name: String,
    pub description: Option<String>,
    /// Its accounts, as counted at most a minute ago.
    pub people: u64,
    /// Anyone may sign up: `REGISTRATIONS=open`.
    pub open_registrations: bool,
}

/// Its sign-in pages and its NodeInfo, which anyone may ask for: the count is kept a minute,
/// so asking again costs nothing.
pub struct DescribeInstance {
    intro: InstanceIntro,
    registrations: Registrations,
    accounts: Arc<dyn Accounts>,
    counted: Mutex<Option<(OffsetDateTime, u64)>>,
}

impl DescribeInstance {
    pub const COUNT_KEPT: Duration = Duration::minutes(1);

    pub fn new(
        intro: InstanceIntro,
        registrations: Registrations,
        accounts: Arc<dyn Accounts>,
    ) -> Self {
        Self {
            intro,
            registrations,
            accounts,
            counted: Mutex::new(None),
        }
    }

    pub async fn execute(&self, now: OffsetDateTime) -> Result<InstanceFacts, AccountsError> {
        let kept = *self.counted.lock().unwrap();
        let people = match kept {
            Some((at, people)) if now - at < Self::COUNT_KEPT => people,
            _ => {
                let people = self.accounts.count().await?;
                *self.counted.lock().unwrap() = Some((now, people));
                people
            }
        };
        Ok(InstanceFacts {
            name: self.intro.name().to_owned(),
            description: self.intro.description().map(str::to_owned),
            people,
            open_registrations: self.registrations.are_open(),
        })
    }
}

#[cfg(test)]
mod tests;
