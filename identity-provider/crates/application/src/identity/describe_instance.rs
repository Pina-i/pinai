use std::sync::{Arc, Mutex};

use domain::auth::Registrations;
use domain::identity::{Accounts, AccountsError, KlipyKey, SourceUrl};
use time::{Duration, OffsetDateTime};

use super::IntroInForce;

/// What this instance tells a visitor about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceFacts {
    pub name: String,
    pub description: Option<String>,
    /// Its accounts, as counted at most a minute ago.
    pub people: u64,
    /// Anyone may sign up: `REGISTRATIONS=open`.
    pub open_registrations: bool,
    /// Where the code it runs can be had: `SOURCE_URL`.
    pub source: SourceUrl,
    /// What turns on its members' GIF picker: `KLIPY_API_KEY`.
    pub klipy_key: Option<KlipyKey>,
}

/// Its sign-in pages and its NodeInfo, which anyone may ask for: the count is kept a minute,
/// so asking again costs nothing.
pub struct DescribeInstance {
    intro: Arc<IntroInForce>,
    source: SourceUrl,
    registrations: Registrations,
    accounts: Arc<dyn Accounts>,
    klipy_key: Option<KlipyKey>,
    counted: Mutex<Option<(OffsetDateTime, u64)>>,
}

impl DescribeInstance {
    pub const COUNT_KEPT: Duration = Duration::minutes(1);

    pub fn new(
        intro: Arc<IntroInForce>,
        source: SourceUrl,
        registrations: Registrations,
        accounts: Arc<dyn Accounts>,
    ) -> Self {
        Self {
            intro,
            source,
            registrations,
            accounts,
            klipy_key: None,
            counted: Mutex::new(None),
        }
    }

    /// The instance hands its members' clients this key for the GIF picker; none, no picker.
    pub fn with_klipy_key(mut self, key: Option<KlipyKey>) -> Self {
        self.klipy_key = key;
        self
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
        let intro = self.intro.shown();
        Ok(InstanceFacts {
            name: intro.name().to_owned(),
            description: intro.description().map(str::to_owned),
            people,
            open_registrations: self.registrations.are_open(),
            source: self.source.clone(),
            klipy_key: self.klipy_key.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
