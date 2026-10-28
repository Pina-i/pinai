//! Test helpers for other contexts' fakes and contracts.

use std::collections::HashMap;
use std::sync::Mutex;

use time::OffsetDateTime;

use crate::{SessionId, UserId};

use super::{
    Account, Accounts, AccountsError, ActorUri, Bearer, FederatedAddress, Handle, IntroText,
    RemoteActor, RemoteActors, RemoteActorsError, SavedIntro, SavedIntroError, SignatureError,
    SignatureVerifier, SignedRequest, TokenError, TokenVerifier,
};

/// A local account on `http://localhost:8080` whose handle starts with `name`.
pub fn account(name: &str) -> Account {
    let username = format!("{name}_t3st0");
    Account {
        id: UserId::generate(),
        actor_uri: ActorUri::parse(&format!("http://localhost:8080/users/{username}")).unwrap(),
        username,
        display_name: Some(name.to_owned()),
        avatar_url: None,
    }
}

#[derive(Default)]
pub struct InMemoryAccounts {
    accounts: Mutex<Vec<Account>>,
}

impl InMemoryAccounts {
    pub fn with(accounts: impl IntoIterator<Item = Account>) -> Self {
        Self {
            accounts: Mutex::new(accounts.into_iter().collect()),
        }
    }

    pub fn add(&self, account: Account) {
        self.accounts.lock().unwrap().push(account);
    }
}

#[async_trait::async_trait]
impl Accounts for InMemoryAccounts {
    async fn find(&self, id: UserId) -> Result<Option<Account>, AccountsError> {
        Ok(self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .find(|a| a.id == id)
            .cloned())
    }

    async fn find_by_uri(&self, uri: &ActorUri) -> Result<Option<Account>, AccountsError> {
        Ok(self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .find(|a| &a.actor_uri == uri)
            .cloned())
    }

    async fn find_by_handle(&self, handle: &Handle) -> Result<Option<Account>, AccountsError> {
        Ok(self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .find(|a| a.username == handle.as_str())
            .cloned())
    }

    async fn search(&self, fragment: &str, limit: i64) -> Result<Vec<Account>, AccountsError> {
        let fragment = fragment.to_lowercase();
        let mut found: Vec<Account> = self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .filter(|a| a.username.to_lowercase().contains(&fragment))
            .cloned()
            .collect();
        found.sort_by(|a, b| a.username.cmp(&b.username));
        found.truncate(usize::try_from(limit).unwrap_or(0));
        Ok(found)
    }

    async fn count(&self) -> Result<u64, AccountsError> {
        Ok(self.accounts.lock().unwrap().len() as u64)
    }
}

#[derive(Default)]
pub struct InMemorySavedIntro {
    saved: Mutex<Option<(IntroText, UserId, OffsetDateTime)>>,
    broken: Mutex<bool>,
}

impl InMemorySavedIntro {
    /// Every save fails from now on.
    pub fn break_down(&self) {
        *self.broken.lock().unwrap() = true;
    }

    /// The text last saved, by whom and when.
    pub fn saved(&self) -> Option<(IntroText, UserId, OffsetDateTime)> {
        self.saved.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl SavedIntro for InMemorySavedIntro {
    async fn get(&self) -> Result<Option<IntroText>, SavedIntroError> {
        Ok(self.saved().map(|(text, _, _)| text))
    }

    async fn save(
        &self,
        text: &IntroText,
        by: UserId,
        at: OffsetDateTime,
    ) -> Result<(), SavedIntroError> {
        if *self.broken.lock().unwrap() {
            return Err(anyhow::anyhow!("the database is down").into());
        }
        *self.saved.lock().unwrap() = Some((text.clone(), by, at));
        Ok(())
    }
}

/// A remote account at `address`, with the conventional Pina'i URI and inbox.
pub fn remote_actor(address: &str) -> RemoteActor {
    let address = FederatedAddress::parse(address).unwrap();
    let actor_uri = ActorUri::parse(&format!(
        "https://{}/users/{}",
        address.domain(),
        address.user()
    ))
    .unwrap();
    RemoteActor {
        inbox: url::Url::parse(&format!("{actor_uri}/inbox")).unwrap(),
        actor_uri,
        display_name: Some(address.user().to_owned()),
        avatar_url: None,
    }
}

#[derive(Default)]
pub struct InMemoryRemoteActors {
    actors: Mutex<Vec<RemoteActor>>,
    /// Remembered here, but their instance no longer knows them.
    cached_only: Mutex<Vec<RemoteActor>>,
    /// Known to their own instance, not to this one yet: resolving one remembers them.
    uncached: Mutex<Vec<RemoteActor>>,
    /// Instances that fail to answer.
    down: Mutex<Vec<String>>,
    /// How many times an instance was asked.
    lookups: Mutex<usize>,
}

impl InMemoryRemoteActors {
    pub fn with(actors: impl IntoIterator<Item = RemoteActor>) -> Self {
        Self {
            actors: Mutex::new(actors.into_iter().collect()),
            ..Self::default()
        }
    }

    /// Also `elsewhere`: accounts their own instance knows, never resolved here.
    pub fn and_uncached(self, elsewhere: impl IntoIterator<Item = RemoteActor>) -> Self {
        self.uncached.lock().unwrap().extend(elsewhere);
        self
    }

    /// How many times `resolve` asked an instance.
    pub fn lookups(&self) -> usize {
        *self.lookups.lock().unwrap()
    }

    /// `domain`'s instance fails to answer: resolving anyone there is `Unavailable`.
    pub fn and_down(self, domain: &str) -> Self {
        self.down.lock().unwrap().push(domain.to_owned());
        self
    }

    /// Also `cached`: found in this instance's cache, unknown to their own instance.
    pub fn and_cached_only(self, cached: impl IntoIterator<Item = RemoteActor>) -> Self {
        self.cached_only.lock().unwrap().extend(cached);
        self
    }
}

#[async_trait::async_trait]
impl RemoteActors for InMemoryRemoteActors {
    async fn discover(&self, uri: &ActorUri) -> Result<RemoteActor, RemoteActorsError> {
        self.actors
            .lock()
            .unwrap()
            .iter()
            .find(|a| &a.actor_uri == uri)
            .cloned()
            .ok_or(RemoteActorsError::NotFound)
    }

    async fn find(&self, uri: &ActorUri) -> Result<Option<RemoteActor>, RemoteActorsError> {
        let known = |actors: &Mutex<Vec<RemoteActor>>| {
            actors
                .lock()
                .unwrap()
                .iter()
                .find(|a| &a.actor_uri == uri)
                .cloned()
        };
        Ok(known(&self.actors).or_else(|| known(&self.cached_only)))
    }

    async fn resolve(&self, address: &FederatedAddress) -> Result<RemoteActor, RemoteActorsError> {
        *self.lookups.lock().unwrap() += 1;
        if self
            .down
            .lock()
            .unwrap()
            .iter()
            .any(|d| d == address.domain().as_str())
        {
            return Err(RemoteActorsError::Unavailable(
                "connection refused".to_owned(),
            ));
        }
        let named = |a: &RemoteActor| a.actor_uri.federated_address().as_ref() == Some(address);
        if let Some(known) = self.actors.lock().unwrap().iter().find(|a| named(a)) {
            return Ok(known.clone());
        }
        let mut uncached = self.uncached.lock().unwrap();
        let at = uncached
            .iter()
            .position(named)
            .ok_or(RemoteActorsError::NotFound)?;
        let resolved = uncached.remove(at);
        self.actors.lock().unwrap().push(resolved.clone());
        Ok(resolved)
    }
}

/// Hands out opaque tokens and accepts only those.
#[derive(Default)]
pub struct InMemoryTokens {
    issued: Mutex<HashMap<String, Bearer>>,
}

impl InMemoryTokens {
    /// A token for `user`, belonging to `session`, whose password was typed just now.
    pub fn issue(&self, user: UserId, session: SessionId) -> String {
        self.issue_signed_in_at(user, session, time::OffsetDateTime::now_utc())
    }

    /// The same, with the password typed at `authenticated_at`.
    pub fn issue_signed_in_at(
        &self,
        user: UserId,
        session: SessionId,
        authenticated_at: time::OffsetDateTime,
    ) -> String {
        let token = format!("token-{}", UserId::generate());
        self.issued.lock().unwrap().insert(
            token.clone(),
            Bearer {
                user,
                session,
                authenticated_at,
            },
        );
        token
    }
}

impl TokenVerifier for InMemoryTokens {
    fn verify(&self, token: &str) -> Result<Bearer, TokenError> {
        self.issued
            .lock()
            .unwrap()
            .get(token)
            .copied()
            .ok_or(TokenError::Invalid)
    }
}

/// Takes a request's `signature` header for the actor that signed it, and a body's `digest`
/// header for its SHA-256 — no signature cryptography.
#[derive(Default)]
pub struct TrustedSignatures;

impl TrustedSignatures {
    /// The header a test sends to sign a request as `actor`.
    pub fn header(actor: &ActorUri) -> (&'static str, String) {
        ("signature", actor.to_string())
    }

    /// The `digest` header value of `body`, as a peer sends it.
    pub fn digest(body: &[u8]) -> String {
        use base64::Engine as _;
        use sha2::Digest as _;
        let hash = sha2::Sha256::digest(body);
        format!(
            "SHA-256={}",
            base64::engine::general_purpose::STANDARD.encode(hash)
        )
    }
}

#[async_trait::async_trait]
impl SignatureVerifier for TrustedSignatures {
    async fn verify(&self, request: &SignedRequest) -> Result<ActorUri, SignatureError> {
        let (_, value) = request
            .headers
            .iter()
            .find(|(name, _)| name == "signature")
            .ok_or_else(|| SignatureError::Malformed("missing Signature header".into()))?;
        let signer =
            ActorUri::parse(value).map_err(|_| SignatureError::Refused("unknown signer".into()))?;
        if let Some(body) = &request.body {
            let (_, digest) = request
                .headers
                .iter()
                .find(|(name, _)| name == "digest")
                .ok_or_else(|| SignatureError::Malformed("missing Digest header".into()))?;
            if *digest != Self::digest(body) {
                return Err(SignatureError::Refused(
                    "Digest does not match request body".into(),
                ));
            }
        }
        Ok(signer)
    }
}

/// What every `Accounts` and `SavedIntro` store must do. Each check takes accounts already in the
/// store — the Postgres ones are real `users` rows.
pub mod contract {
    use time::OffsetDateTime;

    use crate::UserId;
    use crate::identity::{Account, Accounts, IntroText, SavedIntro};

    /// Takes a store nobody saved to.
    pub async fn nothing_is_saved_until_an_admin_saves(intro: &dyn SavedIntro) {
        assert_eq!(intro.get().await.unwrap(), None);
    }

    pub async fn the_last_text_saved_is_read_back(intro: &dyn SavedIntro, admin: UserId) {
        let at = OffsetDateTime::from_unix_timestamp(1_790_000_000).unwrap();
        let first = IntroText::parse(Some("Aotearoa"), Some("Design people.")).unwrap();
        let second = IntroText::parse(None, Some("Weavers.")).unwrap();

        intro.save(&first, admin, at).await.unwrap();
        assert_eq!(intro.get().await.unwrap(), Some(first));
        intro.save(&second, admin, at).await.unwrap();
        assert_eq!(
            intro.get().await.unwrap(),
            Some(second),
            "the name left out"
        );
    }

    /// `alice` and `bob` are named so: `lic` is in the first handle only.
    pub async fn a_search_finds_the_handles_holding_the_query(
        accounts: &dyn Accounts,
        alice: &Account,
        bob: &Account,
    ) {
        let both = vec![alice.clone(), bob.clone()];

        assert_eq!(
            accounts.search("lic", 20).await.unwrap(),
            vec![alice.clone()]
        );
        assert_eq!(
            accounts.search("LIC", 20).await.unwrap(),
            vec![alice.clone()],
            "in any case"
        );
        assert_eq!(accounts.search("_", 20).await.unwrap(), both, "by handle");
        assert_eq!(
            accounts.search("_", 1).await.unwrap(),
            vec![alice.clone()],
            "at most the limit"
        );
        assert!(accounts.search("zzz", 20).await.unwrap().is_empty());
    }

    /// Takes the store holding exactly `alice` and `bob`.
    pub async fn every_account_counts(accounts: &dyn Accounts) {
        assert_eq!(accounts.count().await.unwrap(), 2);
    }

    /// `%` and `_` are no wildcards: `alice` holds `lic`, not `l_c` nor `%e`.
    pub async fn a_search_takes_its_query_literally(accounts: &dyn Accounts, alice: &Account) {
        for query in ["l_c", "%e", "\\"] {
            assert!(
                accounts.search(query, 20).await.unwrap().is_empty(),
                "{query:?} matched {}",
                alice.username
            );
        }
    }
}

#[cfg(test)]
mod tests;
