//! Test helpers for other contexts' fakes and contracts.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::UserId;

use super::{
    Account, Accounts, AccountsError, ActorUri, FederatedAddress, Handle, RemoteActor,
    RemoteActors, RemoteActorsError, SignatureError, SignatureVerifier, SignedRequest, TokenError,
    TokenVerifier,
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
    /// Instances that fail to answer.
    down: Mutex<Vec<String>>,
}

impl InMemoryRemoteActors {
    pub fn with(actors: impl IntoIterator<Item = RemoteActor>) -> Self {
        Self {
            actors: Mutex::new(actors.into_iter().collect()),
            cached_only: Mutex::default(),
            down: Mutex::default(),
        }
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
        self.actors
            .lock()
            .unwrap()
            .iter()
            .find(|a| a.actor_uri.federated_address().as_ref() == Some(address))
            .cloned()
            .ok_or(RemoteActorsError::NotFound)
    }
}

/// Hands out opaque tokens and accepts only those.
#[derive(Default)]
pub struct InMemoryTokens {
    issued: Mutex<HashMap<String, UserId>>,
}

impl InMemoryTokens {
    pub fn issue(&self, user: UserId) -> String {
        let token = format!("token-{}", UserId::generate());
        self.issued.lock().unwrap().insert(token.clone(), user);
        token
    }
}

impl TokenVerifier for InMemoryTokens {
    fn verify(&self, token: &str) -> Result<UserId, TokenError> {
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

/// What every `Accounts` store must do. Each check takes accounts already in the store — the
/// Postgres ones are real `users` rows.
pub mod contract {
    use crate::identity::{Account, Accounts};

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
