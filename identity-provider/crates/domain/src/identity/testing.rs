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
}

impl InMemoryRemoteActors {
    pub fn with(actors: impl IntoIterator<Item = RemoteActor>) -> Self {
        Self {
            actors: Mutex::new(actors.into_iter().collect()),
        }
    }
}

#[async_trait::async_trait]
impl RemoteActors for InMemoryRemoteActors {
    async fn discover(&self, uri: &ActorUri) -> Result<RemoteActor, RemoteActorsError> {
        self.find(uri).await?.ok_or(RemoteActorsError::NotFound)
    }

    async fn find(&self, uri: &ActorUri) -> Result<Option<RemoteActor>, RemoteActorsError> {
        Ok(self
            .actors
            .lock()
            .unwrap()
            .iter()
            .find(|a| &a.actor_uri == uri)
            .cloned())
    }

    async fn resolve(&self, address: &FederatedAddress) -> Result<RemoteActor, RemoteActorsError> {
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

/// Takes a request's `signature` header for the actor that signed it — no cryptography.
#[derive(Default)]
pub struct TrustedSignatures;

impl TrustedSignatures {
    /// The header a test sends to sign a request as `actor`.
    pub fn header(actor: &ActorUri) -> (&'static str, String) {
        ("signature", actor.to_string())
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
        ActorUri::parse(value).map_err(|_| SignatureError::Refused("unknown signer".into()))
    }
}
