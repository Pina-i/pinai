//! Who an account is, and how other instances address it: handles, federated addresses,
//! actor URIs, and the instance that owns them.

mod account;
mod actor_uri;
mod address;
mod handle;
mod intro;
mod origin;
mod ports;
mod search;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use account::{Account, RemoteActor};
pub use actor_uri::ActorUri;
pub use address::{Domain, FederatedAddress};
pub use handle::{Handle, HandleSuffix, UsernameChoice};
pub use intro::InstanceIntro;
pub use origin::{InstanceOrigin, Recipient};
pub use ports::{
    Accounts, AccountsError, RemoteActors, RemoteActorsError, Requester, SignatureError,
    SignatureVerifier, SignedRequest, TokenError, TokenVerifier,
};
pub use search::SearchQuery;
