//! What an account shows of itself — its name, pronouns, bio and avatar — and how a change
//! reaches its friends, here and on other instances — see
//! identity-provider/specs/profile-and-settings.md § 1 and § 3.

mod avatar;
mod edit;
mod error;
mod ports;
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;
mod views;

pub use avatar::{AvatarImage, ImageKind, published_url};
pub use edit::{Bio, DisplayName, ProfileEdit, Pronouns};
pub use error::ProfileError;
pub use ports::{
    AvatarStore, PeerProfiles, ProfileAudience, ProfileFederation, ProfileNotifier, Profiles,
};
pub use views::{OwnProfile, PublicProfile};
