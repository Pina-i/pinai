use time::OffsetDateTime;

use crate::UserId;
use crate::identity::ActorUri;

/// An account of the instance as its admins list it: by its display name, never its handle or
/// its address. An account still to confirm its address is no member yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceMember {
    pub id: UserId,
    /// Whose presence tells whether it is online.
    pub actor: Option<ActorUri>,
    pub display_name: Option<String>,
    pub admin: bool,
    /// The latest use of a live session of it; `None` when signed out everywhere.
    pub last_active_at: Option<OffsetDateTime>,
}
