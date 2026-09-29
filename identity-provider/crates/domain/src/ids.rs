//! Typed ids: a bare `Uuid` parameter can be swapped with another silently. Every id is declared
//! here, so the macro stays private to the crate.

macro_rules! id {
    ($name:ident) => {
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(uuid::Uuid);

        impl $name {
            pub fn generate() -> Self {
                Self(uuid::Uuid::new_v4())
            }

            pub fn as_uuid(&self) -> uuid::Uuid {
                self.0
            }
        }

        impl From<uuid::Uuid> for $name {
            fn from(id: uuid::Uuid) -> Self {
                Self(id)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

id!(AttachmentId);
id!(CommitId);
id!(ConnectionId);
id!(ConversationId);
id!(DeviceId);
id!(FriendshipId);
id!(MessageId);
id!(UserId);
id!(WelcomeId);
