# Domain types

A check that returns `bool` is a leaky cauldron: its result is stored nowhere, so every callee must
check again or trust the whole program. Parse instead — turn raw input into a type that can only
hold valid values, once, at the boundary.

## Contents
1. Value objects
2. Typed ids
3. Closed enums
4. Parsing at the boundaries
5. Property-based tests
6. Layout

## 1. Value objects

```rust
// domain/src/identity/handle.rs
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct Handle(String);

impl Handle {
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let ok_len = (3..=32).contains(&raw.chars().count());
        let ok_chars = raw.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if ok_len && ok_chars {
            Ok(Self(raw.to_owned()))
        } else {
            Err(ValidationError::new("handle", "3–32 characters: a–z, 0–9, _"))
        }
    }
}

impl AsRef<str> for Handle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
```

- The inner field is **private**: outside its module the only way in is `parse`. No `pub` field, no
  `inner_mut`; read access through `AsRef<str>`, `as_str()` or getters.
- `parse` returns `Result`, never panics — a panic on user input is a bug. Panic only on
  programmer errors.
- Keep domain rules loose and add security limits as defence in depth (a maximum length, forbidden
  characters).
- For well-specified formats (email, URL), delegate to a maintained crate (`email_address`, `url`)
  inside `parse` instead of writing a parser.
- Syntactically valid is not "exists": `parse` checks the shape; existence is a use-case question.
- `serde::Serialize` is fine on domain types. For `Deserialize` on a value object, go through the
  parser — `#[serde(try_from = "String")]` — never derive it straight onto the field.

A shared error type for parsers:

```rust
// domain/src/validation.rs
#[derive(Debug, thiserror::Error)]
#[error("{field}: {reason}")]
pub struct ValidationError {
    pub field: &'static str,
    pub reason: String,
}

impl ValidationError {
    pub fn new(field: &'static str, reason: impl Into<String>) -> Self {
        Self { field, reason: reason.into() }
    }
}
```

## 2. Typed ids

Bare `Uuid` parameters can be swapped silently (`upsert_device(user_id, device_id)` called the other
way round). A typed id guards no invariant, it tags the kind — so a public `From<Uuid>` is fine.

```rust
// domain/src/ids.rs — every id is declared here, so the macro stays private to the crate
macro_rules! id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
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

id!(UserId);
id!(ConversationId);
```

- Name the constructor `generate`, not `new`: clippy's `new_without_default` fires on `new()`, and a
  random `Default` would be misleading.
- `Path<ConversationId>` works in Axum through the serde impl.

## 3. Closed enums

A string literal compared with `==` is silently false on a typo, and an inserted typo is a 500.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FriendshipStatus {
    Pending,
    Accepted,
}

impl FriendshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
        }
    }
}

impl std::str::FromStr for FriendshipStatus {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "accepted" => Ok(Self::Accepted),
            other => Err(ValidationError::new("friendship status", format!("unknown value {other:?}"))),
        }
    }
}
```

- **No `sqlx::Type` in the domain**, not even behind a feature — Cargo unifies features across the
  workspace, so the dependency leaks. Infrastructure binds `.as_str()` and parses with `FromStr` in
  its `TryFrom<Row>`.
- Keep the SQL `CHECK (status IN (...))` as defence in depth.

## 4. Parsing at the boundaries

Every boundary converts raw input with `TryFrom`, so errors are typed and the compiler points at
every call site when a field's type changes.

**Request DTO → command** (`api` → `application`). DTOs keep raw `String`s so a bad value produces
*our* 400 body, not Axum's 422 from a failed extractor:

```rust
// api/src/social/dto.rs
#[derive(serde::Deserialize)]
pub struct FriendRequestBody {
    pub address: String,
}

impl TryFrom<FriendRequestBody> for SendFriendRequest {
    type Error = ValidationError;

    fn try_from(body: FriendRequestBody) -> Result<Self, Self::Error> {
        Ok(Self { to: FederatedAddress::parse(&body.address)? })
    }
}

// handler
let command = SendFriendRequest::try_from(body)?; // ValidationError → ApiError 400
```

**DB row → entity** (`infrastructure`). Always re-parse — a URL parse per row is cheap, and an
unknown stored value becomes `Unexpected` ("corrupt row"), not a 400:

```rust
#[derive(sqlx::FromRow)]
struct FriendshipRow {
    id: uuid::Uuid,
    status: String,
    friend_actor_uri: String,
}

impl TryFrom<FriendshipRow> for Friendship {
    type Error = anyhow::Error;

    fn try_from(row: FriendshipRow) -> Result<Self, Self::Error> {
        Ok(Friendship {
            id: row.id.into(),
            status: row.status.parse().context("friendships.status")?,
            friend: ActorUri::parse(&row.friend_actor_uri).context("friendships.friend_actor_uri")?,
        })
    }
}
```

**Inbound external JSON** (federation, webhooks) — the least trusted input. Parse into domain types
inside the adapter that receives it, exactly like a request DTO.

## 5. Property-based tests

Worth it for parsers. Use `proptest` (dev-dependency of `domain`) rather than `quickcheck`: regex
strategies fit identifier formats, shrinking is better, and `fake`'s quickcheck glue no longer
works with quickcheck 1.x.

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn a_rendered_address_parses_back(handle in "[a-z0-9_]{3,20}", host in "[a-z0-9]{1,12}\\.test") {
        let address = FederatedAddress::parse(&format!("{handle}@{host}")).unwrap();
        prop_assert_eq!(FederatedAddress::parse(&address.to_string()).unwrap(), address);
    }

    #[test]
    fn parsing_never_panics(raw in ".*") {
        let _ = FederatedAddress::parse(&raw);
    }
}
```

Properties to look for: round-trip (`parse(x.to_string()) == x`), never panics, normalisation is
idempotent. Property tests widen coverage; they prove nothing — keep the example-based tests for
the edge cases you know.

## 6. Layout

```
domain/src/
├── lib.rs            # pub mod …; flat pub use re-exports
├── ids.rs            # every typed id
├── validation.rs     # ValidationError
├── identity/
│   ├── mod.rs
│   ├── handle.rs     # one file per parser-bearing value object
│   └── handle/
│       └── tests.rs  # its tests, as a child module
└── social/
    ├── mod.rs
    ├── friendship.rs # entity + its small enums (FriendshipStatus, Direction)
    ├── ports.rs      # SocialGraph, SocialStoreError
    └── error.rs      # SocialError
```
