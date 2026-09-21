# CLAUDE.md — pinai

Monorepo for the Pina-i platform: a self-hostable, federated, open-source
Discord alternative. One Cargo workspace spans every Rust crate here.

## Layout

```
compose.yaml               # the platform — `docker compose up` from here
.env.example               # one deployment unit, one env template
specs/                     # platform-wide specs; service specs live in the service
crates/                    # shared libraries (was the core-libs repo)
  common-types/  jwt-utils/  http-signatures/  activitypub/  observability/
  federation-transport/    # S2S: actor resolution, signed delivery, verification
identity-provider/         # Layer 2 — identity & messaging backbone
  crates/  migrations/  keys/  specs/  docker/Dockerfile
chat-server/               # Layer 3 — chat & voice rooms, attached to the IdP
```

The chat server is attached to exactly one identity provider and deploys with
it, so compose and environment live here at the root rather than per service.
Dockerfiles stay with their service — they are build inputs tied to its crates.

`web-client` stays a separate repository: it shares an HTTP contract with
these services, not a dependency graph.

Each service subtree has its own `CLAUDE.md` with its architecture and
constraints — read that one before working inside it.

## Specs

Platform-wide specifications live in `specs/` at the root. Anything scoped to one service
lives in that service's own `specs/` folder, listed by its `CLAUDE.md`.

| File | Contents | Read when working on… |
|---|---|---|
| `specs/02-architecture-diagram.md` | Mermaid flowchart of the whole platform — clients, both IdPs, and their infrastructure | Understanding the global picture; add a component here whenever one is introduced |
| `specs/06-federation-authentication.md` | The two credentials (Bearer JWT vs HTTP Signature), the signing scheme, the three inbound checks, the verifying-key cache, and the peer request policy | Anything server-to-server, in any service: inboxes, inter-IdP calls, HTTP Signatures, key rotation |

A spec belongs at the root when a second service would need the same document — the
federation transport in `crates/federation-transport/` is described once and implemented by
every service that speaks ActivityPub. A spec that declares one service's tables or
endpoints belongs with that service.

**Spec paths are written from the repo root everywhere** — in specs, in `CLAUDE.md` files
and in doc comments. A bare `specs/…` would otherwise mean a different folder depending on
which file you were reading.

### Changing a spec

Specs describe the final, stable state of a feature. They do not narrate development, and
they do not carry change history — that belongs in commits, or in a write-up alongside them.

When a change touches more than one spec:

1. Read every affected spec before editing any of them.
2. Apply the change consistently across all of them, and use a mermaid diagram where it
   shows a mechanism prose would not.
3. Update `specs/02-architecture-diagram.md` if a component or flow was introduced.
4. Define a shared mechanism in exactly one spec and reference it from the others. A
   mechanism documented inside one of its consumers drifts from the code, and from the
   other consumers, without anyone noticing.

## Workspace rules

- Shared crates are `path` dependencies declared once in the root
  `[workspace.dependencies]`; a change to a shared crate and its callers is a
  single atomic commit.
- Every crate inherits common deps with `{ workspace = true }`. Add a new
  shared dependency to the root manifest, not to a leaf crate.
- New crates are picked up by the `crates/*` and `identity-provider/crates/*`
  globs. Add a `chat-server/crates/*` member when that service gets its first
  crate.

## Tests

Unit tests live in their own file, declared as a child module of the code they
cover so they keep access to its private items:

```rust
// src/verify.rs — at the end of the file, nothing else
#[cfg(test)]
mod tests;
```

```
src/verify.rs        # implementation
src/verify/tests.rs  # starts with `use super::*;`
```

A crate root (`lib.rs`, `mod.rs`) puts its tests beside it at `src/tests.rs`.
Integration tests that drive a crate from outside still belong in `tests/`.

## Commands

Run from the repo root:

| Command | Effect |
|---|---|
| `make check` | fmt-check + clippy `-D warnings` + tests, all 21 crates |
| `make fmt` | rustfmt the workspace |
| `make alice` / `make bob` | run a full dev instance |
| `cargo run -p idp-server` | run a single binary |
| `docker compose up -d` | bring up the platform |

`JWT_PRIVATE_KEY_PATH` and the other paths in the env files resolve against the
working directory, so run everything from the repo root.

## Instance signing key

Each instance owns one Ed25519 key, generated on first run and never
regenerated: `make alice` mints `identity-provider/keys/alice/ed25519.pem`, and
`docker compose up` does the same through the `idp-keygen` service. Both are
idempotent, and `IDP_KEYS_DIR` in the env file selects the directory.

Alice and Bob must not share a key. It signs JWTs, federation HTTP Signatures
and E2EE device attestations, so a shared key makes every cross-instance
verification pass whether or not key resolution actually works — the bug then
only surfaces in production.

There is no recovering from losing the key: device attestations carry a
365-day TTL and verify against the issuer's JWKS, so a replacement key breaks
every existing device. Back `IDP_KEYS_DIR` up together with the database.

## Docker

`compose.yaml` is at the root and the build context is `.`, because the
workspace manifest and the shared crates sit above every service subtree. The
`alice` / `bob` targets bring up two independent instances (distinct compose
project names) for exercising federation between them.
