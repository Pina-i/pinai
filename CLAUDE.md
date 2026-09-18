# CLAUDE.md — pinai

Monorepo for the Pina-i platform: a self-hostable, federated, open-source
Discord alternative. One Cargo workspace spans every Rust crate here.

## Layout

```
compose.yaml               # the platform — `docker compose up` from here
.env.example               # one deployment unit, one env template
crates/                    # shared libraries (was the core-libs repo)
  common-types/  jwt-utils/  http-signatures/  activitypub/  observability/
identity-provider/         # Layer 2 — identity & messaging backbone
  crates/  migrations/  keys/  docker/Dockerfile
chat-server/               # Layer 3 — chat & voice rooms, attached to the IdP
```

The chat server is attached to exactly one identity provider and deploys with
it, so compose and environment live here at the root rather than per service.
Dockerfiles stay with their service — they are build inputs tied to its crates.

`web-client` stays a separate repository: it shares an HTTP contract with
these services, not a dependency graph.

Each service subtree has its own `CLAUDE.md` with its architecture and
constraints — read that one before working inside it.

## Workspace rules

- Shared crates are `path` dependencies declared once in the root
  `[workspace.dependencies]`; a change to a shared crate and its callers is a
  single atomic commit.
- Every crate inherits common deps with `{ workspace = true }`. Add a new
  shared dependency to the root manifest, not to a leaf crate.
- New crates are picked up by the `crates/*` and `identity-provider/crates/*`
  globs. Add a `chat-server/crates/*` member when that service gets its first
  crate.

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

## Docker

`compose.yaml` is at the root and the build context is `.`, because the
workspace manifest and the shared crates sit above every service subtree. The
`alice` / `bob` targets bring up two independent instances (distinct compose
project names) for exercising federation between them.
