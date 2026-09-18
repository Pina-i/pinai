# CLAUDE.md — pinai

Monorepo for the Pina-i platform: a self-hostable, federated, open-source
Discord alternative. One Cargo workspace spans every Rust crate here.

## Layout

```
crates/                    # shared libraries (was the core-libs repo)
  common-types/  jwt-utils/  http-signatures/  activitypub/  observability/
identity-provider/         # Layer 2 — identity & messaging backbone
  crates/  migrations/  docker/  keys/  Makefile
chat-server/               # Layer 3 — self-hostable community server
```

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
| `make alice` / `make bob` | run an IdP dev instance (delegates to the subtree) |
| `cargo run -p idp-server` | run a single binary |

Service Makefiles resolve `docker/.env.*` and `./keys` relative to their own
directory, so invoke them as `make -C identity-provider <target>` (or via the
root delegating targets), never from the repo root directly.

## Docker

Images build from the **repo root** as context, because the workspace manifest
and the shared crates sit above each service subtree:

```
docker compose -f identity-provider/docker/docker-compose.yml build
```
