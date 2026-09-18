# syntax=docker/dockerfile:1.7
#
# Production Dockerfile — release build, slim runtime.
#
# Uses cargo-chef to split the build into two layers:
#   1. dependency-only build (re-runs only when Cargo.toml/Cargo.lock change)
#   2. workspace build (re-runs on any source change, but reuses cached deps)
#
# Cache-mount IDs are versioned (-v2) — bump them after big workspace
# restructures to force a clean dep cache without losing the registry/git cache.

# ── Cargo-chef base ──────────────────────────────────────────────────────────
FROM rust:bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /build

# ── Recipe extraction ────────────────────────────────────────────────────────
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY identity-provider/crates/ identity-provider/crates/
RUN cargo chef prepare --recipe-path recipe.json

# ── Build ────────────────────────────────────────────────────────────────────
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json

# Cook deps. target/ is populated as a regular layer (not a cache mount) so
# subsequent stages reuse it.
RUN --mount=type=cache,id=idp-cargo-registry-v2,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=idp-cargo-git-v2,target=/usr/local/cargo/git,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json

# Now copy the actual source and build idp-server. Deps are already compiled.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY identity-provider/crates/ identity-provider/crates/
COPY identity-provider/migrations/ identity-provider/migrations/
RUN --mount=type=cache,id=idp-cargo-registry-v2,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=idp-cargo-git-v2,target=/usr/local/cargo/git,sharing=locked \
    cargo build --release -p idp-server && \
    cp target/release/idp-server /idp-server

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /idp-server /app/idp-server

EXPOSE 8080
CMD ["/app/idp-server"]
