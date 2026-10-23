# syntax=docker/dockerfile:1.7
#
# Production Dockerfile — release build, distroless runtime as the non-root user 65532.
#
# Uses cargo-chef to split the build into two layers:
#   1. dependency-only build (re-runs only when Cargo.toml/Cargo.lock change)
#   2. workspace build (re-runs on any source change, but reuses cached deps)
#
# Cache-mount IDs are versioned (-v2) — bump them after big workspace
# restructures to force a clean dep cache without losing the registry/git cache.

# ── Cargo-chef base ──────────────────────────────────────────────────────────
FROM lukemathwalker/cargo-chef:0.1.78-rust-1.98.1-trixie AS chef
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

# Now copy the actual source and build the idp-server binary. Deps are already compiled.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY identity-provider/crates/ identity-provider/crates/
COPY identity-provider/migrations/ identity-provider/migrations/
RUN --mount=type=cache,id=idp-cargo-registry-v2,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=idp-cargo-git-v2,target=/usr/local/cargo/git,sharing=locked \
    cargo build --release -p idp-app --bin idp-server && \
    cp target/release/idp-server /idp-server

# ── Runtime ──────────────────────────────────────────────────────────────────
# Same Debian release as the build, for glibc. No shell; the instance key must be
# readable by 65532, which compose's idp-keygen sees to.
FROM gcr.io/distroless/cc-debian13:nonroot AS runtime

WORKDIR /app
COPY --from=builder /idp-server /app/idp-server

USER 65532:65532
EXPOSE 8080
CMD ["/app/idp-server"]
