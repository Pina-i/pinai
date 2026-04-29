# syntax=docker/dockerfile:1.7
# Build stage
FROM rust:bookworm AS builder

WORKDIR /build

# Copy the workspace. With cache mounts on the registry / git / target dirs
# below, ordering tricks (manifests-first, then sources) are unnecessary —
# Cargo's incremental compilation handles re-use across rebuilds.
COPY Cargo.toml Cargo.lock* ./
COPY crates/ crates/
COPY migrations/ migrations/

# Cargo registry/index, git checkouts (this is where the `core-libs` git
# dependency lives), and the build's `target/` are all preserved across
# Docker builds via BuildKit cache mounts. The compiled binary is copied
# out into the image's layered filesystem before the cache is unmounted.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target \
    cargo build --release -p idp-server && \
    cp target/release/idp-server /idp-server

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /idp-server /app/idp-server

EXPOSE 8080

CMD ["/app/idp-server"]
