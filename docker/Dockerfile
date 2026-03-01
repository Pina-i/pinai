# Build stage
FROM rust:1.82 AS builder

WORKDIR /build

# Copy workspace manifests
COPY Cargo.toml Cargo.lock* ./
COPY crates/config/Cargo.toml   crates/config/Cargo.toml
COPY crates/db/Cargo.toml       crates/db/Cargo.toml
COPY crates/oidc/Cargo.toml     crates/oidc/Cargo.toml
COPY crates/server/Cargo.toml   crates/server/Cargo.toml

# Copy core-libs (path dependency — must be resolvable from build context)
COPY ../../core-libs /core-libs

# Copy source
COPY crates/ crates/
COPY migrations/ migrations/

# Build release binary
RUN cargo build --release -p idp-server

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/idp-server /app/idp-server

EXPOSE 8080

CMD ["/app/idp-server"]
