# Build the relay. Two stages so the shipped image has no toolchain in it.
FROM rust:1-slim AS build

WORKDIR /src
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy manifests first so dependency compilation caches across code changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/
COPY crates/relay/Cargo.toml crates/relay/
RUN mkdir -p crates/core/src crates/relay/src \
    && echo "" > crates/core/src/lib.rs \
    && echo "fn main() {}" > crates/relay/src/main.rs \
    && cargo build --release -p securechat365-relay || true

COPY crates crates
# Touch so cargo rebuilds the real sources rather than trusting the stubs.
RUN touch crates/core/src/lib.rs crates/relay/src/main.rs \
    && cargo build --release -p securechat365-relay

# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 securechat

COPY --from=build /src/target/release/securechat365-relay /usr/local/bin/securechat365-relay

# Never run as root. The relay handles untrusted input from the open internet.
USER securechat
EXPOSE 8080
ENV RUST_LOG=securechat365_relay=info

CMD ["securechat365-relay"]
