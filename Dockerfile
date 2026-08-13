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
    && cargo build --release -p veil-relay || true

COPY crates crates
# Touch so cargo rebuilds the real sources rather than trusting the stubs.
RUN touch crates/core/src/lib.rs crates/relay/src/main.rs \
    && cargo build --release -p veil-relay

# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 veil

COPY --from=build /src/target/release/veil-relay /usr/local/bin/veil-relay

# Never run as root. The relay handles untrusted input from the open internet.
USER veil
EXPOSE 8080
ENV RUST_LOG=veil_relay=info

CMD ["veil-relay"]
