# Build the relay. Two stages so the shipped image has no toolchain in it.
#
# Image names are fully qualified (docker.io/library/...) because Podman
# refuses short names unless a search registry is configured. Docker accepts
# the long form too, so this stays portable.

FROM docker.io/library/rust:1-slim AS build

WORKDIR /src
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first so dependency compilation caches across code changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/
COPY crates/relay/Cargo.toml crates/relay/

# The workspace lists app/src-tauri as a member, but the desktop app is not
# copied into this image: the relay doesn't need it, and Tauri won't build on a
# headless server without the GTK/WebKit stack. Cargo refuses to work with a
# member it can't find, so drop it from the members list here.
RUN sed -i 's|^members = .*|members = ["crates/core", "crates/relay"]|' Cargo.toml

# Warm the dependency cache against stub sources.
RUN mkdir -p crates/core/src crates/relay/src \
    && echo "" > crates/core/src/lib.rs \
    && echo "fn main() {}" > crates/relay/src/main.rs \
    && cargo build --release -p securechat365-relay || true

COPY crates crates
# Touch so cargo rebuilds the real sources rather than trusting the stubs.
RUN touch crates/core/src/lib.rs crates/relay/src/main.rs \
    && cargo build --release -p securechat365-relay

# ---------------------------------------------------------------------------
FROM docker.io/library/debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 securechat

COPY --from=build /src/target/release/securechat365-relay /usr/local/bin/securechat365-relay

# Never run as root. The relay handles untrusted input from the open internet.
USER securechat
EXPOSE 8080
ENV RUST_LOG=securechat365_relay=info

CMD ["securechat365-relay"]
