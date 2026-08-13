# Veil

An end-to-end encrypted 1:1 messenger. Identity is a 72-character key, not a
phone number. The relay routes ciphertext and cannot read messages.

## Build order

Work through these in sequence. Each step should be green before the next.

1. `cargo test -p veil-core` — identity only
2. Uncomment `pub mod crypto;` in `crates/core/src/lib.rs`, then re-run
3. Uncomment `pub mod client;`, then re-run
4. `cargo run -p veil-relay`

## Status

Not audited. Not ready for anyone who needs it to work.
