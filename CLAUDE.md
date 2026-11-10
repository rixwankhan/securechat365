# SecureChat365 — project handoff

End-to-end encrypted 1:1 messenger. A user's account is a 72-character key, not
a phone number. Rust core, Tauri 2 apps (macOS, Windows, Linux, Android; iOS
pending), and a WebSocket relay that only ever sees ciphertext.

- Site: https://securechat365.com (GitHub Pages, `docs/`)
- Repo: https://github.com/rixwankhan/securechat365
- Relay: wss://relay.securechat365.com/ws
- Local checkout: `/Users/riz/htdocs/securechat/veil`

Status: **alpha, unaudited**. Works end to end on desktop over the deployed
relay. Android builds and signs in CI; on-device testing in progress.

---

## Read this first: rules for working here

Nearly every expensive bug in this project had one shape: **something absent,
mismatched or unrecognised was silently treated as valid.** It built, it ran,
every check passed, and it did not work. These rules exist because of that.

1. **`git pull` before touching anything.** Work has been committed from the
   Mac, the GitHub web editor and the server. Editing a stale checkout and
   pushing has nearly overwritten fixes more than once. Never `push --force`.

2. **Edit files in place; never regenerate a whole file from memory.** Three
   regressions came from replacing a current file with an older copy (the event
   channel name, the relay URL env var, a lost UI feature).

3. **Paired names must match across files.** These live in two places each and
   drifting apart produces no error, only silence:

   | Name | Defined in | Consumed in |
   |---|---|---|
   | Tauri event channel `securechat365` | `app/src-tauri/src/lib.rs` (`emit`) | `app/src/index.html` (`listen`) |
   | `RELAY_URL` | `.github/workflows/*.yml` (env) | `lib.rs` (`option_env!`) |
   | `SECURECHAT_BIND` | `docker-compose.yml` | `crates/relay/src/main.rs` |

   Verify with the script under [Checks](#checks) after any rename.

4. **An unset GitHub secret or variable is an empty string, not "missing".**
   `option_env!` returns `Some("")` for it. Always check emptiness; the
   workflows already do — keep it that way.

5. **Test the artifact, not the description of it.** Status output lies.
   `strings` on the binary, `curl` from outside the server, and the APK grep in
   CI are what settled every real bug.

6. **Failures must be visible on screen.** No fallbacks that quietly store data
   under an unusable key, no optimistic UI that hides an error. If something is
   unrecognised, say so.

7. **Never derive a trust anchor from untrusted input.** The value you compare
   against must be captured before the relay responds (see `pending` in
   `client.rs`).

8. **Changes to `crates/core` need a test that fails before and passes after.**
   Don't delete existing tests to make a refactor pass — several are
   regressions for real bugs.

---

## Layout

```
crates/core/src/
  identity.rs   72-char contact ID: key + nospam + checksum, parsing, QR URI
  crypto.rs     Olm accounts/sessions (vodozemac 0.9), key bundles, vault,
                payload wrapping, safety numbers. ALL security logic is here.
  client.rs     Relay connection: auth handshake, reconnect/backoff, outbox,
                acks, dedupe, bundle fetch, events to the UI
crates/relay/src/main.rs   Axum WebSocket relay, in-memory store
app/src/index.html         Entire frontend, one file, no build step
app/src-tauri/src/lib.rs   Tauri commands; bridges core <-> window
docs/                      Website + CNAME (GitHub Pages)
.github/workflows/
  release.yml   "Build desktop": macOS arm64/x64, Windows, Linux
  mobile.yml    "Build Android": signed APK
Dockerfile, docker-compose.yml, Caddyfile   Relay deployment
```

Cargo workspace members: `crates/core` (`securechat365-core`), `crates/relay`
(`securechat365-relay`), `app/src-tauri` (still named `app` / `app_lib` from the
template — the binary inside the macOS bundle is literally `Contents/MacOS/app`).

The workspace shares **one** `target/` at the repo root. Build artifacts are
never under `app/src-tauri/target`.

---

## How it works

### Identity
`ContactId` = 36 bytes → 72 uppercase hex chars:
`[0..32]` Curve25519 identity key · `[32..34]` nospam · `[34..36]` checksum
(byte 0 = XOR of even-indexed bytes, byte 1 = XOR of odd). Every
single-character typo is caught; there is an exhaustive test.

2-byte nospam (Tox uses 4) to hit exactly 72 chars. **Coupled to the relay's
rate limit** of 10 bundle fetches per target per hour — remove one and you must
restore the other.

### Sessions and messages
- `sessions: HashMap<peer_key, Vec<Session>>` — several per peer, deliberately.
  Decrypt tries all and promotes the winner; encrypt uses the front. A single
  session per peer breaks when someone adds a contact who already messaged them.
- Plaintext wire format v1: `{"v":1,"from":"<sender 72-char id>","body":"..."}`.
  `from` travels inside the ciphertext so the relay never learns the nospam.
  It is only believed if its key matches the session that decrypted it
  (`parse_payload`).
- Ciphertext on the wire is base64. Never put binary in a `String`.
- `KeyBundle` carries an Ed25519 signature over the identity key, binding the
  fingerprint key to it. Required field — no silent downgrade.
- `begin_session` rejects a bundle whose identity key doesn't match the scanned
  ID, and won't replace an existing session.
- The client republishes a fresh bundle on **every** connect so format changes
  propagate.

### Vault
Account + all sessions + peer fingerprints + nospam, encrypted with an
Argon2id-derived key (64 MiB, 3 passes). Format **version 2**. Written
atomically (temp + rename) and **rewritten after every message**, because Olm
session state is the ratchet position and changes on every encrypt/decrypt.

There is no migration path between vault versions yet — changing the format
destroys existing identities.

### Safety numbers
60 digits: SHA-256 over a domain separator + both Ed25519 fingerprint keys
(sorted, so symmetric), iterated 5000×. Domain separator is
`securechat365-safety-number-v1`; changing it changes every safety number.

### Relay
Challenge-response auth (Ed25519 signature over a random nonce). Stores
bundles, serves each one-time key once (falls back to the fallback key), queues
envelopes by recipient public key (not full ID, so nospam rotation doesn't
orphan mail). Limits: 16 KB envelope, 1000 queued per user, 30-day TTL.
Overwrites `from_identity_key` on every envelope so senders can't forge it.
Messages leave the queue only on explicit `Ack`.

**Everything is in memory.** A relay restart drops all undelivered messages and
all published bundles.

### TLS
- Desktop: `native-tls` (OS stack).
- Android/iOS: `rustls` + `ring`, with the provider installed explicitly at the
  top of `RelayClient::run`. rustls 0.23 has no crypto backend by default and
  panics on the first handshake without one — which surfaces only as
  "channel closed" in the UI.

Configured as target-specific dependencies in `crates/core/Cargo.toml`.

### UI
Single-file `index.html`. Events from Rust arrive on the `securechat365`
channel. Sidebar shows a connection indicator (Connected / Connecting /
Offline) — keep it; it replaced hours of reading server logs.

Don't use `alert`/`confirm`/`prompt`: unreliable in Tauri's webview, and
`prompt` returns null on iOS. Use in-page UI.

Respect safe areas on mobile: `100dvh`, and `env(safe-area-inset-*)` on any
edge element.

---

## Running locally

```bash
cargo test -p securechat365-core          # 25 tests, must stay green

# Relay
cargo run -p securechat365-relay          # listens on 0.0.0.0:8080

# Two app instances with separate identities (debug builds only)
cd app
SECURECHAT_DATA_DIR=/tmp/chat-a RELAY_URL=ws://localhost:8080/ws npm run tauri dev
SECURECHAT_DATA_DIR=/tmp/chat-b RELAY_URL=ws://localhost:8080/ws npm run tauri dev
```

Against the real relay, use `RELAY_URL=wss://relay.securechat365.com/ws`.
Without `RELAY_URL` the app falls back to `ws://localhost:8080/ws`.
`SECURECHAT_DATA_DIR` is `#[cfg(debug_assertions)]` only, on purpose.

The relay URL is a **compile-time** constant, deliberately not configurable at
runtime.

---

## Building and releasing

Version comes from `version` in `app/src-tauri/tauri.conf.json` and ends up in
every filename. **Bump it before tagging**, or a new tag ships files named
after the old version.

```bash
git tag vX.Y.Z && git push --tags          # triggers both workflows
gh workflow run "Build desktop"            # or manually
gh workflow run "Build Android"
```

Repository variable: `RELAY_URL`.
Secrets: `ANDROID_KEYSTORE` (base64 .jks), `ANDROID_KEYSTORE_PASSWORD`,
`ANDROID_KEY_ALIAS`. Apple signing secrets are **commented out** in
`release.yml` — referencing unset secrets broke macOS builds. Restore them only
when every one has a value.

The Android keystore is irreplaceable. Losing it means updates can no longer
install over existing copies.

Publishing (manual today):
1. `gh run download <id> --repo rixwankhan/securechat365 --dir <empty dir>`
2. Flatten installers, `shasum -a 256 * > SHA256SUMS.txt`
3. `gh release create vX.Y.Z * --repo rixwankhan/securechat365 ...`
4. Confirm every link returns 200, then update download URLs and the version
   label in `docs/index.html`

Desktop builds are unsigned: macOS reports them as "damaged" (right-click →
Open), Windows shows SmartScreen. Android needs "install unknown apps".

iOS: blocked on an Apple Developer account. Rust compiles for iOS; distribution
needs TestFlight. Mobile projects (`gen/`) are not committed; CI generates them.

---

## Deployment

Relay runs on a Contabo VPS (`vmi3505601`) at `~/securechat365`, cloned from
GitHub. **Treat the server as read-only** — change things in the repo and
`git pull` there. Edits made directly on the server have been lost on redeploy.

```bash
cd ~/securechat365 && git pull && docker compose up -d --build
docker compose logs -f relay
curl https://relay.securechat365.com/health      # -> ok
```

Notes:
- `docker` is **Podman** in disguise. Image names must be fully qualified
  (`docker.io/library/...`).
- Podman's port publishing silently failed on this host (empty
  `NETAVARK-HOSTPORT-DNAT`), so both services use `network_mode: host`. The
  relay binds `127.0.0.1:8080` via `SECURECHAT_BIND`; only Caddy is public.
- Podman has no daemon: containers do **not** restart after a reboot unless
  `podman-restart.service` is enabled. Check `uptime` first when the relay is
  unreachable.
- The Dockerfile trims `app/src-tauri` out of the workspace members, since the
  desktop app isn't in the image.
- Caddy access logs are discarded on purpose (they'd record user IPs).
  Keep `RUST_LOG=securechat365_relay=info` — debug logs who talks to whom.
- Let's Encrypt allows 5 failed validations per hour. Use the staging CA block
  at the top of the Caddyfile while debugging (it's a global option, not a site
  directive).

---

## Checks

Paired-name consistency — run after any rename or file replacement:

```bash
python3 - <<'EOF'
import re, pathlib
checks = [
 ("event channel", "app/src-tauri/src/lib.rs", r'emit\("([^"]+)"', "app/src/index.html", r"listen\('([^']+)'"),
 ("relay URL env", "app/src-tauri/src/lib.rs", r'option_env!\("([^"]+)"', ".github/workflows/release.yml", r'^\s+([A-Z_]+): \$\{\{ vars\.'),
 ("relay bind env", "crates/relay/src/main.rs", r'env::var\("([A-Z_]+)"', "docker-compose.yml", r'([A-Z_]+): "127'),
]
for n, fa, ra, fb, rb in checks:
    a = set(re.findall(ra, pathlib.Path(fa).read_text(), re.M))
    b = set(re.findall(rb, pathlib.Path(fb).read_text(), re.M))
    print("MATCH   " if a & b else "MISMATCH", n, a, b)
EOF
```

Relay URL actually in a shipped binary:

```bash
strings "/Applications/securechat365.app/Contents/MacOS/app" | grep -E "^wss?://"
```

---

## Open work

### In flight
- [ ] **Relay unreachable** — as of 2026-11-11 both Mac and Android showed
      "Offline — retrying". Suspected server reboot without
      `podman-restart.service`. Check `uptime`, `docker compose ps`, relay and
      Caddy logs.
- [ ] **Android: sidebar "Add contact" sits under the navigation bar.**
      `.aside-foot` needs `padding-bottom: max(14px, calc(env(safe-area-inset-bottom) + 8px))`
      (the composer already has this). Verify the WebView reports a non-zero
      inset; add a fixed fallback if not.
- [ ] On-device Android test: connect, message both ways with desktop, compare
      safety numbers.

### Blocking real use
- [ ] Relay persistence (Postgres) — restarts drop queued mail and bundles.
- [ ] Vault migration path between format versions.
- [ ] External security review of `crates/core`.

### Important
- [ ] QR scanning on mobile (`tauri-plugin-barcode-scanner`). Paste-only today.
- [ ] Push notifications: contentless push → app wakes, pulls, decrypts, raises
      a local notification. Backgrounded phones currently receive nothing until
      reopened.
- [ ] `contacts.json` is plaintext on disk — move into the vault.
- [ ] Message requests live in frontend memory; lost on restart.
- [ ] Ignore ≠ Block; there is no block list.
- [ ] Version field on `KeyBundle` so format changes degrade gracefully.
- [ ] Sealed sender — remove `from_identity_key` from what the relay sees.
- [ ] `Transport` trait in `client.rs` to allow iroh/Tor transports later.

### Housekeeping
- [ ] Rename the Tauri crate from `app`/`app_lib` (binary is called `app`).
- [ ] Align `version` in `app/src-tauri/Cargo.toml` with `tauri.conf.json`.
- [ ] Workflows: `actions/setup-java@v5`, pin `ubuntu-24.04`.
- [ ] Automate releases with tauri-action `tagName` + a post-build step that
      greps desktop binaries for `RELAY_URL`.
- [ ] Code signing: Apple Developer ID + notarisation; Windows EV/OV cert.

---

## Things not to say

Not "unbreakable", "military-grade" or "NSA-proof". The honest claim: E2EE with
the Olm double ratchet, keys never leave the device, the relay sees ciphertext
and routing metadata (who, when, how much) but not content. The README's threat
model has the full protects / doesn't-protect list — keep marketing consistent
with it.
