# SecureChat365

An end-to-end encrypted 1:1 messenger. Your identity is a 72-character key, not
a phone number or an email address. The server routes ciphertext and cannot read
what you send.

Built with Rust and Tauri. Runs on macOS, Windows, Linux, iOS and Android from
one codebase.

> **Status: alpha. Not audited. Do not rely on this for anything that matters
> yet.** See [Known gaps](#known-gaps) for the specific reasons.

---

## Contents

- [What it is](#what-it-is)
- [Threat model](#threat-model)
- [How it works](#how-it-works)
- [Repository layout](#repository-layout)
- [Getting started](#getting-started)
- [Running the relay](#running-the-relay)
- [Building for each platform](#building-for-each-platform)
- [Known gaps](#known-gaps)
- [Contributing](#contributing)
- [Reporting security issues](#reporting-security-issues)

---

## What it is

Most messengers tie your identity to a phone number. That number is your
account, your discovery mechanism, and a permanent link between your
conversations and your legal identity. SecureChat365 doesn't have one.

Instead, when you first run the app it generates a keypair on your device. The
public half, plus a small anti-spam value and a checksum, is rendered as 72
hexadecimal characters — your contact ID. You share it however you like: QR
code, in person, over another channel. There is no account, no signup, no
server-side record of who you are.

This is the model Tox uses. What's different here is that the cryptography is
not homebrew: message encryption is [vodozemac](https://github.com/matrix-org/vodozemac),
the audited Rust implementation of the Olm double ratchet that Matrix uses.

### What it is not

It is not a Signal replacement. It has no group chat, no voice or video, no
disappearing messages, no multi-device support, and no push notifications. It
has one job — encrypted text between two people — and it does that job.

---

## Threat model

Be precise about this, because a security tool that overstates itself is worse
than one that makes no claims.

### What it protects against

| Threat | Protected | How |
|---|---|---|
| Server operator reading your messages | Yes | The relay only ever holds ciphertext |
| Server operator impersonating a contact | Yes | Key bundles are checked against the ID you scanned |
| Network eavesdropper | Yes | Olm inside TLS |
| Someone who later seizes the server | Yes | No plaintext ever reaches it; no message keys stored |
| Past messages after a key compromise | Yes | Double ratchet forward secrecy |
| Future messages after a key compromise | Yes | Post-compromise security via ratchet |
| Someone who steals your locked device | Mostly | Vault encrypted with Argon2id-derived key |

### What it does not protect against

- **Metadata.** The relay sees which key talks to which key, when, how often,
  and roughly how much. This is often the more sensitive fact. If that matters
  more to you than reliable delivery, this architecture is the wrong one — you
  want direct peer-to-peer connections instead.
- **A compromised device.** If someone has your unlocked phone or laptop, or
  malware on it, encryption in transit is irrelevant.
- **A compromised operating system.** Nothing at this layer can help.
- **Traffic analysis.** No padding, no cover traffic, no timing defences.
- **The person you're talking to.** They can screenshot, copy, or forward.

### Two things worth understanding

**Verification is not optional.** Encryption stops a passive observer. It does
not by itself stop an active attacker who substitutes their own key. The client
does check that a key bundle matches the ID you scanned — but if you got that ID
from a compromised channel, that check is verifying the wrong thing. Comparing
safety numbers out of band, in person or on a call, is what closes the loop.
(Note: safety numbers are currently a placeholder — see
[Known gaps](#known-gaps).)

**Your passphrase is the only thing protecting your key.** It is not stored
anywhere and cannot be recovered. Lose it and the identity is gone.

---

## How it works

### Identity

A contact ID is 36 bytes rendered as 72 uppercase hex characters:

```
[ 0..32 ]  Curve25519 public key   the Olm account's identity key
[32..34 ]  nospam                  rotatable anti-spam value
[34..36 ]  checksum                XOR of even bytes, XOR of odd bytes
```

The checksum's two bytes cover the even- and odd-indexed bytes separately, so
any single-character typo lands in exactly one parity class and is always
caught. There's an exhaustive test for this — all 72 positions against all 15
substitutions.

The nospam can be rotated without changing your key. Old contact requests stop
working; existing conversations are unaffected.

> Tox uses a 4-byte nospam and a 76-character ID. This uses 2 bytes to hit
> exactly 72, which costs 16 bits of brute-force resistance. The relay
> compensates by rate-limiting bundle lookups to 10 per hour per target. **These
> two choices are coupled** — remove the rate limit and you must go back to a
> 4-byte nospam.

### Starting a conversation

1. Alice scans or pastes Bob's 72-character ID.
2. Her client asks the relay for Bob's published key bundle.
3. **The client checks the bundle's identity key against the ID Alice scanned.**
   If they differ, it refuses and warns her.
4. It creates an outbound Olm session using one of Bob's one-time keys.
5. The first message is a pre-key message; Bob's client uses it to create the
   matching inbound session.

Step 3 is the load-bearing one. Without it, a malicious relay hands you its own
key and reads everything. Note that the client records the scanned ID *before*
the relay responds, and looks the response up against it — deriving the expected
ID from the relay's own answer would make the check circular and useless.

### Sending a message

```
plaintext  ──►  { "v":1, "from":"<sender's ID>", "body":"..." }
           ──►  Olm double ratchet
           ──►  base64
           ──►  { to, from_identity_key, message_type, ciphertext }
           ──►  relay  ──►  recipient
```

The sender's own ID travels *inside* the ciphertext, not in the envelope. That
lets the recipient show a contact request without the relay ever learning the
nospam — which is the entire point of having one. A sender controls their own
plaintext, so the claimed ID is only believed when its public key matches the
key whose session actually decrypted the message.

### Sessions

Sessions are stored as `HashMap<peer_key, Vec<Session>>` — several per peer, not
one. Both sides can open a session before either has replied, and there's no way
to know in advance which one a given message belongs to. Decryption tries every
session and promotes whichever worked; encryption uses the front of the list.

This is not premature generality. A single-session-per-peer implementation
breaks the moment someone adds a contact who has already messaged them: the new
outbound session replaces the working inbound one, the one-time key is already
spent, and every subsequent message fails to decrypt.

### Storage

The vault holds the Olm account, every session, and the nospam, encrypted under
a key derived from the user's passphrase with Argon2id (64 MiB, 3 passes). It is
written atomically — temp file, then rename — because a half-written vault is an
unrecoverable identity, and force-quit during save is common on mobile.

**Olm session state changes on every encrypt and decrypt.** It's the ratchet
position, not setup state, so the vault is rewritten after every message. Skip
that and restarting the app silently loses the ability to talk to contacts still
listed on screen.

### The relay

Deliberately dumb. It authenticates connections by challenge-response over
Ed25519, stores public key bundles, hands out one-time keys (never the same one
twice), and queues ciphertext for offline recipients. It cannot decrypt
anything, and clients don't trust it for key material.

Mailboxes key on the 64-character public key rather than the full ID, so
rotating your nospam doesn't orphan messages in flight.

---

## Repository layout

```
.
├── crates/
│   ├── core/                  # everything security-relevant
│   │   └── src/
│   │       ├── identity.rs    # contact IDs, checksum, nospam, QR payload
│   │       ├── crypto.rs      # Olm sessions, key bundles, vault, safety numbers
│   │       └── client.rs      # relay connection, reconnect, outbox
│   └── relay/
│       └── src/main.rs        # WebSocket server
├── app/
│   ├── src/index.html         # entire frontend, single file
│   └── src-tauri/src/lib.rs   # Tauri commands, bridges core to the UI
├── Dockerfile                 # relay image
├── docker-compose.yml         # relay + Caddy
└── .github/workflows/         # desktop builds for macOS, Windows, Linux
```

**Keep crypto in `crates/core`.** It compiles and tests without a GUI, which is
what makes it reviewable — an auditor reads roughly a thousand lines instead of
a whole application. `app/src-tauri` moves data between the core and the window
and makes no trust decisions.

> Crate names, the `VEIL_*` environment variables, and the `veil:` URI scheme
> still use the project's original working name. Renaming them is a good first
> contribution.

---

## Getting started

You need [Rust](https://rustup.rs) and Node 20+.

```bash
git clone <repo-url> && cd securechat365
cargo test -p securechat365-core
```

That runs the full core test suite — identity, ratchet, vault, and regression
tests for bugs found in development. It should be green before you touch
anything.

Then, in two terminals:

```bash
# 1 — relay
cargo run -p securechat365-relay

# 2 — app
cd app && npm install && npm run tauri dev
```

### Testing with two identities

You need two instances with separate storage. In debug builds only,
`SECURECHAT_DATA_DIR` overrides the data directory:

```bash
cd app && SECURECHAT_DATA_DIR=/tmp/chat-a npm run tauri dev
cd app && SECURECHAT_DATA_DIR=/tmp/chat-b npm run tauri dev
```

Create an identity in each, copy one ID into the other's **Add contact**, and
send. Watch the relay's terminal — you'll see `authenticated` twice and nothing
about the message contents. That's the design working.

The override is `#[cfg(debug_assertions)]` and cannot be used in a release
build. An app whose vault location can be relocated by an environment variable
is an attack surface, not a feature.

---

## Running the relay

```bash
# edit the domain in Caddyfile first
docker compose up -d --build
curl https://your-domain/health   # -> ok
```

Caddy handles certificates automatically. Both services run on the host network
and the relay binds `127.0.0.1:8080`, so only the reverse proxy can reach it.

Point clients at it by baking the URL in at compile time:

```bash
RELAY_URL=wss://your-domain/ws npm run tauri build
```

Compile-time, not runtime, and deliberately so — an app that a config file can
redirect to a different relay is one social-engineering step from routing
someone's traffic somewhere they didn't choose.

**Run more than one relay.** A single one is both a single point of failure and
a single subpoena target. Letting users choose, and publishing the server source
so others can run their own, is the honest answer to "why should I trust your
server": you shouldn't have to.

---

## Building for each platform

| Platform | Command | Notes |
|---|---|---|
| macOS | `npm run tauri build` | Needs Developer ID + notarisation for distribution |
| Windows | via GitHub Actions | Cannot cross-compile; CI builds it |
| Linux | `npm run tauri build` | |
| iOS | `npm run tauri ios dev` | Xcode; a free Apple ID covers a Personal Team |
| Android | `npm run tauri android dev` | Android Studio, SDK and NDK |

CI builds all three desktop platforms on tag push or manual dispatch. Set
`RELAY_URL` as a repository **variable** first, or you'll ship binaries
pointing at localhost.

### Two things that will bite you

**Don't reference Apple signing secrets you haven't set.** An unset GitHub
secret expands to an empty string, not to nothing. `tauri-action` sees
`APPLE_CERTIFICATE` as defined, tries to import a zero-byte certificate, and the
macOS build fails at the bundling step.

**`alert`, `confirm` and `prompt` are unreliable in Tauri's webview.** `prompt`
silently returns null on iOS. Build dialogs into the UI instead.

---

## Known gaps

An honest list. Roughly in the order they should be fixed.

### Blocking any real use

- [ ] **Safety numbers are a placeholder.** `get_safety_number` hashes your own
      fingerprint twice, so two people comparing digits always match — for the
      wrong reason. It needs the peer's Ed25519 key, which arrives in their
      bundle; store it on `Contact` when the bundle lands. Until then the Verify
      button is theatre, which is worse than having no button.
- [ ] **The relay stores queued messages in memory.** Any restart drops
      undelivered mail. Needs Postgres.
- [ ] **No vault migration path.** The format has already changed once, and
      changing it again destroys existing identities with no recovery. `unlock`
      needs to read old shapes and convert them.
- [ ] **No external security review.** The core is ~1,000 lines. Two genuine
      design bugs were found by running it, not reading it. There will be more.

### Important

- [ ] **`contacts.json` is plaintext on disk.** Messages are safe; the social
      graph is not. It belongs inside the vault.
- [ ] **Ignore is not Block.** Dismissing a contact request doesn't stop them
      writing again. There is no block list.
- [ ] **Pending requests don't survive a restart.** They live in frontend memory.
- [ ] **No push notifications.** Both mobile platforms suspend sockets seconds
      after backgrounding, so a backgrounded phone silently receives nothing
      until relaunch. The fix is a contentless push that wakes the app, which
      pulls and decrypts and raises a *local* notification — Apple and Google
      learn timing, never content. This is a redesign, not a patch.
- [ ] **No multi-device.** One identity, one device. Retrofitting this means
      reworking key management, session state, and history sync.

### Wanted

- [ ] Rename the `veil` crates, env vars, and URI scheme
- [ ] Message delete, edit, and delivery receipts
- [ ] Reproducible builds and published checksums
- [ ] Relay federation, so users can choose their server

---

## Contributing

Contributions welcome. A few things specific to this project.

### Where to start

The [Known gaps](#known-gaps) list is the roadmap. `contacts.json` encryption
and the block list are self-contained and don't require deep Olm knowledge. The
safety-number fix is small but security-critical, so it'll get careful review.

### Before you touch `crates/core`

That's the security boundary. Changes there need:

- A test that fails before your change and passes after
- An explanation of what an attacker gains or loses
- No new dependencies without discussion

The existing tests include regressions for real bugs — session clobbering,
binary-in-a-String ciphertext corruption, forged sender IDs. Don't delete them
to make a refactor pass.

### Conventions

- Comments explain **why**, not what. If a line looks wrong but isn't, say why.
- Failures must be visible. Two bugs here hid because a fallback quietly
  discarded state — a session map overwrote a session, and the UI dropped a
  decrypted message. Neither logged anything a user would see.
- Never invent a trust anchor. The value you compare against must be captured
  before the untrusted party speaks.
- Security-relevant UI copy is blunt on purpose. "This contact's keys don't
  match their ID. Do not send anything." should not be softened.

### Pull requests

Small and focused. `cargo test -p securechat365-core` must pass. Say what you tested by
hand — most of the interesting bugs here only appear with two live clients.

---

## Reporting security issues

**Please don't open a public issue for security bugs.**

Email `security@securechat365.com` with what you found, how to reproduce it, and
what an attacker could do. You'll get a response within 72 hours. Reasonable
disclosure timelines are welcome; so is credit, if you want it.

Especially interested in: key substitution paths, session-handling edge cases,
anything letting the relay learn more than it should, and vault or memory
handling of key material.

---

## What not to claim

If you fork or redistribute this, don't call it "unbreakable", "military-grade",
or "NSA-proof". All three are false, all three are what scam apps say, and any
researcher who reads the marketing before the code will discount the code.

Say what's true: end-to-end encrypted with the Olm double ratchet, keys never
leave the device, the server sees ciphertext and routing metadata only, source
is public, here's the threat model, here's what it doesn't protect.

That's a stronger claim, because it survives scrutiny.

---

## License

AGPL-3.0. If you run a modified version as a service, publish your changes.
