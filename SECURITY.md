# Security Policy

SecureChat365 is **alpha software and has not been independently audited.**
Do not rely on it where a compromise would put someone at risk.

## Reporting a vulnerability

Please report security issues **privately**, not in public issues.

Email **security@securechat365.com** with:

- what you found and what an attacker could do with it
- how to reproduce it
- the version or commit you tested

You'll get a response within 72 hours. Please allow up to 90 days for a fix
before disclosing publicly. If the issue is being actively exploited, say so
and it will be handled first.

There is no paid bug bounty. Valid reports are credited in the release notes
and advisory, unless you'd rather stay anonymous.

Especially interested in: key substitution paths, session-handling edge cases,
anything letting the relay learn more than it should, and vault or memory
handling of key material.

## Scope

In scope:

- `crates/core`: identity and contact ID parsing, Olm session handling, key
  bundles, the encrypted vault, payload wrapping, safety numbers, and the
  relay client
- `crates/relay`: authentication, bundle and one-time-key distribution,
  message queueing, rate limits
- The desktop and Android apps (`app/`), including how they store keys and
  contacts
- The deployed relay at `relay.securechat365.com` — please don't run denial of
  service or load tests against it; run the relay locally instead (see the
  README)

Out of scope:

- vodozemac itself — report upstream to
  [matrix-org/vodozemac](https://github.com/matrix-org/vodozemac)
- The known limitations below
- macOS and Windows warnings about unsigned installers

## Known limitations

These are documented and already on the roadmap, so they don't need a report:

- The relay sees metadata: which public keys talk to each other, when, and
  message sizes. It never sees message content.
- `contacts.json` (contact names) is stored unencrypted on disk.
- The relay keeps everything in memory; a restart drops queued messages and
  published key bundles.
- Desktop builds are not code-signed; the Android app is sideloaded.
- No external security audit yet.

The README's [threat model](README.md#threat-model) lists what the design does
and does not protect against.

## Supported versions

Only the latest release receives security fixes.
