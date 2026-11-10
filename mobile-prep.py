#!/usr/bin/env python3
"""
Prepare SecureChat365 for Android and iOS builds.

Edits your CURRENT files in place rather than replacing them, so it can't
clobber newer changes. Safe to run twice: every step checks whether it has
already been applied.

    cd /path/to/securechat365      # repo root, where Cargo.toml lives
    python3 mobile-prep.py

What it changes:
  1. crates/core/Cargo.toml   TLS backend becomes target-specific:
                              desktop keeps native-tls, mobile uses rustls+ring
  2. crates/core/src/client.rs installs the ring crypto provider on mobile
                              (rustls 0.23 panics at first TLS connection
                              without one)
  3. .github/workflows/mobile.yml  Android CI build, signed APK
"""

import pathlib
import re
import sys

ROOT = pathlib.Path.cwd()
CORE_TOML = ROOT / "crates/core/Cargo.toml"
CLIENT_RS = ROOT / "crates/core/src/client.rs"
WORKFLOW = ROOT / ".github/workflows/mobile.yml"

if not CORE_TOML.exists() or not CLIENT_RS.exists():
    sys.exit("error: run this from the repository root (crates/core not found)")


def report(name, status):
    print(f"  {status:<9} {name}")


# --------------------------------------------------------------- 1. Cargo.toml
toml = CORE_TOML.read_text()
MOBILE = "cfg(any(target_os = \"android\", target_os = \"ios\"))"

if MOBILE in toml:
    report("crates/core/Cargo.toml", "skipped")
else:
    line = re.search(r'^tokio-tungstenite\s*=.*$', toml, re.M)
    if not line:
        sys.exit("error: no tokio-tungstenite line in crates/core/Cargo.toml")
    toml = toml.replace(line.group(0) + "\n", "").replace(line.group(0), "")
    toml = toml.rstrip() + f"""

# TLS backend differs by platform.
#
# Desktop: native-tls, i.e. the OS's own TLS stack and trust store.
#
# Mobile: rustls with the ring backend. native-tls means OpenSSL on Android,
# which has to be cross-compiled for four CPU architectures. rustls 0.23 also
# ships with NO crypto backend unless one is chosen, and panics at the first
# TLS connection without one — so ring is named explicitly here and installed
# in client.rs.
[target.'cfg(not(any(target_os = "android", target_os = "ios")))'.dependencies]
tokio-tungstenite = {{ version = "0.24", features = ["native-tls"] }}

[target.'{MOBILE}'.dependencies]
tokio-tungstenite = {{ version = "0.24", features = ["rustls-tls-webpki-roots"] }}
rustls = {{ version = "0.23", default-features = false, features = ["ring", "std", "tls12", "logging"] }}
"""
    CORE_TOML.write_text(toml)
    report("crates/core/Cargo.toml", "patched")


# ---------------------------------------------------------------- 2. client.rs
rs = CLIENT_RS.read_text()
if "install_default" in rs:
    report("crates/core/src/client.rs", "skipped")
else:
    anchor = re.search(r'pub async fn run\(&self, mut commands:[^\n]*\{\n', rs)
    if not anchor:
        sys.exit("error: could not find `pub async fn run` in client.rs")
    insert = """        // rustls has no crypto backend until one is installed, and the first
        // TLS handshake panics without it. That panic kills this task, the
        // command channel's receiver is dropped, and the UI reports
        // "channel closed" with no hint of the cause. Desktop uses native-tls
        // and never reaches this.
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let _ = rustls::crypto::ring::default_provider().install_default();

"""
    rs = rs[: anchor.end()] + insert + rs[anchor.end():]
    CLIENT_RS.write_text(rs)
    report("crates/core/src/client.rs", "patched")


# ------------------------------------------------------------- 3. mobile.yml
WORKFLOW_BODY = r"""name: Build Android

# Signed APK for direct download from the website.
# Play Store distribution needs an .aab instead; see the comment at the end.

on:
  push:
    tags: ["v*"]
  workflow_dispatch:

jobs:
  android:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      # Everything that would otherwise produce a broken-but-green build.
      # An unset variable or secret is an empty string, never "missing",
      # so check emptiness explicitly before spending 20 minutes compiling.
      - name: Check required configuration
        env:
          RELAY_URL: ${{ vars.RELAY_URL }}
          KS: ${{ secrets.ANDROID_KEYSTORE }}
          KS_PASS: ${{ secrets.ANDROID_KEYSTORE_PASSWORD }}
          KS_ALIAS: ${{ secrets.ANDROID_KEY_ALIAS }}
        run: |
          missing=0
          for v in RELAY_URL KS KS_PASS KS_ALIAS; do
            if [ -z "${!v}" ]; then echo "::error::$v is not set"; missing=1; fi
          done
          [ "$missing" = 0 ] || exit 1
          echo "Building against $RELAY_URL"

      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: "17"

      - name: Point Tauri at the runner's NDK
        run: echo "NDK_HOME=$ANDROID_NDK_LATEST_HOME" >> "$GITHUB_ENV"

      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: aarch64-linux-android,armv7-linux-androideabi,i686-linux-android,x86_64-linux-android

      - uses: swatinem/rust-cache@v2
        with:
          workspaces: ". -> target"
          key: android

      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
          cache-dependency-path: app/package-lock.json

      - name: Install frontend dependencies
        working-directory: app
        run: npm ci

      # gen/android is not committed, so generate it fresh each run. This also
      # guarantees it always matches the identifier in tauri.conf.json.
      - name: Generate Android project
        working-directory: app
        run: npm run tauri android init -- --ci

      - name: Build APK
        working-directory: app
        env:
          RELAY_URL: ${{ vars.RELAY_URL }}
        run: npm run tauri android build -- --apk

      - name: Locate APK
        id: apk
        run: |
          apk=$(find app/src-tauri/gen/android -name '*release-unsigned.apk' | head -1)
          [ -n "$apk" ] || { echo "::error::no unsigned release APK produced"; exit 1; }
          echo "path=$apk" >> "$GITHUB_OUTPUT"
          echo "version=$(node -p "require('./app/src-tauri/tauri.conf.json').version")" >> "$GITHUB_OUTPUT"
          echo "Found $apk"

      # The check that actually matters: the URL in the shipped binary, not the
      # variable we intended to pass. Three releases shipped pointing at
      # localhost while every earlier check passed.
      - name: Verify relay URL was compiled in
        env:
          RELAY_URL: ${{ vars.RELAY_URL }}
        run: |
          mkdir -p apkcheck
          unzip -o -q "${{ steps.apk.outputs.path }}" 'lib/*' -d apkcheck
          if grep -rqaF "$RELAY_URL" apkcheck/lib; then
            echo "OK: $RELAY_URL is in the native library"
          else
            echo "::error::RELAY_URL is not in the APK. It will connect to localhost."
            exit 1
          fi

      - name: Sign APK
        env:
          KS: ${{ secrets.ANDROID_KEYSTORE }}
          KS_PASS: ${{ secrets.ANDROID_KEYSTORE_PASSWORD }}
          KS_ALIAS: ${{ secrets.ANDROID_KEY_ALIAS }}
        run: |
          echo "$KS" | base64 -d > release.jks
          BT=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
          OUT="securechat365_${{ steps.apk.outputs.version }}_android.apk"

          "$BT/zipalign" -p -f 4 "${{ steps.apk.outputs.path }}" aligned.apk
          "$BT/apksigner" sign \
            --ks release.jks --ks-pass env:KS_PASS \
            --ks-key-alias "$KS_ALIAS" --key-pass env:KS_PASS \
            --out "$OUT" aligned.apk
          "$BT/apksigner" verify --print-certs "$OUT"

          rm -f release.jks aligned.apk
          sha256sum "$OUT"
          echo "OUT=$OUT" >> "$GITHUB_ENV"

      - uses: actions/upload-artifact@v4
        with:
          name: securechat365-android
          path: ${{ env.OUT }}
          if-no-files-found: error

# Play Store: replace `--apk` with `--aab`, and sign the .aab with the same
# keystore using jarsigner instead of apksigner. Google re-signs it with an
# app signing key they hold; your keystore becomes the "upload key".
"""

if WORKFLOW.exists() and WORKFLOW.read_text() == WORKFLOW_BODY:
    report(".github/workflows/mobile.yml", "skipped")
else:
    WORKFLOW.parent.mkdir(parents=True, exist_ok=True)
    WORKFLOW.write_text(WORKFLOW_BODY)
    report(".github/workflows/mobile.yml", "written")

print("\nNext: cargo test -p securechat365-core")
