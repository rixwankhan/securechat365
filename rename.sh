#!/usr/bin/env bash
# Rename veil -> securechat365 across the project.
#
# Run from the repository root. Commit first — this rewrites many files.
#
#   chmod +x rename.sh && ./rename.sh
#
# Deliberately does NOT do a blanket s/veil/securechat365/. Directory paths,
# the repo folder name, and prose all contain the word, and a blind replace
# mangles them. Each token below is replaced explicitly, longest first, so
# "securechat365-core" is handled before a bare "veil" could half-match it.

set -euo pipefail

if [ ! -f Cargo.toml ] || [ ! -d crates ]; then
  echo "error: run this from the repository root (where Cargo.toml lives)"
  exit 1
fi

if command -v git >/dev/null && [ -n "$(git status --porcelain 2>/dev/null || true)" ]; then
  echo "warning: you have uncommitted changes."
  read -r -p "Continue anyway? [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]] || exit 1
fi

# Files to rewrite: source and config only. Never touch build output,
# dependencies, or the generated mobile projects (those get regenerated).
FILES=$(find . \
  -type d \( -name target -o -name node_modules -o -name .git -o -name gen \) -prune -o \
  -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.json' -o -name '*.html' \
             -o -name '*.yml' -o -name '*.yaml' -o -name '*.md' -o -name '*.sh' \
             -o -name 'Dockerfile' -o -name 'Caddyfile' \) -print)

replace() {
  local from="$1" to="$2" hits=0
  # In a sed replacement, & means "the whole match" and \ escapes. Both appear
  # in Rust snippets like `&str`, so escape them or the line gets mangled.
  local from_esc to_esc
  from_esc=$(printf '%s' "$from" | sed 's/[]\/$*.^[]/\\&/g')
  to_esc=$(printf '%s' "$to" | sed 's/[\/&]/\\&/g')

  for f in $FILES; do
    if grep -qF -- "$from" "$f" 2>/dev/null; then
      # -i '' is the BSD/macOS form; GNU sed wants -i with no argument.
      if sed --version >/dev/null 2>&1; then
        sed -i "s/$from_esc/$to_esc/g" "$f"
      else
        sed -i '' "s/$from_esc/$to_esc/g" "$f"
      fi
      hits=$((hits + 1))
    fi
  done
  printf '  %-28s -> %-32s %d file(s)\n' "$from" "$to" "$hits"
}

echo
echo "Crate names"
replace "securechat365-core"  "securechat365-core"
replace "securechat365_core"  "securechat365_core"
replace "securechat365-relay" "securechat365-relay"
replace "securechat365_relay" "securechat365_relay"

echo
echo "Environment variables"
replace "RELAY_URL" "RELAY_URL"
replace "SECURECHAT_DATA_DIR"  "SECURECHAT_DATA_DIR"

echo
echo "Protocol constants"
# Baked into QR codes and deep-link registration. Change it now, before
# anyone has shared an ID — afterwards, every existing QR code stops
# opening the app.
replace 'URI_SCHEME: &str = "securechat365"' 'URI_SCHEME: &str = "securechat365"'
# Domain separator for safety numbers. Changing it changes every safety
# number, so this is a one-time-only move while nobody is verifying yet.
replace 'b"securechat365-safety-number-v1"' 'b"securechat365-safety-number-v1"'

echo
echo "Tauri event channel (frontend and backend must match)"
replace 'emit("securechat365"' 'emit("securechat365"'
replace "listen('securechat365'" "listen('securechat365'"

echo
echo "Container and CI"
replace "useradd --system --no-create-home --uid 10001 securechat" \
        "useradd --system --no-create-home --uid 10001 securechat"
replace "/usr/local/bin/securechat365-relay" "/usr/local/bin/securechat365-relay"
replace "USER securechat"    "USER securechat"
replace 'CMD ["securechat365-relay"]' 'CMD ["securechat365-relay"]'
replace "name: securechat365-" "name: securechat365-"

echo
echo "Links"
replace "github.com/rixwankhan/securechat365" "github.com/rixwankhan/securechat365"
replace "github.com/rixwankhan/securechat365" "github.com/rixwankhan/securechat365"

echo
echo "Done. Remaining mentions of 'veil' (check these by hand):"
grep -rn --exclude-dir={target,node_modules,.git,gen} -i "veil" . 2>/dev/null \
  | grep -v "^./rename.sh" | head -30 || echo "  none"

echo
cat <<'NEXT'

Next steps, in order:

  1. cargo test -p securechat365-core
  2. Set identifier in app/src-tauri/tauri.conf.json  (see notes below)
  3. rm -rf app/src-tauri/gen        # regenerate mobile projects
  4. cargo clean && cargo build
  5. RELAY_URL=wss://relay.securechat365.com/ws npm run tauri dev   (in app/)

On the server:
  6. Rename the GitHub Actions variable RELAY_URL -> RELAY_URL
  7. Redeploy the relay: docker compose up -d --build
NEXT
