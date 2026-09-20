#!/usr/bin/env bash
# Build a first-party plugin into a `.kxp` package.
#
# Usage: scripts/build-plugin.sh <plugin-dir>
#   e.g. scripts/build-plugin.sh plugins/antigravity-oauth
#
# Produces <plugin-dir>/<id>-<version>.kxp (a deterministic tar archive with
# plugin.toml, plugin.wasm, README.md, LICENSE, and optionally
# signature.ed25519). Requires the wasm32-unknown-unknown target and wasm-tools.
#
# Set KINETIX_PLUGIN_SIGNING_KEY_FILE to an Ed25519 private key in PEM format to
# sign SHA256(plugin.wasm || plugin.toml), matching the host verifier.
set -euo pipefail

DIR="${1:?usage: build-plugin.sh <plugin-dir>}"
DIR="${DIR%/}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/$DIR"

NAME="$(basename "$DIR")"
PKG_NAME="$(grep -m1 '^name' "$DIR/Cargo.toml" | sed -E 's/.*"(.*)".*/\1/')"
VERSION="$(grep -m1 '^version' "$DIR/Cargo.toml" | sed -E 's/.*"(.*)".*/\1/')"
PLUGIN_ID="$(grep -m1 '^id' "$DIR/plugin.toml" | sed -E 's/.*"(.*)".*/\1/')"

command -v wasm-tools >/dev/null || { echo "wasm-tools is required" >&2; exit 1; }
SIGNING_KEY_FILE="${KINETIX_PLUGIN_SIGNING_KEY_FILE:-}"
if [ -n "$SIGNING_KEY_FILE" ]; then
  command -v openssl >/dev/null || { echo "openssl is required for plugin signing" >&2; exit 1; }
  [ -f "$SIGNING_KEY_FILE" ] || { echo "plugin signing key not found: $SIGNING_KEY_FILE" >&2; exit 1; }
fi
rustup target list --installed | grep -q wasm32-unknown-unknown \
  || { echo "run: rustup target add wasm32-unknown-unknown" >&2; exit 1; }

echo "==> building $PKG_NAME $VERSION ($PLUGIN_ID)"
( cd "$ROOT/plugins" && cargo build --release --target wasm32-unknown-unknown -p "$PKG_NAME" )

WASM="$ROOT/plugins/target/wasm32-unknown-unknown/release/${PKG_NAME//-/_}.wasm"
[ -f "$WASM" ] || { echo "expected $WASM" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> encoding component"
wasm-tools component new "$WASM" -o "$WORK/plugin.wasm"
wasm-tools validate --features component-model "$WORK/plugin.wasm"

cp "$DIR/plugin.toml" "$WORK/plugin.toml"
[ -f "$DIR/README.md" ] && cp "$DIR/README.md" "$WORK/README.md"
[ -f "$DIR/LICENSE" ] && cp "$DIR/LICENSE" "$WORK/LICENSE"

if [ -n "$SIGNING_KEY_FILE" ]; then
  echo "==> signing package payload"
  cat "$WORK/plugin.wasm" "$WORK/plugin.toml" \
    | openssl dgst -sha256 -binary > "$WORK/signing-digest.bin"
  openssl pkeyutl -sign -rawin \
    -inkey "$SIGNING_KEY_FILE" \
    -in "$WORK/signing-digest.bin" \
    -out "$WORK/signature.ed25519"
  [ "$(wc -c < "$WORK/signature.ed25519")" -eq 64 ] \
    || { echo "Ed25519 signature must be exactly 64 bytes" >&2; exit 1; }
fi

OUT="$DIR/${PLUGIN_ID}-${VERSION}.kxp"
FILES=(plugin.toml plugin.wasm)
[ -f "$WORK/README.md" ] && FILES+=(README.md)
[ -f "$WORK/LICENSE" ] && FILES+=(LICENSE)
[ -f "$WORK/signature.ed25519" ] && FILES+=(signature.ed25519)

# Deterministic archive: fixed mtime, sorted entries, no owner names.
tar --sort=name --mtime='UTC 2020-01-01' --owner=0 --group=0 --numeric-owner \
    -C "$WORK" -cf "$OUT" "${FILES[@]}" 2>/dev/null \
  || tar -C "$WORK" -cf "$OUT" "${FILES[@]}"

echo "==> wrote $OUT"
sha256sum "$OUT" | awk '{print "    sha256 " $1}'
