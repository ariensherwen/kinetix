#!/usr/bin/env bash
# Print the raw Ed25519 public key as base64 for plugins/trusted-publishers.json.
#
# Usage:
#   scripts/plugin-publisher-key.sh <ed25519-private-or-public.pem>
set -euo pipefail

KEY="${1:?usage: plugin-publisher-key.sh <ed25519-private-or-public.pem>}"
[ -f "$KEY" ] || { echo "key not found: $KEY" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

if grep -q "BEGIN PUBLIC KEY" "$KEY"; then
  DER="$(mktemp)"
  trap 'rm -f "$DER"' EXIT
  openssl pkey -pubin -in "$KEY" -outform DER -out "$DER"
else
  DER="$(mktemp)"
  trap 'rm -f "$DER"' EXIT
  openssl pkey -in "$KEY" -pubout -outform DER -out "$DER"
fi

# RFC 8410 Ed25519 SubjectPublicKeyInfo ends with the 32-byte raw public key.
[ "$(wc -c < "$DER")" -ge 32 ] || { echo "invalid Ed25519 public key" >&2; exit 1; }
tail -c 32 "$DER" | base64 | tr -d '\n'
printf '\n'
