#!/usr/bin/env bash
# scripts/release-local.sh
# Build releases locally for x86_64-unknown-linux-gnu and aarch64-unknown-linux-gnu,
# package tarballs, compute SHA256SUMS, and optionally publish directly to GitHub Releases.
#
# Usage:
#   scripts/release-local.sh <tag> [--publish] [--draft]
# Example:
#   scripts/release-local.sh v0.1.0 --publish

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$ROOT_DIR/target/dist"

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m==>\033[0m %s\n' "$*" >&2; exit 1; }

if [ $# -lt 1 ]; then
  echo "Usage: $0 <tag> [--publish] [--draft]"
  echo "  <tag>        Release tag, e.g. v0.1.0"
  echo "  --publish    Upload artifacts directly to GitHub Release using gh CLI"
  echo "  --draft      Create release as draft when publishing"
  exit 1
fi

TAG="$1"
shift

PUBLISH=0
DRAFT_FLAG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --publish) PUBLISH=1; shift ;;
    --draft) DRAFT_FLAG="--draft"; shift ;;
    *) err "Unknown option: $1" ;;
  esac
done

if ! printf '%s' "$TAG" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  err "Tag must match vX.Y.Z exactly (got '$TAG')"
fi

cd "$ROOT_DIR"

command -v git >/dev/null 2>&1 || err "git is required"
command -v cargo >/dev/null 2>&1 || err "cargo is required"
command -v rustup >/dev/null 2>&1 || err "rustup is required"
command -v npm >/dev/null 2>&1 || err "npm is required"
command -v tar >/dev/null 2>&1 || err "tar is required"
command -v sha256sum >/dev/null 2>&1 || err "sha256sum is required"

PLUGIN_SIGNING_KEY_FILE="${KINETIX_PLUGIN_SIGNING_KEY_FILE:-}"
if [ -n "$PLUGIN_SIGNING_KEY_FILE" ]; then
  command -v wasm-tools >/dev/null 2>&1 || err "wasm-tools is required when signing plugin release assets"
  command -v openssl >/dev/null 2>&1 || err "openssl is required when signing plugin release assets"
  [ -f "$PLUGIN_SIGNING_KEY_FILE" ] || err "plugin signing key not found: $PLUGIN_SIGNING_KEY_FILE"
fi

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || err "must be run from a git checkout"

if [ "$PUBLISH" -eq 1 ]; then
  command -v gh >/dev/null 2>&1 || err "gh CLI is required to publish"
  gh auth status >/dev/null 2>&1 || err "gh CLI is not authenticated"

  log "Refreshing remote tags before resolving $TAG..."
  git fetch --tags origin
fi

TAG_REF="refs/tags/$TAG"
TAG_EXISTS=0
if git rev-parse --verify --quiet "$TAG_REF^{commit}" >/dev/null; then
  TAG_EXISTS=1
  SOURCE_SHA="$(git rev-parse "$TAG_REF^{commit}")"
  log "Building existing tag $TAG at $SOURCE_SHA"
else
  if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    err "working tree is not clean; commit or stash changes before building a new release tag"
  fi
  SOURCE_SHA="$(git rev-parse HEAD)"
  log "Tag $TAG does not exist yet; building clean HEAD at $SOURCE_SHA"
fi

PACKAGE_VERSION="$(
  git show "$SOURCE_SHA:Cargo.toml" |
    awk -F'"' '/^version[[:space:]]*=/{print $2; exit}'
)"
[ -n "$PACKAGE_VERSION" ] || err "could not read package version from Cargo.toml at $SOURCE_SHA"
if [ "$TAG" != "v$PACKAGE_VERSION" ]; then
  err "release tag $TAG does not match Cargo package version $PACKAGE_VERSION"
fi

WORK_PARENT="$(mktemp -d)"
BUILD_ROOT="$WORK_PARENT/source"
WORKTREE_ADDED=0

cleanup() {
  if [ "$WORKTREE_ADDED" -eq 1 ]; then
    git -C "$ROOT_DIR" worktree remove --force "$BUILD_ROOT" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK_PARENT"
}
trap cleanup EXIT

git worktree add --detach "$BUILD_ROOT" "$SOURCE_SHA" >/dev/null
WORKTREE_ADDED=1

TARGETS=("x86_64-unknown-linux-gnu" "aarch64-unknown-linux-gnu")

# 1. Build dashboard frontend from the exact source commit that will be released.
log "Installing and building embedded dashboard frontend..."
(
  cd "$BUILD_ROOT/dashboard"
  npm ci
  npm run build
)

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# 2. Build each target from the same detached source worktree.
for TARGET in "${TARGETS[@]}"; do
  log "Building binary for target: $TARGET"

  if [ "$TARGET" = "x86_64-unknown-linux-gnu" ]; then
    rustup target add "$TARGET" >/dev/null 2>&1 || true
    (
      cd "$BUILD_ROOT"
      cargo build --release --locked --target "$TARGET"
    )
  else
    if command -v cross >/dev/null 2>&1; then
      log "Cross-compiling $TARGET via cross..."
      (
        cd "$BUILD_ROOT"
        cross build --release --locked --target "$TARGET"
      )
    else
      err "cross command not found. Install cross to build aarch64."
    fi
  fi

  BIN_SRC="$BUILD_ROOT/target/$TARGET/release/kinetix"
  [ -f "$BIN_SRC" ] || err "Built binary not found at $BIN_SRC"

  ARCHIVE_NAME="kinetix-$TAG-$TARGET.tar.gz"
  ARCHIVE_PATH="$DIST_DIR/$ARCHIVE_NAME"

  log "Creating archive: $ARCHIVE_NAME"
  TMP_STAGE="$WORK_PARENT/stage-$TARGET"
  mkdir -p "$TMP_STAGE"
  cp "$BIN_SRC" "$TMP_STAGE/kinetix"
  chmod 0755 "$TMP_STAGE/kinetix"
  tar -czf "$ARCHIVE_PATH" -C "$TMP_STAGE" kinetix

  (
    cd "$DIST_DIR"
    sha256sum "$ARCHIVE_NAME" > "$ARCHIVE_NAME.sha256"
  )
done

# 3. Optionally build signed first-party plugin release assets.
if [ -n "$PLUGIN_SIGNING_KEY_FILE" ]; then
  log "Building signed first-party plugin packages..."
  rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
  (
    cd "$BUILD_ROOT"
    KINETIX_PLUGIN_SIGNING_KEY_FILE="$PLUGIN_SIGNING_KEY_FILE" \
      scripts/build-plugin.sh plugins/antigravity-oauth
  )
  cp "$BUILD_ROOT"/plugins/antigravity-oauth/*.kxp "$DIST_DIR"/
fi

# 4. Create consolidated SHA256SUMS file.
log "Generating canonical SHA256SUMS..."
(
  cd "$DIST_DIR"
  shopt -s nullglob
  ASSETS=(kinetix-"$TAG"-*.tar.gz *.kxp)
  [ "${#ASSETS[@]}" -gt 0 ] || err "no release assets were produced"
  sha256sum "${ASSETS[@]}" > SHA256SUMS
)

log "Release artifacts prepared in $DIST_DIR from source $SOURCE_SHA:"
ls -lh "$DIST_DIR"

# 5. Optional publish via gh. Create a new tag only after every artifact succeeds.
if [ "$PUBLISH" -eq 1 ]; then
  log "Publishing release $TAG to GitHub..."

  if [ "$TAG_EXISTS" -eq 0 ]; then
    log "Creating git tag $TAG at $SOURCE_SHA..."
    git tag -a "$TAG" "$SOURCE_SHA" -m "Release $TAG"
  fi

  TAG_SHA="$(git rev-parse "$TAG_REF^{commit}")"
  if [ "$TAG_SHA" != "$SOURCE_SHA" ]; then
    err "tag $TAG resolves to $TAG_SHA, but artifacts were built from $SOURCE_SHA"
  fi

  log "Pushing tag $TAG to origin..."
  git push origin "refs/tags/$TAG"

  log "Ensuring GitHub Release exists..."
  if ! gh release view "$TAG" >/dev/null 2>&1; then
    gh release create "$TAG" --title "Kinetix $TAG" --generate-notes $DRAFT_FLAG
  fi

  log "Uploading artifacts to release $TAG..."
  shopt -s nullglob
  RELEASE_ASSETS=(
    "$DIST_DIR"/kinetix-"$TAG"-*.tar.gz
    "$DIST_DIR"/kinetix-"$TAG"-*.sha256
    "$DIST_DIR"/*.kxp
    "$DIST_DIR"/SHA256SUMS
  )
  gh release upload "$TAG" "${RELEASE_ASSETS[@]}" --clobber

  log "Release $TAG published successfully!"
  gh release view "$TAG"
fi
