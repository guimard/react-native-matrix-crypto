#!/usr/bin/env bash
set -euo pipefail

# Rehearse the publish, against the real built artifact, without publishing.
#
#   ./scripts/rehearse-publish.sh
#
# Checks the tree the way the release workflow checks it, packs the package
# exactly as the release workflow packs it, runs the same assertion the
# release workflow runs on the packed bytes, and then runs
# `npm publish --dry-run` on that tarball so you can read the file list npm
# would upload. It needs no npm token, no tag, and no write access to
# anything: `--dry-run` does everything except the upload.
#
# It does need the binaries on disk, because the whole point is to rehearse
# against the artifact that would really be published rather than against a
# source-only pack. Build them first:
#
#   cd packages/react-native-matrix-crypto
#   yarn exec ubrn -- build ios --config ../../ubrn.config.yaml \
#     --targets aarch64-apple-ios,aarch64-apple-ios-sim,x86_64-apple-ios --release
#   yarn exec ubrn -- build android --config ../../ubrn.config.yaml \
#     --targets aarch64-linux-android,armv7-linux-androideabi,x86_64-linux-android,i686-linux-android --release
#
# Two commands, the whole recipe. A root `.aar` used to be a third output,
# built with Gradle's `assembleRelease` and copied to the package root --
# removed 2026-08-28 along with `*.aar` from package.json's "files": nothing
# autolinked against it, no document told a consumer how to, and it was 13%
# of the unpacked package for a file nothing loaded. See M2 spec section 9
# step 2.
#
# The iOS leg needs macOS and Xcode; the Android leg needs the NDK and
# cargo-ndk. If you have only one of the two, this script will still run and
# the assertion will tell you precisely which binaries are missing -- which
# is a useful thing to see, and exactly what it would say to the release
# workflow.
#
# The tarball is packed into a temporary directory rather than into the
# package, so a rehearsal never leaves a 70 MB file in the working tree.

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PKG_DIR="$REPO_ROOT/packages/react-native-matrix-crypto"

if [ ! -s "$PKG_DIR/package.json" ]; then
  echo "FAIL: no package.json at $PKG_DIR." >&2
  exit 1
fi

VERSION=$(node -p "require('$PKG_DIR/package.json').version")
NAME=$(node -p "require('$PKG_DIR/package.json').name")

# npm does not infer a distribution tag from the version: `npm publish` with
# no --tag always sets `latest`, prerelease or not. Same derivation
# release.yml's preflight job uses, so this rehearsal exercises exactly what
# CI would do rather than the plain-version-only default.
if printf '%s' "$VERSION" | grep -qE -- '^[0-9]+\.[0-9]+\.[0-9]+-'; then
  NPM_TAG=$(printf '%s' "$VERSION" | sed -E 's/^[0-9]+\.[0-9]+\.[0-9]+-([0-9A-Za-z-]+).*/\1/')
else
  NPM_TAG="latest"
fi

OUT_DIR="${1:-$(mktemp -d)}"
mkdir -p "$OUT_DIR"

echo "== 1/4  Checking the tree this will pack from"
echo
# The release workflow runs this immediately after unpacking the two build
# artifacts, and it runs here for the same reason: it separates "the binaries
# are not on disk" from "the binaries are on disk and npm will not pack them",
# which the tarball assertion in step 3 cannot tell apart.
#
# It also prints the npm version, which is the one number a local rehearsal
# most needs to show. A rehearsal is only predictive of CI to the extent the
# two agree about what `npm pack` includes, and on 2026-08-28 they did not:
# this script passed on npm 12 while the release failed on the npm 10.9.8 that
# `actions/setup-node` installs alongside the .nvmrc Node, over a "files"
# entry the two versions read differently. Neither said which npm it was.
if ! "$REPO_ROOT/scripts/assert-tree-ships-binaries.sh" "$PKG_DIR"; then
  echo
  echo "Nothing was packed. Build the binaries with the two ubrn commands in"
  echo "the header of this script, or read the message above for why npm"
  echo "would have dropped ones that are already there."
  exit 1
fi

echo
echo "== 2/4  Packing $NAME@$VERSION into $OUT_DIR"
cd "$PKG_DIR"
npm pack --pack-destination "$OUT_DIR" >/dev/null
TGZ="$OUT_DIR/$(ls -t "$OUT_DIR" | head -1)"
if [ ! -s "$TGZ" ]; then
  echo "FAIL: npm pack produced no tarball in $OUT_DIR." >&2
  exit 1
fi
echo "   $TGZ ($(du -k "$TGZ" | cut -f1) KB)"

echo
echo "== 3/4  Asserting the packed bytes carry the prebuilt binaries"
if ! "$REPO_ROOT/scripts/assert-tarball-ships-binaries.sh" "$TGZ" "$VERSION"; then
  echo
  echo "The tarball above is NOT publishable. If the missing pieces are"
  echo "binaries, build them with the two ubrn commands in the header of this"
  echo "script and run this again."
  exit 1
fi

echo
echo "== 4/4  npm publish --dry-run --tag $NPM_TAG"
echo "   No token is used and nothing is uploaded."
echo
npm publish --dry-run --tag "$NPM_TAG" "$TGZ"

echo
echo "Rehearsal complete. Nothing was published."
echo
echo "The release workflow (.github/workflows/release.yml) does the same four"
echo "steps on a tag push, then publishes THIS tarball -- the same bytes it"
echo "asserted on -- with --provenance, which only works inside GitHub Actions"
echo "and is therefore not part of this local rehearsal."
echo
echo "To rehearse the other half, the tag/manifest/npm-tag agreement:"
echo "   ./scripts/assert-release-ready.sh v$VERSION $NPM_TAG"
