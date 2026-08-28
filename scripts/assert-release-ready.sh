#!/usr/bin/env bash
set -euo pipefail

# Assert that a release tag and the manifest it is supposed to name agree,
# before anything is built or published.
#
# A tag reading v0.1.0 against a manifest reading 0.2.0 publishes 0.2.0 and
# leaves a tag pointing at a version that was never released. Nobody can
# reconstruct afterwards which commit produced which registry entry, and the
# provenance attestation the publish attaches would tie the wrong tag to the
# artifact. The mismatch is cheap to detect and expensive to discover later,
# so it is detected here, in the first thirty seconds of the release run,
# rather than ninety minutes in.
#
# The assertion lives in a script rather than in the workflow so that a
# contributor can run byte-for-byte what CI runs:
#
#   ./scripts/assert-release-ready.sh v0.1.0
#
# Usage: scripts/assert-release-ready.sh <tag>

if [ $# -lt 1 ]; then
  echo "usage: $0 <tag>            e.g. $0 v0.1.0" >&2
  exit 2
fi

TAG="$1"
MANIFEST="packages/react-native-matrix-crypto/package.json"

if [ ! -s "$MANIFEST" ]; then
  echo "FAIL: $MANIFEST is missing or empty."
  echo "      Run this from the repository root. Refusing to pass having"
  echo "      compared the tag against nothing."
  exit 1
fi

PKG_NAME=$(node -p "require('./$MANIFEST').name || ''")
PKG_VERSION=$(node -p "require('./$MANIFEST').version || ''")

if [ -z "$PKG_NAME" ] || [ -z "$PKG_VERSION" ]; then
  echo "FAIL: $MANIFEST declares no name or no version."
  echo "      Refusing to pass having read no version to compare."
  exit 1
fi

# The tag convention is a leading v, which npm's own version numbers do not
# carry. Accept exactly that one difference and nothing looser: a tag of
# "release-0.1.0" or "0.1.0-hotfix" should stop the run rather than be
# massaged into agreement.
TAG_VERSION="${TAG#v}"

if [ "$TAG_VERSION" = "$TAG" ]; then
  echo "FAIL: the tag '$TAG' does not start with 'v'."
  echo "      This project's release tags are v<version>, e.g. v$PKG_VERSION."
  exit 1
fi

if [ "$TAG_VERSION" != "$PKG_VERSION" ]; then
  echo "FAIL: the tag and the manifest disagree about what is being released."
  echo "      tag       $TAG          (version $TAG_VERSION)"
  echo "      $MANIFEST   version $PKG_VERSION"
  echo
  echo "      Publishing now would put $PKG_VERSION on the registry under a tag"
  echo "      naming $TAG_VERSION, and nobody could reconstruct afterwards which"
  echo "      commit produced which release. Fix one of the two and tag again."
  exit 1
fi

# Reject a version npm would not accept, before spending an hour building for
# it. Deliberately strict: MAJOR.MINOR.PATCH with an optional prerelease and
# build metadata, per semver.
if ! printf '%s' "$PKG_VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
  echo "FAIL: '$PKG_VERSION' is not a semantic version."
  exit 1
fi

echo "Tag and manifest agree: $PKG_NAME@$PKG_VERSION from tag $TAG"

# A version already on the registry cannot be republished -- npm answers 403
# with a message about "cannot publish over the previously published
# versions", which reads like an authentication problem and is not one. Say so
# here instead, in the first job, where the fix (bump the version, retag) is
# obvious.
#
# A network failure is NOT a release-blocking condition: npm publish itself
# refuses a duplicate, so this check is an early, friendlier report of
# something the registry enforces anyway. Only a definite "this version
# exists" stops the run.
echo
echo "Asking the registry whether $PKG_NAME@$PKG_VERSION already exists..."
REGISTRY_OUT=$(npm view "$PKG_NAME@$PKG_VERSION" version 2>&1) && REGISTRY_RC=0 || REGISTRY_RC=$?

if [ "$REGISTRY_RC" -eq 0 ] && [ -n "${REGISTRY_OUT//[[:space:]]/}" ]; then
  echo "FAIL: $PKG_NAME@$PKG_VERSION is already published."
  echo "      npm does not allow republishing a version. Bump the version in"
  echo "      $MANIFEST, commit, and tag the new version."
  exit 1
fi

if printf '%s' "$REGISTRY_OUT" | grep -q 'E404\|404 Not Found'; then
  echo "  not on the registry yet -- this would be a new publish."
else
  echo "  could not reach a definite answer; npm said:"
  printf '%s\n' "$REGISTRY_OUT" | sed 's/^/    /' | head -5
  echo "  Continuing: npm publish refuses a duplicate on its own, so this"
  echo "  check is an early warning, not the enforcement."
fi

echo
echo "PASS: ready to release $PKG_NAME@$PKG_VERSION as $TAG"
