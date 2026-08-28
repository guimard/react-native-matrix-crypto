#!/usr/bin/env bash
set -euo pipefail

# The root README and the published package's README must be identical.
#
# They are two files rather than one because npm shows the package copy on the
# registry page and GitHub shows the root copy, and npm does not follow a
# symlink out of the package directory when packing. So the only mechanism
# available is a copy, and a copy kept in sync by hand drifts.
#
# It already did. A contributing section describing how to run the
# interoperability proof was added to the root copy alone -- which is the
# section a consumer arriving from npm would most want, and the one they would
# not have seen.
ROOT_README="README.md"
PKG_README="packages/react-native-matrix-crypto/README.md"

# Refuse to pass having scanned nothing. A renamed or moved file would
# otherwise make `diff` fail loudly on a missing path, or -- worse, if someone
# "fixed" that with a `-N` -- make two absent files compare equal. The sibling
# gates carry the same guard for the same reason.
for f in "$ROOT_README" "$PKG_README"; do
  if [ ! -s "$f" ]; then
    echo "FAIL: refusing to pass having scanned nothing."
    echo "      $f is missing or empty, so this gate cannot compare anything."
    exit 1
  fi
done

if ! diff -u "$ROOT_README" "$PKG_README"; then
  echo
  echo "FAIL: the two READMEs have diverged."
  echo "      The package copy is what npm shows a consumer. Copy the root one over it:"
  echo "        cp $ROOT_README $PKG_README"
  exit 1
fi

echo "PASS: READMEs identical ($(wc -l < "$ROOT_README" | tr -d ' ') lines)"
