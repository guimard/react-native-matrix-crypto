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

# --- "Every one of these runs in CI." ---------------------------------------
#
# The README's build-gate table stands under that sentence. On 2026-08-28 it
# was false in both directions at once: the table listed six gates where
# package.json declared seven, and the missing one -- gate:readme, this script
# -- was invoked by no workflow either. It had been written that same day,
# added to package.json, and wired into nothing, while the review that found
# it was closing seven other instances of a check that exists and never runs.
#
# So the sentence is enforced rather than repeated. Every `gate:*` script in
# package.json must appear in the workflow, as a step that runs it, and in the
# README's table, as a row that names it. A gate added tomorrow fails this
# gate until both are true, which is cheaper than finding out in a review.
WORKFLOW=".github/workflows/ci.yml"

if [ ! -s "$WORKFLOW" ]; then
  echo "FAIL: $WORKFLOW is missing or empty, so this gate cannot check that"
  echo "      the README's \"Every one of these runs in CI\" is true."
  exit 1
fi

GATES=$(node -e '
  const pkg = JSON.parse(require("fs").readFileSync("package.json", "utf8"));
  Object.keys(pkg.scripts || {})
    .filter(s => s.startsWith("gate:"))
    .forEach(s => console.log(s));
')

# Refuse to pass having compared nothing: an unreadable package.json or a
# renamed script prefix would leave this empty and every loop below would
# trivially agree.
if [ -z "${GATES//[[:space:]]/}" ]; then
  echo "FAIL: refusing to pass having compared nothing."
  echo "      package.json declares no gate:* script, which means this check"
  echo "      broke rather than that every gate is wired up."
  exit 1
fi

UNWIRED=""
UNLISTED=""
for gate in $GATES; do
  if ! grep -qE "^[[:space:]]*-[[:space:]]*run:[[:space:]]*yarn[[:space:]]+$gate[[:space:]]*$" "$WORKFLOW"; then
    UNWIRED="${UNWIRED:+$UNWIRED
}$gate"
  fi
  if ! grep -qF "| \`$gate\` |" "$ROOT_README"; then
    UNLISTED="${UNLISTED:+$UNLISTED
}$gate"
  fi
done

if [ -n "$UNWIRED" ]; then
  echo "FAIL: a gate exists in package.json and no CI job runs it:"
  echo "$UNWIRED"
  echo "      Add a '- run: yarn <gate>' step to $WORKFLOW."
  echo "      A gate nobody runs is documentation, not enforcement."
  exit 1
fi

if [ -n "$UNLISTED" ]; then
  echo "FAIL: a gate runs in CI and the README's build-gate table does not"
  echo "      name it:"
  echo "$UNLISTED"
  echo "      That table stands under \"Every one of these runs in CI\", so a"
  echo "      missing row makes the sentence describe fewer checks than exist."
  exit 1
fi

GATE_COUNT=$(printf '%s\n' "$GATES" | grep -c .)

echo "PASS: READMEs identical ($(wc -l < "$ROOT_README" | tr -d ' ') lines);"
echo "      all $GATE_COUNT gates run in CI and appear in the README's table"
