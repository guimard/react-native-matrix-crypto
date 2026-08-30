#!/usr/bin/env bash
set -euo pipefail

# The README's worked example for the user-interactive authentication loop
# must be the loop a test actually runs, step for step.
#
# That loop is the one path this library hands to a product whole: upstream
# surfaces no authentication for the signing-keys upload, so a product sends
# the request, reads the challenge out of the refusal, asks its user, and
# sends the same body again with an `auth` object merged in. Documentation is
# most of what a product has to go on there, which is exactly why it must not
# be documentation alone.
#
# The two files are in different languages, so bytes cannot be compared. What
# is compared is the ordered list of steps each declares, with a `uia-step:`
# comment at each one. A step added to the test and not to the README, a step
# reordered, or a step quietly dropped from either, fails here.
#
# This is deliberately a check on structure and not on behaviour. It cannot
# tell you the TypeScript works; nothing but running it could. What it can
# tell you is that the example stopped describing the thing that is proven,
# which is the failure this repository keeps finding: a model that drifted
# from the core it stood for, a gate that existed and ran nowhere, a table
# claiming more checks than existed.
#
# WATCHED FAILING, per the README's rule that a new gate arrives with the step
# that proves it fails on a real violation. Six, each applied and reverted:
# a step renamed in the README; a step deleted from the README; two steps
# swapped in the README; a step deleted from the TEST; the example emptied
# between its markers; and a marker renamed. Each exits 1. The first four
# print the differing step lists, the last two say the gate refused to pass
# having compared nothing.

TEST="rust/matrix-crypto-core/tests/level_two_identity_challenge.rs"
README="README.md"
BEGIN="<!-- uia-example:begin -->"
END="<!-- uia-example:end -->"

for f in "$TEST" "$README"; do
  if [ ! -s "$f" ]; then
    echo "FAIL: refusing to pass having scanned nothing."
    echo "      $f is missing or empty, so this gate cannot compare anything."
    exit 1
  fi
done

# The package copy is not read here. `gate:readme` already requires the two
# READMEs to be byte-identical, so a change to one that skipped the other
# fails there rather than being half-checked in two places.

steps_from() {
  sed -n 's|^[[:space:]]*//[[:space:]]*uia-step:[[:space:]]*\([A-Za-z0-9-]*\).*|\1|p' "$1"
}

TEST_STEPS=$(steps_from "$TEST")

# Only the fenced block between the markers, so a `uia-step:` written into the
# surrounding prose cannot satisfy this gate.
EXAMPLE=$(awk -v b="$BEGIN" -v e="$END" '
  $0 == b { inside = 1; next }
  $0 == e { inside = 0; next }
  inside  { print }
' "$README")

if [ -z "${EXAMPLE//[[:space:]]/}" ]; then
  echo "FAIL: $README has no worked example between"
  echo "        $BEGIN"
  echo "      and"
  echo "        $END"
  echo "      Refusing to pass having compared nothing. Either the markers were"
  echo "      renamed, or the example this gate exists to protect was deleted."
  exit 1
fi

README_STEPS=$(printf '%s\n' "$EXAMPLE" | steps_from /dev/stdin)

if [ -z "${TEST_STEPS//[[:space:]]/}" ]; then
  echo "FAIL: $TEST declares no 'uia-step:' markers."
  echo "      Refusing to pass having compared nothing: without them this gate"
  echo "      would agree that an empty list matches an empty list."
  exit 1
fi

if [ -z "${README_STEPS//[[:space:]]/}" ]; then
  echo "FAIL: the worked example in $README declares no 'uia-step:' markers."
  echo "      Refusing to pass having compared nothing."
  exit 1
fi

if ! diff -u \
  --label "$TEST" <(printf '%s\n' "$TEST_STEPS") \
  --label "$README (worked example)" <(printf '%s\n' "$README_STEPS"); then
  echo
  echo "FAIL: the README's worked example and the test that proves it no longer"
  echo "      run the same steps in the same order."
  echo
  echo "      The example is meant to be the code the test runs, not a second"
  echo "      account of it. Whichever one changed, change the other, and if a"
  echo "      step really has gone away, take it out of both rather than"
  echo "      loosening this comparison."
  exit 1
fi

COUNT=$(printf '%s\n' "$TEST_STEPS" | grep -c .)

# A floor, so that deleting six of the seven steps from both files at once
# cannot pass by agreeing about almost nothing. The loop is not the loop
# without a send, a refusal, the challenge read out of it, and a second send.
MINIMUM=7
if [ "$COUNT" -lt "$MINIMUM" ]; then
  echo "FAIL: only $COUNT steps are declared, and this loop has $MINIMUM."
  echo "      The two files agree, which is why the comparison above passed,"
  echo "      but they agree about too little to be the loop. If a step was"
  echo "      genuinely removed from the protocol, change $MINIMUM on purpose."
  exit 1
fi

echo "PASS: the README's worked example runs the same $COUNT steps, in the same"
echo "      order, as $TEST:"
printf '%s\n' "$TEST_STEPS" | paste -sd' ' - | sed 's/^/      /'
