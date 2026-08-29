#!/usr/bin/env bash
set -euo pipefail

# Faces every refusal in scripts/measure-signal-latency.sh with the case it
# exists to reject, and the accepting case with the run it must accept.
#
# WHY THIS IS A GATE AND NOT A PARAGRAPH
#
# That harness is the only artifact in this milestone whose correctness nothing
# else can confirm: it is what decides whether an A/B measurement is an A/B at
# all. Two of its guards shipped unable to fire, one of them through two review
# cycles, and both were found by *running* the case rather than by reading or
# by shellcheck -- which passes on both defects. The second was found only
# because a reviewer enumerated a case the manual pass had not thought of.
#
# That is the property of a manual check: it covers the cases someone thought
# of, at the moment they thought of them. This covers the same cases on every
# commit, by someone who does not have to remember. Spec section 3.2 counts
# instances of "a check that reports success without having examined its
# target"; two of them are in that one file.
#
# WHAT IT ASSERTS, AND WHY BOTH HALVES
#
# Each case asserts the exit status AND a distinctive substring of the
# diagnostic. Neither alone is enough, and both real defects prove it:
#
#   - the trap defect exited 127 with the right *message* already printed, so
#     asserting the message alone would have passed it;
#   - the `set -e` defect exits 1 -- the correct status -- with no message at
#     all, so asserting the status alone would have passed it.
#
# WHAT IS FAKED, AND WHAT IS NOT
#
# `adb` is scripts/testdata/fake-adb, which supplies device properties and
# `logcat` bytes and nothing else. The APKs are real zip files built here with
# python3's zipfile module. Everything under test -- the digest comparison, the
# `grep | head | awk` extraction, the `LAST_BUILD` return, the arm comparison,
# the row written -- is the shipped script, unmodified. No device, no emulator,
# no Android SDK, no Rust.
#
# The seam this cannot reach is the one from Rust's `EMIT_BUILD` const to the
# `PROBE_EMIT_BUILD` line. That is closed from the other end by
# `matrix-crypto-core`'s `the_build_suffix_is_derived_rather_than_constant`.

HARNESS=scripts/measure-signal-latency.sh
STUB_DIR=scripts/testdata
ABI=arm64-v8a

[ -x "$HARNESS" ] || { echo "FAIL: $HARNESS is missing or not executable."; exit 1; }
[ -x "$STUB_DIR/fake-adb" ] || { echo "FAIL: $STUB_DIR/fake-adb is missing or not executable."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "FAIL: python3 is needed to build the fixture APKs."; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# `adb` must resolve to the stub and to nothing else, including on a machine
# with a real one installed.
mkdir -p "$WORK/bin"
cp "$STUB_DIR/fake-adb" "$WORK/bin/adb"
chmod +x "$WORK/bin/adb"
export PATH="$WORK/bin:$PATH"
export FAKE_STATE="$WORK/state"
export FAKE_ABI="$ABI"
# The harness waits this long after each summary for a late callback. Real
# runs want it; this one would only be slower for it.
export LATE_GRACE_SECONDS=0

# --------------------------------------------------------------- fixtures
# Real zips. `armA` and `armB` differ in the member the harness digests;
# `armCopy` is byte-identical to `armA`; `nolib` carries no library at all.
mkdir -p "$WORK/src/lib/$ABI" "$WORK/src/assets" "$WORK/nolib"
printf 'ELF-A' > "$WORK/src/lib/$ABI/libmatrix_crypto_ffi.so"
printf 'bundle' > "$WORK/src/assets/index.android.bundle"
printf 'not a library' > "$WORK/nolib/README"

( cd "$WORK/src" && python3 -m zipfile -c "$WORK/armA.apk" . )
printf 'ELF-B' > "$WORK/src/lib/$ABI/libmatrix_crypto_ffi.so"
( cd "$WORK/src" && python3 -m zipfile -c "$WORK/armB.apk" . )
( cd "$WORK/nolib" && python3 -m zipfile -c "$WORK/nolib.apk" . )
cp "$WORK/armA.apk" "$WORK/armCopy.apk"

FAILURES=0

# $1 case name, $2 expected exit, $3 substring the output must contain,
# rest: the harness's arguments. Runs with whatever FAKE_* the caller exported.
expect() {
  local name=$1 want=$2 needle=$3
  shift 3
  local out status
  set +e
  out=$("$HARNESS" "$@" 2>&1)
  status=$?
  set -e
  if [ "$status" != "$want" ]; then
    echo "FAIL: $name exited $status, expected $want."
    printf '%s\n' "$out" | sed 's/^/      | /'
    FAILURES=$((FAILURES + 1))
    return 0
  fi
  if ! printf '%s' "$out" | grep -qF -- "$needle"; then
    echo "FAIL: $name exited $want but never said \"$needle\"."
    echo "      A guard that refuses without saying why is half a guard, and"
    echo "      one of this file's two real defects had exactly this shape."
    printf '%s\n' "$out" | sed 's/^/      | /'
    FAILURES=$((FAILURES + 1))
    return 0
  fi
  echo "ok: $name"
}

# 1. An APK with no library where the harness looks. Wrong ABI, or a stub
#    build that linked nothing.
expect "an APK carrying no libmatrix_crypto_ffi.so" 1 "carries no lib/$ABI/libmatrix_crypto_ffi.so" \
  "$WORK/nolib.apk" "$WORK/armA.apk" 1 "$WORK/out.tsv" none

# 2. Two APKs whose library is the same bytes: the arm swap that forgot to
#    rebuild.
expect "two APKs carrying the same library" 1 "both APKs carry the same" \
  "$WORK/armA.apk" "$WORK/armCopy.apk" 1 "$WORK/out.tsv" none

# 3. Different libraries on disk, same emission build at run time. This is the
#    case the on-disk digest cannot see, and the guard for it shipped unable to
#    fire.
FAKE_BUILD_armA=cafef00d FAKE_BUILD_armB=cafef00d \
  expect "both arms reporting one emission build" 1 "both arms reported the same emission build" \
    "$WORK/armA.apk" "$WORK/armB.apk" 1 "$WORK/out.tsv" none

# 4. A launch that printed no PROBE_EMIT_BUILD line. The diagnostic for this
#    was unreachable for two review cycles: `grep` matching nothing aborted the
#    assignment under `set -e`, so the run died at the right exit code with
#    nothing said.
FAKE_OMIT=EMIT_BUILD \
  expect "a launch with no PROBE_EMIT_BUILD line" 1 "printed no PROBE_EMIT_BUILD line" \
    "$WORK/armA.apk" "$WORK/armB.apk" 1 "$WORK/out.tsv" none

# 5. A launch whose callback never arrived. This one must NOT refuse: a lost
#    callback is the event this harness is kept to observe, so it has to be
#    recorded as a NONE row rather than aborting the run.
rm -f "$WORK/lost.tsv"
FAKE_OMIT=SIGNAL_MS,SIGNAL2_MS FAKE_BUILD_armA=aaaaaaaa FAKE_BUILD_armB=bbbbbbbb \
  expect "a launch whose callback never arrived" 0 "NONE" \
    "$WORK/armA.apk" "$WORK/armB.apk" 1 "$WORK/lost.tsv" none

if [ -f "$WORK/lost.tsv" ]; then
  LOST_ROWS=$(grep -c 'NONE' "$WORK/lost.tsv" || true)
  if [ "$LOST_ROWS" != "2" ]; then
    echo "FAIL: a lost callback wrote $LOST_ROWS rows carrying NONE, expected 2."
    echo "      The row is the record of the event; aborting instead of writing"
    echo "      it is how this harness stopped being able to see the thing it"
    echo "      is kept for."
    FAILURES=$((FAILURES + 1))
  else
    echo "ok: a lost callback is recorded rather than fatal"
  fi
fi

# 6. The accepting case. Without it, a "fix" that refuses everything passes
#    every check above.
rm -f "$WORK/happy.tsv"
FAKE_BUILD_armA=8e8c3246 FAKE_BUILD_armB=9c223b45 \
  expect "the real pair, which must be accepted" 0 "armA ran emission build 0.1.0+emit.8e8c3246" \
    "$WORK/armA.apk" "$WORK/armB.apk" 2 "$WORK/happy.tsv" none

if [ -f "$WORK/happy.tsv" ]; then
  ROWS=$(wc -l < "$WORK/happy.tsv" | tr -d ' ')
  if [ "$ROWS" != "4" ]; then
    echo "FAIL: the accepted run wrote $ROWS rows, expected 4 (2 rounds x 2 arms)."
    FAILURES=$((FAILURES + 1))
  else
    echo "ok: the accepted run wrote 4 rows"
  fi
fi

echo
if [ "$FAILURES" -ne 0 ]; then
  echo "FAIL: $FAILURES of the measurement harness's guards did not behave as documented."
  echo "      docs/measurements/2026-08-29-signal-delivery-latency.md describes"
  echo "      what each one refuses; one of them is now wrong."
  exit 1
fi

echo "PASS: measurement guards (5 refusals faced, 1 acceptance, exit status and"
echo "      diagnostic asserted on each)"
