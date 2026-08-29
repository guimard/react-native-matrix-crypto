#!/usr/bin/env bash
set -euo pipefail

# Faces four of the thirteen refusals in scripts/measure-signal-latency.sh
# with the case each exists to reject, plus the accepting case with the run it
# must accept, and asserts the accepted row field by field.
#
# WHICH FOUR, AND WHY NOT THIRTEEN
#
# The four are the ones that have actually broken: the on-disk digest
# comparison, the run-time emission-build comparison, the
# missing-PROBE_EMIT_BUILD diagnostic, and the "carries no .so" guard -- that
# last one in both argument positions, because the gate used to face it only in
# position A and the B-position copy could be deleted outright with everything
# green. The nine not faced are argument and environment checks: usage, adb or
# unzip absent, a missing APK file, two APKs with the same basename, no device,
# and an unknown load name. They fail before anything is measured, they have
# never been wrong, and none of them can produce a bad measurement -- only no
# measurement. If one of them ever breaks, it belongs here the same day.
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
# WHAT IT ASSERTS: THREE LAYERS, AND EACH ONE EXISTS BECAUSE THE OTHERS MISSED
# SOMETHING
#
# 1. Exit status. The trap defect exited 127 with the right message already
#    printed, so the message alone would have passed it.
# 2. A distinctive substring of the diagnostic. The `set -e` defect exits 1 --
#    the correct status -- and says nothing at all, so the status alone would
#    have passed it.
# 3. The accepted run's rows, field by field, against values chosen to be all
#    different. This layer was missing for a whole review cycle, and its
#    absence is the fourth instance of the pattern this file exists to stop:
#    the gate asserted that four rows existed and never what was in them, so
#    changing one token to read `PROBE_SIGNAL2_MS` where `PROBE_SIGNAL_MS` was
#    meant -- publishing the warm second signal under the first signal's column,
#    which is the exact contrast B2's conclusion rests on -- kept every guard
#    firing, every refusal refusing, four rows written, shellcheck clean and
#    this gate green. So could transposing two columns, or dropping one. The
#    proof needed no experiment: this file was byte-identical at the commit
#    that introduced it and at the tip of the round after, passing at both,
#    while the harness's row went from eight fields to nine with the new column
#    inserted in the middle.
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

# The four numbers the stub reports and the harness sorts into four columns.
# All different, on purpose: with the old 2/1/1/1 a transposition among three
# of them produced a row identical to the correct one.
S_MS=41
S_NTH=42
S2_MS=43
P_MS=44
export FAKE_SIGNAL_MS=$S_MS FAKE_SIGNAL_NTH=$S_NTH
export FAKE_SIGNAL2_MS=$S2_MS FAKE_PROMISE_MS=$P_MS

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

# $1 label, $2 file, $3 row number, $4 the row that must be there, verbatim.
#
# Compares the whole tab-separated row rather than a field or a count. A count
# cannot see a value in the wrong column, and a single field cannot see a
# column that has moved; the row can see both, and it is what a reader of the
# published samples actually consumes.
expect_row() {
  local name=$1 file=$2 n=$3 want=$4 got fields
  if [ ! -f "$file" ]; then
    echo "FAIL: $name -- $file was never written."
    FAILURES=$((FAILURES + 1))
    return 0
  fi
  got=$(sed -n "${n}p" "$file")
  if [ "$got" != "$want" ]; then
    fields=$(printf '%s' "$got" | awk -F'\t' '{print NF}')
    echo "FAIL: $name -- row $n is not the row this harness is documented to write."
    echo "      want ($(printf '%s' "$want" | awk -F'\t' '{print NF}') fields): $want"
    echo "      got  (${fields:-0} fields): $got"
    echo "      A value in the wrong column publishes one measurement under"
    echo "      another one's name, with every guard still firing."
    FAILURES=$((FAILURES + 1))
    return 0
  fi
  echo "ok: $name"
}

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

# 4b. The same guard in the other argument position. It used to be faced only
#     in position A, so its position-B copy could be deleted outright with this
#     gate green -- which made the automated check weaker on this one point
#     than the manual pass it replaced.
expect "an APK with no library in the B position" 1 "carries no lib/$ABI/libmatrix_crypto_ffi.so" \
  "$WORK/armA.apk" "$WORK/nolib.apk" 1 "$WORK/out.tsv" none

# 5. A launch whose first callback never arrived. This one must NOT refuse: a
#    lost callback is the event this harness is kept to observe, so it has to
#    be recorded as a NONE row rather than aborting the run.
#
#    Only PROBE_SIGNAL_MS is omitted, not the second signal with it. Omitting
#    both let the `sig` extraction read either line and still produce NONE,
#    which is how a `sig` that reads `PROBE_SIGNAL2_MS` went unnoticed.
rm -f "$WORK/lost.tsv"
FAKE_OMIT=SIGNAL_MS FAKE_BUILD_armA=aaaaaaaa FAKE_BUILD_armB=bbbbbbbb \
  expect "a launch whose first callback never arrived" 0 "NONE" \
    "$WORK/armA.apk" "$WORK/armB.apk" 1 "$WORK/lost.tsv" none

expect_row "the lost-callback row records NONE in the first-signal column only" \
  "$WORK/lost.tsv" 1 \
  "$(printf 'armA\t1\tnone\tNONE\t%s\t%s\t%s\t0.1.0+emit.aaaaaaaa\tPROBE_SUMMARY 12/12' \
       "$S_NTH" "$S2_MS" "$P_MS")"

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

# The rows themselves. Both arms, both rounds: the arms alternate, so this also
# pins the interleaving the whole measurement design rests on.
happy_row() {
  printf '%s\t%s\tnone\t%s\t%s\t%s\t%s\t0.1.0+emit.%s\tPROBE_SUMMARY 12/12' \
    "$1" "$2" "$S_MS" "$S_NTH" "$S2_MS" "$P_MS" "$3"
}
expect_row "the accepted run's row 1 (armA, round 1)" "$WORK/happy.tsv" 1 \
  "$(happy_row armA 1 8e8c3246)"
expect_row "the accepted run's row 2 (armB, round 1)" "$WORK/happy.tsv" 2 \
  "$(happy_row armB 1 9c223b45)"
expect_row "the accepted run's row 3 (armA, round 2)" "$WORK/happy.tsv" 3 \
  "$(happy_row armA 2 8e8c3246)"
expect_row "the accepted run's row 4 (armB, round 2)" "$WORK/happy.tsv" 4 \
  "$(happy_row armB 2 9c223b45)"

echo
if [ "$FAILURES" -ne 0 ]; then
  echo "FAIL: $FAILURES of the measurement harness's guards did not behave as documented."
  echo "      docs/measurements/2026-08-29-signal-delivery-latency.md describes"
  echo "      what each one refuses; one of them is now wrong."
  exit 1
fi

echo "PASS: measurement guards -- 4 of the harness's 13 refusals faced (the four"
echo "      that have broken, one of them in both argument positions), plus the"
echo "      accepting case, with exit status, diagnostic and every field of"
echo "      every written row asserted"
