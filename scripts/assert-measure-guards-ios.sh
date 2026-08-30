#!/usr/bin/env bash
set -euo pipefail

# Faces the refusals in scripts/measure-signal-latency-ios.sh with the case
# each exists to reject, plus the accepting case with the run it must accept,
# and asserts the accepted rows field by field.
#
# WHY THIS EXISTS ON THE DAY THE HARNESS DOES, RATHER THAN A REVIEW LATER
#
# Its Android sibling, scripts/assert-measure-guards.sh, does not exist
# because someone wanted more tests. It exists because two of that harness's
# guards shipped unable to fire, one of them through two review cycles, and
# both were found by running the case rather than by reading. `shellcheck`
# passes on both defects. The manual pass that preceded this gate was
# published as a named limitation and then found to have missed a case the
# next reader thought of straight away.
#
# So the iOS harness starts with its gate rather than earning one. The
# argument for it is written out in the Android file and is not repeated
# here; what follows is what this one faces, and the one case that is new.
#
# THE CASE THAT IS NEW, AND IT IS THE MOST IMPORTANT ONE HERE
#
# A booted simulator keeps no log archive, so there is no `logcat -d` to read
# after the fact and the only route is a live `log stream`. A stream that
# attached a moment too late loses the `PROBE_SIGNAL_MS` line, and the
# harness records a missing first signal as `NONE`, which is the finding this
# whole family of scripts is kept to observe. A capture race would therefore
# manufacture a lost callback out of nothing.
#
# The harness closes that by refusing to launch until an `installd` line
# naming the bundle identifier, produced by its own `simctl uninstall`, is in
# the capture. Two cases below hold that closed:
#
#   * a stream that never becomes live must REFUSE, not record NONE, and it
#     must write no row while doing it, and
#   * the beacon must not be satisfied by `log stream`'s own header, which
#     echoes the predicate back and therefore contains the word "installd".
#
# The second is not hypothetical. The first draft of this gate's own
# readiness probe, written while the mechanism was being explored, matched
# `installd` anywhere in the capture and reported the stream live off that
# header, having examined no log line at all. The stub prints that header
# verbatim so the shipped pattern has to survive it.
#
# WHICH SEVEN, OUT OF TWENTY-TWO
#
# The harness has twenty-two refusals. The seven faced here are every one that
# can produce a WRONG measurement rather than no measurement: a bundle with no
# executable, a bundle with no embedded JavaScript, two bundles that are one
# file copied twice, two arms reporting one emission build, a launch that named
# no emission build, and a stream that was never shown to be live. Two of the
# seven are faced in both argument positions, because the Android gate faced
# its equivalent only in position A and the position-B copy could then be
# deleted outright with everything green.
#
# The fifteen not faced are argument and environment checks: usage, `xcrun` or
# `plutil` absent, a missing bundle, two bundles sharing a basename or
# disagreeing on their identifier, a bundle whose Info.plist names neither an
# executable nor an identifier, no simulator, a simulator that will not boot,
# and an unknown load name. Each of them fails before anything is launched, and
# none can produce a bad row, only no row. That is the reason and not an
# excuse: the day one of them is wrong it belongs here.
#
# WHAT IS FAKED, AND WHAT IS NOT
#
# `xcrun` is scripts/testdata/fake-xcrun, which supplies the simulator and
# the bytes `log stream` produces and nothing else. The app bundles are real
# directories with real `Info.plist` files, read by the real `plutil`.
# Everything under test is the shipped script, unmodified: the readiness
# proof, the digest comparison, the extraction, the `LAST_BUILD` return, the
# arm comparison, and the row written. No simulator, no Xcode, no Rust.
#
# The seam this cannot reach is the one from Rust's `EMIT_BUILD` const to the
# `PROBE_EMIT_BUILD` line. That is closed from the other end by
# `matrix-crypto-core`'s `the_build_suffix_is_derived_rather_than_constant`.

HARNESS=scripts/measure-signal-latency-ios.sh
STUB_DIR=scripts/testdata
BUNDLE_ID=org.example.fake

# The four numbers the stub reports and the harness sorts into four columns.
# All different, on purpose: with values that repeat, a transposition among
# them produces a row identical to the correct one.
S_MS=41
S_NTH=42
S2_MS=43
P_MS=44
export FAKE_SIGNAL_MS=$S_MS FAKE_SIGNAL_NTH=$S_NTH
export FAKE_SIGNAL2_MS=$S2_MS FAKE_PROMISE_MS=$P_MS

[ -x "$HARNESS" ] || { echo "FAIL: $HARNESS is missing or not executable."; exit 1; }
[ -x "$STUB_DIR/fake-xcrun" ] || { echo "FAIL: $STUB_DIR/fake-xcrun is missing or not executable."; exit 1; }
command -v plutil >/dev/null 2>&1 || { echo "FAIL: plutil is needed to read the fixture bundles."; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# `xcrun` must resolve to the stub and to nothing else, including on a
# machine with Xcode installed.
mkdir -p "$WORK/bin"
cp "$STUB_DIR/fake-xcrun" "$WORK/bin/xcrun"
chmod +x "$WORK/bin/xcrun"
export PATH="$WORK/bin:$PATH"
export FAKE_STATE="$WORK/state"
export FAKE_UDID=00000000-0000-0000-0000-000000000000
export FAKE_BUNDLE_ID=$BUNDLE_ID
export SIM_UDID=$FAKE_UDID
# The harness waits this long after each summary for a late callback. Real
# runs want it; this one would only be slower for it.
export LATE_GRACE_SECONDS=0
# Three tries at one second each, so the "never became live" case costs three
# seconds rather than twenty.
export STREAM_READY_TRIES=3

# ---------------------------------------------------------------- fixtures
# Real directories with real Info.plist files. `armA` and `armB` differ in
# the executable the harness digests; `armCopy` is a byte-for-byte copy of
# `armA`; `noexec` names an executable it does not contain; `nobundle` is
# what a Debug build looks like, with no embedded JavaScript.
make_app() {
  local dir=$1 exec_bytes=$2 with_exec=$3 with_bundle=$4
  mkdir -p "$dir"
  cat > "$dir/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>ExampleApp</string>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
</dict>
</plist>
PLIST
  [ "$with_exec" = yes ] && printf '%s' "$exec_bytes" > "$dir/ExampleApp"
  [ "$with_bundle" = yes ] && printf 'jsbundle' > "$dir/main.jsbundle"
  return 0
}

make_app "$WORK/armA.app" MACHO-A yes yes
make_app "$WORK/armB.app" MACHO-B yes yes
make_app "$WORK/noexec.app" '' no yes
make_app "$WORK/nobundle.app" MACHO-C yes no
rm -rf "$WORK/armCopy.app"
cp -R "$WORK/armA.app" "$WORK/armCopy.app"

FAILURES=0

# $1 label, $2 file, $3 row number, $4 the row that must be there, verbatim.
#
# Compares the whole tab-separated row rather than a field or a count. A
# count cannot see a value in the wrong column, and a single field cannot see
# a column that has moved; the row sees both, and it is what a reader of the
# published samples actually consumes.
expect_row() {
  local name=$1 file=$2 n=$3 want=$4 got fields
  if [ ! -f "$file" ]; then
    echo "FAIL: $name."
    echo "      $file was never written."
    FAILURES=$((FAILURES + 1))
    return 0
  fi
  got=$(sed -n "${n}p" "$file")
  if [ "$got" != "$want" ]; then
    fields=$(printf '%s' "$got" | awk -F'\t' '{print NF}')
    echo "FAIL: $name."
    echo "      Row $n is not the row this harness is documented to write."
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
# rest: the harness's arguments. Runs with whatever FAKE_* the caller
# exported.
expect() {
  local name=$1 want=$2 needle=$3
  shift 3
  local out status
  rm -rf "$FAKE_STATE"
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
    echo "      A guard that refuses without saying why is half a guard."
    printf '%s\n' "$out" | sed 's/^/      | /'
    FAILURES=$((FAILURES + 1))
    return 0
  fi
  echo "ok: $name"
}

# 1. A bundle whose Info.plist names an executable it does not contain.
expect "a bundle carrying no executable" 1 "carries no executable named" \
  "$WORK/noexec.app" "$WORK/armA.app" 1 "$WORK/out.tsv" none

# 1b. The same guard in the other argument position. The Android gate faced
#     its equivalent only in position A, so the position-B copy could be
#     deleted outright with everything green.
expect "a bundle carrying no executable, in the B position" 1 "carries no executable named" \
  "$WORK/armA.app" "$WORK/noexec.app" 1 "$WORK/out.tsv" none

# 2. Two bundles whose executable is the same bytes: the arm swap that never
#    rebuilt. Two Mach-O files built from identical source still differ, so
#    identical bytes mean one file was copied twice.
expect "two bundles carrying the same executable" 1 "both bundles carry the same" \
  "$WORK/armA.app" "$WORK/armCopy.app" 1 "$WORK/out.tsv" none

# 3. A Debug bundle, with no embedded JavaScript. It would fetch its bundle
#    from Metro at launch, which is a different artifact from the one this
#    harness reports on, measured silently on a machine where Metro happens
#    to be up.
#
#    Faced in both argument positions, for the reason 1b gives.
expect "a bundle with no main.jsbundle" 1 "carries no main.jsbundle" \
  "$WORK/armA.app" "$WORK/nobundle.app" 1 "$WORK/out.tsv" none
expect "a bundle with no main.jsbundle, in the A position" 1 "carries no main.jsbundle" \
  "$WORK/nobundle.app" "$WORK/armA.app" 1 "$WORK/out.tsv" none

# 4. Different executables on disk, same emission build at run time. This is
#    the case the on-disk digest cannot see, and on iOS it can see less than
#    on Android: the Rust is linked into the executable rather than sitting
#    beside it as its own file.
FAKE_BUILD_armA=cafef00d FAKE_BUILD_armB=cafef00d \
  expect "both arms reporting one emission build" 1 "both arms reported the same emission build" \
    "$WORK/armA.app" "$WORK/armB.app" 1 "$WORK/out.tsv" none

# 5. A launch that printed no PROBE_EMIT_BUILD line.
FAKE_OMIT=EMIT_BUILD \
  expect "a launch with no PROBE_EMIT_BUILD line" 1 "printed no PROBE_EMIT_BUILD line" \
    "$WORK/armA.app" "$WORK/armB.app" 1 "$WORK/out.tsv" none

# 6. THE IOS-SPECIFIC ONE. A log stream that never proves itself live must
#    refuse. It must not launch into an unproven stream and record the
#    missing first signal as a lost callback.
#
#    This case also holds the beacon pattern to the log rather than to the
#    query: the stub still prints `log stream`'s real header, which echoes
#    the predicate and so contains the word "installd". A readiness check
#    that matched that header would see a live stream here and this case
#    would pass by launching, which is the opposite of what it asserts.
FAKE_NO_BEACON=1 \
  expect "a log stream that never proves itself live" 1 "was never shown to be live" \
    "$WORK/armA.app" "$WORK/armB.app" 1 "$WORK/out.tsv" none

# 6b. And it must refuse without writing a row. A refusal that still
#     published a NONE would put the manufactured finding in the samples.
if [ -s "$WORK/out.tsv" ]; then
  echo "FAIL: the unproven-stream case wrote a row:"
  sed 's/^/      | /' "$WORK/out.tsv"
  echo "      That row is a lost callback this harness invented."
  FAILURES=$((FAILURES + 1))
else
  echo "ok: the unproven-stream case wrote no row"
fi

# 7. A launch whose first callback never arrived. This one must NOT refuse: a
#    lost callback is the event this harness is kept to observe, so it has to
#    be recorded as a NONE row rather than aborting the run.
#
#    Only PROBE_SIGNAL_MS is omitted, not the second signal with it. Omitting
#    both would let the first-signal extraction read either line and still
#    produce NONE, which is how a `sig` that reads `PROBE_SIGNAL2_MS` went
#    unnoticed on the Android side.
rm -f "$WORK/lost.tsv"
FAKE_OMIT=SIGNAL_MS FAKE_BUILD_armA=aaaaaaaa FAKE_BUILD_armB=bbbbbbbb \
  expect "a launch whose first callback never arrived" 0 "NONE" \
    "$WORK/armA.app" "$WORK/armB.app" 1 "$WORK/lost.tsv" none

expect_row "the lost-callback row records NONE in the first-signal column only" \
  "$WORK/lost.tsv" 1 \
  "$(printf 'armA\t1\tnone\tNONE\t%s\t%s\t%s\t0.1.0+emit.aaaaaaaa\tPROBE_SUMMARY 12/12' \
       "$S_NTH" "$S2_MS" "$P_MS")"

# 8. The accepting case. Without it, a "fix" that refuses everything passes
#    every check above.
rm -f "$WORK/happy.tsv"
FAKE_BUILD_armA=8e8c3246 FAKE_BUILD_armB=9c223b45 \
  expect "the real pair, which must be accepted" 0 "armA ran emission build 0.1.0+emit.8e8c3246" \
    "$WORK/armA.app" "$WORK/armB.app" 2 "$WORK/happy.tsv" none

if [ -f "$WORK/happy.tsv" ]; then
  ROWS=$(wc -l < "$WORK/happy.tsv" | tr -d ' ')
  if [ "$ROWS" != "4" ]; then
    echo "FAIL: the accepted run wrote $ROWS rows, expected 4 (2 rounds x 2 arms)."
    FAILURES=$((FAILURES + 1))
  else
    echo "ok: the accepted run wrote 4 rows"
  fi
fi

# The rows themselves. Both arms, both rounds: the arms alternate, so this
# also pins the interleaving the whole measurement design rests on.
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
  echo "FAIL: $FAILURES of the iOS measurement harness's guards did not behave"
  echo "      as documented. The measurement record kept outside this"
  echo "      repository describes what each one refuses; one of them is now"
  echo "      wrong."
  exit 1
fi

echo "PASS: iOS measurement guards. 7 of the harness's 22 refusals faced with"
echo "      the case each rejects, two of them in both argument positions, plus"
echo "      the two runs it must accept, with exit status, diagnostic and every"
echo "      field of every written row asserted"
