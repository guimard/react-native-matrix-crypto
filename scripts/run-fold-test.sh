#!/usr/bin/env bash
set -euo pipefail

# Folds and unfolds a foldable device under the example app, and reports what
# survived.
#
#   Usage: scripts/run-fold-test.sh [apk] [cycles]
#
# WHY THIS EXISTS
#
# Folding a phone is a configuration change. A configuration change the
# activity has not declared destroys and recreates that activity while the
# process keeps running, so this library's Rust statics -- the crypto machine,
# the store handle, the installed observer -- outlive a JavaScript tree that
# is torn down and rebuilt around them. `signals.ts` uninstalls the native
# observer when the last listener unsubscribes and reinstalls it when the
# first one subscribes again, and `useEffect(() => onCryptoSignal(h), [])` is
# what a React component writes, so an unmount/remount pair drives exactly
# that transition. A person folds their phone dozens of times a day and
# nothing had ever tested it.
#
# THE FAILURE THIS SCRIPT IS BUILT NOT TO HAVE
#
# A fold that reaches a stopped activity changes nothing, because Android
# defers configuration changes for an activity it has stopped until that
# activity comes back. A phone sitting on a desk behind its lock screen has a
# stopped activity. So the first draft of this test read silence and the
# silence was indistinguishable from "the fold was harmless" -- the shape this
# repository keeps rediscovering, an absence of bad news read as good news.
# It was watched happening: with the lock screen up, a *density* change, which
# this activity does not declare and therefore cannot survive, also produced
# no recreation and no log line at all.
#
# Two things follow, and both are in the code below rather than in a comment
# telling an operator to be careful.
#
#   1. The activity must be RESUMED before and after every change, asserted
#      each time, and the run aborts if it is not. `-PshowWhenLocked=true` is
#      what makes that reachable on a locked phone; see the example app's
#      build.gradle.
#   2. A positive control runs first: a change this activity *cannot* survive,
#      which must be seen to recreate it. If the control does not recreate,
#      nothing this script reports afterwards means anything, and it says so
#      and stops. A detector nobody has watched fire is decoration.
#
# WHAT IS OBSERVED, AND FROM WHERE
#
# Three independent sources, because no one of them is enough:
#
#   * `dumpsys activity activities` -- the ActivityRecord's identity hash. A
#     recreation gives a new one. This is the system's view and needs nothing
#     from the app.
#   * the `-b events` log -- `wm_on_create_called` / `wm_on_destroy_called`
#     with that same identity. A second, independent witness to the same
#     event, from a different subsystem.
#   * the app's own `FOLD_` lines (`src/FoldWatch.tsx`) -- which say what the
#     library still had afterwards, which is the actual question. The two
#     above can only say whether the activity was rebuilt.
#
# `pidof` is read every time as well: every claim here is about a process that
# survived, so a run in which the process restarted is a different experiment
# and is reported as one.

PACKAGE=com.exampleapp
ACTIVITY=.MainActivity

APK=${1:-packages/example-app/android/app/build/outputs/apk/release/app-release.apk}
CYCLES=${2:-5}

# How long one launch gets to reach a crypto machine. Matches
# run-probe-on-emulator.sh: the probe creates a real store and does a full
# Megolm round trip, and slow is normal while silent is not.
LAUNCH_TIMEOUT_SECONDS=${LAUNCH_TIMEOUT_SECONDS:-240}

# How long to let a configuration change settle before reading anything. A
# recreation is not instantaneous and neither is the remount that follows it.
SETTLE_SECONDS=${SETTLE_SECONDS:-8}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

command -v adb >/dev/null 2>&1 || fail "adb is not on PATH."
[ -s "$APK" ] || fail "no APK at '$APK'. Build one first:
      (cd packages/example-app/android && ./gradlew :app:assembleRelease \\
         -PreactNativeArchitectures=arm64-v8a -PshowWhenLocked=true)"

# More than one target attached and no ANDROID_SERIAL is the mistake that
# silently measures the wrong machine. adb itself refuses an ambiguous
# command, but only for the commands that go through it -- so refuse here,
# once, with the reason, rather than partway through a run.
if [ -z "${ANDROID_SERIAL:-}" ]; then
  ATTACHED=$(adb devices | awk 'NR>1 && $2=="device"' | wc -l | tr -d ' ')
  [ "$ATTACHED" = "1" ] || fail "$ATTACHED targets are attached and ANDROID_SERIAL is not set.
      Name the one to test: ANDROID_SERIAL=<serial> $0 ...
      A measurement attributed to hardware that ran on an emulator is worse
      than no measurement."
fi

adb wait-for-device

MODEL=$(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r')
SDK=$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
ABI=$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')
echo "device: $MODEL (API $SDK, $ABI)"

STATES=$(adb shell cmd device_state print-states-simple 2>/dev/null | tr -d '\r')
case "$STATES" in
  *OPENED*) : ;;
  *) fail "this device reports no OPENED state (\`cmd device_state print-states-simple\`
      said '$STATES'). This test needs a foldable." ;;
esac
echo "fold states: $STATES"

# ---------------------------------------------------------------------------
# Readers.
# ---------------------------------------------------------------------------

# The ActivityRecord identity hash, or empty. `head -1` because the activity
# appears in several sections of the dump.
record_id() {
  adb shell dumpsys activity activities 2>/dev/null | tr -d '\r' \
    | grep -oE "ActivityRecord\{[0-9a-f]+ u0 $PACKAGE/$ACTIVITY" \
    | head -1 | sed -E 's/.*\{([0-9a-f]+) .*/\1/'
}

# RESUMED, STOPPED, PAUSED, or empty when the activity is gone.
activity_state() {
  adb shell dumpsys activity activities 2>/dev/null | tr -d '\r' \
    | grep -A20 "Hist  #0: ActivityRecord{$(record_id) " \
    | grep -oE 'state=[A-Z]+' | head -1 | cut -d= -f2
}

app_pid() { adb shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r'; }

fold_lines() {
  adb logcat -d -v raw ReactNativeJS:V '*:S' 2>/dev/null | tr -d '\r' | grep -E '^FOLD_' || true
}

# A real phone is far chattier than an emulator, so the log window is short.
# Every reader here is called immediately after the event it is reading.
lifecycle_lines() {
  adb logcat -d -b events 2>/dev/null | tr -d '\r' \
    | grep -E 'wm_on_(create|destroy)_called' | grep -F "$PACKAGE" || true
}

require_resumed() {
  local st
  st=$(activity_state)
  [ "$st" = "RESUMED" ] || fail "the activity is $st, not RESUMED, $1.
      Android defers configuration changes for an activity it has stopped, so
      a fold delivered now would change nothing and this run would report that
      as 'the fold was harmless'. Build with -PshowWhenLocked=true, or unlock
      the device."
}

# ---------------------------------------------------------------------------
# Launch.
# ---------------------------------------------------------------------------

adb uninstall "$PACKAGE" >/dev/null 2>&1 || true
echo "installing $APK"
adb install "$APK" >/dev/null

adb shell svc power stayon true >/dev/null 2>&1 || true
adb shell cmd device_state state reset >/dev/null 2>&1 || true
adb logcat -c >/dev/null 2>&1 || true
adb shell am start -n "$PACKAGE/$ACTIVITY" >/dev/null
adb shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1 || true

echo "waiting for the app to reach a crypto machine"
DEADLINE=$(( $(date +%s) + LAUNCH_TIMEOUT_SECONDS ))
READY=""
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  READY=$(fold_lines | grep -E '^FOLD_MACHINE ok$' || true)
  [ -n "$READY" ] && break
  sleep 3
done
[ -n "$READY" ] || fail "the app never printed 'FOLD_MACHINE ok' within ${LAUNCH_TIMEOUT_SECONDS}s.
      This is NOT a pass. Either the app never started, or it never built a
      crypto machine, and there is nothing to ask a question about."

BASE_PID=$(app_pid)
BASE_KEYS=$(fold_lines | grep -E '^FOLD_KEYS ' | head -1 | awk '{print $2}')
echo "pid $BASE_PID, identity keys fingerprint $BASE_KEYS"
require_resumed "before the control"

# ---------------------------------------------------------------------------
# The positive control: a change this activity cannot survive.
#
# `android:configChanges` on MainActivity does not list `density`, so a density
# change must destroy and recreate it. If that is not observed, this script's
# detector cannot fire and nothing below would mean anything.
# ---------------------------------------------------------------------------

BASE_DENSITY=$(adb shell wm density 2>/dev/null | tr -d '\r' | sed -n 's/.*density: //p' | head -1)
[ -n "$BASE_DENSITY" ] || fail "could not read the display density."
CONTROL_DENSITY=$(( BASE_DENSITY + 40 ))

echo
echo "== control: density $BASE_DENSITY -> $CONTROL_DENSITY (undeclared, must recreate) =="
BEFORE_ID=$(record_id)
adb logcat -c >/dev/null 2>&1 || true
adb shell wm density "$CONTROL_DENSITY" >/dev/null 2>&1
sleep "$SETTLE_SECONDS"
AFTER_ID=$(record_id)
CONTROL_LIFECYCLE=$(lifecycle_lines)
adb shell wm density reset >/dev/null 2>&1 || true
sleep "$SETTLE_SECONDS"

echo "  ActivityRecord $BEFORE_ID -> $AFTER_ID"
[ -z "$CONTROL_LIFECYCLE" ] || printf '  %s\n' "$CONTROL_LIFECYCLE"
if [ "$BEFORE_ID" = "$AFTER_ID" ]; then
  fail "the control did not recreate the activity.
      A density change is not in MainActivity's android:configChanges, so it
      must. Since it did not, this script cannot detect a recreation, and a
      fold that produced no recreation below would be unreadable -- it could
      equally mean the fold was harmless or that nothing was ever delivered.
      The usual cause is an activity that is not actually RESUMED."
fi
echo "  control recreated the activity, so a recreation is detectable"

# ---------------------------------------------------------------------------
# The folds.
# ---------------------------------------------------------------------------

CLOSED=$(adb shell cmd device_state print-states 2>/dev/null | tr -d '\r' \
  | sed -n "s/.*identifier=\([0-9]*\), name='CLOSED'.*/\1/p" | head -1)
OPENED=$(adb shell cmd device_state print-states 2>/dev/null | tr -d '\r' \
  | sed -n "s/.*identifier=\([0-9]*\), name='OPENED'.*/\1/p" | head -1)
[ -n "$CLOSED" ] && [ -n "$OPENED" ] \
  || fail "could not read the CLOSED and OPENED state identifiers."

echo
printf '%-8s %-9s %-11s %-11s %-9s %-8s %s\n' \
  step state record-before record-after recreated pid folds
RECREATIONS=0
for c in $(seq 1 "$CYCLES"); do
  for target in "$OPENED" "$CLOSED"; do
    require_resumed "before cycle $c"
    BEFORE_ID=$(record_id)
    adb logcat -c >/dev/null 2>&1 || true
    adb shell cmd device_state state "$target" >/dev/null 2>&1
    sleep "$SETTLE_SECONDS"
    AFTER_ID=$(record_id)
    NEW_FOLD=$(fold_lines | tr '\n' ';')
    RECREATED=no
    if [ "$BEFORE_ID" != "$AFTER_ID" ]; then
      RECREATED=yes
      RECREATIONS=$(( RECREATIONS + 1 ))
    fi
    printf '%-8s %-9s %-11s %-11s %-9s %-8s %s\n' \
      "$c" "$target" "$BEFORE_ID" "$AFTER_ID" "$RECREATED" "$(app_pid)" "${NEW_FOLD:-none}"
  done
done

adb shell cmd device_state state reset >/dev/null 2>&1 || true
sleep "$SETTLE_SECONDS"

# ---------------------------------------------------------------------------
# What the app says it still had.
# ---------------------------------------------------------------------------

echo
echo "--- FOLD_ output ---"
fold_lines
echo "--- end FOLD_ output ---"
echo

END_PID=$(app_pid)
[ "$END_PID" = "$BASE_PID" ] || fail "the process restarted during the run ($BASE_PID -> $END_PID).
      Everything above is about a process that survived a configuration
      change. A run in which it did not is a different experiment and its
      rows cannot be read as this one's."

MOUNTS=$(fold_lines | grep -c '^FOLD_MOUNT ' || true)
UNMOUNTS=$(fold_lines | grep -c '^FOLD_UNMOUNT ' || true)
KEYS=$(fold_lines | grep '^FOLD_KEYS ' | awk '{print $2}' | sort -u | tr '\n' ' ')
BAD_MACHINE=$(fold_lines | grep '^FOLD_MACHINE err' || true)
BAD_STORE=$(fold_lines | grep '^FOLD_STORE err' || true)
MAX_SUBS=$(fold_lines | grep -oE 'subs=[0-9]+' | cut -d= -f2 | sort -n | tail -1)

echo "activity recreations over $CYCLES fold/unfold cycles: $RECREATIONS"
echo "FoldWatch mounts: $MOUNTS, unmounts: $UNMOUNTS, peak subscriptions: ${MAX_SUBS:-0}"
echo "identity key fingerprints seen: $KEYS"
[ -z "$BAD_MACHINE" ] || echo "machine errors: $BAD_MACHINE"
[ -z "$BAD_STORE" ] || echo "store errors:   $BAD_STORE"

# The invariants, asserted rather than left for a reader of the table.
[ -z "$BAD_MACHINE" ] || fail "the crypto machine stopped answering during the run."
[ -z "$BAD_STORE" ] || fail "the crypto store stopped answering during the run."
[ "$(printf '%s' "$KEYS" | wc -w | tr -d ' ')" = "1" ] \
  || fail "the live machine reported more than one identity across the run ($KEYS).
      Something re-initialised it, which is the thing this test exists to find."
[ "${MAX_SUBS:-0}" -le 1 ] \
  || fail "this app held ${MAX_SUBS} simultaneous onCryptoSignal subscriptions.
      It subscribes once per mounted FoldWatch, so more than one at a time
      means a mount happened without the previous cleanup running -- a leaked
      listener, and with it a second native observer registration."

echo
echo "PASS: the process, its crypto machine and its store survived $CYCLES fold/unfold cycles on $MODEL (API $SDK)."
