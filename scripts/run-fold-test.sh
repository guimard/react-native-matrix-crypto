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

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

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

# `print-states`, not `print-states-simple`: the simple form prints bare
# identifiers (`0,1,2,3,4,5` on a Pixel 10 Pro Fold), so a name test against it
# can never match and this guard refused a real foldable the first time it ran.
STATES=$(adb shell cmd device_state print-states 2>/dev/null | tr -d '\r' \
  | grep -oE "name='[A-Z_]+'" | cut -d"'" -f2 | tr '\n' ' ')
case " $STATES " in
  *" OPENED "*) : ;;
  *) fail "this device reports no OPENED state (it offers: $STATES).
      This test needs a foldable." ;;
esac
echo "fold states: $STATES"

# ---------------------------------------------------------------------------
# Readers.
# ---------------------------------------------------------------------------

# EVERY READER BELOW MUST TOLERATE MATCHING NOTHING, AND THAT IS NOT A STYLE
# POINT
#
# `grep` exits 1 when it matches nothing, `pipefail` promotes that to the
# pipeline, and `set -e` then aborts the command substitution -- so a reader
# without a fallback kills the run at the assignment, before the diagnostic
# that was about to explain it. The first run of this script did exactly that:
# `activity_state` found no `state=` line, the script exited 1 with no output
# after "identity keys fingerprint", and the `require_resumed` message it had
# just earned never printed. `scripts/measure-signal-latency.sh` carries the
# same warning over its own extraction block, for the same reason.

# The activity dump, read once per call, so a reader cannot fail on a
# transport hiccup and be mistaken for one reporting an absence.
activities_dump() {
  adb shell dumpsys activity activities 2>/dev/null | tr -d '\r' || true
}

# The ActivityRecord identity hash, or empty. `head -1` because the activity
# appears in several sections of the dump.
record_id() {
  activities_dump \
    | grep -oE "ActivityRecord\{[0-9a-f]+ u0 $PACKAGE/$ACTIVITY" \
    | head -1 | sed -E 's/.*\{([0-9a-f]+) .*/\1/' || true
}

# RESUMED, STOPPED, PAUSED, or empty when the activity is gone. The `state=`
# line sits a little below the line that names the record, and the exact
# offset is not something to depend on, so this takes the first `state=` after
# the first mention of the activity.
activity_state() {
  activities_dump \
    | sed -n "/ActivityRecord{[0-9a-f]* u0 $PACKAGE\/$ACTIVITY/,\$p" \
    | grep -oE 'state=[A-Z]+' | head -1 | cut -d= -f2 || true
}

app_pid() { adb shell pidof "$PACKAGE" 2>/dev/null | tr -d '\r'; }

# ONLY the events buffer, which is the one `recreations_since_clear` counts.
#
# `adb logcat -c` clears the main buffer and leaves `-b events` untouched, so
# a run that cleared with one and counted with the other counted every launch
# since boot. That is what the first run to reach the fold cycles did: it
# reported 8 recreations per half-cycle, the same 8 every time, while the
# app's own lines said nothing had remounted at all. Two readers disagreeing
# is the only reason it was caught.
#
# The main buffer is deliberately NOT cleared here: the app's FOLD_ lines are
# the cumulative record the assertions at the end read, and clearing it each
# cycle emptied that record so those assertions had nothing to examine. New
# lines per cycle are found by length instead -- see `new_fold_lines`.
clear_events() {
  adb logcat -c -b events >/dev/null 2>&1 || true
}

# The FOLD_ lines that appeared since the last call. By length rather than by
# content, so two identical mounts are two entries and not one.
new_fold_lines() {
  local prev=0
  if [ -f "$WORK/fold.log" ]; then
    prev=$(wc -l < "$WORK/fold.log" | tr -d ' ')
  fi
  fold_lines > "$WORK/fold.log"
  tail -n "+$(( prev + 1 ))" "$WORK/fold.log"
}

fold_lines() {
  adb logcat -d -v raw ReactNativeJS:V '*:S' 2>/dev/null | tr -d '\r' | grep -E '^FOLD_' || true
}

# A real phone is far chattier than an emulator, so the log window is short.
# Every reader here is called immediately after the event it is reading.
lifecycle_lines() {
  adb logcat -d -b events 2>/dev/null | tr -d '\r' \
    | grep -E 'wm_on_(create|destroy)_called' | grep -F "$PACKAGE" || true
}

# How many times the activity was rebuilt since the log was last cleared.
#
# NOT the ActivityRecord identity, which was this script's first detector and
# was simply wrong. `ActivityRecord` lives in system_server and is the window
# token; a configuration relaunch destroys and rebuilds the *client* Activity
# object behind that same record, so the identity is unchanged across exactly
# the event this test exists to observe. The first run to reach the control
# saw `wm_on_destroy_called` and `wm_on_create_called` 17 ms apart, with
# FOLD_UNMOUNT and FOLD_MOUNT between them, and still reported the record as
# unchanged and refused. The client-side lifecycle entries are logged by the
# app's own pid and are the right witness.
recreations_since_clear() {
  adb logcat -d -b events 2>/dev/null | tr -d '\r' \
    | grep -E 'wm_on_create_called' | grep -cF "$PACKAGE" || true
}

require_resumed() {
  local st
  st=$(activity_state) || st=""
  [ -n "$st" ] || fail "could not read the activity's state from dumpsys $1.
      Not a pass: an unreadable state is not a RESUMED one, and the run that
      first hit this exited silently instead of saying so."
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
clear_events
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

# Wait for the probe to finish too, not just for a machine to exist. The run
# that first got this far fired its control 7.8 s after launch, while the
# probe suite was still going; the suite survived it and still reported 12/12,
# which is a result worth having but not the one this script is asking for.
# A control that lands mid-probe measures a different thing every time.
PROBE_DEADLINE=$(( $(date +%s) + LAUNCH_TIMEOUT_SECONDS ))
while [ "$(date +%s)" -lt "$PROBE_DEADLINE" ]; do
  SUMMARY=$(adb logcat -d -v raw ReactNativeJS:V '*:S' 2>/dev/null | tr -d '\r' \
    | grep -E '^PROBE_SUMMARY ' || true)
  [ -n "$SUMMARY" ] && break
  sleep 3
done
[ -n "${SUMMARY:-}" ] || fail "the app never printed a PROBE_SUMMARY line.
      The probe is what proves the machine and store this test then folds are
      the ones a working launch produces."
echo "launch reported: $SUMMARY"

BASE_PID=$(app_pid)
BASE_KEYS=$(new_fold_lines | grep -E '^FOLD_KEYS ' | head -1 | awk '{print $2}' || true)
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
clear_events
adb shell wm density "$CONTROL_DENSITY" >/dev/null 2>&1
sleep "$SETTLE_SECONDS"
CONTROL_RECREATIONS=$(recreations_since_clear)
CONTROL_LIFECYCLE=$(lifecycle_lines)
adb shell wm density reset >/dev/null 2>&1 || true
sleep "$SETTLE_SECONDS"

[ -z "$CONTROL_LIFECYCLE" ] || printf '  %s\n' "$CONTROL_LIFECYCLE"
if [ "$CONTROL_RECREATIONS" -lt 1 ]; then
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
printf '%-8s %-9s %-11s %-13s %-9s %s\n' \
  cycle state recreations size pid app-lines
RECREATIONS=0
for c in $(seq 1 "$CYCLES"); do
  for target in "$OPENED" "$CLOSED"; do
    require_resumed "before cycle $c"
    clear_events
    adb shell cmd device_state state "$target" >/dev/null 2>&1
    sleep "$SETTLE_SECONDS"
    N=$(recreations_since_clear)
    SIZE=$(adb shell wm size 2>/dev/null | tr -d '\r' | sed -n 's/.*size: //p' | head -1)
    NEW_FOLD=$(new_fold_lines | tr '\n' ';')
    RECREATIONS=$(( RECREATIONS + N ))
    printf '%-8s %-9s %-11s %-13s %-9s %s\n' \
      "$c" "$target" "$N" "$SIZE" "$(app_pid)" "${NEW_FOLD:-none}"
  done
done

adb shell cmd device_state state reset >/dev/null 2>&1 || true
sleep "$SETTLE_SECONDS"

# ---------------------------------------------------------------------------
# What the app says it still had.
# ---------------------------------------------------------------------------

new_fold_lines >/dev/null   # flush anything printed after the last cycle

echo
echo "--- FOLD_ output ---"
cat "$WORK/fold.log"
echo "--- end FOLD_ output ---"
echo

END_PID=$(app_pid)
[ "$END_PID" = "$BASE_PID" ] || fail "the process restarted during the run ($BASE_PID -> $END_PID).
      Everything above is about a process that survived a configuration
      change. A run in which it did not is a different experiment and its
      rows cannot be read as this one's."

MOUNTS=$(grep -c '^FOLD_MOUNT ' "$WORK/fold.log" || true)
UNMOUNTS=$(grep -c '^FOLD_UNMOUNT ' "$WORK/fold.log" || true)
KEYS=$(grep '^FOLD_KEYS ' "$WORK/fold.log" | awk '{print $2}' | sort -u | tr '\n' ' ')
BAD_MACHINE=$(grep '^FOLD_MACHINE err' "$WORK/fold.log" || true)
BAD_STORE=$(grep '^FOLD_STORE err' "$WORK/fold.log" || true)
MAX_SUBS=$(grep -oE 'subs=[0-9]+' "$WORK/fold.log" | cut -d= -f2 | sort -n | tail -1)

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
if [ "$RECREATIONS" -eq 0 ]; then
  cat <<NOTE
NOTE: no fold recreated the activity on this device, so the survival
      assertions above were exercised by the control's recreations and not by
      the folds. That is a result about this manifest, not a clean bill of
      health for folding in general: MainActivity declares screenLayout,
      screenSize, smallestScreenSize and orientation in android:configChanges,
      and both of this device's panels report the same density, so a fold
      changes nothing the activity has not declared. An app whose manifest
      omits any of those, or a foldable whose two panels differ in density,
      would be recreated -- which is what the control stands in for.
NOTE
fi
echo "PASS: the process, its crypto machine and its store survived $CYCLES fold/unfold cycles on $MODEL (API $SDK)."
