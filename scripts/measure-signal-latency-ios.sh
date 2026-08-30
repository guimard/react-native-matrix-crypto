#!/usr/bin/env bash
set -euo pipefail

# Measures observer-signal delivery latency on an iOS simulator, as an
# interleaved A/B between two release `.app` bundles, and writes one TSV row
# per launch.
#
#   Usage: scripts/measure-signal-latency-ios.sh <a.app> <b.app> <rounds> <out.tsv> [none|cpu|io]
#
# This is the iOS sibling of scripts/measure-signal-latency.sh. The design is
# that script's, and the reasons for the design are written there rather than
# repeated here: the arms alternate launch by launch so host drift falls on
# both equally, the two artifacts must be shown to differ before anything is
# launched, and a round whose two launches do not say which arm they are is
# refused rather than recorded. What follows is only what iOS does
# differently, because that is the part a reader cannot get from the Android
# script.
#
# WHAT IOS MAKES HARDER, AND WHAT IT MAKES IMPOSSIBLE
#
# 1. THERE IS NO `logcat -d`. The simulator's log system runs in
#    STREAM_LIVE mode and keeps no archive: `log show --last 2m` inside a
#    booted simulator returns nothing at all, and `log show` there does not
#    even accept `--level`. Nor does the host's own log carry the
#    simulator's messages, so a host-side `log show` cannot recover them
#    either. All three were checked on a booted iOS 26.5 simulator before
#    this script was written.
#
#    So there is no dump to read after the fact. The only route is a live
#    `log stream`, which has to be attached BEFORE the app emits anything
#    and has to be shown to have been attached. Android could clear the
#    buffer and read it back at leisure; this cannot.
#
# 2. A STREAM THAT ATTACHED LATE LOOKS EXACTLY LIKE A LOST CALLBACK.
#    That is the hazard this file exists to close, and it is worse than a
#    missing row: a `PROBE_SIGNAL_MS` line the stream was not yet live to
#    catch is recorded as `NONE`, and `NONE` is the event this whole harness
#    is kept to observe (spec section 5.1, B2). A capture race would
#    manufacture the finding.
#
#    So the stream proves itself live before every launch. The proof is the
#    harness's own `simctl uninstall`, which the run performs anyway to get
#    a cold process on a fresh container: `installd` logs the uninstall
#    naming the bundle identifier, so a captured `installd` line carrying
#    that identifier is evidence that the stream was attached at a moment
#    strictly before the install and the launch that follow it. Nothing is
#    launched until that line is in the capture, and a launch that cannot
#    get it is refused with a diagnostic rather than recorded.
#
#    The beacon is deliberately not a marker planted by some other tool.
#    `logger` was tried first and does not reach the unified log inside a
#    simulator: the message never appears in `log stream`, on any level,
#    which is a silent no-op and exactly the wrong shape for a readiness
#    proof.
#
# 3. THE RUST IS NOT A SEPARATE FILE IN THE ARTIFACT. `ubrn build ios`
#    produces a static archive (`libmatrix_crypto_ffi.a`) inside
#    `MatrixCryptoFramework.xcframework`, and the linker folds it into the
#    app's single Mach-O executable. There is no `lib/<abi>/*.so` member to
#    digest on its own. So the on-disk comparison here is over the whole
#    executable, which is coarser than the Android one in a way worth saying
#    plainly: it can tell "these two arms are the same file" from "these two
#    arms are not", and it CANNOT tell a difference in the Rust from a
#    difference in the app's own Objective-C or Swift. What separates those
#    is `PROBE_EMIT_BUILD`, below, which is a fingerprint of the emission
#    source and of nothing else.
#
#    The staleness hazard that guard exists for is the same on both
#    platforms. Xcode has no dependency edge from the app target back to the
#    Rust crate either: the archive arrives as a vendored framework, so
#    `xcodebuild` will relink yesterday's Rust without complaint if the arm
#    swap forgot `ubrn build ios`.
#
# 4. THE ON-DISK DIGEST PROVES LESS HERE THAN IT DOES ON ANDROID, in the
#    direction that does not matter. Two Mach-O executables built from
#    identical source differ anyway, in their LC_UUID and their ad-hoc
#    signature. So "the digests differ" is not evidence the source differed.
#    It is still worth checking, because the mistake it catches is the
#    opposite one: an arm swap that never rebuilt copies the same file
#    twice, and identical digests catch that. The claim that the arms ran
#    different emission code rests on `PROBE_EMIT_BUILD` alone, and that is
#    true on Android too.

# `xcrun simctl launch` needs a bundle identifier; both are read out of the
# app bundles rather than hardcoded, so this script does not have to be
# edited when the example app is renamed, and so a mismatched pair is
# refused instead of measured.

# How long one launch gets to print its summary. The probe creates a real
# crypto store and does a full Megolm round trip. Matches the Android
# harness.
LAUNCH_TIMEOUT_SECONDS=${LAUNCH_TIMEOUT_SECONDS:-240}

# A signal that lost the race to the promise arrives after the summary, so
# the capture is read once more this many seconds later. Without it, a late
# delivery is absent from the record and reads as a lost one.
LATE_GRACE_SECONDS=${LATE_GRACE_SECONDS:-15}

# How many `simctl uninstall` attempts the stream gets to prove itself live
# before a launch is refused. Two is typical on an idle machine.
STREAM_READY_TRIES=${STREAM_READY_TRIES:-20}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[ "$#" -ge 4 ] || fail "usage: $0 <a.app> <b.app> <rounds> <out.tsv> [none|cpu|io]"

APP_A=$1
APP_B=$2
ROUNDS=$3
OUT=$4
LOAD=${5:-none}

LABEL_A=$(basename "$APP_A" .app)
LABEL_B=$(basename "$APP_B" .app)

command -v xcrun >/dev/null 2>&1 || fail "xcrun is not on PATH."
command -v plutil >/dev/null 2>&1 || fail "plutil is not on PATH."
[ -d "$APP_A" ] || fail "no app bundle at '$APP_A'."
[ -d "$APP_B" ] || fail "no app bundle at '$APP_B'."
[ "$LABEL_A" != "$LABEL_B" ] || fail "both bundles are named '$LABEL_A'; the rows would be unreadable."

LOAD_PIDS=()
STREAM_PID=""

# Defined before the traps that call them, not after. The Android harness
# shipped with its `stop_load` declared seventy lines below the trap that
# called it, so every diagnostic exit ran the trap against an undefined
# function and reported 127 instead of the 1 it had earned.
stop_load() {
  [ "${#LOAD_PIDS[@]}" -gt 0 ] || return 0
  for p in "${LOAD_PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  LOAD_PIDS=()
}

stop_stream() {
  [ -n "$STREAM_PID" ] || return 0
  kill "$STREAM_PID" 2>/dev/null || true
  wait "$STREAM_PID" 2>/dev/null || true
  STREAM_PID=""
}

WORK=$(mktemp -d)
trap 'stop_stream; stop_load; rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# Step 1: read the two bundles, and refuse a pair that is not an A/B.
# ---------------------------------------------------------------------------

# $1 app bundle, $2 Info.plist key. Prints the value, or returns 1.
plist_value() {
  plutil -extract "$2" raw -o - "$1/Info.plist" 2>/dev/null
}

# $1 app bundle, $2 path relative to the bundle. Prints the digest, or
# returns 1 if the file is absent.
#
# The membership test is its own step for the reason the Android harness
# gives: a digest of nothing is a perfectly good-looking digest, so a caller
# testing the output for emptiness would be testing nothing.
digest_member() {
  [ -f "$1/$2" ] || return 1
  shasum -a 256 "$1/$2" | cut -c1-16
}

A_EXEC=$(plist_value "$APP_A" CFBundleExecutable) || A_EXEC=""
B_EXEC=$(plist_value "$APP_B" CFBundleExecutable) || B_EXEC=""
[ -n "$A_EXEC" ] || fail "'$APP_A' has no CFBundleExecutable in its Info.plist.
      That is not an application bundle this script can launch."
[ -n "$B_EXEC" ] || fail "'$APP_B' has no CFBundleExecutable in its Info.plist.
      That is not an application bundle this script can launch."

A_ID=$(plist_value "$APP_A" CFBundleIdentifier) || A_ID=""
B_ID=$(plist_value "$APP_B" CFBundleIdentifier) || B_ID=""
[ -n "$A_ID" ] || fail "'$APP_A' has no CFBundleIdentifier in its Info.plist."
[ -n "$B_ID" ] || fail "'$APP_B' has no CFBundleIdentifier in its Info.plist."
[ "$A_ID" = "$B_ID" ] || fail "the two bundles carry different identifiers
      ('$A_ID' and '$B_ID'). Each launch installs over the other precisely
      because they share one, so that a round is two launches of one app and
      not two apps side by side."
BUNDLE_ID=$A_ID

# `|| VAR=` on each: without it a missing file returns non-zero, `set -e`
# aborts the assignment, and the diagnostic below never runs.
A_BIN=$(digest_member "$APP_A" "$A_EXEC") || A_BIN=""
B_BIN=$(digest_member "$APP_B" "$B_EXEC") || B_BIN=""
A_BUNDLE=$(digest_member "$APP_A" main.jsbundle) || A_BUNDLE=""
B_BUNDLE=$(digest_member "$APP_B" main.jsbundle) || B_BUNDLE=""

[ -n "$A_BIN" ] || fail "'$APP_A' carries no executable named '$A_EXEC'.
      Its Info.plist names one and the bundle does not contain it, which is
      what a half-copied or interrupted build looks like."
[ -n "$B_BIN" ] || fail "'$APP_B' carries no executable named '$B_EXEC'.
      Its Info.plist names one and the bundle does not contain it, which is
      what a half-copied or interrupted build looks like."

# A Debug build has no main.jsbundle: it reaches for Metro at launch instead.
# Such a run would measure a different artifact from the one this script
# claims to measure, and would do it silently on a machine where Metro
# happened to be running.
[ -n "$A_BUNDLE" ] || fail "'$APP_A' carries no main.jsbundle.
      A Release build embeds one; a Debug build fetches the bundle from
      Metro at launch instead. This harness measures release artifacts."
[ -n "$B_BUNDLE" ] || fail "'$APP_B' carries no main.jsbundle.
      A Release build embeds one; a Debug build fetches the bundle from
      Metro at launch instead. This harness measures release artifacts."

if [ "$A_BIN" = "$B_BIN" ]; then
  fail "both bundles carry the same '$A_EXEC' ($A_BIN).
      There is no A/B here: the arms would run identical code. Two Mach-O
      executables built from identical source still differ in their LC_UUID
      and their signature, so identical bytes mean one file was copied
      twice. That is what an arm swap that skipped 'ubrn build ios', or that
      forgot to rebuild the app after it, looks like."
fi

echo "arms differ in $A_EXEC: $LABEL_A=$A_BIN $LABEL_B=$B_BIN"
if [ "$A_BUNDLE" != "$B_BUNDLE" ]; then
  echo "WARNING: the two bundles also carry different main.jsbundle" >&2
  echo "         ($LABEL_A=$A_BUNDLE $LABEL_B=$B_BUNDLE). The arms differ in" >&2
  echo "         more than emission, so a difference in the numbers below" >&2
  echo "         cannot be attributed to emission alone." >&2
fi

# ---------------------------------------------------------------------------
# Step 2: the simulator.
# ---------------------------------------------------------------------------
UDID=${SIM_UDID:-}
if [ -z "$UDID" ]; then
  UDID=$(xcrun simctl list devices booted 2>/dev/null \
    | sed -n 's/.*(\([0-9A-F-]\{36\}\)) (Booted).*/\1/p' | head -1) || UDID=""
fi
[ -n "$UDID" ] || fail "no booted simulator, and SIM_UDID names none.
      Boot one with 'xcrun simctl boot <udid>', or set SIM_UDID."

xcrun simctl bootstatus "$UDID" >/dev/null 2>&1 \
  || fail "simulator '$UDID' did not reach a booted state."

DEVICE_NAME=$(xcrun simctl list devices 2>/dev/null | grep -F "$UDID" \
  | sed -E 's/^ *(.*) \([0-9A-F-]{36}\).*/\1/' | head -1) || DEVICE_NAME=""
# Absolute path: `simctl spawn` resolves a bare name against a PATH that does
# not have this on it, and answers "No such file or directory" on stderr while
# exiting 0, so a bare `sw_vers` prints an empty version and says nothing.
RUNTIME=$(xcrun simctl spawn "$UDID" /usr/bin/sw_vers -productVersion 2>/dev/null | tr -d '\r') || RUNTIME=""
echo "simulator: ${DEVICE_NAME:-unknown} ($UDID, iOS ${RUNTIME:-unknown}, $BUNDLE_ID)"

# ---------------------------------------------------------------------------
# Step 3: host load, so the tail is measured under something rather than only
# on an idle machine. Identical to the Android harness, and here the host is
# also the machine the "device" runs on, so the contention is more direct
# than an emulator's.
# ---------------------------------------------------------------------------
start_load() {
  case "$LOAD" in
    none) return 0 ;;
    cpu)
      local n
      n=$(sysctl -n hw.ncpu 2>/dev/null || echo 4)
      for _ in $(seq 1 "$n"); do
        # shellcheck disable=SC2216  # `yes` is the load, its output is waste
        yes > /dev/null &
        LOAD_PIDS+=("$!")
      done
      echo "load: cpu, $n busy loops"
      ;;
    io)
      # Bounded on purpose: an unbounded writer fills the disk the simulator
      # image lives on, which measures something else entirely.
      for i in 1 2 3 4; do
        ( while :; do
            dd if=/dev/zero of="$WORK/churn.$i" bs=1m count=64 2>/dev/null
            sync
            dd if="$WORK/churn.$i" of=/dev/null bs=1m 2>/dev/null
          done ) &
        LOAD_PIDS+=("$!")
      done
      echo "load: io, 4 write/read loops over 64 MiB each"
      ;;
    *) fail "unknown load '$LOAD'; expected none, cpu or io." ;;
  esac
}

# ---------------------------------------------------------------------------
# Step 4: one launch.
# ---------------------------------------------------------------------------

# React Native forwards JavaScript console output to the unified log at info
# level, under subsystem com.facebook.react.log. `log stream` excludes info
# level unless asked, which is why `--level info` is here: without it the
# capture is empty and every launch looks like a lost callback.
#
# `installd` is in the predicate for the readiness beacon described at the
# top of this file, not because anything in the measurement reads it.
LOG_PREDICATE='(subsystem == "com.facebook.react.log") OR (process == "installd")'

CAPTURE=""

probe_lines() {
  [ -n "$CAPTURE" ] || return 0
  # `log stream --style compact` prefixes every line with a timestamp, a
  # level and the process, so the probe lines cannot be anchored with `^`
  # the way `logcat -v raw` allows. They are cut out of the line instead,
  # which gives the same `PROBE_X value` shape the rest of this script
  # greps with `^`.
  tr -d '\r' < "$CAPTURE" 2>/dev/null | grep -oE 'PROBE_[A-Z0-9_]+ [^ ]+' || true
}

# The beacon is an installd line naming this bundle identifier, on a
# timestamped log line. Anchoring on the timestamp matters: `log stream`
# echoes its own predicate back as a header, and that header contains the
# word "installd" and would match a looser pattern. A readiness check
# satisfied by the text of its own query is a check that examines nothing.
beacon_seen() {
  [ -n "$CAPTURE" ] || return 1
  grep -qE "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:.]+ +[A-Za-z]+ +installd\[.*$BUNDLE_ID" "$CAPTURE" 2>/dev/null
}

launch_once() {
  local app=$1 label=$2 round=$3

  CAPTURE="$WORK/capture.$label.$round"
  : > "$CAPTURE"

  xcrun simctl spawn "$UDID" log stream --level info --style compact \
    --predicate "$LOG_PREDICATE" > "$CAPTURE" 2>&1 &
  STREAM_PID=$!

  # Prove the stream is attached before anything is installed or launched.
  # The uninstall is not a probe added for this: the run needs it anyway, to
  # start each launch from a cold process on a container with no crypto
  # store in it.
  local ready=""
  local t
  for t in $(seq 1 "$STREAM_READY_TRIES"); do
    xcrun simctl uninstall "$UDID" "$BUNDLE_ID" >/dev/null 2>&1 || true
    if beacon_seen; then ready=$t; break; fi
    sleep 1
  done
  [ -n "$ready" ] || fail "launch $round of '$label': the log stream was never shown to be live.
      $STREAM_READY_TRIES uninstalls of '$BUNDLE_ID' went by without one
      installd line naming it reaching the capture.
      Nothing is launched into a stream that cannot be shown to have been
      attached first: a line the stream was not yet live to catch would be
      recorded as a lost callback, which is the one finding this harness
      exists to report and the one it must never manufacture."

  xcrun simctl install "$UDID" "$app" >/dev/null
  xcrun simctl launch "$UDID" "$BUNDLE_ID" >/dev/null

  local deadline summary
  deadline=$(( $(date +%s) + LAUNCH_TIMEOUT_SECONDS ))
  summary=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    summary=$(probe_lines | grep -E '^PROBE_SUMMARY [0-9]+/[0-9]+$' || true)
    [ -n "$summary" ] && break
    sleep 2
  done

  # The signal can still be in flight when the summary prints. That race is
  # the whole subject, so the capture is read once more after a grace period
  # rather than immediately.
  sleep "$LATE_GRACE_SECONDS"

  # EVERY ONE OF THESE NEEDS ITS `|| VAR=""`. `grep` exits 1 when it matches
  # nothing, `pipefail` promotes that to the pipeline, and `set -e` then
  # aborts the assignment, so without the fallback a launch that printed no
  # `PROBE_SIGNAL_MS` would kill the run at this line with no diagnostic and
  # no row. It matters most for the one line that is supposed to be missing
  # sometimes: a lost callback is the event this harness is kept for.
  local log sig nth sig2 prom build
  log=$(probe_lines) || log=""
  sig=$(printf '%s\n' "$log" | grep -E '^PROBE_SIGNAL_MS ' | head -1 | awk '{print $2}') || sig=""
  nth=$(printf '%s\n' "$log" | grep -E '^PROBE_SIGNAL_NTH ' | head -1 | awk '{print $2}') || nth=""
  sig2=$(printf '%s\n' "$log" | grep -E '^PROBE_SIGNAL2_MS ' | head -1 | awk '{print $2}') || sig2=""
  prom=$(printf '%s\n' "$log" | grep -E '^PROBE_PROMISE_MS ' | head -1 | awk '{print $2}') || prom=""
  build=$(printf '%s\n' "$log" | grep -E '^PROBE_EMIT_BUILD ' | head -1 | awk '{print $2}') || build=""

  if [ -z "$build" ]; then
    fail "launch $round of '$label' printed no PROBE_EMIT_BUILD line.
      Without it this row cannot say which emission path produced it, which
      is the one thing this harness refuses to guess."
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$label" "$round" "$LOAD" "${sig:-NONE}" "${nth:-NONE}" "${sig2:-NONE}" \
    "${prom:-NONE}" "$build" "${summary:-NOSUMMARY}" \
    | tee -a "$OUT"

  xcrun simctl terminate "$UDID" "$BUNDLE_ID" >/dev/null 2>&1 || true
  stop_stream

  # Through a global, NOT through stdout. This function already writes the
  # row to stdout, so a caller using `$(launch_once ...)` would capture the
  # row and the id together. That is exactly how the Android harness's arm
  # guard came to be unable to fire: the row begins with the arm's label,
  # which is forced to differ, so the comparison was false in every run
  # including the one it exists to reject.
  LAST_BUILD=$build
}

start_load

: > "$OUT"
LAST_BUILD=""
SEEN_A=""
SEEN_B=""
for r in $(seq 1 "$ROUNDS"); do
  launch_once "$APP_A" "$LABEL_A" "$r"
  SEEN_A=$LAST_BUILD
  launch_once "$APP_B" "$LABEL_B" "$r"
  SEEN_B=$LAST_BUILD
  if [ "$SEEN_A" = "$SEEN_B" ]; then
    fail "round $r: both arms reported the same emission build ($SEEN_A).
      The two bundles differ on disk but the running processes do not
      distinguish themselves, so nothing measured here is an A/B. On iOS the
      Rust is linked into the app executable, so the on-disk comparison
      cannot see which archive went in; this is the check that can."
  fi
done

stop_load

echo
echo "$LABEL_A ran emission build $SEEN_A; $LABEL_B ran $SEEN_B"
echo "rows: $(wc -l < "$OUT" | tr -d ' ') in $OUT"
