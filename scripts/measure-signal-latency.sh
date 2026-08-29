#!/usr/bin/env bash
set -euo pipefail

# Measures observer-signal delivery latency on a device, as an interleaved A/B
# between two release APKs, and writes one TSV row per launch.
#
# This exists because `interop/suite.ts`'s SIGNAL_WAIT_MS is a measured number,
# and the first time it was measured the harness that produced it lived in a
# scratch directory and was thrown away. Re-deriving the budget then meant
# rebuilding the launch loop, the arm swapping and the log extraction by hand,
# which is most of the cost of the measurement. It is here so the next person
# re-runs it instead.
#
#   Usage: scripts/measure-signal-latency.sh <a.apk> <b.apk> <rounds> <out.tsv> [none|cpu|io]
#
# WHAT MAKES THIS AN A/B AND NOT TWO RUNS
#
# The arms alternate launch by launch, so drift in emulator or host state falls
# on both arms equally rather than on whichever one ran second. A block of A
# followed by a block of B measures the machine's afternoon as much as the code.
#
# THE CHECK THAT HAS TO COME FIRST
#
# Android imports the Rust library as a prebuilt (`android/CMakeLists.txt`) from
# a gitignored `jniLibs/`, and Gradle has no dependency edge back to the crate.
# `:app:assembleRelease` will therefore repackage a stale `.so` without
# complaint, and an arm swap that forgot `ubrn build android` produces two APKs
# that differ in nothing at all. Two indistinguishable distributions is exactly
# what that mistake looks like in the output, so it has to be excluded before
# the numbers mean anything -- not after, and not by remembering the build
# steps correctly.
#
# So this refuses to run until the two APKs are shown to differ where it
# matters, and then refuses to accept a launch that does not say which arm it
# is. Both halves are needed: the first compares the artifacts on disk, the
# second reads what the running process reports about itself
# (`PROBE_EMIT_BUILD`, from `observer.rs`'s `EMIT_BUILD` by way of
# `coreVersion`).

PACKAGE=com.exampleapp
ACTIVITY=.MainActivity

# How long one launch gets to print its summary. The probe creates a real
# crypto store and does a full Megolm round trip; slow is normal on an
# emulator, silent is not. Matches run-probe-on-emulator.sh.
LAUNCH_TIMEOUT_SECONDS=${LAUNCH_TIMEOUT_SECONDS:-240}

# A signal that lost the race to the promise arrives after the summary, so the
# log is read once more this many seconds later. Without it, a late delivery is
# absent from the record and reads as a lost one.
LATE_GRACE_SECONDS=${LATE_GRACE_SECONDS:-15}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[ "$#" -ge 4 ] || fail "usage: $0 <a.apk> <b.apk> <rounds> <out.tsv> [none|cpu|io]"

APK_A=$1
APK_B=$2
ROUNDS=$3
OUT=$4
LOAD=${5:-none}

LABEL_A=$(basename "$APK_A" .apk)
LABEL_B=$(basename "$APK_B" .apk)

command -v adb >/dev/null 2>&1 || fail "adb is not on PATH."
command -v unzip >/dev/null 2>&1 || fail "unzip is not on PATH."
[ -s "$APK_A" ] || fail "no APK at '$APK_A'."
[ -s "$APK_B" ] || fail "no APK at '$APK_B'."
[ "$LABEL_A" != "$LABEL_B" ] || fail "both APKs are named '$LABEL_A'; the rows would be unreadable."

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; stop_load' EXIT

# ---------------------------------------------------------------------------
# Step 1: the two artifacts must differ in the Rust library and nowhere else.
#
# "And nowhere else" is not pedantry. If the JavaScript bundle differs too, the
# arms differ in more than the thing under test and the comparison says nothing
# about emission.
# ---------------------------------------------------------------------------
ABI=$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')
[ -n "$ABI" ] || fail "no device: adb reported no ro.product.cpu.abi."

digest_member() {
  # $1 apk, $2 member path. Empty output means the member is absent.
  unzip -p "$1" "$2" 2>/dev/null | shasum -a 256 | cut -c1-16
}

CORE_SO="lib/$ABI/libmatrix_crypto_ffi.so"
BUNDLE=assets/index.android.bundle

A_CORE=$(digest_member "$APK_A" "$CORE_SO")
B_CORE=$(digest_member "$APK_B" "$CORE_SO")
A_BUNDLE=$(digest_member "$APK_A" "$BUNDLE")
B_BUNDLE=$(digest_member "$APK_B" "$BUNDLE")

[ -n "$A_CORE" ] || fail "'$APK_A' carries no $CORE_SO. Wrong ABI, or a stub build."
[ -n "$B_CORE" ] || fail "'$APK_B' carries no $CORE_SO. Wrong ABI, or a stub build."

if [ "$A_CORE" = "$B_CORE" ]; then
  fail "both APKs carry the same $CORE_SO ($A_CORE).
      There is no A/B here: the arms would run identical Rust. jniLibs/ is
      gitignored and Gradle does not depend on the crate, so this is what a
      missing 'ubrn build android' between the two arms looks like."
fi

echo "arms differ in $CORE_SO: $LABEL_A=$A_CORE $LABEL_B=$B_CORE"
if [ "$A_BUNDLE" != "$B_BUNDLE" ]; then
  echo "WARNING: the two APKs also carry different $BUNDLE" >&2
  echo "         ($LABEL_A=$A_BUNDLE $LABEL_B=$B_BUNDLE). The arms differ in" >&2
  echo "         more than emission, so a difference in the numbers below" >&2
  echo "         cannot be attributed to emission alone." >&2
fi

# ---------------------------------------------------------------------------
# Step 2: host load, so the tail is measured under something rather than only
# on an idle machine.
#
# The observation this budget exists to absorb was taken while this repository
# was being built -- CPU, disk and page cache all contended. 'cpu' reproduces
# only the first of those, which is why 'io' exists as well.
# ---------------------------------------------------------------------------
LOAD_PIDS=()

stop_load() {
  [ "${#LOAD_PIDS[@]}" -gt 0 ] || return 0
  for p in "${LOAD_PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  LOAD_PIDS=()
}

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
      # Four writers churning a bounded file each, plus a reader pulling it
      # back through the page cache. Bounded on purpose: an unbounded writer
      # fills the disk the emulator's own image lives on, which measures
      # something else entirely and does not give the disk back.
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
# Step 3: one launch, exactly as run-probe-on-emulator.sh launches it.
# ---------------------------------------------------------------------------
probe_lines() {
  adb logcat -d -v raw ReactNativeJS:V '*:S' 2>/dev/null | tr -d '\r' | grep -E '^PROBE_' || true
}

launch_once() {
  local apk=$1 label=$2 round=$3

  adb uninstall "$PACKAGE" >/dev/null 2>&1 || true
  adb install -r "$apk" >/dev/null
  adb logcat -c
  adb shell am start -n "$PACKAGE/$ACTIVITY" >/dev/null

  local deadline summary
  deadline=$(( $(date +%s) + LAUNCH_TIMEOUT_SECONDS ))
  summary=""
  while [ "$(date +%s)" -lt "$deadline" ]; do
    summary=$(probe_lines | grep -E '^PROBE_SUMMARY [0-9]+/[0-9]+$' || true)
    [ -n "$summary" ] && break
    sleep 2
  done

  # The signal can still be in flight when the summary prints -- that race is
  # the whole subject -- so read the log once more after a grace period rather
  # than immediately.
  sleep "$LATE_GRACE_SECONDS"

  local log sig prom build
  log=$(probe_lines)
  sig=$(printf '%s\n' "$log" | grep -E '^PROBE_SIGNAL_MS ' | head -1 | awk '{print $2}')
  prom=$(printf '%s\n' "$log" | grep -E '^PROBE_PROMISE_MS ' | head -1 | awk '{print $2}')
  build=$(printf '%s\n' "$log" | grep -E '^PROBE_EMIT_BUILD ' | head -1 | awk '{print $2}')

  if [ -z "$build" ]; then
    fail "launch $round of '$label' printed no PROBE_EMIT_BUILD line.
      Without it this row cannot say which emission path produced it, which is
      the one thing this harness refuses to guess. An APK built before
      ProbeHarness.tsx grew that line will do this."
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$label" "$round" "$LOAD" "${sig:-NONE}" "${prom:-NONE}" "$build" "${summary:-NOSUMMARY}" \
    | tee -a "$OUT"

  adb shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  printf '%s' "$build"
}

adb wait-for-device
echo "device: $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r') (API $(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r'), $ABI)"

start_load

: > "$OUT"
SEEN_A=""
SEEN_B=""
for r in $(seq 1 "$ROUNDS"); do
  SEEN_A=$(launch_once "$APK_A" "$LABEL_A" "$r")
  SEEN_B=$(launch_once "$APK_B" "$LABEL_B" "$r")
  if [ "$SEEN_A" = "$SEEN_B" ]; then
    fail "round $r: both arms reported the same emission build ($SEEN_A).
      The two APKs differ on disk but the running processes do not
      distinguish themselves, so nothing measured here is an A/B."
  fi
done

stop_load

echo
echo "$LABEL_A ran emission build $SEEN_A; $LABEL_B ran $SEEN_B"
echo "rows: $(wc -l < "$OUT" | tr -d ' ') in $OUT"
