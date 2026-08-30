#!/usr/bin/env bash
set -euo pipefail

# Runs the example app's probe on a connected Android device or emulator and
# asserts on what it printed.
#
# Why this exists: every fast check in this repo passed for the whole of M2
# while the example app's probe was failing on real native code.
# `getDeviceIdentityKeys` started refusing a caller who names a different
# identity than the live machine holds, and the probe's `real_crypto` step
# called it with no machine created at all -- so it had been failing since that
# change, and nothing said so until someone ran it by hand (task-10-report.md,
# finding 1). Host `cargo test`, `vitest`, `tsc` and every gate stayed green
# throughout. Only running the thing finds this class of defect.
#
# WHAT THIS ASSERTS, AND WHY IT IS THE VERBATIM SUMMARY LINE
#
# Not "the process exited 0": the app is launched with `am start` and detaches
# immediately, so its exit status says nothing. Not "no FAIL line appeared":
# an app that crashes on launch, or one that was never installed, prints no
# FAIL line either, and that is precisely the failure this repo keeps
# rediscovering -- an absence of bad news read as good news.
#
# So: a PROBE_SUMMARY line must be *found*, exactly one of them, and it must
# equal EXPECTED_SUMMARY below. Nothing about this script can pass by finding
# nothing.

PACKAGE=com.exampleapp
ACTIVITY=".MainActivity"

# The example app's ProbeHarness reports 5 checks from interop/suite.ts, 6 from
# interop/crypto-suite.ts (CRYPTO_SUITE_STEPS), and `real_crypto`. Twelve, all
# passing.
#
# Hardcoded rather than derived, deliberately. The harness reports a *thirteenth*
# check named `harness` when a suite rejects instead of returning failures, so
# the denominator is a real signal, not bookkeeping: a run that went wrong in
# that particular way reports 13, and a check that quietly disappeared would
# report 11. Deriving the number from the sources would make both invisible.
# If you add or remove a probe check, update this line in the same commit --
# CI failing until you do is the point.
#
# WHAT THESE TWELVE DO NOT COVER: CROSS-SIGNING, AND WHAT IT WOULD TAKE
#
# None of the twelve looks at a signing identity or at what a decrypted event
# says about its sender. That is a real hole on hardware and it is named here
# rather than left for someone to discover, because the number above is the
# only place on the device path where coverage is stated at all.
#
# The two halves are not equally out of reach, so they are separated:
#
#   * THE GATE IS REACHABLE HERE and is not counted. `bootstrapCrossSigning`
#     refuses with `account_keys_not_fetched` on a device with no homeserver,
#     which is exactly what the guided walkthrough's step 6 drives on every
#     launch of this same app. But the walkthrough prints nothing this script
#     scrapes -- only ProbeHarness emits PROBE_CHECK / PROBE_SUMMARY -- so a
#     device run exercises it and reports nothing about it. A thirteenth check
#     could close that, at the cost of moving this number and the copies of it
#     in scripts/assert-measure-guards.sh, scripts/assert-measure-guards-ios.sh,
#     scripts/assert-no-logger.sh and scripts/assert-generated-not-stubbed.sh.
#     It has not been done, and this paragraph is the alternative to doing it
#     silently.
#
#   * A SERVED BOOTSTRAP IS NOT REACHABLE HERE, and could not be made so
#     honestly. Publishing an identity needs a `/keys/query` naming the account
#     to have been sent AND answered, and this app has no homeserver. The only
#     way to get past the gate on a device with no network is to hand
#     `markRequestSent` a body the app invented, which is the precise mistake
#     that call's own documentation exists to prevent and which would make the
#     check a demonstration of the wrong thing.
#
#   * NOR IS ANY SENDER VALUE ABOVE `unsigned_device`. The `round_trip` check
#     already decrypts a real event on the device; it simply does not read
#     `senderVerification`. If it did, the only value reachable with no
#     homeserver and no counterparty is `unsigned_device`, because every value
#     above it needs a peer whose client published a cross-signing identity.
#
# Where each is covered instead: the gate and both refusals in
# rust/matrix-crypto-core/tests/identity_bootstrap*.rs; `unverified_identity`
# from a cross-signed peer in tests/cross_signed_peer.rs; `verified` through
# the whole chain in tests/verified_sender.rs; and all of it against a real
# homeserver and a third-party client in tests/level_two_identity.rs, run by
# scripts/run-level-two-interop.sh.
EXPECTED_SUMMARY="PROBE_SUMMARY 12/12"

APK=${1:-packages/example-app/android/app/build/outputs/apk/release/app-release.apk}

# How long to wait for the summary after launch. The probe creates a real
# crypto store (passphrase-derived key included) and does a full Megolm round
# trip, on an emulator; slow is normal, silent is not.
TIMEOUT_SECONDS=${PROBE_TIMEOUT_SECONDS:-240}

# How long to keep reading the log after the summary has been found, before
# dumping the PROBE_ lines.
#
# The observer callback races the promise `runProbe` returns, and the summary
# is printed once the suite's own bounded wait has given up on it. A callback
# that arrives after that still prints its `PROBE_SIGNAL_MS` line -- the app is
# still running -- but this script used to read the log once, immediately, and
# would have missed it. `interop/suite.ts` tells whoever is debugging a red
# `signal` check that the line's absence means the callback was lost and its
# presence means it was late; that guidance is only true if the log is read
# after the window in which a late callback can still arrive. This is that
# window, and it is a fixed cost on a job that already takes most of an hour.
LATE_GRACE_SECONDS=${PROBE_LATE_GRACE_SECONDS:-15}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

command -v adb >/dev/null 2>&1 || fail "adb is not on PATH."

[ -f "$APK" ] || fail "no APK at '$APK'. Build one first:
      (cd packages/example-app/android && ./gradlew :app:assembleRelease -PreactNativeArchitectures=<abi>)"
[ -s "$APK" ] || fail "the APK at '$APK' is empty."

echo "Waiting for a device..."
adb wait-for-device
# `wait-for-device` returns as soon as adb can talk to the device, which is
# well before the framework is up; installing then fails in ways that read
# like a broken APK.
for _ in $(seq 1 60); do
  if [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
    break
  fi
  sleep 5
done
[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] \
  || fail "the device never reported sys.boot_completed=1."

echo "Device: $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r') (API $(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r'), $(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r'))"

# Uninstall rather than `install -r`: the probe's `key_upload_present` step
# asserts what a *fresh* device offers to publish, so it must not inherit
# anything a previous run left in the app's data directory.
adb uninstall "$PACKAGE" >/dev/null 2>&1 || true
echo "Installing $APK"
adb install "$APK"

adb logcat -c
echo "Launching $PACKAGE/$ACTIVITY"
adb shell am start -n "$PACKAGE/$ACTIVITY"

SUMMARY=""
DEADLINE=$(( $(date +%s) + TIMEOUT_SECONDS ))
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
  # -v raw prints the message and nothing else, so the comparison below is
  # against exactly what the app printed rather than against a log format.
  SUMMARY=$(adb logcat -d -v raw ReactNativeJS:V '*:S' 2>/dev/null \
    | tr -d '\r' \
    | grep -E '^PROBE_SUMMARY [0-9]+/[0-9]+$' || true)
  [ -n "$SUMMARY" ] && break
  # A process that has died will never print anything; say so now rather than
  # waiting out the timeout and reporting silence.
  if ! adb shell pidof "$PACKAGE" >/dev/null 2>&1; then
    CRASH=$(adb logcat -d -v brief AndroidRuntime:E '*:S' 2>/dev/null | tr -d '\r' || true)
    if [ -n "$CRASH" ]; then
      echo "--- AndroidRuntime ---" >&2
      echo "$CRASH" >&2
      fail "$PACKAGE is no longer running and no PROBE_SUMMARY was printed."
    fi
  fi
  sleep 5
done

if [ -n "$SUMMARY" ]; then
  echo "Waiting ${LATE_GRACE_SECONDS}s for a late signal before reading the log."
  sleep "$LATE_GRACE_SECONDS"
fi

echo
echo "--- probe output ---"
adb logcat -d -v raw ReactNativeJS:V '*:S' 2>/dev/null | tr -d '\r' | grep -E '^PROBE_' || true
echo "--- end probe output ---"
echo

if [ -z "$SUMMARY" ]; then
  echo "--- AndroidRuntime ---" >&2
  adb logcat -d -v brief AndroidRuntime:E '*:S' 2>/dev/null | tr -d '\r' >&2 || true
  fail "no PROBE_SUMMARY line was printed within ${TIMEOUT_SECONDS}s.
      This is NOT a pass. The app either never started, crashed before the
      probe ran, or stopped forwarding console output to logcat."
fi

LINES=$(printf '%s\n' "$SUMMARY" | awk 'END { print NR }')
if [ "$LINES" != "1" ]; then
  fail "expected exactly one PROBE_SUMMARY line, found $LINES:
$SUMMARY
      The harness memoises its run so a launch prints exactly one summary;
      more than one means something re-ran it and the result is ambiguous."
fi

if [ "$SUMMARY" != "$EXPECTED_SUMMARY" ]; then
  GOT_DEN=${SUMMARY##*/}
  WANT_DEN=${EXPECTED_SUMMARY##*/}
  if [ "$GOT_DEN" != "$WANT_DEN" ]; then
    fail "the probe reported '$SUMMARY', but this job expects $WANT_DEN checks.
      The set of probe checks changed. Update EXPECTED_SUMMARY in
      scripts/run-probe-on-emulator.sh in the same commit that changed it."
  fi
  fail "the probe reported '$SUMMARY', expected '$EXPECTED_SUMMARY'.
      See the PROBE_CHECK lines above for which step failed."
fi

echo "PASS: $SUMMARY on $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r')"
