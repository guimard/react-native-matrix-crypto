import { useEffect } from 'react'
import {
  getDeviceIdentityKeys,
  getDeviceStatuses,
  isCryptoError,
  onCryptoSignal,
} from 'react-native-matrix-crypto'
import { DEMO_DEVICE_ID, DEMO_USER_ID } from './cryptoConfig'

/**
 * What survives a configuration change, reported once per mount.
 *
 * WHY THIS EXISTS
 *
 * Folding or unfolding a phone is a configuration change, and a
 * configuration change an activity has not declared destroys and recreates
 * that activity while the process keeps running. This library keeps its
 * crypto machine, its store handle and its native observer registration in
 * Rust statics that are scoped to the process, and keeps its listener set
 * in JavaScript module scope, while a React tree built on
 * `useEffect(() => onCryptoSignal(h), [])` is torn down and rebuilt. Those
 * two lifetimes had never been observed against each other on hardware.
 *
 * The hazard is specific and was found once already: `signals.ts`
 * uninstalls the native observer when the last listener unsubscribes and
 * reinstalls it when the first one subscribes again, because an observer
 * left installed behind an empty listener set does not merely waste work,
 * it consumes announcements irrecoverably. An unmount/remount pair drives
 * exactly that transition. Whether it comes back correctly is a question
 * about a real device, not about a unit test.
 *
 * WHAT EACH LINE IS, AND WHAT IT IS NOT
 *
 * These are instrument lines, not checks. Nothing here passes or fails,
 * nothing reaches `PROBE_SUMMARY`, and `scripts/run-fold-test.sh` is what
 * reads them. The example app is not the bridge and may log; the bridge
 * itself never does.
 *
 * - `FOLD_MOUNT <n> subs=<s>` -- how many times this component has mounted
 *   in this JavaScript context, and how many `onCryptoSignal`
 *   subscriptions this app holds after the mount. `n` is the load-bearing
 *   one: it lives in module scope, so a run where it climbs 1, 2, 3 says
 *   the JavaScript context outlived the activity, and a run where it is 1
 *   every time says the context was rebuilt with it. The two cases have
 *   completely different consequences for everything below and cannot be
 *   told apart from the outside.
 * - `FOLD_UNMOUNT <n> subs=<s>` -- the cleanup ran. Its absence between two
 *   mounts is itself a result: it means the tree was rebuilt without the
 *   old one being torn down, which is the shape that leaks a listener.
 * - `FOLD_KEYS <hex8>` -- a fingerprint of the live machine's two identity
 *   keys. A fingerprint rather than the keys because a log line is the
 *   wrong place for key material even when the key is public and the
 *   identity is fictional; all this has to support is "same or not same
 *   across a fold", and equality of a hash answers that.
 * - `FOLD_MACHINE ok` / `FOLD_MACHINE err <kind>` -- whether the process
 *   still has the machine it had before. `getDeviceIdentityKeys` refuses a
 *   caller who names a different identity than the live machine holds and
 *   refuses when there is no machine at all, so it is a real question
 *   about the Rust static rather than a formality.
 * - `FOLD_STORE ok <n>` / `FOLD_STORE err <kind>` -- whether the SQLite
 *   store handle still answers. `getDeviceStatuses` reads it and writes
 *   nothing.
 *
 * NOTHING HERE MUTATES, AND THAT IS DELIBERATE
 *
 * `ProbeHarness`'s `key_upload_present` step asserts what a *fresh* device
 * offers to publish, so an instrument that called `takeOutgoingRequests`
 * would change the answer to the probe's own question. Both calls used
 * here are reads.
 *
 * The first mount's report waits for a machine to exist rather than
 * assuming one: on a cold launch this component mounts alongside
 * `GuidedFlow` and `ProbeHarness`, and neither has created the machine
 * yet. Until one does, `getDeviceIdentityKeys` rejects with
 * `not_initialised`, which is the correct answer to a question asked too
 * early and not something to report as a failure.
 */

/**
 * Module scope on purpose, and not reset. The question is what survives a
 * teardown of the React tree, so a counter that the teardown could reset
 * would answer a different one -- the same reasoning as `signalOrder.ts`.
 */
let mounts = 0
let subscriptions = 0

/** FNV-1a, 32 bit -- the same construction `observer.rs` uses for `EMIT_BUILD`. */
function fingerprint(text: string): string {
  let hash = 0x811c9dc5
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i) & 0xff
    hash = Math.imul(hash, 0x01000193) >>> 0
  }
  return hash.toString(16).padStart(8, '0')
}

const POLL_INTERVAL_MS = 500
const POLL_BUDGET_MS = 60000

async function reportWhatSurvived(): Promise<void> {
  const deadline = Date.now() + POLL_BUDGET_MS
  for (;;) {
    try {
      const keys = await getDeviceIdentityKeys(DEMO_USER_ID, DEMO_DEVICE_ID)
      console.log(
        `FOLD_KEYS ${fingerprint(`${keys.ed25519}:${keys.curve25519}`)}`,
      )
      console.log('FOLD_MACHINE ok')
      break
    } catch (e) {
      const kind = isCryptoError(e) ? e.kind : 'untyped'
      // `not_initialised` before anything has created the machine is the
      // expected answer on a cold launch, not a result. Any other kind is
      // reported at once: it is an answer, and waiting out the budget for
      // it would only delay saying so.
      if (kind !== 'not_initialised' || Date.now() >= deadline) {
        console.log(`FOLD_MACHINE err ${kind}`)
        return
      }
      await new Promise<void>(resolve => {
        setTimeout(resolve, POLL_INTERVAL_MS)
      })
    }
  }

  try {
    const statuses = await getDeviceStatuses(DEMO_USER_ID)
    console.log(`FOLD_STORE ok ${statuses.length}`)
  } catch (e) {
    console.log(`FOLD_STORE err ${isCryptoError(e) ? e.kind : 'untyped'}`)
  }
}

export function FoldWatch(): null {
  useEffect(() => {
    mounts += 1
    const n = mounts
    // The ordinary React Native idiom, which is the thing under test:
    // subscribe on mount, unsubscribe on unmount. A signal that arrives
    // while this is registered prints `FOLD_SIGNAL`; producing one needs a
    // verification peer, so a run with no peer is expected to print none.
    const unsubscribe = onCryptoSignal(signal => {
      console.log(`FOLD_SIGNAL ${signal.kind} mount=${n}`)
    })
    subscriptions += 1
    console.log(`FOLD_MOUNT ${n} subs=${subscriptions}`)
    void reportWhatSurvived()
    return () => {
      unsubscribe()
      subscriptions -= 1
      console.log(`FOLD_UNMOUNT ${n} subs=${subscriptions}`)
    }
  }, [])

  return null
}
