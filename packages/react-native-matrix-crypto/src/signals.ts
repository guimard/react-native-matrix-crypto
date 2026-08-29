import {
  CryptoSignal as NativeCryptoSignal,
  CryptoSignal_Tags as NativeCryptoSignalTag,
  setCryptoObserver,
  TrustState as NativeTrustState,
} from './generated/matrix_crypto'
import type { CryptoScopeId, TrustState } from './types'

/**
 * Typed, silent by default. Takes no product decision. Spec sections 7, 11.
 *
 * State changes that belong to no call in flight and every subscriber
 * should learn about. `runProbe`'s own diagnostic (`probe_started`) is not
 * one of these -- it is a per-call result of that function, not a crypto
 * state change, so it never reaches this union or this channel. See
 * `probe.ts`'s `ProbeSignal` and its `runProbe` comment.
 *
 * The union is open to additions and closed to removals: adding a variant
 * is a minor version bump per spec section 4bis.4, so a consumer must
 * handle a `kind` it has never seen rather than assume this list is final.
 */
export type CryptoSignal =
  | { kind: 'trust_changed'; user: string; state: TrustState }
  | { kind: 'verification_requested'; user: string; device: string; verificationId: string }
  | { kind: 'unexpected_device'; scope: CryptoScopeId; user: string }
  | { kind: 'key_missing'; scope: CryptoScopeId }

export type Unsubscribe = () => void

const listeners = new Set<(s: CryptoSignal) => void>()

/**
 * Whether the native observer has been installed for this process.
 *
 * Installed on the first subscription rather than at import time, which is
 * what makes the channel free when nobody is listening: the Rust side reads
 * whether an observer exists before it does any work, so an application
 * that never calls {@link onCryptoSignal} pays nothing on its sync path.
 */
let nativeInstalled = false

/**
 * Installs the one native observer this process has, at most once.
 *
 * Deliberately not a function a product calls. A registration call that a
 * caller can forget would fail by producing silence, which is precisely
 * what this channel already looked like and precisely the failure mode the
 * `trackUsers` rejection ruled out. Subscribing is what installs it, so
 * there is nothing to forget.
 *
 * Not wrapped in a `try`/`catch`: if the native module is not installed,
 * subscribing must throw where the mistake is rather than return an
 * unsubscribe function for a channel that will never deliver.
 */
function installNativeObserver(): void {
  if (nativeInstalled) return
  nativeInstalled = true
  setCryptoObserver({
    onSignal(signal: NativeCryptoSignal): void {
      emitCryptoSignal(cryptoSignalOf(signal))
    },
  })
}

/**
 * Rebuilds the public union from the generated tagged one.
 *
 * `switch` on the tag with no `default`, like `facade.ts`'s own readers: a
 * variant added to the Rust enum must fail this file to compile rather than
 * fall through to a silent drop. The `never` return below is what makes
 * that a compile error rather than an implicit `undefined`.
 */
function cryptoSignalOf(signal: NativeCryptoSignal): CryptoSignal {
  switch (signal.tag) {
    case NativeCryptoSignalTag.TrustChanged:
      return {
        kind: 'trust_changed',
        user: signal.inner.user,
        state: trustStateOf(signal.inner.state),
      }
    case NativeCryptoSignalTag.VerificationRequested:
      return {
        kind: 'verification_requested',
        user: signal.inner.user,
        device: signal.inner.deviceId,
        verificationId: signal.inner.verificationId,
      }
  }
}

/** Exhaustive by compile error, like `facade.ts`'s twin of this function. */
function trustStateOf(trust: NativeTrustState): TrustState {
  switch (trust) {
    case NativeTrustState.Unverified:
      return 'unverified'
    case NativeTrustState.Recognized:
      return 'recognized'
    case NativeTrustState.Verified:
      return 'verified'
  }
}

/**
 * Subscribes to the crypto signal channel. Returns an unsubscribe function.
 *
 * **Two of the four variants have a producer, and both belong to device
 * verification.** Subscribing installs the native observer, so a listener
 * registered here starts receiving as soon as this call returns; the
 * channel was silent for the whole of M1 and M2, and this is where that
 * stops being true.
 *
 * - `verification_requested` -- **another device has asked to verify
 *   itself against this one, and `verificationId` is what you pass to
 *   {@link acceptVerification}.** This is the only way a receiving side
 *   learns that identifier. There is no call that lists inbound flows, and
 *   before this signal existed a product had to filter its own
 *   `to_device_events` for `m.key.verification.request` and read
 *   `content.transaction_id` out of one -- a protocol detail this library
 *   keeps to itself everywhere else.
 * - `trust_changed` -- a comparison finished and a device belonging to
 *   `user` moved. Read {@link getDeviceStatuses} for that user to see
 *   which; the signal deliberately does not duplicate that answer.
 * - `unexpected_device` and `key_missing` still have no producer. The
 *   conditions they name do occur, and reach you elsewhere: a missing key
 *   arrives as a rejected {@link decryptEvent} with kind `missing_key`, not
 *   as a `key_missing` signal here.
 *
 * # When they arrive, and what has to have happened first
 *
 * **Both producers run inside {@link receiveSyncChanges}.** Nothing is
 * announced on a timer, and nothing is announced for an event you have not
 * fed in. A product that stops syncing stops being told.
 *
 * **An invitation from a device this library has never been told about
 * builds no flow, and so is not announced.** That is not a gap in the
 * channel; it is the channel refusing to hand you an identifier no call
 * here would answer to. See {@link acceptVerification} for the recovery,
 * which is unchanged except that you no longer have to read anything out of
 * the event you kept.
 *
 * # Subscribe before you sync
 *
 * A signal produced while nobody is listening is dropped, not queued. In
 * practice that means subscribing at start-up, before the first
 * {@link receiveSyncChanges}, rather than when a screen mounts -- an
 * invitation announced to nobody is an invitation the person on the other
 * device is waiting on, and it expires in ten minutes.
 *
 * A listener that throws does not affect the others, and does not affect
 * the sync that produced the signal: delivery happens on a thread of the
 * library's own, after the call that caused it has completed.
 */
export function onCryptoSignal(cb: (s: CryptoSignal) => void): Unsubscribe {
  installNativeObserver()
  listeners.add(cb)
  return () => {
    listeners.delete(cb)
  }
}

/**
 * Internal. Called by the shim when the native observer fires.
 *
 * Exported for this module's own tests, which drive it directly to exercise
 * fan-out and isolation without a native module. The shipped path into it
 * is `installNativeObserver` above, and nothing else calls it.
 */
export function emitCryptoSignal(signal: CryptoSignal): void {
  // Snapshot before dispatch: a listener that subscribes while we are
  // iterating must not receive the signal that triggered its own
  // registration. Unsubscribing mid-dispatch remains safe either way.
  for (const listener of [...listeners]) {
    try {
      listener(signal)
    } catch {
      // Isolate. One throwing listener must never starve the others, and
      // that matters more now than it did while nothing emitted: this
      // channel is how a receiving product learns an invitation exists, so
      // a buggy listener registered ahead of the one that opens the
      // verification screen would otherwise make inbound verification stop
      // working with no error anywhere.
      // Deliberately silent - the bridge has no logger.
    }
  }
}
