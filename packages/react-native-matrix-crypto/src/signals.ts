import {
  clearCryptoObserver,
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
 * Whether the native observer is installed for this process.
 *
 * Tracked here so it can be kept in lockstep with `listeners`: installed
 * when the set becomes non-empty, uninstalled when it becomes empty again.
 * Nothing else may write it.
 */
let nativeInstalled = false

/**
 * Installs the one native observer this process has.
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
 * Uninstalls it again once the last listener has gone.
 *
 * **This is not tidying up.** While an observer is installed the native
 * side does its full pass on every sync: an inbound invitation is
 * enumerated, *registered*, marked announced, and delivered here -- into an
 * empty listener set. Registration is the producer's deduplication, so the
 * same invitation is never announced again for the rest of its life, and no
 * call lists inbound flows. The invitation is then simply lost until it
 * expires, ten minutes after it was sent, with no error anywhere.
 *
 * The shape that reaches this is `useEffect(() => onCryptoSignal(h), [])`
 * -- subscribe on mount, unsubscribe on unmount -- which is the ordinary
 * React Native idiom, so it is the default integration rather than an edge
 * case. Uninstalling restores the property the channel rests on: with
 * nobody listening, nothing is consumed, and whatever is still live is
 * announced to whoever subscribes next.
 *
 * **One window this cannot close.** A hot reload re-evaluates this module,
 * resetting `nativeInstalled`, while the native side still holds the
 * observer built by the previous copy -- pointing at a listener set that is
 * now unreachable. Nothing runs on unload, so nothing can uninstall it. The
 * next `onCryptoSignal` replaces it (the native registry is a lock, not a
 * once-cell, for exactly this reason), but an invitation arriving in
 * between is consumed by the stale observer and lost the same way. That is
 * a development-time hazard rather than a shipped one, and it is recorded
 * rather than claimed away.
 */
function uninstallNativeObserver(): void {
  if (!nativeInstalled) return
  nativeInstalled = false
  clearCryptoObserver()
}

/**
 * Rebuilds the public union from the generated tagged one.
 *
 * `switch` on the tag with no `default`, like `facade.ts`'s own readers: a
 * variant added to the Rust enum must fail this file to compile rather than
 * fall through to a silent drop.
 *
 * The mechanism is `noImplicitReturns` in this package's `tsconfig.json`,
 * together with the declared return type. A tag with no `case` makes the
 * function fall off its end, `noImplicitReturns` rejects a function that
 * returns a value on some paths and not others, and the declared
 * `CryptoSignal` means the implicit `undefined` is not assignable anyway.
 * There is no explicit `never` here and none is needed; an earlier draft of
 * this comment claimed one, which sent the next reader looking for it.
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
 *   {@link acceptVerification}.** This is the only way *this library* hands
 *   you that identifier: there is no call that lists inbound flows. The
 *   value itself is the `transaction_id` on the wire, and before this
 *   signal existed a product had to go and get it -- filter its own
 *   `to_device_events` for `m.key.verification.request` and read the field
 *   out of one, which is a protocol detail this library keeps to itself
 *   everywhere else.
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
 * # What happens across an unsubscribe, which is less than you might fear
 *
 * **The channel re-offers what is still live rather than replaying what it
 * once sent.** Nothing is queued for a subscriber that is not there; what
 * happens instead is that nothing is *consumed* while nobody is listening,
 * because the native producer does no work at all with no observer
 * installed. So an invitation that arrives while you are unsubscribed is
 * still `requested` when you come back, and the first
 * {@link receiveSyncChanges} after you resubscribe announces it. Subscribe
 * at start-up if you can, but `useEffect(() => onCryptoSignal(h), [])` does
 * not lose invitations.
 *
 * Two things it genuinely does not do. A `trust_changed` for a comparison
 * that finished while you were away is not re-offered -- ask
 * {@link getDeviceStatuses}, which is the durable answer and always was.
 * And a hot reload leaves the previous module copy's observer installed
 * until something subscribes again; an invitation arriving in that window
 * is consumed by a listener set nothing can reach.
 *
 * A listener that throws does not affect the others, and does not affect
 * the sync that produced the signal: delivery happens on a thread of the
 * library's own, after the call that caused it has completed.
 */
export function onCryptoSignal(cb: (s: CryptoSignal) => void): Unsubscribe {
  listeners.add(cb)
  installNativeObserver()
  return () => {
    listeners.delete(cb)
    // The last one out uninstalls. See `uninstallNativeObserver` for why an
    // observer left installed behind an empty set does not merely waste
    // work -- it consumes announcements irrecoverably.
    if (listeners.size === 0) uninstallNativeObserver()
  }
}

/**
 * Internal. Called by the shim when the native observer fires, and by
 * nothing else -- `installNativeObserver` above is its only caller.
 *
 * Not exported. It was, so that this module's tests could drive fan-out and
 * isolation without a native module; they now drive the installed observer
 * instead, which exercises the reader as well as the fan-out, so the export
 * was a hole in the public shape with nothing left behind it.
 * `index.ts` never re-exported it, so removing it changes no published API.
 */
function emitCryptoSignal(signal: CryptoSignal): void {
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
