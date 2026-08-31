import {
  clearCryptoObserver,
  CryptoSignal as NativeCryptoSignal,
  CryptoSignal_Tags as NativeCryptoSignalTag,
  setCryptoObserver,
  TrustState as NativeTrustState,
} from './generated/matrix_crypto'
import type { CryptoScopeId, TrustState } from './types'
// Imported for the documentation below and used by nothing here.
// `{@link}` resolves against what is in scope in the file it is written in,
// so without this the four names the comments below send a reader to are
// plain text in an editor's hover: a link that promises navigation and does
// not deliver it. Type-only, so it is erased and adds no runtime edge, and
// `facade.ts` imports nothing from this module, so it adds no cycle either.
// `tsconfig.json` sets `noUnusedLocals: false`, which is what lets an import
// exist for a reader rather than for the compiler.
import type {
  acceptVerification,
  confirmScan,
  decryptEvent,
  getDeviceStatuses,
  getIdentityStatus,
  getVerificationStage,
  receiveSyncChanges,
  requestSelfVerification,
  submitScannedCode,
} from './facade'

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
  | { kind: 'verification_completed'; verificationId: string }
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
 *
 * **Written after the call it describes, never before, in both directions.**
 * This is a record of something that has happened, not an intention to make
 * it happen, and the two functions below are the only places the difference
 * can be got wrong. Setting it first is what shipped in `0.1.1`: a
 * `setCryptoObserver` that threw left this reading `true`, the early return
 * in `installNativeObserver` then swallowed every later subscribe, and the
 * channel was silent for the rest of the process with nothing thrown and
 * nothing logged. The failure it hid is the one this channel exists to
 * prevent, since an inbound verification request a product is never told
 * about expires ten minutes after it was sent.
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
 *
 * **A throw must therefore leave this module exactly as it found it.** The
 * flag is written after `setCryptoObserver` returns, so a failed install
 * records nothing and the next subscribe attempts it again. Retrying is the
 * right answer rather than a hopeful one: the condition that makes this
 * call fail is a JSI host object that is not there yet, which `index.ts`
 * describes and which is a property of the runtime at one moment rather
 * than of this process forever. Remembering the failure instead would be
 * the same defect with its sign reversed, and just as quiet.
 */
function installNativeObserver(): void {
  if (nativeInstalled) return
  setCryptoObserver({
    onSignal(signal: NativeCryptoSignal): void {
      emitCryptoSignal(cryptoSignalOf(signal))
    },
  })
  nativeInstalled = true
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
 * **The sync this lands in the middle of is the native side's problem, not
 * this one's.** The JavaScript thread is free while `await
 * receiveSyncChanges(..)` is in flight, so an unmount runs its cleanup
 * there, and the native producer reads the observer once at entry and
 * consumes afterwards. That is handled where it happens: an announcement
 * that finds nobody releases the registration it made, so the invitation is
 * offered again to whoever subscribes next.
 *
 * **Two windows this cannot close.** A hot reload re-evaluates this module,
 * resetting `nativeInstalled`, while the native side still holds the
 * observer built by the previous copy -- pointing at a listener set that is
 * now unreachable. Nothing runs on unload, so nothing can uninstall it. The
 * next `onCryptoSignal` replaces it (the native registry is a lock, not a
 * once-cell, for exactly this reason), but an invitation arriving in
 * between is consumed by the stale observer and lost the same way. That is
 * a development-time hazard rather than a shipped one, and it is recorded
 * rather than claimed away.
 *
 * **The second is inherent and ships.** The native side reads its observer,
 * hands the signal to a thread of its own, and returns; an unsubscribe
 * landing between that read and the delivery arriving here cannot be told
 * apart from a delivery, so nothing puts that invitation back. Closing it
 * would mean the sync path holding a lock across the call into JavaScript,
 * which is the deadlock the detached delivery exists to avoid. It is
 * narrower than it sounds, because `listeners` below is module state that
 * outlives this function: a component remounting before the delivery thread
 * runs receives the signal into the same set. The loss needs the set to be
 * empty at that instant and to stay empty until the invitation expires.
 *
 * **The same ordering rule as its counterpart, for a smaller but real
 * gain.** The flag is written after `clearCryptoObserver` returns, so a
 * clear that throws leaves it reading `true`, which is what it is: the native
 * side still holds the observer this module built, and that observer
 * dispatches into `listeners`, which is module state the failed unsubscribe
 * did not touch. Recording it as gone would lay a second registration over
 * a first that never left, and would make the next empty set take the early
 * return above instead of retrying the clear, which is the one thing that
 * can still put this right. The throw propagates, for the same reason its
 * counterpart's does.
 */
function uninstallNativeObserver(): void {
  if (!nativeInstalled) return
  clearCryptoObserver()
  nativeInstalled = false
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
    case NativeCryptoSignalTag.VerificationCompleted:
      return {
        kind: 'verification_completed',
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
 * **Three of the five variants have a producer, and all three belong to
 * device verification.** Subscribing installs the native observer, so a
 * listener registered here starts receiving as soon as this call returns;
 * the channel was silent for the whole of M1 and M2, and this is where that
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
 * - `trust_changed` -- something this library will now say differently about
 *   `user` changed. **Two things produce it and they are indistinguishable
 *   from the value alone**, which is why the rule for this variant is to
 *   read rather than to count. A comparison finished and a device belonging
 *   to `user` moved: {@link getDeviceStatuses} for that user says which. Or,
 *   when `user` is **your own** user id, the account's private signing keys
 *   arrived on this device by gossip from another of your devices, after
 *   {@link requestSelfVerification}: {@link getIdentityStatus} says so, with
 *   `privateKeysHeld === true`, and that is the moment a new login becomes
 *   able to sign. A self-verification produces both, on consecutive syncs,
 *   so a product that reads both answers when told is correct under either.
 * - `verification_completed` -- **a flow that was verified by scanning a
 *   code has finished, and `verificationId` names it.** It arrives on both
 *   screens: the one that showed a code and called {@link confirmScan}, and
 *   the one that read a code and called {@link submitScannedCode}. Without
 *   it a product had no way at all to learn that a code verification
 *   succeeded, because no call returns when the other side acknowledges,
 *   and {@link getVerificationStage} would have to be polled.
 *
 *   **It is not a `trust_changed`, and the difference is not cosmetic.** In
 *   two of the three modes the protocol defines, nothing about a *device*
 *   changes at this moment: what those flows verify is an identity. And for
 *   another user, {@link getDeviceStatuses} still reads unverified when this
 *   arrives, because verifying them signs their master key and your store
 *   does not carry that signature until a later key query brings it back.
 *   So read the durable answers when you get this, exactly as for
 *   `trust_changed`, and expect another user's devices to turn verified a
 *   sync or two later rather than instantly.
 *
 *   **Only a flow verified by a code produces it.** A short-string
 *   comparison announces its completion as `trust_changed` and nothing
 *   else, and a flow that was refused or timed out announces nothing at
 *   all: {@link getVerificationStage} is what says `'cancelled'`.
 *
 *   **That asymmetry is a known limit of this release, and it is the one
 *   that will cost you code.** The two variants carry disjoint halves of the
 *   same fact: `trust_changed` names a user and no flow, so you cannot tell
 *   which of two verifications with that user finished;
 *   `verification_completed` names a flow and no trust. So "show a success
 *   screen for *this* verification" is two paths, and the side that
 *   *received* an invitation cannot know in advance which it will get,
 *   because the peer decides that by scanning a code or by starting a string
 *   comparison. Hold your own map from `verificationId` to what you are
 *   showing, and treat either signal as "read the durable answer now".
 *
 *   The fix is additive and is deferred rather than forgotten: every
 *   completed flow announcing `verification_completed`, with `trust_changed`
 *   left exactly as it is. Nothing already true would stop being true. It is
 *   not in this release because it reaches back into the short-string flows
 *   settled two milestones ago, and re-settling those belongs to a change
 *   that can carry them rather than to the corner of one that added codes.
 * - `unexpected_device` and `key_missing` still have no producer. The
 *   conditions they name do occur, and reach you elsewhere: a missing key
 *   arrives as a rejected {@link decryptEvent} with kind `missing_key`, not
 *   as a `key_missing` signal here.
 *
 * # When they arrive, and what has to have happened first
 *
 * **Every producer runs inside {@link receiveSyncChanges}.** Nothing is
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
 * not lose **those** -- with the one exception named below, which is a real
 * exception and not a hedge.
 *
 * Four things it genuinely does not do. **A comparison's `trust_changed` is
 * not re-offered** -- ask {@link getDeviceStatuses}, which is the durable
 * answer and always was. Its sibling behaves the other way and the two are
 * worth keeping apart: the private-keys arrival **is** re-offered, because
 * the latch that makes it fire once is only touched while somebody is
 * listening, so an arrival that happened while you were away is announced on
 * the first sync after you resubscribe. {@link getIdentityStatus} is still
 * the durable answer to it, and reading that is still the rule.
 * A hot reload leaves the previous module copy's observer installed
 * until something subscribes again; an invitation arriving in that window
 * is consumed by a listener set nothing can reach. An unsubscribe can land
 * in the last instant of a sync, after the native side has read its
 * observer and before the signal reaches this module, and an invitation
 * caught there is not re-offered either -- narrower than it sounds, because
 * resubscribing before the delivery arrives still receives it, and closing
 * it entirely would mean your sync call holding a lock across a call into
 * JavaScript. And **one shape of invitation is not re-offered at all**: a
 * peer that opens the comparison
 * directly, without asking first -- see {@link acceptVerification} for who
 * does that and why it makes no difference to your code -- leaves nothing
 * behind that can be enumerated on a later sync. The sync that carried it
 * is its only witness, which is why "subscribe at start-up if you can"
 * above is the stronger advice for it.
 *
 * A listener that throws does not affect the others, and does not affect
 * the sync that produced the signal: delivery happens on a thread of the
 * library's own, after the call that caused it has completed.
 *
 * # It throws rather than hand you a channel that is not there
 *
 * **Returning normally has exactly one meaning: the native observer is
 * installed and this listener is on it.** Installing is the only thing this
 * call does that can fail, and it fails as a whole, so a failure is
 * reported by throwing out of here and never by returning an unsubscribe
 * function for something that will not deliver. The realistic cause is the
 * native module not being reachable, which `index.ts` describes; the throw
 * is whatever the generated binding raised, not a type of this library's
 * own, because there is nothing this layer could add to it.
 *
 * Nothing is left behind by a throw. The listener is not registered, so a
 * caller that catches one is not subscribed and is not silently holding the
 * observer open behind an empty set, and the next call here attempts the
 * install again rather than assuming it is beyond help.
 *
 * The ordinary integration subscribes inside an effect, where a throw
 * reaches the nearest error boundary rather than the code that called this,
 * and that is the intended outcome and not a wrinkle: it is the same
 * treatment the rest of this surface gives an unusable native module, and
 * it is louder than any value this function could return, all of which a
 * caller is free to ignore. What a product must never be able to do is wait
 * on this channel for a signal that was never going to arrive.
 */
export function onCryptoSignal(cb: (s: CryptoSignal) => void): Unsubscribe {
  // Install first, then register. Not a style choice: it is what makes a
  // failed subscribe leave nothing behind, with no rollback path to get
  // wrong. Nothing can be delivered in between, because `setCryptoObserver`
  // stores a handle and returns without calling through it, and this
  // function holds the JavaScript thread throughout.
  installNativeObserver()
  listeners.add(cb)
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
