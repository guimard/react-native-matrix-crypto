// Imported for the documentation in this file and used by nothing in it.
// `{@link}` resolves against what is in scope in the file it is written in,
// so without this every name below that sends a reader to a facade call is
// plain text in an editor's hover -- a link promising navigation it does not
// deliver. Type-only, so it is erased: no runtime import, and the cycle it
// makes with `facade.ts`, which imports the types below, exists only for the
// typechecker, which resolves it. `tsconfig.json` sets
// `noUnusedLocals: false`, which is what lets an import exist for a reader
// rather than for the compiler.
import type {
  acceptVerification,
  getDeviceStatuses,
  getVerificationMaterial,
  markRequestSent,
  receiveSyncChanges,
  startVerificationComparison,
} from './facade'

/**
 * Opaque identifier for a cryptographic scope.
 *
 * Today this wraps a Matrix room id. Tomorrow it may wrap an MLS group id.
 * Nothing in the public API says "room", so spec section 6's agility
 * requirement holds by construction rather than by convention.
 */
export type CryptoScopeId = string & { readonly __brand: unique symbol }

/**
 * The only way to construct a CryptoScopeId.
 * Note: this performs no runtime validation — the guarantee is compile-time only.
 */
export function asCryptoScopeId(raw: string): CryptoScopeId {
  return raw as CryptoScopeId
}

/**
 * Deliberately open. Adding 'mls' is an additive change and therefore a minor
 * version bump, per spec section 4bis.4. Consumers must handle unknown values.
 */
export type CryptoAlgorithm = 'megolm' | 'olm' | (string & {})

/**
 * Product-facing trust signal. Only 'verified' has cryptographic value.
 *
 * **Closed, unlike `CryptoAlgorithm` and `CryptoErrorKind`.** A product may
 * switch on this exhaustively, and is meant to: a trust decision with a
 * silent default branch is the shape this library exists to prevent.
 *
 * - `'unverified'` — this library holds the device's keys and has no reason
 *   to trust it beyond that. Every device reads this until a comparison
 *   finishes. A device an administrator has blacklisted reads it too: this
 *   build exposes no call that can set that state, so folding it here says
 *   exactly as much as this build can honestly say.
 * - `'recognized'` — **not produced by this build.** Reserved for a device
 *   believable without a person having compared anything, which needs
 *   cross-signing. Declared now because widening a closed union later
 *   breaks every consumer that switched on it exhaustively, and would do so
 *   precisely when a product had stopped expecting the shape to move. Write
 *   the branch; it will not run yet.
 * - `'verified'` — a person compared a short authentication string on this
 *   device and on the far one, both said it matched, and the flow
 *   completed. See {@link getDeviceStatuses}, including why your own device
 *   reads this from the moment it exists and therefore proves nothing.
 *
 * **This is about a device, not about an event.** A completed comparison
 * does not change what a decrypted event says about its sender, because the
 * event path consults cross-signing and a comparison sets local trust. M3
 * design, section 7, question 6.
 */
export type TrustState = 'unverified' | 'recognized' | 'verified'

/**
 * How far along a verification flow is.
 *
 * **Closed**, like {@link TrustState} and for the same reason: a product
 * branches on this to decide what to show, and a stage it has never seen
 * must be a compile error rather than a silent default.
 *
 * Deliberately coarser than the nineteen states the underlying protocol
 * distinguishes. What a caller has to decide is which of a small set of
 * things to do next, and every distinction that does not change that answer
 * is one this surface would be inviting a product to branch on for no
 * reason.
 *
 * - `'requested'` — asked for, by one side or the other, and not yet
 *   answered. The other side must call {@link acceptVerification}.
 * - `'ready'` — both sides have agreed, and either may now call
 *   {@link startVerificationComparison}.
 * - `'started'` — the comparison has begun and the keys are not exchanged
 *   yet, so there is nothing to show. **A flow that stays here has one of
 *   two causes, and they need opposite things done about them.** If the
 *   *other* side opened the comparison, their start is a question this side
 *   has not answered: call {@link acceptVerification} again, and only then
 *   wait. Otherwise the flow's requests were drained and never reported
 *   sent, and {@link markRequestSent} is what moves it. Which one you are
 *   in follows from who started: a side that never called
 *   {@link startVerificationComparison} and finds itself here is in the
 *   first. See {@link getVerificationMaterial}, which reports both as
 *   `'material_not_ready'`.
 * - `'keys-exchanged'` — the short authentication string is available.
 *   Show it, and ask.
 * - `'confirmed'` — this side has said the strings match; the other side
 *   has not yet.
 * - `'done'` — both sides said so. The other device now reads `'verified'`
 *   from {@link getDeviceStatuses}.
 * - `'cancelled'` — over without a verification, whether a side refused, a
 *   side abandoned it, or it timed out.
 */
export type VerificationStage =
  | 'requested'
  | 'ready'
  | 'started'
  | 'keys-exchanged'
  | 'confirmed'
  | 'done'
  | 'cancelled'

/**
 * One symbol of a short authentication string, with the word for it.
 *
 * `description` is the protocol's own English word for the symbol. A
 * product showing these in another language looks the word up from the
 * symbol's position in the array, which is why both travel together.
 */
export interface SasEmoji {
  symbol: string
  description: string
}

/**
 * The short authentication string, in both of the forms the protocol can
 * produce.
 *
 * **Show one of these to a person and ask whether it matches what the other
 * person sees, out of band.** Comparing them programmatically across a
 * channel this flow itself established proves nothing: that channel is what
 * is being verified.
 *
 * **Treat this value as secret while the flow is open.** Anything that
 * learns it learns what an interposed party would need to answer the
 * comparison correctly. Do not log it, do not persist it, do not put it in
 * a crash report. The Rust core hand-writes a redacting debug format for
 * exactly this reason and cannot reach across this boundary to do the same
 * for JavaScript.
 *
 * `emoji` is optional and `decimals` is not, and that asymmetry belongs to
 * the protocol rather than being a convenience: the symbol form exists only
 * when both sides negotiated it, so a screen offering only symbols has a
 * live path with nothing to show. The digits are always there once the keys
 * are exchanged.
 */
export interface SasMaterial {
  emoji?: SasEmoji[]
  decimals: [number, number, number]
}

/**
 * The five fields `receiveSyncChanges` reads. Named as the native call names
 * them, not as a `/sync` response names them: the two vocabularies have no
 * member in common, and renaming here would only move the rename into a
 * place with no compile-time help.
 *
 * Every field is optional and defaults independently, native-side, when
 * absent. Omit a field the caller has nothing for; do not set it to
 * `undefined` explicitly instead -- `encryptionSlice` (in `facade.ts`) only
 * ever assigns a key it has a real value for, and a hand-built `SyncDelta`
 * should follow the same rule so `Object.keys` on the result means what it
 * looks like it means.
 */
export interface SyncDelta {
  to_device_events?: unknown[]
  changed_devices?: unknown
  one_time_keys_counts?: Record<string, number>
  unused_fallback_keys?: string[]
  next_batch_token?: string
}

/**
 * What this library knew about the sender of one decrypted event, at the
 * moment it decrypted it.
 *
 * **This is not {@link TrustState}, and the difference is why there are
 * two.** `TrustState` describes a *device*, and a completed comparison
 * changes it. This describes *one event's sender at one moment*, and a
 * completed comparison does not change it. Two subjects, two vocabularies.
 * Folding them would lose the difference between an unverified identity, an
 * unsigned device and a sender mismatch, which are three different things
 * for a product to do about one event.
 *
 * **Closed**, like `TrustState` and {@link VerificationStage}: switch on
 * `state`, then on `reason`, and the compiler tells you when a later
 * version adds a case.
 *
 * ## Three of these cannot happen yet, and the ones that can
 *
 * `'verified'`, `'unverified_identity'` and `'verification_violation'` each
 * require the sending device to carry a signature from a cross-signing
 * identity its owner published. Nothing in this release publishes or
 * follows one, so **none of the three can occur**. Write the branches; they
 * will not run yet. They are declared now because the union is closed, and
 * widening a closed union later is a breaking change for every consumer
 * that switched on it exhaustively -- and because the alternative to a
 * complete type is not a smaller true one but a different false one: a
 * four-value type would say that four values is all this vocabulary has,
 * which is not true of what it models.
 *
 * The three that do occur are `'unsigned_device'` (the ordinary case for
 * every peer), `'no_device'` in both its forms, and `'mismatched_sender'`.
 *
 * ## `'verified'` in particular
 *
 * **Completing a verification with someone does not make their events read
 * `'verified'`.** It makes their *device* read `'verified'` from
 * {@link getDeviceStatuses}, which is a different question with a different
 * answer. The decrypted-event path consults cross-signing; a short-string
 * comparison sets local trust. If your product needs "did this specific
 * event come from a device we have verified", the honest answer today is
 * assembled from two calls, and this field alone is not it. M3 design,
 * section 7, questions 3 and 6.
 *
 * ## `'mismatched_sender'` in particular
 *
 * The only member here reporting an act rather than an absence of evidence:
 * the event's claimed sender is not the owner of the session that encrypted
 * it. Decryption succeeded -- the ciphertext really was encrypted with a
 * session this device holds -- and the `sender` field is still false. Treat
 * it as an impersonation signal, not as a weaker `'no_device'`.
 */
export type SenderVerification =
  // NOT PRODUCED BY THIS RELEASE. The event came from a device belonging to
  // a user this library has verified -- the only state in which authenticity
  // is guaranteed. Needs a published cross-signing master key; completing a
  // comparison does not produce it. See the type's doc comment above.
  | { state: 'verified' }
  // The sending device is known and carries no cross-signature. The ordinary
  // case for every peer in this release, before and after a comparison alike.
  | { state: 'unverified'; reason: 'unsigned_device' }
  // NOT PRODUCED BY THIS RELEASE. The device is cross-signed by its owner and
  // that identity is unverified. Needs a published master key.
  | { state: 'unverified'; reason: 'unverified_identity' }
  // NOT PRODUCED BY THIS RELEASE. The device is cross-signed, that identity
  // was verified once, and it is not the same identity now. Needs a published
  // master key and a previous verification of it.
  | { state: 'unverified'; reason: 'verification_violation' }
  // The claimed sender is not the owner of the session that encrypted the
  // event. An impersonation signal; decryption succeeded regardless.
  | { state: 'unverified'; reason: 'mismatched_sender' }
  // No device could be linked to the event: `'missing'` because none is in
  // the store, `'insecure_source'` because the key came from an imported
  // session, a legacy backup or an unsafe forward.
  | { state: 'unverified'; reason: 'no_device'; problem: 'missing' | 'insecure_source' }

/** Typed envelope for an encrypted or decrypted event. */
export interface EventEnvelope {
  scope: CryptoScopeId
  /**
   * From `encryptEvent`, the group-session algorithm this build used.
   *
   * From `decryptEvent`, spec section 7.1: this library decrypts events, it
   * does not authenticate their senders. This value is read from the
   * incoming event, not independently verified, and is **unauthenticated
   * transport metadata** — treat it accordingly, not as a claim this
   * library has confirmed. Not scoped to a milestone, because the milestone
   * a reader would infer from it has passed and the property has not: it
   * holds until cross-signing lands, which is M4.
   */
  algorithm: CryptoAlgorithm
  eventType: string
  /**
   * **Do not trust this field's name on the decrypt path.**
   *
   * From `encryptEvent`, this is the wire ciphertext: send it as the
   * content of your `m.room.encrypted` event.
   *
   * From `decryptEvent`, this is the **plaintext** that call just
   * recovered. One type describes both directions, so the name comes from
   * the direction that produced it first and is wrong for the other. There
   * is no second field to read instead.
   *
   * The consequence is a handling rule, not a naming quibble. Everything a
   * product does to plaintext, it must do to this value on the decrypt
   * path: do not log it, do not persist it unencrypted, do not put it in a
   * crash report or an analytics event, and do not let it into a `console`
   * statement written while debugging. The Rust core hand-writes a
   * redacting `Debug` for exactly this reason, and it cannot reach across
   * this boundary to do the same for JavaScript.
   */
  ciphertext: Uint8Array
  /**
   * Fully qualified `@user:server`, verbatim. Spec section 10.
   *
   * From `encryptEvent`, this device's own identity — authenticated by
   * definition.
   *
   * From `decryptEvent`, spec section 7.1: this library decrypts events, it
   * does not authenticate their senders. This is the sender the
   * homeserver delivered on the outer, not-yet-decrypted event, not a
   * value this library independently confirmed, and it is
   * **unauthenticated transport metadata**. Verifying the sending device
   * does not change that; cross-signing is what would, and it is M4. A
   * product that reads it as the cryptographic sender of a successfully
   * decrypted event has assumed something this library does not provide,
   * and that
   * assumption is the shape impersonation takes. Read it together with
   * `senderVerification` below, which is what says how much of a claim it
   * is -- and note that `'mismatched_sender'` is exactly the case where
   * this string is a lie decryption did not catch.
   */
  sender: string
  /**
   * What this library knew about the sender of this event **at the moment
   * it decrypted it** -- see {@link SenderVerification}, including which
   * three of its values cannot occur yet and why completing a verification
   * does not change this one.
   *
   * **Present on every successful `decryptEvent`. Absent from
   * `encryptEvent`.** The same one-type-two-directions caveat `algorithm`
   * and `sender` above each carry, in its strongest form: those two hold a
   * real value in both directions, and this one is *discarded* on the
   * encrypt path rather than missing from it. The layer underneath does
   * receive a value when it encrypts, and that value is `'verified'` --
   * upstream reporting on this device's own keys, which is a statement
   * about a *device*, true of a machine that has never verified anything,
   * and the one word this release cannot honestly attach to an event. It is
   * dropped rather than forwarded onto the field a decrypted event reads.
   * Absent here means "this question was not asked of this event".
   *
   * **It is a snapshot, and it can go stale.** Upstream defines it as the
   * state of the sending device at the time of decryption: it "may change
   * in the future if a device gets verified or deleted", and callers who
   * persist it are told to mark it dirty when a device change is received
   * down the sync. That obligation is yours once you hold this value. The
   * trigger is already in your hands -- `device_lists.changed` on the
   * `/sync` response you pass to {@link receiveSyncChanges} -- and nothing
   * in this library re-derives a stored value for you. A record that looks
   * static is not the same as a fact that stays true.
   */
  senderVerification?: SenderVerification
}
