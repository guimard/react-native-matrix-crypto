import type {
  CryptoAlgorithm,
  CryptoScopeId,
  EventEnvelope,
  SenderVerification,
  SasEmoji,
  SasMaterial,
  SyncDelta,
  TrustState,
  VerificationStage,
} from './types'
import { asCryptoScopeId } from './types'
import { toCryptoError } from './errors'
import {
  acceptVerification as nativeAcceptVerification,
  bootstrapIdentity as nativeBootstrapIdentity,
  cancelVerification as nativeCancelVerification,
  confirmVerification as nativeConfirmVerification,
  createCryptoMachine as nativeCreateCryptoMachine,
  decryptEvent as nativeDecryptEvent,
  deviceIdentityKeys as nativeDeviceIdentityKeys,
  deviceStatuses as nativeDeviceStatuses,
  encryptEvent as nativeEncryptEvent,
  identityStatus as nativeIdentityStatus,
  markRequestFailed as nativeMarkRequestFailed,
  markRequestSent as nativeMarkRequestSent,
  openCryptoStore as nativeOpenCryptoStore,
  receiveSyncChanges as nativeReceiveSyncChanges,
  requestSelfVerification as nativeRequestSelfVerification,
  requestVerification as nativeRequestVerification,
  shareScopeKey as nativeShareScopeKey,
  startVerificationComparison as nativeStartVerificationComparison,
  takeOutgoingRequests as nativeTakeOutgoingRequests,
  SenderVerification as NativeSenderVerification,
  TrustState as NativeTrustState,
  verificationMaterial as nativeVerificationMaterial,
  verificationStage as nativeVerificationStage,
  VerificationStage as NativeVerificationStage,
} from './generated/matrix_crypto'
// Type-only, and imported rather than restated structurally: a field renamed
// in the Rust record must be a compile error here rather than a silently
// absent value. `sasMaterialOf` below is the one place that reads it.
import type { SasMaterial as NativeSasMaterial } from './generated/matrix_crypto'

function notImplemented(name: string): Promise<never> {
  return Promise.reject(toCryptoError({ name: 'NotImplemented', reason: `${name} is not implemented yet` }))
}

/**
 * `JSON.stringify` returns the *value* `undefined`, not a string, for
 * `undefined` itself and for a few other top-level inputs that type-check
 * fine against `unknown` (a function, a symbol). Passed straight through,
 * that `undefined` would reach a native `string` parameter as `undefined`,
 * surfacing later as an untyped `kind: 'unknown'` error rather than
 * `malformed_payload` at the boundary that actually rejected it. Rejected
 * here instead, before any native call -- shared by every function below
 * that stringifies an `unknown` payload.
 */
function stringifyOrMalformed(value: unknown): string {
  let json: string | undefined
  try {
    json = JSON.stringify(value)
  } catch {
    // `JSON.stringify` has two failure modes and this one was missed until
    // server-side recovery's own tests hit it: a value it cannot represent
    // returns `undefined`, and a value that *refers to itself* throws a
    // `TypeError` instead. Uncaught, that leaves the boundary as a raw
    // `TypeError` rather than a `CryptoError`, so `isCryptoError` is false
    // and a product's error handling has nothing to read. A cycle is an
    // ordinary shape for an object a product assembled itself, which is
    // what every caller of this helper is handed.
    throw toCryptoError({ name: 'MalformedPayload' })
  }
  if (json === undefined) {
    throw toCryptoError({ name: 'MalformedPayload' })
  }
  return json
}

// Spec section 5's surface, re-typed onto the branded scope and the open
// algorithm tag. Written when the types were real and the runtime was not;
// M2 landed the runtime behind all of it, and the sentence is kept because
// it records why the shapes were frozen before anything implemented them.

export interface CryptoMachineConfig {
  userId: string
  deviceId: string
  storePath: string
  /**
   * Required, not optional: an optional field lets a caller omit it by
   * accident and get unencrypted key material with no signal. `string |
   * null` forces the caller to write `null` deliberately, where a code
   * review can see it. Spec section 6: the store is encrypted with whatever
   * passphrase the product supplies here.
   */
  storePassphrase: string | null
}

export interface DeviceStatus {
  deviceId: string
  trust: TrustState
}

/**
 * What the product must send to its homeserver, or feed to another device
 * -- design doc section 3bis. `body` is JSON this library never
 * interprets, sent as-is; `kind` is an open tag mirroring upstream's own
 * request kinds, deliberately typed `string` rather than a union for the
 * same reason `CryptoAlgorithm` is open (the set grows upstream, and a
 * consumer must already handle a value it does not recognise).
 *
 * Today's values, the endpoint each addresses, and what
 * {@link markRequestSent}'s own `responseJson` must contain to report one
 * sent -- that endpoint's response body, unwrapped, exactly as the
 * homeserver returned it, and nothing this library adds or removes. No
 * count stands over the table: the tag is open, the table grew by a row in
 * this release, and a count is the part of a claim most likely to go stale
 * and least likely to be re-read.
 *
 * **A wrong `responseJson` is not reliably rejected**, so do not treat the
 * column below as validated input. A body that is *not* shaped like that
 * endpoint's response is always rejected with `malformed_payload`: being an
 * object with no keys, or carrying at least one of the fields in its row
 * below, is what that means.
 *
 * **Being shaped right is necessary, not sufficient.** A body carrying a real
 * field alongside a Matrix error's `errcode`, a gateway's `error` or a
 * challenge's `flows` is still rejected, and `{}` is rejected for
 * `keys_upload`, `keys_claim` and `room_message`, whose responses each have
 * one required field. What survives all of that, and why, is set out once in
 * {@link markRequestFailed}.
 *
 * | `kind` | Method & path | `responseJson` must contain |
 * |---|---|---|
 * | `'keys_upload'` | `POST /_matrix/client/v3/keys/upload` | `{ one_time_key_counts: { [algorithm: string]: number } }` |
 * | `'keys_query'` | `POST /_matrix/client/v3/keys/query` | `{ device_keys?, master_keys?, self_signing_keys?, user_signing_keys?, failures? }` (all optional; `{}` is valid) |
 * | `'keys_claim'` | `POST /_matrix/client/v3/keys/claim` | `{ one_time_keys: {...}, failures? }` |
 * | `'to_device'` | `PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}` | `{}`, and only `{}`. The machine ignores the contents and the response type declares no fields, so there is no field that could widen the shape: an object with any key at all is rejected here |
 * | `'signature_upload'` | `POST /_matrix/client/v3/keys/signatures/upload` | `{ failures? }` (optional; `{}` is valid) |
 * | `'room_message'` | `PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}` | `{ event_id: string }` |
 * | `'signing_keys_upload'` | `POST /_matrix/client/v3/keys/device_signing/upload` | `{}`, and only `{}`, for the reason `'to_device'` gives: the response type declares no fields, so no key could widen the shape. **This is the row where that costs you something.** The endpoint is user-interactive, its refusal is a `401` with a challenge, and `{}` is also what a 502 with no body arrives as. Branch on the status and send anything that is not a 2xx to {@link markRequestFailed}: reporting a challenge here would mark an identity published that never was |
 *
 * `'to_device'` and `'room_message'` carry their own path segments
 * (`eventType`/`txnId`, and for the latter `roomId` too) inside `body`
 * itself, alongside the wire content, since this library has no other way
 * to hand them to the product -- see the two disclosed exceptions the
 * core's own `describe_outgoing` documents for itself.
 *
 * See {@link shareScopeKey}'s own doc comment for the order a key has to
 * travel in, which is not optional: design doc section 3ter. See
 * {@link takeOutgoingRequests} for the separate rule that a *batch* must be
 * sent in the order it was handed to you, while marking stays unordered.
 */
export interface OutgoingRequest {
  /** Opaque; hand it back verbatim to {@link markRequestSent}. */
  id: string
  kind: string
  body: string
}

export async function createCryptoMachine(config: CryptoMachineConfig): Promise<void> {
  try {
    await nativeCreateCryptoMachine({
      userId: config.userId,
      deviceId: config.deviceId,
      storePath: config.storePath,
      // The generated binding's field is UniFFI's `Option<String>`, spelled
      // in TS as optional-with-undefined, not `| null`. This is the one
      // place that translates the facade's deliberate `null` into the shape
      // the native call expects.
      storePassphrase: config.storePassphrase ?? undefined,
    })
  } catch (e) {
    throw toCryptoError(e)
  }
}

export async function openCryptoStore(config: CryptoMachineConfig): Promise<void> {
  try {
    await nativeOpenCryptoStore({
      userId: config.userId,
      deviceId: config.deviceId,
      storePath: config.storePath,
      // See createCryptoMachine above: null -> undefined for the native call.
      storePassphrase: config.storePassphrase ?? undefined,
    })
  } catch (e) {
    throw toCryptoError(e)
  }
}

export function restoreCryptoMachine(_bundle: Uint8Array): Promise<void> {
  return notImplemented('restoreCryptoMachine')
}

/**
 * The five field names `receiveSyncChanges` actually reads -- matching
 * `matrix-sdk-crypto`'s own `EncryptionSyncChanges`, snake_case, not the
 * camelCase a product's own HTTP client may re-case a `/sync` response
 * into. Used only to decide whether an object payload names *any*
 * recognised field at all; see `receiveSyncChanges`'s own doc comment.
 */
const RECOGNISED_SYNC_FIELDS = [
  'to_device_events',
  'changed_devices',
  'one_time_keys_counts',
  'unused_fallback_keys',
  'next_batch_token',
]

/**
 * True for a non-empty object naming none of `RECOGNISED_SYNC_FIELDS`. The
 * core's own `SyncChangesPayload` defaults every field independently
 * (`#[serde(default)]`) and silently ignores unknown keys (no
 * `deny_unknown_fields` -- a homeserver adding a field this library does
 * not consume must keep working), so a differently-cased or entirely
 * unrecognised payload parses into an all-default value and reports
 * success while teaching the machine nothing. An empty object is *not*
 * flagged: `{}` is the shape an ordinary, uneventful sync sends, and doing
 * nothing with it is correct.
 */
function syncDeltaNamesNoRecognisedField(syncDelta: unknown): boolean {
  if (typeof syncDelta !== 'object' || syncDelta === null) return false
  const keys = Object.keys(syncDelta)
  return keys.length > 0 && !keys.some((key) => RECOGNISED_SYNC_FIELDS.includes(key))
}

/**
 * Maps a `/sync` response to the slice {@link receiveSyncChanges} consumes
 * -- the five-row rename table on that function's own doc comment, as code,
 * so a product never hand-writes it. A field is copied when its source key
 * is present at all, `null` included; it is not copied when the source key
 * is absent, which is what leaves it to `SyncDelta`'s own per-field default
 * rather than forwarding `undefined`.
 *
 * A transcription of `encryption_slice` in
 * `rust/matrix-crypto-core/tests/level_two_interop.rs`, which is the same
 * mapping exercised against a real homeserver and a third-party client, and
 * the two must stay identical in behaviour -- that Rust function is this
 * one's source of truth, not the other way around.
 */
export function encryptionSlice(sync: Record<string, unknown>): SyncDelta {
  const slice: SyncDelta = {}
  const toDevice = sync.to_device as Record<string, unknown> | undefined
  if (toDevice?.events !== undefined) slice.to_device_events = toDevice.events as unknown[]
  if (sync.device_lists !== undefined) slice.changed_devices = sync.device_lists
  if (sync.device_one_time_keys_count !== undefined) {
    slice.one_time_keys_counts = sync.device_one_time_keys_count as Record<string, number>
  }
  if (sync.device_unused_fallback_key_types !== undefined) {
    slice.unused_fallback_keys = sync.device_unused_fallback_key_types as string[]
  }
  if (sync.next_batch !== undefined) slice.next_batch_token = sync.next_batch as string
  return slice
}

/**
 * Feeds the encryption-relevant slice of a `/sync` response into the
 * crypto machine -- design doc section 7. This is how the machine learns
 * which devices exist: a product that never calls this encrypts to
 * nobody.
 *
 * **Accepted shape.** `syncDelta` must be a plain object using exactly
 * `matrix-sdk-crypto`'s own snake_case field names below, every one
 * optional and defaulting independently when absent:
 *
 * ```ts
 * {
 *   to_device_events?: object[]                         // raw to-device events, as received
 *   changed_devices?: { changed: string[]; left: string[] }
 *   one_time_keys_counts?: Record<string, number>
 *   unused_fallback_keys?: string[]
 *   next_batch_token?: string
 * }
 * ```
 *
 * **This is not a `/sync` response, and a `/sync` response is rejected.**
 * It is the encryption-relevant slice of one, under `matrix-sdk-crypto`'s
 * field names, and the two sets of names have no member in common: a real
 * `/sync` body's top-level keys are `next_batch`, `rooms`, `presence`,
 * `account_data`, `to_device`, `device_lists`,
 * `device_one_time_keys_count` and `device_unused_fallback_key_types`,
 * none of which is one of the five above. So passing the response verbatim
 * throws `malformed_payload` before native is called -- deliberately and
 * loudly, because the alternative was a call that resolves and teaches the
 * machine nothing.
 *
 * An earlier version of this paragraph said the whole response could be
 * handed over verbatim. That was false, and the guard eleven lines above
 * proved it false; it was corrected by the level 2 interoperability test,
 * which is the first thing that ever fed this function a payload a real
 * homeserver produced.
 *
 * Five fields must be renamed, and nothing else forwarded:
 *
 * | in a `/sync` response | in `syncDelta` |
 * | --- | --- |
 * | `to_device.events` | `to_device_events` |
 * | `device_lists` | `changed_devices` |
 * | `device_one_time_keys_count` | `one_time_keys_counts` |
 * | `device_unused_fallback_key_types` | `unused_fallback_keys` |
 * | `next_batch` | `next_batch_token` |
 *
 * Omit a field the response does not carry rather than passing
 * `undefined`; each defaults independently. Everything else the response
 * holds -- `rooms`, `presence`, `account_data` -- is no part of this
 * payload.
 *
 * Use {@link encryptionSlice} to build `syncDelta` from a `/sync` response
 * rather than writing this mapping again -- it is this same rename table,
 * as code:
 *
 * ```ts
 * await receiveSyncChanges(encryptionSlice(await fetchSync()))
 * ```
 *
 * `{}` is the shape an ordinary, uneventful sync sends, and is accepted:
 * it reports nothing, correctly. **camelCase silently does nothing**, and
 * this is the one call where that matters most -- every field above
 * defaults independently and unknown keys are ignored, so
 * `{ toDeviceEvents: [...] }` parses into an entirely-default payload,
 * resolves successfully, and teaches the machine nothing, indistinguishable
 * from `{}` on the caller's side (the return type is frozen `void`). A
 * non-empty payload naming *none* of the five fields above -- the shape a
 * camelCase mistake, or any other wrong shape, produces -- is rejected
 * with `malformed_payload` before native is ever called. A payload naming
 * at least one recognised field alongside others this library does not
 * consume (a homeserver-added `/sync` field, for instance) is accepted,
 * and the extra field is ignored -- tolerance for exactly that case is why
 * this guard checks for *some* recognised field rather than rejecting any
 * unrecognised one.
 *
 * Returns `void`, not the native call's own to-device/session counts: that
 * return type is frozen from M1a. A product that needs those counts reads
 * them off the sync response it already holds.
 */
export async function receiveSyncChanges(syncDelta: SyncDelta): Promise<void> {
  if (syncDeltaNamesNoRecognisedField(syncDelta)) {
    throw toCryptoError({ name: 'MalformedPayload' })
  }
  const syncDeltaJson = stringifyOrMalformed(syncDelta)
  try {
    await nativeReceiveSyncChanges(syncDeltaJson)
  } catch (e) {
    throw toCryptoError(e)
  }
}

export async function encryptEvent(
  scope: CryptoScopeId,
  eventType: string,
  payload: unknown,
): Promise<EventEnvelope> {
  const payloadJson = stringifyOrMalformed(payload)
  try {
    const encrypted = await nativeEncryptEvent(scope, eventType, payloadJson)
    // Destructured, not returned/field-accessed directly: a field added to
    // the generated record later must be a deliberate choice to expose,
    // not something that leaks through this boundary unreviewed. See
    // Global Constraints and the M1 final review finding fixed below at
    // getDeviceIdentityKeys.
    const { scope: encryptedScope, algorithm, eventType: encryptedEventType, ciphertext, sender } = encrypted
    return {
      scope: asCryptoScopeId(encryptedScope),
      algorithm,
      eventType: encryptedEventType,
      // The generated binding speaks ArrayBuffer; EventEnvelope speaks
      // Uint8Array, the idiomatic React Native shape -- same conversion
      // probe.ts's runProbe already makes for ProbeResult.payload.
      ciphertext: new Uint8Array(ciphertext),
      sender,
    }
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Decrypts a previously-received `m.room.encrypted` event for `scope` --
 * the same value passed to `encryptEvent`, since decryption needs it for
 * the same reason: the native call this delegates to requires an explicit
 * scope to look up the right group session, and reading one out of the
 * unauthenticated, not-yet-decrypted event JSON would mean trusting
 * attacker-influenced input for a security-relevant lookup.
 *
 * A deliberate break from the M1a-frozen `decryptEvent(rawEvent)`: that
 * shape cannot express a required scope without smuggling it into the
 * `unknown` (e.g. `{ scope, event }`), which compiles but hides a required
 * argument where the type system cannot see it and bypasses the branded
 * `CryptoScopeId` that exists precisely so a caller cannot pass a bare
 * string -- trading a compile error for a runtime one in a cryptographic
 * API. `getDeviceIdentityKeys` is the counter-case: its parameters stayed
 * because keeping them cost nothing. Here, keeping the frozen shape would
 * have cost the caller the type system.
 *
 * `rawEvent` is the `m.room.encrypted` event as received, verbatim --
 * JSON-stringified as-is before crossing to native.
 *
 * **This library decrypts events. It does not authenticate their
 * senders** -- spec section 7.1. The returned envelope's `sender` and
 * `algorithm` are read from the fields the homeserver delivered, not
 * independently verified, and are **unauthenticated transport metadata**.
 * That was scoped to "until cross-signing lands, which is M4" twice, and
 * cross-signing has now landed without changing it: these two fields are
 * never re-derived, whatever this library knows about the sender. What
 * cross-signing adds is the separate value below, not a promotion of these
 * two. Verifying the sending device does not change it either: see
 * {@link EventEnvelope.sender} and
 * {@link EventEnvelope.algorithm} for what that means and why. A product
 * that reads the sender of a successfully decrypted event as the
 * cryptographic sender has assumed something this milestone does not
 * provide, and that assumption is the shape impersonation takes.
 *
 * **What the returned envelope now adds is the size of that assumption.**
 * `senderVerification` carries what this library knew about the sender at
 * the moment it decrypted -- see {@link SenderVerification}. It does not
 * turn `sender` into an authenticated value. **It can read `'verified'`
 * through this surface from this release**, which it could not before: the
 * last missing step was the bridged call that lets a product create this
 * account's own cross-signing identity, and that call is
 * {@link bootstrapCrossSigning}. Reaching the value is still a chain rather
 * than a setting, and the chain is the seven steps
 * {@link SenderVerification} sets out; what changed is that every one of
 * them can now be driven from TypeScript. What the value can already do
 * without any of that is tell three different things
 * apart: an ordinary unsigned device, a device its owner cross-signed whose
 * owner you have not verified (`'unverified_identity'`, which this release
 * does produce, from any peer whose client has cross-signing set up), and
 * an event whose claimed sender is not the owner of the session that
 * encrypted it. The last of those is an impersonation signal a product
 * should react to. It is a snapshot taken at decryption time, not a live
 * value; see the field.
 */
export async function decryptEvent(scope: CryptoScopeId, rawEvent: unknown): Promise<EventEnvelope> {
  // `CryptoScopeId` performs no runtime validation (see types.ts) --
  // enforced by the type system for a caller that goes through it, but a
  // caller that bypasses it (plain JS, or `as any`) can still reach this
  // with a non-string value. Rejected before native is ever called, the
  // same discipline the old `{ scope, event }` guard applied.
  //
  // `malformed_identifier`, not `malformed_payload`: what is wrong is the
  // scope argument, and `rawEvent` may be perfectly good. This matches what
  // the core reports for a scope that is a string but not a parseable
  // identifier, so both ways of getting the scope wrong name the scope.
  if (typeof scope !== 'string') {
    throw toCryptoError({ name: 'MalformedIdentifier' })
  }
  const rawEventJson = stringifyOrMalformed(rawEvent)
  try {
    const decrypted = await nativeDecryptEvent(scope, rawEventJson)
    // Destructured, not returned directly. See encryptEvent above.
    const { scope: decryptedScope, algorithm, eventType, ciphertext, sender, senderVerification } = decrypted
    return {
      scope: asCryptoScopeId(decryptedScope),
      algorithm,
      eventType,
      // See encryptEvent above: ArrayBuffer -> Uint8Array.
      ciphertext: new Uint8Array(ciphertext),
      sender,
      // Derived from what native reported for this event, not inferred
      // from decryption having succeeded. Those are different questions,
      // and `mismatched_sender` is the case that proves it: the ciphertext
      // decrypts perfectly and the sender is still not who the event says.
      //
      // The absent case is handled here rather than inside
      // `senderVerificationOf`, which is not a style preference: a mapping
      // whose return type admits `undefined` is not exhaustive by compile
      // error, and that exhaustiveness is the only thing covering the one
      // arm no test may exercise. See the function's own doc comment.
      // Native only omits this on the encrypt path, which does not reach
      // here, so in practice this reads `Some` every time.
      senderVerification:
        senderVerification === undefined ? undefined : senderVerificationOf(senderVerification),
    }
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Ensures `scope` has a group session and shares it with `userIds`' known
 * devices -- the prerequisite `encryptEvent` documents for itself: a scope
 * must have a group session before encryption can succeed. Not a change to
 * the frozen surface; a new public name for what the core calls
 * `share_scope_key`, chosen to say what it does without naming an
 * algorithm (design doc section 3bis / spec section 6).
 *
 * **Delivering a key to a device with no prior session takes two calls to
 * this function, not one** -- design doc section 3ter, and the ordering is
 * not optional. A device this machine has never shared with has no Olm
 * session yet, and a session key can only reach a device over one; that
 * needs a `/keys/claim` round trip first. So the *first* call to
 * `shareScopeKey` for a new device queues a `'keys_claim'` request (among
 * {@link takeOutgoingRequests}' output) alongside a to-device request that
 * cannot yet carry the key -- it is an `m.room_key.withheld` notice, not
 * the key itself. Only once the product has sent that claim and reported
 * it with {@link markRequestSent} does calling `shareScopeKey` **again**,
 * for the same scope and users, produce the to-device request that
 * actually carries the session key. The full sequence, per device:
 *
 * 1. `shareScopeKey` (queues `'keys_claim'`, if no session yet)
 * 2. send the `'keys_claim'` request, `markRequestSent` it
 * 3. `shareScopeKey` again, same scope and users (now produces the
 *    key-carrying `'to_device'` request)
 * 4. send that request, `markRequestSent` it
 *
 * A product that calls this once, sends what {@link takeOutgoingRequests}
 * returns, and moves on silently under-delivers to every device it has not
 * already shared with -- the same silent-failure shape design doc section
 * 3bis is named for, one step further in. `receiveSyncChanges` (which
 * queues the `'keys_query'` step that must come before either of the above,
 * so this machine knows the device exists at all) and this function
 * together are what section 3ter's ordering describes.
 */
export async function shareScopeKey(scope: CryptoScopeId, userIds: string[]): Promise<void> {
  try {
    await nativeShareScopeKey(scope, userIds)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Drains every outstanding request this library needs the product to send
 * to its homeserver, or feed to another device -- design doc section 3bis.
 * An addition to the frozen surface, not a change to it: `OlmMachine` has
 * an outbound side (device/one-time key uploads, key queries, key claims,
 * and the to-device requests that actually carry a shared session key),
 * and discarding what this returns is the mistake section 3bis is named
 * for -- a machine that encrypts to nobody and never learns that any of it
 * happened.
 *
 * **The returned order is significant, and you must preserve it. Send the
 * requests in the order this returns them** -- not "start them in that order
 * and let them race": each one has to reach your homeserver before the next
 * is sent, because the server relays them to the other device in the order
 * it receives them.
 *
 * That is a real constraint with exactly one source, and it is worth naming
 * so it is not optimised away. A verification flow's last two messages are a
 * confirmation and the acknowledgement that closes the flow, and the far
 * side **silently discards** an acknowledgement that arrives before the
 * confirmation it acknowledges. It then waits for one that has already been
 * sent. The failure is asymmetric -- your side completes and records the
 * other device as verified, the other side records nothing -- and neither
 * side is told. Both messages can land in the same batch, from two different
 * queues inside the library, so a product that pumps on a timer rather than
 * after every call is the one that meets this.
 *
 * **Resolving them with {@link markRequestSent} is a different matter and is
 * not ordered at all.** It is a lookup by id, so mark them in whatever order
 * the responses come back, and do not wait for request *n* to be marked
 * before sending request *n+1*.
 *
 * Requests from *different* batches were never orderable against each other
 * -- a batch is a snapshot -- and nothing here changes that. What this
 * function guarantees is that within one batch, the order it returns is the
 * order the requests were produced in, across both of the places inside the
 * library they come from.
 *
 * **What that guarantee is worth, stated so it is not read as more.** Two
 * requests this library produced in an order that matters come out in it,
 * which is the whole point and is what the verification pair needs. Two
 * requests with no ordering requirement between them may come out in either
 * order, run to run, and nothing here promises otherwise -- the last
 * paragraph of this comment is a measured example of exactly that. So:
 * preserve the order you are given, and do not read meaning into the
 * relative position of two requests that have none.
 *
 * Up to and including `0.1.0-rc.2` this comment said the opposite: that the
 * array was an unordered set and a product must not infer sequencing from
 * position. That was true of every request the library could then produce,
 * and it stopped being true when device verification arrived. The sentence
 * is recorded here rather than deleted because a consumer who read the old
 * one and built on it has to be able to find out that it changed.
 *
 * **{@link markRequestSent} is not the only thing that ends a request's
 * life. A later call to this function ends some of them too.** Four of the
 * kinds handed out here -- `keys_upload`, `keys_query`, `keys_claim` and
 * `signing_keys_upload` -- are evicted the moment a *subsequent* call hands
 * out a fresh request of the same kind, whether or not the older one was
 * ever marked sent. `markRequestSent` then rejects that older id with
 * `unknown_request`.
 *
 * That is designed, not a defect, and it is worth knowing why, because
 * `unknown_request` for an id a product is legitimately holding otherwise
 * reads as a library bug. The first three describe a standing need
 * ("these keys want uploading", "these users want querying") rather than
 * one message. `matrix-sdk-crypto` re-derives that need from current state
 * on every call, mints a new and uncorrelated id for it, and forgets the id
 * it handed out last. So once a fresh one exists, the older id names
 * nothing the machine is still waiting to hear about, and the fresh request
 * in that same batch carries what the older one was for.
 *
 * **`signing_keys_upload` is in that group for a different reason and on a
 * narrower trigger, and it is the one that will actually catch a product
 * out.** Nothing upstream forgets its id; this library re-derives it, and
 * only when {@link bootstrapCrossSigning} is called again. A second bootstrap
 * publishes the identical three keys, so keeping both entries would hand a
 * caller two ids for one publication and two rounds of user-interactive
 * authentication to finish it. **An ordinary second drain does not touch
 * it**, because no fresh one exists to evict it; a second bootstrap followed
 * by a drain does. That matters because this is the one id a product is
 * meant to hold across a slow loop with a person in the middle of it: it
 * survives any number of refused attempts, since only success consumes an
 * entry, and it does not survive being superseded. Do not call
 * `bootstrapCrossSigning` again while an authentication loop is in flight.
 *
 * **What a caller must do about it: resolve a batch before drawing the
 * next.** Drain, send in order, `markRequestSent` each response, and only
 * then call this again.
 *
 * Within one batch, marking may overlap sending -- nothing in one batch
 * evicts another member of it, so request *n* need not be marked before
 * request *n+1* is sent. **The sends themselves stay ordered**, which is
 * the half of this that changed after `0.1.0-rc.2`; see the ordering rule
 * at the top of this comment. This paragraph used to say sending and
 * marking within a single batch were both safe to do concurrently, which
 * is the sentence that section retracts.
 *
 * What is not safe is a second drain overlapping unresolved requests from
 * an earlier one: two pumps racing, or a drain on a timer alongside a drain
 * after a write, will produce `unknown_request` for ids the product still
 * holds.
 *
 * **On `unknown_request` for an id from an earlier batch, do not retry it.**
 * Discard the response that id was going to carry and pump again. Nothing
 * is lost: the need was re-derived rather than dropped, and the request that
 * supersedes it is either already in hand or waiting in the next drain.
 *
 * **`to_device`, `signature_upload` and `room_message` ids are never
 * evicted this way.** Each names one independently deliverable message, so
 * it stays outstanding until `markRequestSent` resolves it. For every kind,
 * marking is not optional bookkeeping; it is what advances the underlying
 * state machine. A product that calls this but never calls
 * `markRequestSent` keeps being handed the same requests, including -- for
 * a to-device request the machine could not yet deliver -- a stale
 * `m.room_key.withheld` notice sitting alongside the actual session key, in
 * no reliable order relative to it (measured across ten runs of the same
 * sequence: six with the notice first, four with the key first). That is
 * not a counter-example to the ordering rule above and is the reason it is
 * scoped as it is: neither of those two requests is order-significant
 * against the other, they are held keyed by transaction id rather than by
 * production order, and a transaction id is random. The
 * measured harm from that specific case is bounded -- that withheld notice
 * carries no scope and no session id of its own, so it names nothing for a
 * recipient to act on, and a `matrix-sdk-crypto`-based recipient's own
 * `add_withheld_info` deliberately ignores exactly this notice kind -- but
 * relying on that is not a substitute for calling `markRequestSent`: it is
 * the only thing that stops the duplication at the source.
 */
export async function takeOutgoingRequests(): Promise<OutgoingRequest[]> {
  try {
    const requests = await nativeTakeOutgoingRequests()
    // Destructured per element, not returned directly. See encryptEvent above.
    return requests.map(({ id, kind, body }) => ({ id, kind, body }))
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Reports that the request named by `id` (from {@link takeOutgoingRequests})
 * was sent, handing back the server's raw JSON response so the machine can
 * update its own state. An addition to the frozen surface, not a change to
 * it -- see {@link takeOutgoingRequests}.
 *
 * **`responseJson` must be that request's own endpoint's response body,
 * unwrapped** -- see {@link OutgoingRequest}'s own doc comment for the
 * table mapping each `kind` to what it must contain.
 *
 * **Call this only for a 2xx. Send everything else to
 * {@link markRequestFailed}.** `markRequestSent(id, await res.text())`
 * without branching on the status is the obvious wrapper and it is wrong.
 * No HTTP status crosses this boundary on this call, so a body shaped like
 * an answer *is* an answer here. Reported that way, an errored `keys_query`
 * tells the machine the server answered and this account has no signing
 * identity, which is exactly the fact that authorises minting a new one over
 * whatever the account already had.
 *
 * **What is rejected for you.** A body is rejected with `malformed_payload`
 * unless it is shaped like this endpoint's response, which means an object
 * with no keys, or an object carrying at least one field that endpoint
 * really returns (its row in {@link OutgoingRequest}'s table). So a Matrix
 * error (`errcode`), an authentication challenge (`flows`), a gateway's
 * `{"error":"Bad Gateway"}`, an array or a proxy's HTML page, and a plain
 * `{"message":"Internal server error"}` are all refused. Beyond that,
 * `keys_upload`, `keys_claim` and `room_message` also reject a body missing
 * their one required field. When a body is rejected the request named by
 * `id` stays outstanding, so the same `id` can be retried with corrected
 * input, and the ordinary "retry with `auth` merged in" flow after a 401
 * needs nothing special.
 *
 * **What that still leaves through is set out once in
 * {@link markRequestFailed}**, and it is not restated here so the two cannot
 * drift. Branch on `res.ok` and call that instead of this one.
 *
 * **This call is what stops `id` being handed out again**, not a courtesy
 * notification after the fact -- see {@link takeOutgoingRequests}'s own doc
 * comment for what a product observes if it is skipped.
 *
 * **`unknown_request` does not always mean the id was never real.** A
 * `keys_upload`, `keys_query`, `keys_claim` or `signing_keys_upload` id is
 * evicted when a later `takeOutgoingRequests` hands out a fresh request of
 * the same kind, so an id held across a second drain rejects here even
 * though this library did hand it out. The first three are re-derived on
 * every drain; a fresh `signing_keys_upload` exists only after another
 * {@link bootstrapCrossSigning}, so that one survives an ordinary second
 * drain and not a second bootstrap. See {@link takeOutgoingRequests} for why
 * that is deliberate and what to do instead of retrying.
 */
export async function markRequestSent(id: string, responseJson: string): Promise<void> {
  try {
    await nativeMarkRequestSent(id, responseJson)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Reports that the request named by `id` (from {@link takeOutgoingRequests})
 * was **refused**: you sent it, and what came back was not a success. Pass
 * the HTTP status you received, or `0` if nothing came back at all, such as
 * a dropped connection, a DNS failure, or a timeout.
 *
 * An addition to the frozen surface, not a change to it. This is the
 * counterpart to {@link markRequestSent}, and the reason that call is no
 * longer the only thing you can say. A 502 from a proxy, or a 503 with an
 * empty body, used to have nowhere to go but the success path.
 *
 * ```ts
 * const res = await fetch(url, { method, body: request.body })
 * if (res.ok) await markRequestSent(request.id, await res.text())
 * else await markRequestFailed(request.id, res.status)
 * ```
 *
 * **This changes nothing about what the library knows, deliberately.** A
 * refused request taught it nothing. The request stays outstanding, so the
 * retry is an ordinary second send, and nothing is recorded as answered.
 *
 * **Forgetting to call this is safe.** A request you never report stays
 * pending exactly as if you had reported it refused. Reporting a refusal and
 * reporting nothing are the same to this library, and both are the safe
 * direction: what advances its state is {@link markRequestSent}, and only
 * that. The cross-signing bootstrap this protects arrives in a later
 * release; when it does, it will refuse to run rather than mint an identity
 * on a question it was never told the answer to. The failure mode of silence
 * is work that will not proceed, which you will notice, and never an
 * identity destroyed.
 *
 * **What is not safe is calling {@link markRequestSent} for a response the
 * server refused, and this library cannot detect that for you in every
 * case.** It sees a body and no status.
 *
 * A body is accepted there when it is shaped like that endpoint's response:
 * an object with no keys, or an object carrying at least one field that
 * endpoint really returns. That refuses a Matrix error, an authentication
 * challenge, a gateway's `{"error":"Bad Gateway"}`, an array, a proxy's HTML
 * page, and a bare `{"message":"Internal server error"}`. What it accepts is
 * every genuine success and, unavoidably, any failure whose body falls
 * inside the same shape. **The member that matters is the object with no
 * keys:** `{}` is what `/keys/query` answers for an account it knows no
 * identity for, and it is the entire success response of the signing-keys
 * upload, so a 503 that carried nothing and a 200 with nothing to say are
 * the same bytes. An empty body is turned into `{}` before parsing.
 *
 * That is the gap this call exists to let you close, and it can only be
 * closed from your side, by branching on the status before you choose which
 * of the two calls to make.
 *
 * The one confusion of the pair this library *can* catch is a 2xx passed
 * here, which is rejected with `not_a_failure_status`: a success has a body
 * worth reporting, and it belongs in {@link markRequestSent}. Statuses
 * outside `0` and `300`-`599` are rejected the same way.
 *
 * `unknown_request` means the same thing it does on {@link markRequestSent},
 * including the eviction case described there.
 */
export async function markRequestFailed(id: string, status: number): Promise<void> {
  try {
    await nativeMarkRequestFailed(id, status)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * What this library will say about this account's signing identity, as
 * returned by {@link getIdentityStatus}.
 *
 * Three independent facts, none of which implies another. **The pair that
 * looks redundant is the pair that matters:** `identityKnown === false`
 * means something completely different depending on `accountKeysFetched`.
 * With that false it means "nobody has asked". With it true it means "the
 * server says there is none", and only the second is a basis for creating
 * one. That is why both are reported instead of one collapsed answer.
 */
export interface IdentityStatus {
  /**
   * Whether a key query naming this account has been sent **and answered**
   * in this process.
   *
   * Not persisted. A process that has just reopened a store has asked
   * nothing yet, whatever the process before it did, and the account may
   * have gained an identity in between. `false` is not a claim that the
   * account has no identity; it is a refusal to guess.
   */
  accountKeysFetched: boolean
  /**
   * Whether this library holds a public signing identity for the account.
   *
   * Read only alongside `accountKeysFetched`. A successful
   * {@link bootstrapCrossSigning} sets this true as a side effect, so it is
   * also how a caller sees that its own bootstrap took effect.
   */
  identityKnown: boolean
  /**
   * Whether this device holds the account's complete private signing keys,
   * and can therefore sign with the identity rather than only recognise
   * it.
   *
   * **True does not mean the server agrees.** Until `accountKeysFetched` is
   * also true, these keys may belong to an identity the account has since
   * replaced: a restored backup holds a complete set that is simply out of
   * date. So this field is only trustworthy alongside that one.
   */
  privateKeysHeld: boolean
}

/**
 * What this library will say about this account's signing identity right
 * now. Reads only: it asks the server nothing and creates nothing.
 *
 * See {@link IdentityStatus} for why two of the three fields have to be read
 * together. Two calls change them: {@link bootstrapCrossSigning} creates the
 * identity, and {@link requestSelfVerification} joins one the account already
 * has.
 *
 * **This is the durable answer the signal channel sends you to.** Nothing
 * returns to a caller when a join's seeds arrive; what happens instead is a
 * `'trust_changed'` for your own user id on `onCryptoSignal`, and reading
 * `privateKeysHeld` here is what that signal means. It is the same variant a
 * completed comparison produces, so read this rather than counting signals.
 */
export async function getIdentityStatus(): Promise<IdentityStatus> {
  try {
    const status = await nativeIdentityStatus()
    // Destructured, not returned directly. See encryptEvent above.
    const { accountKeysFetched, identityKnown, privateKeysHeld } = status
    return { accountKeysFetched, identityKnown, privateKeysHeld }
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Publishes this account's cross-signing identity, creating one first if
 * the account provably has none.
 *
 * This is the call the rest of M4 hangs off. Until an account has a signing
 * identity of its own, a decrypted event can never report
 * `senderVerification.state === 'verified'`, however many people compare
 * however many strings: that value needs **our** user-signing key over the
 * sender's master key, read back out of our own store. See
 * {@link SenderVerification}.
 *
 * **Safe to call on every launch.** The first call in a process is normally
 * refused once, with the key query that lifts the refusal already queued by
 * the refusal itself; the call after that answer is served. Further calls in
 * the same process republish the identity this device already holds rather
 * than creating a second one.
 *
 * # Nothing here reaches the network
 *
 * This library performs no request, here or anywhere. On success, drain
 * {@link takeOutgoingRequests} and send what it hands back **in the order it
 * hands it back**, reporting each with {@link markRequestSent}. The order
 * matters here more than anywhere else on this surface, because a signature
 * may reference a key that is not published yet: device keys, then
 * `'signing_keys_upload'`, then `'signature_upload'`.
 *
 * **Four of the batch's entries come from this call, and the batch is
 * longer than four. Do not assert a length.** Observed after a served
 * bootstrap on a fresh machine: `['keys_upload', 'signing_keys_upload',
 * 'signature_upload', 'keys_upload', 'keys_query']`. The second
 * `'keys_upload'` carries the same device keys under a different id and is
 * harmless to send twice; the endpoint is idempotent.
 *
 * # The part your product has to write, and why this call cannot
 *
 * **The `'signing_keys_upload'` request needs user-interactive
 * authentication.** Expect the first attempt to be refused with a `401`
 * carrying a challenge, merge an `auth` object into `body`, and send the
 * same body again. `body` is opaque JSON this library never interprets, so
 * adding a field to it is an ordinary edit.
 *
 * **There is deliberately no `auth` parameter on this function, and there
 * will not be one.** The challenge is only known *after* the first request
 * is refused, so an argument here would have to be guessed before the
 * server has said what it wants. This library has never touched an account
 * credential and this is where that property would have gone if it were
 * going to. The cost is real and is named rather than hidden: a product
 * cannot complete this step without implementing an authentication flow
 * this library gives it no help with.
 *
 * **The id survives any number of refused attempts.** {@link markRequestSent}
 * removes an entry only on success, so loop on the `401` for as long as your
 * user needs. What retires the id is calling this function again and
 * draining again, because a second bootstrap re-derives the same three keys
 * and supersedes the pending publication: the held id then reports
 * `'unknown_request'`, and the recovery is to drain again and use the newer
 * id for the identical body. If an authentication loop is in flight, do not
 * call this again until it finishes. See {@link takeOutgoingRequests} for
 * the general rule this is one case of.
 *
 * # Report only what a success returned
 *
 * **Never report a non-2xx body through {@link markRequestSent}, and that
 * includes the `401` challenge.** Send it to {@link markRequestFailed}, or
 * report nothing at all, and report the eventual success through
 * `markRequestSent`. This matters more here than anywhere else on the
 * surface, in two different ways. A failed `'keys_query'` reported as a
 * success is read as "the server answered and this account has no identity",
 * which is the one fact that authorises creating one over whatever the
 * account already had. And the signing-keys upload's success response is
 * `{}`, so a reported challenge would mark an identity published that never
 * was.
 *
 * # Refusals
 *
 * `'account_keys_not_fetched'` means this process has not yet asked the
 * server about this account, so it cannot know whether publishing would
 * destroy an existing identity. **This call queues that key query before
 * returning the refusal**, so the remedy is the ordinary loop: drain, send,
 * report sent, call this again. Holding the private keys is not an
 * exemption, because a store restored from a backup holds a complete
 * identity the server may already have replaced.
 *
 * `'identity_already_exists'` means the answer named an identity this device
 * does not hold the private keys for. There is no remedy through this call
 * and there should not be: this device joins that identity, it does not
 * replace it. **{@link requestSelfVerification} is the call that joins it**,
 * and it is where a second login goes from here.
 *
 * # After a join, this call starts being served again
 *
 * A device that has joined holds the account's private keys, so this
 * republishes the identity it now holds rather than being refused, and the
 * `'signing_keys_upload'` in the batch needs the same user-interactive
 * authentication as the first time. "Call it on every launch" is still the
 * right advice, but a joined device following it meets an authentication
 * challenge, and a product that only expected one during setup should expect
 * this one too.
 */
export async function bootstrapCrossSigning(): Promise<void> {
  try {
    await nativeBootstrapIdentity()
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Every device this library has been told about for `userId`, and the trust
 * it currently reports for each, sorted by device id.
 *
 * **This is the only place a completed verification becomes visible.** A
 * device that has been through {@link requestVerification} to
 * {@link confirmVerification}, with both sides agreeing, reads `'verified'`
 * here where it read `'unverified'` before. Nothing else in this library
 * changes as a result of a verification -- in particular a decrypted
 * event's sender does not become authenticated, because that path consults
 * cross-signing and a short-string comparison sets local trust. See
 * {@link TrustState}.
 *
 * # `'verified'` no longer means a person compared a string with this device
 *
 * **Read it as "trusted", and read nothing more into it.** This call maps
 * from one boolean underneath, which is "locally trusted OR signed by an
 * identity we have verified". The second half of that had no way to be true
 * until this library could hold a signing identity of its own. It can, from
 * {@link bootstrapCrossSigning}, and the consequence is immediate and
 * deliberate: **verifying one device of a user moves every device of that
 * user to `'verified'` at once, including devices that appear afterwards,
 * with nobody comparing anything on any of them.**
 *
 * That is correct rather than a defect. It is the entire point of
 * cross-signing: you verify a person once instead of once per device they
 * own. But it is a behaviour change a caller cannot see coming, so it is
 * said here rather than left to be discovered. **Anything that read this
 * value as "a human compared a string with this exact device" was right
 * before this release and is wrong from it.** If that is the question your
 * product is really asking, this call has never been the one to ask, and it
 * is now further from it than it was: what an individual event can be said
 * to prove is {@link EventEnvelope.senderVerification}, which is a different
 * question with a different and more expensive answer.
 *
 * # `'recognized'` stays folded into `'verified'`, deliberately
 *
 * {@link TrustState} declares a third value for exactly the state the
 * paragraph above creates -- a device believed because its owner's identity
 * signed it, with no person having compared anything -- and this call does
 * not produce it. That is a decision taken in this release rather than an
 * absence left over from an earlier one, and the reasoning is at
 * {@link TrustState} so a product reading the union meets it there too.
 *
 * **An empty array does not mean the user has no devices.** It means this
 * library has been told about none of them. Devices arrive through the
 * outbound pump: {@link receiveSyncChanges} flags a user as changed, that
 * produces a `'keys_query'` request among {@link takeOutgoingRequests}'
 * output, and only {@link markRequestSent} on that request puts anything in
 * the store. A caller that has never done that gets `[]` for a user with a
 * dozen devices, and gets it successfully. There is no way for this library
 * to tell the two apart, because it sends nothing itself.
 *
 * **Your own device always reads `'verified'`, and always has.** This
 * library marks it locally trusted the moment it creates the machine,
 * because this process holds its private keys and there is nothing left to
 * prove. That is correct, and it is a trap for anything reading this list:
 * "some device here reads verified" is true of an installation that has
 * never run a verification in its life. What carries a claim is a device of
 * *another* user changing from `'unverified'` to `'verified'`.
 */
export async function getDeviceStatuses(userId: string): Promise<DeviceStatus[]> {
  try {
    const statuses = await nativeDeviceStatuses(userId)
    // Destructured per element, not returned directly. See encryptEvent above.
    return statuses.map(({ deviceId, trust }) => ({ deviceId, trust: trustStateOf(trust) }))
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Asks `deviceId`, belonging to `userId`, to verify itself against this
 * device, and returns the opaque identifier every other call below
 * addresses that flow by.
 *
 * The identifier is opaque: hand it back verbatim and parse nothing out of
 * it.
 *
 * **The device must already be known**, which means a `'keys_query'` for
 * that user must have been pumped and marked sent -- see
 * {@link getDeviceStatuses}. A device this library has never been told
 * about rejects with kind `'unknown_device'`, which is fixed by querying
 * and calling again, and is deliberately a different kind from
 * `'malformed_identifier'`, which no retry fixes.
 *
 * **Nothing reaches the other device until you pump.** This queues an
 * invitation among {@link takeOutgoingRequests}' output; the far side sees
 * nothing until you have sent it and reported it with
 * {@link markRequestSent}. That is true of every call in this group.
 *
 * The full sequence, for the side that asks:
 *
 * 1. `requestVerification` -> pump
 * 2. wait for {@link getVerificationStage} to read `'ready'` (the other
 *    side has called {@link acceptVerification} and you have pumped their
 *    answer in through {@link receiveSyncChanges})
 * 3. {@link startVerificationComparison} -> pump
 * 4. wait for the stage to read `'keys-exchanged'`, pumping throughout
 * 5. {@link getVerificationMaterial}, and show it to a person
 * 6. {@link confirmVerification} with what you showed, or
 *    {@link cancelVerification} if the person says it does not match
 * 7. pump again -- the flow reaches `'done'`, and only then does
 *    {@link getDeviceStatuses} report the device verified
 *
 * The side that was asked does the same from step 2, calling
 * {@link acceptVerification} first. Its `verificationId` is handed to it by
 * `onCryptoSignal` -- exported from this package's root alongside these,
 * and the thing that announces inbound invitations. See
 * `acceptVerification`'s own comment. Either side may call
 * {@link startVerificationComparison}; the other gets
 * `'comparison_already_started'`, answers the comparison with a second
 * {@link acceptVerification}, and carries on from step 4.
 */
export async function requestVerification(userId: string, deviceId: string): Promise<string> {
  try {
    return await nativeRequestVerification(userId, deviceId)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Asks this account's **other** devices to verify this one, so that this
 * device can join the cross-signing identity the account already has.
 *
 * This is what a second login does. A device that does not hold the account's
 * private signing keys joins the identity; it does not create one.
 * {@link bootstrapCrossSigning} refuses such a device with
 * `'identity_already_exists'`, and that refusal is the one thing standing
 * between an ordinary second login and an account whose identity has been
 * silently replaced, resetting the trust of every device and every person who
 * had verified it. **This call is the remedy that refusal points at, and it
 * is not a way around it.**
 *
 * # Three ways it differs from {@link requestVerification}
 *
 * **It names no device**, because a new login is in no position to choose
 * one. The invitation goes to every other device of yours that the account's
 * identity has signed, and whichever is in front of a person answers first;
 * the others are told the flow was taken. A device of yours that the identity
 * has never signed is not invited, which is deliberate: it is a login this
 * account's identity has never vouched for.
 *
 * **The signature at the end is made with a different key**, and by the other
 * side. The device that already holds the private keys signs this one with
 * the account's self-signing key. This device has nothing to sign with yet,
 * which is the whole reason it is asking.
 *
 * **It asks for the account's secrets, which verifying somebody else never
 * does.** Once the comparison completes, this library asks your other devices
 * for the cross-signing seeds it lacks. Those go out as ordinary entries in
 * {@link takeOutgoingRequests}' output, and the encrypted answer arrives in a
 * later {@link receiveSyncChanges}, which imports it.
 *
 * # Nothing returns to you when the seeds land
 *
 * The call that started all this resolved long before. Two things tell you it
 * happened, and you want the first:
 *
 * - **`onCryptoSignal`** announces `'trust_changed'` for your own user id on
 *   the sync that carried the seeds. That is the signal to read
 *   {@link getIdentityStatus} again. It is the same variant a completed
 *   comparison produces, so read the status rather than counting signals;
 *   see `onCryptoSignal`'s own comment.
 * - **{@link getIdentityStatus}** is the durable answer:
 *   `privateKeysHeld === true` means this device can now sign with the
 *   account's identity rather than only recognise it. Read it when you are
 *   told to, not on a timer.
 *
 * # Driving the flow
 *
 * Identical to {@link requestVerification} from the moment this resolves:
 * pump, wait for {@link getVerificationStage} to read `'ready'`,
 * {@link startVerificationComparison}, pump, read
 * {@link getVerificationMaterial}, show it, and
 * {@link confirmVerification} or {@link cancelVerification}. The person is
 * comparing two of their own screens instead of talking to somebody else,
 * which changes none of the calls.
 *
 * # Refusals
 *
 * `'account_keys_not_fetched'` means this process has not yet asked the
 * server about this account, so it cannot know whether there is an identity
 * to join. **This call queues that key query before returning the refusal**,
 * so the remedy is the ordinary loop: drain the pump, send, report sent, and
 * call this again. You do not have to reach for
 * {@link bootstrapCrossSigning} to get unstuck, and on a device that is
 * joining you should not: it is the call that would create a second identity
 * if the state ever moved under you.
 *
 * Expect this refusal on **every** launch, not only the first. Whether the
 * server has been asked is not persisted, and the layer underneath will not
 * volunteer the question for an account it already knows about, so a
 * relaunched store starts out having asked nothing.
 *
 * `'identity_not_known'` means the server was asked and said this account has
 * no identity. There is nothing to join, and the answer is
 * {@link bootstrapCrossSigning} rather than a retry.
 */
export async function requestSelfVerification(): Promise<string> {
  try {
    return await nativeRequestSelfVerification()
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Agrees to a verification the other side asked for, and queues the answer
 * for the pump.
 *
 * For the side that *received* an invitation. The flow reaches `'ready'`
 * once the answer has been sent and reported.
 *
 * # Where `verificationId` comes from on this side
 *
 * **`onCryptoSignal` announces it**, which this package's root exports
 * alongside every function here. Forward the sync to
 * {@link receiveSyncChanges} as usual -- that is what makes the flow exist
 * at all -- and a subscriber receives:
 *
 * ```ts
 * onCryptoSignal((signal) => {
 *   if (signal.kind !== 'verification_requested') return
 *   // signal.user and signal.device say who is asking.
 *   // Ask the person, then:
 *   acceptVerification(signal.verificationId) // or cancelVerification
 * })
 * ```
 *
 * From there the flow is the one {@link requestVerification} documents,
 * from its step 2 onward.
 *
 * # You may need to call this twice, and it is not a retry
 *
 * There are two things the other side can ask you, and this answers both.
 * The invitation asks *may we verify?*. The comparison -- which either side
 * may open once both are ready -- asks *here it is, will you take part?*.
 * If the other side opens it before you do, that second question is
 * outstanding and only this call answers it: they are waiting for your
 * answer and {@link getVerificationStage} sits at `'started'` until you
 * give it.
 *
 * You do not have to work out which is which. Call this whenever the stage
 * reads `'requested'` or `'started'` and the flow is waiting on you; it
 * rejects with `'wrong_stage'` when nothing is.
 *
 * **Subscribe before your first sync**, and prefer keeping the
 * subscription for the process's life. Nothing is queued for a subscriber
 * that is not there -- but for an ordinary invitation nothing is consumed
 * either, because the layer underneath does no work at all with nobody
 * subscribed. So one that arrives while you are unsubscribed is still
 * `'requested'` when you come back, and the first
 * {@link receiveSyncChanges} after you resubscribe announces it.
 * `useEffect(() => onCryptoSignal(h), [])` does not lose those. What you
 * cannot get back is an invitation that arrived before this process existed
 * at all; see the restart note below. **The one exception is the shape
 * described two sections down**, which cannot be re-offered.
 *
 * This used to be a listing of the `m.key.verification.request` to-device
 * event's JSON, with an instruction to filter your own `to_device_events`
 * for it and read `content.transaction_id` out of one. That was a real seam
 * -- one field of protocol JSON this library otherwise keeps to itself --
 * and the announcement is what closes it. The identifier still *is* that
 * transaction id on the wire; you no longer have to know that.
 *
 * # The other shape an invitation arrives in, and the one thing it costs
 *
 * Some clients -- `matrix-nio` among them, and it is the whole of what it
 * implements -- do not send an invitation at all. They open the comparison
 * directly, with the older message the specification deprecated but did not
 * remove. **Nothing about this call changes**: such a flow is announced on
 * the same channel, under the same `'verification_requested'` signal, and
 * this is still what you call to agree to it.
 *
 * Two differences are visible afterwards, and neither needs a branch in
 * your code:
 *
 * - the flow never reads `'ready'`. It is a comparison from the moment it
 *   exists, so it goes straight to `'started'` and
 *   {@link startVerificationComparison} on it rejects with
 *   `'comparison_already_started'` -- which already means "the other side
 *   started it, carry on and wait for the string";
 * - {@link confirmVerification} can finish it outright, rather than leaving
 *   it `'confirmed'` until the other side acknowledges. The device is
 *   verified when that call resolves; the `'trust_changed'` signal for it
 *   still arrives on your next {@link receiveSyncChanges}, because that is
 *   where the channel's producers run. Read {@link getDeviceStatuses} if
 *   you need the answer without waiting for a sync.
 *
 * **What it costs: this shape is not re-offered across an unsubscribe.** An
 * ordinary invitation is re-announced after you resubscribe because it can
 * be enumerated afresh on every sync; this one cannot -- the sync that
 * carried it is its only witness. Subscribing before your first sync is
 * therefore load-bearing for it rather than merely advisable.
 *
 * # An unmet sender's invitation is dropped on arrival, and not announced
 *
 * **If this library has never been told about the sender's device, the
 * invitation is discarded as it arrives.** The layer underneath needs the
 * sender's device keys to build the flow at all; without them it drops the
 * event. `receiveSyncChanges` still resolves successfully, no flow exists,
 * nothing is announced, and this function rejects that transaction id with
 * `'unknown_flow'`.
 *
 * The silence is deliberate rather than a gap. The channel announces flows,
 * and there is no flow: announcing the wire event's own identifier instead
 * would hand you a value every call in this group then rejects.
 *
 * **It is recoverable, and recovering it is your job because nothing here
 * kept the event.** What was discarded is that *arrival*, not the
 * invitation: the same event fed in again, once the device is known, does
 * create the flow -- and announces it, exactly as a first-time arrival
 * would. So:
 *
 * 1. keep the to-device events you could not act on. You never have to open
 *    one: what you keep is an opaque blob, and what you get back is the
 *    announcement. Keep the ones you *did* act on too, until their flow
 *    finishes -- see the restart note below;
 * 2. learn the sender's devices -- a real `/sync` names them in
 *    `device_lists.changed`, which {@link encryptionSlice} maps to
 *    `changed_devices`; forward that, then drain the resulting
 *    `'keys_query'` and report it with {@link markRequestSent}.
 *    {@link getDeviceStatuses} for that user answering non-empty is how you
 *    know it worked;
 * 3. pass the kept events to {@link receiveSyncChanges} a second time, and
 *    wait to be told.
 *
 * Promptly, though: an invitation expires ten minutes after it was sent, so
 * a recovery that takes longer than that leaves the other side to ask
 * again. A product that discards to-device events it could not act on has
 * no way back, which is the reason this is spelled out rather than left to
 * the error kind.
 *
 * # A restart loses the flow, and the recovery is the same one
 *
 * Flows live in memory, on both sides of this boundary. A process that
 * restarts mid-verification holds a `verificationId` that now rejects with
 * `'unknown_flow'`, and nothing is announced for it, because there is
 * nothing left to announce. The only way back is the one above: feed the
 * kept `m.key.verification.request` event in again, and be told the flow's
 * name as though it had just arrived.
 *
 * That is why the retention advice covers events you *did* act on and not
 * only ones you could not. An invitation you accepted a second before the
 * process died is exactly the event you now need, and the ten-minute expiry
 * is still running.
 *
 * **Skipping this call does not fail silently.** Nothing advances: the flow
 * stays at `'requested'`, and {@link startVerificationComparison} on it
 * rejects with `'wrong_stage'` rather than starting a comparison the other
 * side never agreed to.
 *
 * Rejects with `'wrong_stage'` for a flow this device asked for itself, or
 * one already answered, cancelled or finished. It is never a successful
 * no-op. Rejects with `'unknown_flow'` for a transaction id that names no
 * flow -- see the two sections above for the two ways that happens.
 */
export async function acceptVerification(verificationId: string): Promise<void> {
  try {
    await nativeAcceptVerification(verificationId)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Starts the comparison itself, once both sides are ready, and queues its
 * opening message for the pump.
 *
 * Either side may call this, and only while {@link getVerificationStage}
 * reads `'ready'`. Two sides calling it at the same moment is safe: the
 * protocol settles which comparison survives.
 *
 * **The same side calling twice is refused, and that is deliberate.** A
 * double tap on a button, or a retry after an unrelated failure, would
 * otherwise build a second comparison under the same identifier and destroy
 * the flow while reporting success.
 *
 * **Three different rejections, because three different things have to
 * happen next.** The layer underneath reports one error for all of them;
 * this function reads {@link getVerificationStage} to tell them apart,
 * because a screen that shows a person one sentence for all three is
 * showing the wrong one most of the time:
 *
 * - `'comparison_already_started'` -- the *other* side started it first.
 *   Nothing is wrong, but there **is** something left for you to do:
 *   call {@link acceptVerification} again. Their start is a question, and
 *   until you answer it they are waiting and the flow does not move. This
 *   used to say "wait for `'keys-exchanged'`", which was wrong: waiting
 *   alone never produced one. Then read
 *   {@link getVerificationMaterial} as usual.
 * - `'verification_ended'` -- the flow is over, whether it finished or was
 *   refused. There is nothing to carry on with; ask again with
 *   {@link requestVerification} if you still want to.
 * - `'wrong_stage'` -- anything else, which today means the flow has not
 *   been accepted by both sides yet. Wait, or call
 *   {@link acceptVerification} if the invitation was yours to answer.
 */
export async function startVerificationComparison(verificationId: string): Promise<void> {
  try {
    await nativeStartVerificationComparison(verificationId)
  } catch (e) {
    throw await unfoldStartRejection(e, verificationId)
  }
}

/**
 * How far along the flow is. The free discriminator: it is the one call in
 * this group that reads state without changing any, so it costs nothing to
 * poll and it is what tells apart conditions the calls below can only
 * report as one error.
 *
 * Rejects with `'unknown_flow'` for an identifier this library is not
 * taking part in -- including a flow that finished and has since been
 * released, which happens the next time a flow is *registered* rather than
 * on a timer. Registration is broader than starting one: an inbound
 * invitation announced down `onCryptoSignal` registers, and so does
 * the first call made against a flow this library is not already caching.
 * Nothing observable turns on the difference; it is stated because "started"
 * reads narrower than the rule is.
 */
export async function getVerificationStage(verificationId: string): Promise<VerificationStage> {
  try {
    return verificationStageOf(await nativeVerificationStage(verificationId))
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * The short authentication string for this flow, once there is one.
 *
 * **Show it to a person and ask whether it matches what the person at the
 * other device sees, over a channel this flow did not establish.** See
 * {@link SasMaterial}, including why the value is secret while the flow is
 * open.
 *
 * **`'material_not_ready'` has two causes, and they need opposite things
 * done about them.** Retrying this call alone fixes neither. Read
 * {@link getVerificationStage} to tell them apart, because doing the wrong
 * one waits forever:
 *
 * - **The peer opened the comparison and you have not answered it.** The
 *   stage is `'started'` and you never called
 *   {@link startVerificationComparison}. Their start is a question; call
 *   {@link acceptVerification} a second time, and the exchange proceeds.
 *   This is the ordinary receiving side against a client that starts
 *   directly, `matrix-nio` among them -- it is not an edge case, and
 *   nothing you pump will move it.
 * - **You drained the pump and never called {@link markRequestSent}.** The
 *   underlying state machine advances from "accepted" to "keys exchanged"
 *   on that report and on nothing else, so a caller that skips it parks the
 *   flow permanently with no error and no timeout anywhere else. This call
 *   names that state instead of resolving with an empty record or hanging.
 *   Supplying the missing report, and nothing else, completes the exchange.
 *
 * The other failure kind is worth keeping apart from both:
 *
 * - `'wrong_stage'` -- it never will: the flow is over, or no comparison was
 *   ever started on it.
 */
export async function getVerificationMaterial(verificationId: string): Promise<SasMaterial> {
  try {
    return sasMaterialOf(await nativeVerificationMaterial(verificationId))
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Says the strings matched, and queues the confirmation for the pump.
 *
 * **`data` is the material you showed the person**, exactly as
 * {@link getVerificationMaterial} returned it. It is checked against what
 * the flow currently holds, and a mismatch rejects with
 * `'material_mismatch'` rather than confirming.
 *
 * **What that argument does and does not guarantee.** It guarantees the
 * confirmation names *this flow's current string*: the caller cannot
 * produce a passing `data` without having read the material, because the
 * digits and symbols are derived from keys only this flow has, and the
 * layer underneath checks only that a string exists. So the material a
 * product confirms is material it obtained, for the flow it is confirming.
 *
 * It does not guarantee that anybody looked. `confirmVerification(id, await
 * getVerificationMaterial(id))` satisfies every check here while displaying
 * nothing, and no API can do better: whether a human read a string off a
 * screen and compared it with another human is not observable from inside
 * this process. **That last step is yours, and it is the step the whole
 * protocol rests on.** A product that confirms without asking a person has
 * verified nothing, however well-formed its arguments were.
 *
 * `'material_mismatch'` therefore means one thing: `data` is not this
 * flow's current string. In practice that is material obtained from a
 * different flow, or a value constructed rather than read.
 *
 * It is *not* what you get for a flow that ended while the string was on
 * screen -- cancelled by either side, timed out, or refused. A flow's
 * string does not change once the keys are exchanged, and a replacement
 * flow has a different id, so that case is caught one step earlier, by the
 * read this function makes before it compares anything: `'unknown_flow'` or
 * `'wrong_stage'`. Worth knowing which check catches what, because the two
 * kinds tell a product different things -- ask the person again on a new
 * flow, versus you are holding the wrong string.
 *
 * `data` was typed `unknown` up to `0.1.0-rc.2`, on a function that had only
 * ever rejected with `'not_implemented'`, so no caller has ever passed
 * anything to it successfully.
 *
 * **Confirming is not verifying.** When this resolves, the flow reads
 * `'confirmed'` and the other device is *not* verified: the other side has
 * still to say the same, and two more messages have to cross. Pump, and
 * watch for {@link getVerificationStage} to read `'done'`.
 *
 * Rejects with `'material_not_ready'` if the string is not available (see
 * {@link getVerificationMaterial}), and with `'wrong_stage'` if the flow is
 * over or never became a comparison. Both come from the read above, before
 * anything is confirmed.
 */
export async function confirmVerification(verificationId: string, data: SasMaterial): Promise<void> {
  // Read before confirming, not after: this is the check, and a check that
  // ran after the confirmation had already been queued would be reporting
  // on something it could no longer prevent. It also produces exactly the
  // error the confirmation itself would have -- 'material_not_ready' or
  // 'wrong_stage' -- for a flow with nothing to show, so nothing is lost by
  // reaching this first.
  const current = await getVerificationMaterial(verificationId)
  if (!sameMaterial(current, data)) {
    throw toCryptoError({ name: 'MaterialMismatch' })
  }
  try {
    await nativeConfirmVerification(verificationId)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Refuses the verification, or abandons it, and queues the refusal for the
 * pump.
 *
 * **The call a product must be able to make at any point a person can look
 * at a screen and say "that is not what I see".** Refusing is not a failure
 * of this library; a comparison that can only ever agree proves nothing.
 *
 * Cancels the comparison if one has started -- which cancels the invitation
 * behind it -- and the invitation otherwise. Nothing is verified, on either
 * side.
 *
 * Rejects with `'wrong_stage'` for a flow that was already cancelled.
 * "Already refused" and "refused by this call" are the same outcome, but a
 * caller told `Ok` for a cancellation it did not perform has been told
 * something false.
 *
 * **Skipping this does not fail silently, but it does fail slowly.** A flow
 * nobody cancels sits open until the protocol's own ten-minute timeout
 * retires it.
 */
export async function cancelVerification(verificationId: string): Promise<void> {
  try {
    await nativeCancelVerification(verificationId)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Maps the generated numeric enum onto the facade's closed string union.
 *
 * A `switch` with no `default`, over an enum the code generator emits from
 * the Rust source: a stage added to that source and not handled here is a
 * compile error, which is the only way this mapping can be kept honest
 * without a runtime test per variant. The `never` return is unreachable and
 * exists so the exhaustiveness is enforced rather than merely intended.
 */
function verificationStageOf(stage: NativeVerificationStage): VerificationStage {
  switch (stage) {
    case NativeVerificationStage.Requested:
      return 'requested'
    case NativeVerificationStage.Ready:
      return 'ready'
    case NativeVerificationStage.Started:
      return 'started'
    case NativeVerificationStage.KeysExchanged:
      return 'keys-exchanged'
    case NativeVerificationStage.Confirmed:
      return 'confirmed'
    case NativeVerificationStage.Done:
      return 'done'
    case NativeVerificationStage.Cancelled:
      return 'cancelled'
  }
}

/**
 * See {@link verificationStageOf}: exhaustive by compile error.
 *
 * **The return type is what makes that true, and an earlier version of this
 * function did not have it.** It took `NativeSenderVerification | undefined`
 * and returned `SenderVerification | undefined`, to fold the encrypt
 * direction's absent value into the same call. That looked tidier and
 * silently destroyed the guarantee this comment claims: with `undefined` in
 * the return type, a missing `case` falls off the end, implicitly returns
 * `undefined`, and compiles. The `Verified` arm was deleted outright in
 * review and `tsc --noEmit` exited 0 with all 108 tests still green.
 * `tsconfig.json` sets `strict` but not `noImplicitReturns`, so nothing else
 * caught it either.
 *
 * So the absent case is handled at the call site instead, and this function
 * takes and returns non-optional values -- the same shape
 * {@link verificationStageOf} and {@link trustStateOf} already have, for the
 * same reason. Falling off the end is now
 * `TS2366: Function lacks ending return statement and return type does not
 * include 'undefined'`.
 *
 * That mattered more than a tidier signature because of what this arm was
 * for a whole milestone. **No test in this repository fed this function
 * `Verified`**, because the M3 design ruling required the suite to hold no
 * case that appeared to produce it, and the library could not produce it
 * anyway. The compiler was the only thing standing behind that arm, which
 * is precisely why it had to actually be standing there.
 *
 * That is history now. M4 gives the core a cross-signing identity, and the
 * ruling was replaced rather than dropped by the stricter form written at
 * `matrix_crypto_core::SenderVerification`: nothing except the real chain
 * produces `Verified`. `facade.test.ts` feeds this function every native
 * value including `Verified`, and asserts that `'verified'` comes out for
 * that one and for no other. Both directions matter now. Something else
 * arriving *as* `'verified'` is still the failure that hurts most, and a
 * `Verified` the chain earned being dropped here is the one M4 added.
 */
function senderVerificationOf(verification: NativeSenderVerification): SenderVerification {
  switch (verification) {
    case NativeSenderVerification.Verified:
      return { state: 'verified' }
    case NativeSenderVerification.UnverifiedIdentity:
      return { state: 'unverified', reason: 'unverified_identity' }
    case NativeSenderVerification.VerificationViolation:
      return { state: 'unverified', reason: 'verification_violation' }
    case NativeSenderVerification.UnsignedDevice:
      return { state: 'unverified', reason: 'unsigned_device' }
    case NativeSenderVerification.NoDeviceMissing:
      return { state: 'unverified', reason: 'no_device', problem: 'missing' }
    case NativeSenderVerification.NoDeviceInsecureSource:
      return { state: 'unverified', reason: 'no_device', problem: 'insecure_source' }
    case NativeSenderVerification.MismatchedSender:
      return { state: 'unverified', reason: 'mismatched_sender' }
  }
}

/** See {@link verificationStageOf}: exhaustive by compile error. */
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
 * Rebuilds the facade's `SasMaterial` from the generated record.
 *
 * The three decimals travel as three separate fields because the boundary
 * has no tuple type; they are a fixed-length tuple again here, so a consumer
 * cannot index past the end of something it believed was an array.
 */
function sasMaterialOf(material: NativeSasMaterial): SasMaterial {
  // Destructured, not returned directly. See encryptEvent above.
  const { emoji, decimalOne, decimalTwo, decimalThree } = material
  const rebuilt: SasMaterial = { decimals: [decimalOne, decimalTwo, decimalThree] }
  if (emoji !== undefined) {
    rebuilt.emoji = emoji.map(({ symbol, description }): SasEmoji => ({ symbol, description }))
  }
  return rebuilt
}

/**
 * Is `offered` the material the flow is actually showing?
 *
 * Compares the digits always and the symbols when either side has them. The
 * digits alone would be enough to catch a stale or fabricated argument --
 * they are always present, and they are derived from the same key material
 * the symbols are -- but comparing only them would let a caller pass a
 * record whose symbols are wrong, which is what a screen showing symbols
 * actually displayed. `description` is deliberately not compared: it is a
 * label for the symbol and a product may translate it.
 */
function sameMaterial(current: SasMaterial, offered: SasMaterial): boolean {
  // Read through `unknown` rather than through the declared type: this
  // argument is the check, and a caller that reaches this function from
  // plain JavaScript, or past an `as any`, is exactly the caller it exists
  // to stop. The same discipline `decryptEvent` applies to its `scope`.
  const raw: unknown = offered
  if (typeof raw !== 'object' || raw === null) return false
  const { decimals, emoji } = raw as { decimals?: unknown; emoji?: unknown }

  if (!Array.isArray(decimals) || decimals.length !== current.decimals.length) return false
  if (!current.decimals.every((digit, index) => digit === decimals[index])) return false

  const currentSymbols = current.emoji?.map(({ symbol }) => symbol)
  // A flow with no symbols must be confirmed with a record that has none:
  // a caller offering symbols for a comparison that negotiated none is
  // describing a different screen from the one this flow produced.
  if (currentSymbols === undefined) return emoji === undefined
  if (!Array.isArray(emoji) || emoji.length !== currentSymbols.length) return false
  return currentSymbols.every(
    (symbol, index) => symbol === (emoji[index] as SasEmoji | undefined)?.symbol,
  )
}

/**
 * Splits {@link startVerificationComparison}'s one rejection into the three
 * a product has to answer differently. See that function's own doc comment
 * for what each means.
 *
 * Only a `'wrong_stage'` rejection is unfolded; everything else is passed
 * through unchanged, because everything else already says what it means. If
 * reading the stage itself fails -- the flow was released between the two
 * calls, say -- the original rejection is what the caller gets, since an
 * error about the diagnosis would be worse than the one it replaced.
 */
async function unfoldStartRejection(raw: unknown, verificationId: string): Promise<Error> {
  const original = toCryptoError(raw)
  if (original.kind !== 'wrong_stage') return original

  let stage: VerificationStage
  try {
    stage = await getVerificationStage(verificationId)
  } catch {
    return original
  }

  switch (stage) {
    case 'started':
    case 'keys-exchanged':
    case 'confirmed':
      return toCryptoError({ name: 'ComparisonAlreadyStarted' })
    case 'done':
    case 'cancelled':
      return toCryptoError({ name: 'VerificationEnded' })
    case 'requested':
    case 'ready':
      return original
  }
}

export function exportSecrets(_passphrase: string): Promise<Uint8Array> {
  return notImplemented('exportSecrets')
}

export function importSecrets(_bundle: Uint8Array, _passphrase: string): Promise<void> {
  return notImplemented('importSecrets')
}

/** Algorithms this build can carry. Open by design; see spec section 6. */
export function getSupportedAlgorithms(): CryptoAlgorithm[] {
  return ['megolm', 'olm']
}

// M1b: the first genuine cryptographic value to cross the whole chain, not
// the probe's echo. Everything above it was a NotImplemented stub when this
// was written; M2 and M3 implemented all but the calls the roadmap still
// lists as deferred.

export interface IdentityKeys {
  curve25519: string
  ed25519: string
}

export async function getDeviceIdentityKeys(userId: string, deviceId: string): Promise<IdentityKeys> {
  try {
    // Destructured, not returned directly: the M1 final review's deferred
    // item (`facade.ts:87`), applied here. A field added to the generated
    // record later must be a deliberate choice to expose through this
    // boundary, not something that leaks through unreviewed because it
    // structurally satisfies this function's own `IdentityKeys` shape. See
    // Global Constraints.
    const { curve25519, ed25519 } = await nativeDeviceIdentityKeys(userId, deviceId)
    return { curve25519, ed25519 }
  } catch (e) {
    throw toCryptoError(e)
  }
}
