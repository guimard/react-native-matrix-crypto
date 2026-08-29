import type {
  CryptoAlgorithm,
  CryptoScopeId,
  EventEnvelope,
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
  cancelVerification as nativeCancelVerification,
  confirmVerification as nativeConfirmVerification,
  createCryptoMachine as nativeCreateCryptoMachine,
  decryptEvent as nativeDecryptEvent,
  deviceIdentityKeys as nativeDeviceIdentityKeys,
  deviceStatuses as nativeDeviceStatuses,
  encryptEvent as nativeEncryptEvent,
  markRequestSent as nativeMarkRequestSent,
  openCryptoStore as nativeOpenCryptoStore,
  receiveSyncChanges as nativeReceiveSyncChanges,
  requestVerification as nativeRequestVerification,
  shareScopeKey as nativeShareScopeKey,
  startVerificationComparison as nativeStartVerificationComparison,
  takeOutgoingRequests as nativeTakeOutgoingRequests,
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
  const json = JSON.stringify(value)
  if (json === undefined) {
    throw toCryptoError({ name: 'MalformedPayload' })
  }
  return json
}

// Spec section 5's surface, re-typed onto the branded scope and the open
// algorithm tag. Types are real so consumers can compile today; runtime
// arrives in M2.

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
 * Today's six values, the endpoint each addresses, and what
 * {@link markRequestSent}'s own `responseJson` must contain to report one
 * sent -- that endpoint's response body, unwrapped, exactly as the
 * homeserver returned it; nothing this library adds or removes, and a
 * differently-shaped `responseJson` is rejected with `malformed_payload`
 * rather than silently accepted:
 *
 * | `kind` | Method & path | `responseJson` must contain |
 * |---|---|---|
 * | `'keys_upload'` | `POST /_matrix/client/v3/keys/upload` | `{ one_time_key_counts: { [algorithm: string]: number } }` |
 * | `'keys_query'` | `POST /_matrix/client/v3/keys/query` | `{ device_keys?, master_keys?, self_signing_keys?, user_signing_keys?, failures? }` (all optional; `{}` is valid) |
 * | `'keys_claim'` | `POST /_matrix/client/v3/keys/claim` | `{ one_time_keys: {...}, failures? }` |
 * | `'to_device'` | `PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}` | `{}` -- the machine ignores the body, but it must still be valid JSON |
 * | `'signature_upload'` | `POST /_matrix/client/v3/keys/signatures/upload` | `{ failures? }` (optional; `{}` is valid) |
 * | `'room_message'` | `PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}` | `{ event_id: string }` |
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
 * **This milestone decrypts events. It does not authenticate their
 * senders** -- spec section 7.1. The returned envelope's `sender` and
 * `algorithm` are read from the fields the homeserver delivered, not
 * independently verified, and are **unauthenticated transport metadata**
 * for all of M2: see {@link EventEnvelope.sender} and
 * {@link EventEnvelope.algorithm} for what that means and why. A product
 * that reads the sender of a successfully decrypted event as the
 * cryptographic sender has assumed something this milestone does not
 * provide, and that assumption is the shape impersonation takes.
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
    const { scope: decryptedScope, algorithm, eventType, ciphertext, sender } = decrypted
    return {
      scope: asCryptoScopeId(decryptedScope),
      algorithm,
      eventType,
      // See encryptEvent above: ArrayBuffer -> Uint8Array.
      ciphertext: new Uint8Array(ciphertext),
      sender,
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
 * Up to and including `0.1.0-rc.2` this comment said the opposite: that the
 * array was an unordered set and a product must not infer sequencing from
 * position. That was true of every request the library could then produce,
 * and it stopped being true when device verification arrived. The sentence
 * is recorded here rather than deleted because a consumer who read the old
 * one and built on it has to be able to find out that it changed.
 *
 * **{@link markRequestSent} is not the only thing that ends a request's
 * life. A later call to this function ends some of them too.** Three of the
 * kinds handed out here -- `keys_upload`, `keys_query` and `keys_claim` --
 * are evicted the moment a *subsequent* call hands out a fresh request of
 * the same kind, whether or not the older one was ever marked sent.
 * `markRequestSent` then rejects that older id with `unknown_request`.
 *
 * That is designed, not a defect, and it is worth knowing why, because
 * `unknown_request` for an id a product is legitimately holding otherwise
 * reads as a library bug. Those three requests describe a standing need
 * ("these keys want uploading", "these users want querying") rather than
 * one message. `matrix-sdk-crypto` re-derives that need from current state
 * on every call, mints a new and uncorrelated id for it, and forgets the id
 * it handed out last. So once a fresh one exists, the older id names
 * nothing the machine is still waiting to hear about, and the fresh request
 * in that same batch carries what the older one was for.
 *
 * **What a caller must do about it: resolve a batch before drawing the
 * next.** Drain, send, and `markRequestSent` each response, and only then
 * call this again. Sending and marking the members of a *single* batch
 * concurrently is safe, because nothing in one batch evicts another member
 * of it. What is not safe is a second drain overlapping unresolved requests
 * from an earlier one: two pumps racing, or a drain on a timer alongside a
 * drain after a write, will produce `unknown_request` for ids the product
 * still holds.
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
 * sequence: six with the notice first, four with the key first). The
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
 * table mapping each `kind` to what it must contain. It is parsed per
 * `kind`, and a `responseJson` that does not match rejects with
 * `malformed_payload` rather than being accepted or silently ignored; the
 * request named by `id` stays outstanding when that happens, so the same
 * `id` can be retried with corrected input.
 *
 * **This call is what stops `id` being handed out again**, not a courtesy
 * notification after the fact -- see {@link takeOutgoingRequests}'s own doc
 * comment for what a product observes if it is skipped.
 *
 * **`unknown_request` does not always mean the id was never real.** A
 * `keys_upload`, `keys_query` or `keys_claim` id is evicted when a later
 * `takeOutgoingRequests` hands out a fresh request of the same kind, so an
 * id held across a second drain rejects here even though this library did
 * hand it out. See {@link takeOutgoingRequests} for why that is deliberate
 * and what to do instead of retrying.
 */
export async function markRequestSent(id: string, responseJson: string): Promise<void> {
  try {
    await nativeMarkRequestSent(id, responseJson)
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
 * {@link acceptVerification} first. Either side may call
 * {@link startVerificationComparison}; the other gets
 * `'comparison_already_started'` and carries on from step 4.
 */
export async function requestVerification(userId: string, deviceId: string): Promise<string> {
  try {
    return await nativeRequestVerification(userId, deviceId)
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
 * **Skipping this does not fail silently.** Nothing advances: the flow
 * stays at `'requested'`, and {@link startVerificationComparison} on it
 * rejects with `'wrong_stage'` rather than starting a comparison the other
 * side never agreed to.
 *
 * Rejects with `'wrong_stage'` for a flow this device asked for itself, or
 * one already answered, cancelled or finished. It is never a successful
 * no-op.
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
 *   Nothing is wrong. Carry on from the stage the flow is at: wait for
 *   `'keys-exchanged'` and call {@link getVerificationMaterial}.
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
 * released, which happens the next time a flow is started rather than on a
 * timer.
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
 * **If you drained the pump and never called {@link markRequestSent}, this
 * is where you find out.** The underlying state machine advances from
 * "accepted" to "keys exchanged" on that report and on nothing else, so a
 * caller that skips it parks the flow permanently with no error and no
 * timeout anywhere else. This call names that state instead: it rejects
 * with kind `'material_not_ready'` rather than resolving with an empty
 * record or hanging. Supplying the missing report, and nothing else, is
 * what completes the exchange.
 *
 * The two failure kinds are worth keeping apart:
 *
 * - `'material_not_ready'` -- the flow is live and has not got there yet,
 *   which in practice almost always means the report above is missing.
 *   Retrying this call alone never fixes it.
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
 * That argument is the whole reason this call cannot be got wrong quietly.
 * Without it, a product could confirm a comparison it never displayed --
 * the layer underneath only checks that a string *exists*, not that anybody
 * saw it -- and "verified" would then mean nothing at all. It also catches
 * the case where the flow was cancelled and a new one started between the
 * moment the string went on screen and the moment the person answered: the
 * material a person actually compared is the material that gets confirmed,
 * or nothing is.
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
 * over or never became a comparison.
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

// M1b: the first genuine cryptographic value to cross the whole chain, not the
// probe's echo. Everything else above remains a NotImplemented stub until M2.

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
