import type { CryptoAlgorithm, CryptoScopeId, EventEnvelope, TrustState } from './types'
import { asCryptoScopeId } from './types'
import { toCryptoError } from './errors'
import {
  createCryptoMachine as nativeCreateCryptoMachine,
  decryptEvent as nativeDecryptEvent,
  deviceIdentityKeys as nativeDeviceIdentityKeys,
  encryptEvent as nativeEncryptEvent,
  markRequestSent as nativeMarkRequestSent,
  openCryptoStore as nativeOpenCryptoStore,
  receiveSyncChanges as nativeReceiveSyncChanges,
  shareScopeKey as nativeShareScopeKey,
  takeOutgoingRequests as nativeTakeOutgoingRequests,
} from './generated/matrix_crypto'

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
 * See {@link shareScopeKey}'s own doc comment for the order these must be
 * sent and marked in, which is not optional: design doc section 3ter.
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
 * Worked example, the whole mapping, which is what a product's sync loop
 * actually needs:
 *
 * ```ts
 * type SyncResponse = Record<string, any>
 *
 * function encryptionSlice(sync: SyncResponse): Record<string, unknown> {
 *   const syncDelta: Record<string, unknown> = {}
 *   if (sync.to_device?.events) syncDelta.to_device_events = sync.to_device.events
 *   if (sync.device_lists) syncDelta.changed_devices = sync.device_lists
 *   if (sync.device_one_time_keys_count) {
 *     syncDelta.one_time_keys_counts = sync.device_one_time_keys_count
 *   }
 *   if (sync.device_unused_fallback_key_types) {
 *     syncDelta.unused_fallback_keys = sync.device_unused_fallback_key_types
 *   }
 *   if (sync.next_batch) syncDelta.next_batch_token = sync.next_batch
 *   return syncDelta
 * }
 *
 * await receiveSyncChanges(encryptionSlice(await fetchSync()))
 * ```
 *
 * `encryptionSlice` above is a transcription of `encryption_slice` in
 * `rust/matrix-crypto-core/tests/level_two_interop.rs`, which is the same
 * mapping exercised against a real homeserver and a third-party client.
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
export async function receiveSyncChanges(syncDelta: unknown): Promise<void> {
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
  if (typeof scope !== 'string') {
    throw toCryptoError({ name: 'MalformedPayload' })
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
 * **The returned array is an unordered set, not a sequence.** Nothing about
 * a request's position says anything about when it should be sent relative
 * to the others: the underlying order is lexicographic on each request's own
 * randomly-generated transaction id, which carries no meaning of its own. A
 * product must not infer sequencing -- "send index 0 before index 1" -- from
 * array position.
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

export function getDeviceStatuses(_userId: string): Promise<DeviceStatus[]> {
  return notImplemented('getDeviceStatuses')
}

export function requestVerification(_userId: string, _deviceId: string): Promise<string> {
  return notImplemented('requestVerification')
}

export function confirmVerification(_verificationId: string, _data: unknown): Promise<void> {
  return notImplemented('confirmVerification')
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
