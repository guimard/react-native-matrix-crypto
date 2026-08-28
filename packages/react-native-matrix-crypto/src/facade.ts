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
 * consumer must already handle a value it does not recognise). Today's
 * values are `'keys_upload'`, `'keys_query'`, `'keys_claim'`,
 * `'to_device'`, `'signature_upload'` and `'room_message'`.
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
 * Feeds the encryption-relevant slice of a `/sync` response into the
 * crypto machine -- design doc section 7. `syncDelta` is whatever
 * JSON-serialisable value the product already fetched; this library never
 * performs the request itself. The prerequisite every later crypto
 * operation depends on: a product that never calls this encrypts to
 * nobody, because this is how the machine learns which devices exist.
 *
 * Returns `void`, not the native call's own to-device/session counts: that
 * return type is frozen from M1a. A product that needs those counts reads
 * them off the sync response it already holds.
 */
export async function receiveSyncChanges(syncDelta: unknown): Promise<void> {
  try {
    await nativeReceiveSyncChanges(JSON.stringify(syncDelta))
  } catch (e) {
    throw toCryptoError(e)
  }
}

export async function encryptEvent(
  scope: CryptoScopeId,
  eventType: string,
  payload: unknown,
): Promise<EventEnvelope> {
  try {
    const encrypted = await nativeEncryptEvent(scope, eventType, JSON.stringify(payload))
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
  try {
    const decrypted = await nativeDecryptEvent(scope, JSON.stringify(rawEvent))
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
 * **Every request returned here stays outstanding, and will be handed out
 * again by the next call, until {@link markRequestSent} reports it sent.**
 * Marking is not optional bookkeeping; it is what advances the underlying
 * state machine. A product that calls this but never calls
 * `markRequestSent` will keep receiving the same requests on every
 * subsequent call, including -- for a to-device request the machine could
 * not yet deliver -- a stale `m.room_key.withheld` notice sitting alongside
 * the actual session key, in no reliable order relative to it (measured
 * across ten runs of the same sequence: six with the notice first, four with
 * the key first). The measured harm from that specific case is bounded --
 * that withheld notice carries no scope and no session id of its own, so it
 * names nothing for a recipient to act on, and a `matrix-sdk-crypto`-based
 * recipient's own `add_withheld_info` deliberately ignores exactly this
 * notice kind -- but relying on that is not a substitute for calling
 * `markRequestSent`: it is the only thing that stops the duplication at the
 * source.
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
 * **This call is what stops `id` being handed out again**, not a courtesy
 * notification after the fact -- see {@link takeOutgoingRequests}'s own doc
 * comment for what a product observes if it is skipped.
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
