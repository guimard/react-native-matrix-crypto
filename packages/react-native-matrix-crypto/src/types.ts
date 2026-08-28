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

/** Product-facing trust signal. Only 'verified' has cryptographic value. */
export type TrustState = 'unverified' | 'recognized' | 'verified'

/** Typed envelope for an encrypted or decrypted event. */
export interface EventEnvelope {
  scope: CryptoScopeId
  /**
   * From `encryptEvent`, the group-session algorithm this build used.
   *
   * From `decryptEvent`, spec section 7.1: this milestone decrypts events,
   * it does not authenticate their senders. This value is read from the
   * incoming event, not independently verified, and for all of M2 it is
   * **unauthenticated transport metadata** — treat it accordingly, not as
   * a claim this library has confirmed.
   */
  algorithm: CryptoAlgorithm
  eventType: string
  ciphertext: Uint8Array
  /**
   * Fully qualified `@user:server`, verbatim. Spec section 10.
   *
   * From `encryptEvent`, this device's own identity — authenticated by
   * definition.
   *
   * From `decryptEvent`, spec section 7.1: this milestone decrypts events,
   * it does not authenticate their senders. This is the sender the
   * homeserver delivered on the outer, not-yet-decrypted event, not a
   * value this library independently confirmed, and for all of M2 it is
   * **unauthenticated transport metadata**. A product that reads it as
   * the cryptographic sender of a successfully decrypted event has
   * assumed something this milestone does not provide, and that
   * assumption is the shape impersonation takes.
   */
  sender: string
}
