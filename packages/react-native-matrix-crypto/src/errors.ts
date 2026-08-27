import type { CryptoScopeId } from './types'

/**
 * Deliberately open, per spec section 4bis.4: a new variant is a minor bump,
 * so every consumer must have a default branch.
 */
export type CryptoErrorKind =
  | 'missing_key'
  | 'unshared_session'
  | 'unknown_device'
  | 'revoked_device'
  | 'undecryptable'
  | 'store_corrupt'
  | 'rejected'
  | 'not_implemented'
  | 'unknown'
  | (string & {})

export interface CryptoError extends Error {
  kind: CryptoErrorKind
  scope?: CryptoScopeId
  /** Fully qualified `@user:server`, verbatim. Spec section 10. */
  sender?: string
  /** The bridge reports transience. The product layer decides what to do. */
  retriable: boolean
}

const BRAND = Symbol.for('react-native-matrix-crypto.CryptoError')

const KIND_BY_NAME = new Map<string, CryptoErrorKind>([
  ['Rejected', 'rejected'],
  ['NotImplemented', 'not_implemented'],
  ['MissingKey', 'missing_key'],
  ['UnsharedSession', 'unshared_session'],
  ['UnknownDevice', 'unknown_device'],
  ['RevokedDevice', 'revoked_device'],
  ['Undecryptable', 'undecryptable'],
  ['StoreCorrupt', 'store_corrupt'],
])

const RETRIABLE: ReadonlySet<CryptoErrorKind> = new Set(['missing_key', 'unshared_session'])

export function isCryptoError(e: unknown): e is CryptoError {
  return e instanceof Error && BRAND in e
}

/**
 * Normalizes anything thrown by the generated layer into a CryptoError.
 *
 * Only `reason` is ever copied into the message. Payload content and
 * ciphertext are never read, so they cannot reach a crash report.
 */
export function toCryptoError(raw: unknown): CryptoError {
  const source = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>
  const name = typeof source.name === 'string' ? source.name : ''
  const kind = KIND_BY_NAME.get(name) ?? 'unknown'
  const reason = typeof source.reason === 'string' ? source.reason : undefined

  const err = new Error(reason ?? `crypto error: ${kind}`) as CryptoError
  err.name = 'CryptoError'
  err.kind = kind
  err.retriable = RETRIABLE.has(kind)
  if (typeof source.sender === 'string') err.sender = source.sender
  if (typeof source.scope === 'string') err.scope = source.scope as CryptoScopeId
  Object.defineProperty(err, BRAND, { value: true, enumerable: false })
  return err
}
