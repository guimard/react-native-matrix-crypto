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
  | 'malformed_identifier'
  | 'not_implemented'
  | 'not_initialised'
  | 'already_initialised'
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
  ['MalformedIdentifier', 'malformed_identifier'],
  ['NotInitialised', 'not_initialised'],
  ['AlreadyInitialised', 'already_initialised'],
])

const RETRIABLE: ReadonlySet<CryptoErrorKind> = new Set(['missing_key', 'unshared_session'])

export function isCryptoError(e: unknown): e is CryptoError {
  return e instanceof Error && BRAND in e
}

/**
 * `@ubjs/core`'s `UniffiError` (the base class every generated error variant
 * extends) never sets `.name` -- confirmed by reading its source, and by a
 * real device run throwing a real `ProbeFfiError.Rejected` instance whose
 * `.name` is the inherited, useless `"Error"`. What it does set, always, is
 * `.message`, to exactly `"<EnumTypeName>.<VariantName>"` (optionally
 * followed by `": <message>"`) -- its own comment explains why: it cannot
 * rely on an overridden `toString()` being called. That format is the one
 * stable, codegen-version-independent way to recover the variant name
 * without importing a specific enum shape from ./generated, which would
 * couple this file to one Rust error type and need editing for every future
 * variant. `interop/reference.ts` and this file's own tests construct plain
 * `{ name: 'Rejected', ... }` objects instead, which is why this bug was
 * invisible until a real UniFFI error crossed the bridge for the first time
 * on a real build (Task 11) -- so `.name` is still checked first, both for
 * those and for any future binding that does set it directly.
 */
function variantNameFromMessage(message: unknown): string | undefined {
  if (typeof message !== 'string') return undefined
  const dot = message.indexOf('.')
  if (dot === -1) return undefined
  const afterDot = message.slice(dot + 1)
  const colon = afterDot.indexOf(': ')
  return colon === -1 ? afterDot : afterDot.slice(0, colon)
}

/**
 * A generated error's payload (`reason`, and per spec section 10 eventually
 * `sender`/`scope`) is nested under `.inner`, not on the error itself --
 * confirmed the same way as the `.name` gap above. Checked second, so a
 * hand-built fixture with the field at the top level still works.
 */
function stringField(source: Record<string, unknown>, field: string): string | undefined {
  if (typeof source[field] === 'string') return source[field] as string
  const inner = source.inner
  if (typeof inner === 'object' && inner !== null) {
    const value = (inner as Record<string, unknown>)[field]
    if (typeof value === 'string') return value
  }
  return undefined
}

/**
 * Normalizes anything thrown by the generated layer into a CryptoError.
 *
 * Only `reason` (falling back to `detail`, e.g. `IdentityFfiError.
 * MalformedIdentifier`'s field) is ever copied into the message. Both are
 * fixed diagnostics the Rust side deliberately chose to expose, never
 * caller-supplied payload or ciphertext content, so this stays safe to
 * surface without reaching a crash report.
 */
export function toCryptoError(raw: unknown): CryptoError {
  const source = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>
  const name = typeof source.name === 'string' ? source.name : ''
  const kind =
    KIND_BY_NAME.get(name) ?? KIND_BY_NAME.get(variantNameFromMessage(source.message) ?? '') ?? 'unknown'
  const reason = stringField(source, 'reason') ?? stringField(source, 'detail')

  const err = new Error(reason ?? `crypto error: ${kind}`) as CryptoError
  err.name = 'CryptoError'
  err.kind = kind
  err.retriable = RETRIABLE.has(kind)
  const sender = stringField(source, 'sender')
  const scope = stringField(source, 'scope')
  if (sender !== undefined) err.sender = sender
  if (scope !== undefined) err.scope = scope as CryptoScopeId
  Object.defineProperty(err, BRAND, { value: true, enumerable: false })
  return err
}
