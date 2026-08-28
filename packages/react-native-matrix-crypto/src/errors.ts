import type { CryptoScopeId } from './types'

/**
 * Deliberately open, per spec section 4bis.4: a new variant is a minor bump,
 * so every consumer must have a default branch.
 */
export type CryptoErrorKind =
  | 'missing_key'
  | 'unshared_session'
  // The policy half of the withheld-code split (G26 in the milestone's own
  // ledger): `m.blacklisted` and `m.unauthorised` are the sender's own
  // deliberate refusal, which no retry can ever change, so this kind is
  // deliberately absent from RETRIABLE below -- unlike its sibling
  // 'unshared_session', which keeps every other withheld code and stays
  // retriable.
  | 'session_refused'
  | 'unknown_device'
  // Forward scaffolding, not dead: nothing produces this yet (device
  // revocation is trust/M3 work), but it stays in the union, commented,
  // rather than being silently dropped or silently absent -- the same
  // treatment 'not_implemented' gets in KIND_BY_NAME. Give it the same
  // treatment if it turns out never to be needed: keep it commented, or
  // remove it; either is fine, silence about which is not.
  | 'revoked_device'
  | 'undecryptable'
  | 'malformed_payload'
  | 'unknown_request'
  | 'failed'
  // Reserved for genuine store corruption, which decryption work does not
  // currently detect; nothing maps to it yet. Kept distinct from
  // 'store_unavailable', which KIND_BY_NAME's own comment on ['Store', ...]
  // explains further.
  | 'store_corrupt'
  | 'store_unavailable'
  | 'mismatched_account'
  | 'rejected'
  | 'malformed_identifier'
  | 'not_implemented'
  | 'not_initialised'
  | 'already_initialised'
  | 'unknown'
  | (string & {})

export interface CryptoError extends Error {
  kind: CryptoErrorKind
  /**
   * **Always `undefined` in M2.** Declared, and never populated: every
   * `SessionFfiError` variant is fieldless by construction, so nothing on
   * the decryption path can carry a scope across the FFI boundary for
   * `toCryptoError` to find. See `sender` below for why the fields stay.
   *
   * A product handling a failed `decryptEvent` must therefore take the
   * scope from the call it made, not from the error it caught.
   */
  scope?: CryptoScopeId
  /**
   * Fully qualified `@user:server`, verbatim. Spec section 10.
   *
   * **Always `undefined` in M2**, for the same reason as `scope` above:
   * `SessionFfiError` is fieldless throughout, `MachineFfiError` carries
   * only `detail` and `ProbeFfiError` only `reason`, so no FFI error
   * variant can carry a sender. Both fields are optional and both are read
   * defensively by `toCryptoError`, so a later milestone that starts
   * populating them is additive rather than breaking. That is why they are
   * declared now and said to be empty, rather than removed and re-added.
   *
   * Note that a sender would not become authoritative merely by appearing
   * here. Spec section 7.1 applies to it exactly as it applies to
   * `EventEnvelope.sender`: until device verification lands, a sender is
   * unauthenticated transport metadata.
   */
  sender?: string
  /** The bridge reports transience. The product layer decides what to do. */
  retriable: boolean
}

const BRAND = Symbol.for('react-native-matrix-crypto.CryptoError')

const KIND_BY_NAME = new Map<string, CryptoErrorKind>([
  ['Rejected', 'rejected'],
  // The one entry with no Rust variant, and never will have one: synthesised
  // in TypeScript by facade.ts:17's `notImplemented` helper for every
  // still-stubbed function, so it never crosses the FFI boundary at all.
  // Not dead scaffolding like the `RevokedDevice`/`StoreCorrupt` entries two
  // reviews found and removed -- this one is reachable today, from every
  // M3-deferred function.
  ['NotImplemented', 'not_implemented'],
  ['MissingKey', 'missing_key'],
  ['UnsharedSession', 'unshared_session'],
  ['SessionRefused', 'session_refused'],
  ['UnknownDevice', 'unknown_device'],
  ['Undecryptable', 'undecryptable'],
  // The remaining three `SessionFfiError` variants (Task 7): `raw_json`
  // that did not parse, an upstream crypto operation that failed for a
  // reason spec section 7 forbids echoing, and a `mark_request_sent` id
  // that does not match anything `take_outgoing_requests` handed out.
  ['MalformedPayload', 'malformed_payload'],
  ['Failed', 'failed'],
  ['UnknownRequest', 'unknown_request'],
  // `MachineError::Store` means the store could not be opened -- often a
  // wrong passphrase or a permissions problem, not damaged data. Mapping it
  // to 'store_corrupt' would send a product down a destructive recovery path
  // over what might just be a typo'd passphrase. 'store_corrupt' stays in
  // the CryptoErrorKind union for genuine corruption, which decryption work
  // later in M2 can detect; nothing maps to it yet.
  ['Store', 'store_unavailable'],
  // A parked finding from Task 2's review: opening a store that belongs to
  // a different account (a different user id, device id, or both) is a
  // recoverable configuration mistake -- point this config at the right
  // store, or the right account -- not a storage failure like a full disk,
  // which reconfiguring cannot fix. Kept out of 'store_unavailable' so a
  // product can tell the two apart, matching Task 6's own decryption kinds:
  // being able to run this classification once is not a reason to leave a
  // distinguishable condition unclassified. Not in RETRIABLE: retrying with
  // the same mismatched config fails the same way every time.
  ['MismatchedAccount', 'mismatched_account'],
  ['MalformedIdentifier', 'malformed_identifier'],
  ['NotInitialised', 'not_initialised'],
  ['AlreadyInitialised', 'already_initialised'],
])

// 'session_refused' is deliberately not here: see its own doc comment on
// CryptoErrorKind above. It is the one kind this set must never gain by a
// well-meaning edit that assumes every withheld-session kind belongs next
// to 'unshared_session'.
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
