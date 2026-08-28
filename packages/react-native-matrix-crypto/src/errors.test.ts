import { describe, expect, it } from 'vitest'
import { isCryptoError, toCryptoError } from './errors'

describe('toCryptoError', () => {
  it('maps a generated Rejected error to a typed CryptoError', () => {
    const raw = { name: 'Rejected', reason: 'input must not be empty' }
    const err = toCryptoError(raw)
    expect(err.kind).toBe('rejected')
    expect(err.message).toContain('input must not be empty')
    expect(err.retriable).toBe(false)
  })

  it('maps an unknown error to a stable unknown kind rather than throwing', () => {
    const err = toCryptoError(new Error('something else'))
    expect(err.kind).toBe('unknown')
    expect(err.retriable).toBe(false)
  })

  it('carries the sender verbatim when present, per spec section 10', () => {
    const err = toCryptoError({ name: 'MissingKey', sender: '@b:server2' })
    expect(err.kind).toBe('missing_key')
    expect(err.sender).toBe('@b:server2')
  })

  it('never places payload content in the message, per spec section 7', () => {
    const err = toCryptoError({ name: 'Undecryptable', ciphertext: 'SECRET' })
    expect(err.message).not.toContain('SECRET')
  })

  it('recognises its own errors', () => {
    expect(isCryptoError(toCryptoError(new Error('x')))).toBe(true)
    expect(isCryptoError(new Error('x'))).toBe(false)
  })

  it('rejects bare objects that are not Error instances', () => {
    const fakeErr = { [Symbol.for('react-native-matrix-crypto.CryptoError')]: true }
    expect(isCryptoError(fakeErr)).toBe(false)
  })

  it('maps prototype collision name "constructor" to unknown, not a function', () => {
    const err = toCryptoError({ name: 'constructor' })
    expect(err.kind).toBe('unknown')
    expect(typeof err.kind).toBe('string')
  })

  it('maps prototype collision name "toString" to unknown, not a function', () => {
    const err = toCryptoError({ name: 'toString' })
    expect(err.kind).toBe('unknown')
    expect(typeof err.kind).toBe('string')
  })

  it('maps prototype collision name "__proto__" to unknown, not an object', () => {
    const err = toCryptoError({ name: '__proto__' })
    expect(err.kind).toBe('unknown')
    expect(typeof err.kind).toBe('string')
  })
})

/**
 * The tests above use `{ name: 'Rejected', reason: '...' }` fixtures, which
 * is how a hand-built binding may still shape an error. It is not how a real
 * generated one does. `@ubjs/core`'s `UniffiError` base class (confirmed by
 * reading its source, `node_modules/@ubjs/core/src/errors.ts`) never sets
 * `.name` -- it stays the inherited `"Error"` -- and always sets `.message`
 * to exactly `"<EnumTypeName>.<VariantName>"`, optionally followed by
 * `": <message>"`; the variant's payload lives under `.inner`, set by the
 * generated per-variant subclass (confirmed against the actual generated
 * `ProbeFfiError.Rejected` in `src/generated/matrix_crypto.ts`), never at
 * the top level. This is exactly the shape `interop/reference.ts` throws.
 *
 * This gap -- tests and the reference binding restating a contract nothing
 * implements -- is why 19 green tests missed a real bug: `toCryptoError`
 * read `.name`/top-level `.reason`, which happened to satisfy these old
 * fixtures and nothing else. See `errors.ts`'s `variantNameFromMessage` and
 * `stringField` doc comments, and Task 11's report.
 */
describe('toCryptoError against the real UniFFI error shape', () => {
  it('maps a real UniFFI-shaped Rejected error end to end: name inherited "Error", variant in .message, payload under .inner', () => {
    const raw = Object.assign(new Error('ProbeFfiError.Rejected'), {
      inner: { reason: 'input must not be empty' },
    })
    // Sanity check that this fixture is the real shape, not the fiction the
    // tests above use.
    expect(raw.name).toBe('Error')

    const err = toCryptoError(raw)
    expect(err.kind).toBe('rejected')
    expect(err.message).toContain('input must not be empty')
    expect(err.retriable).toBe(false)
  })

  it('maps a real UniFFI-shaped MachineFfiError.NotInitialised to kind not_initialised', () => {
    // A fieldless ("flat") variant carries no `.inner` at all -- confirmed
    // against the actual generated `MachineFfiError.NotInitialised` in
    // src/generated/matrix_crypto.ts, whose constructor takes no arguments
    // and so calls `super("MachineFfiError", "NotInitialised")` with no
    // third `message` argument, leaving `.message` exactly
    // "MachineFfiError.NotInitialised" with no trailing ": <message>".
    const raw = new Error('MachineFfiError.NotInitialised')
    expect(raw.name).toBe('Error')

    const err = toCryptoError(raw)
    expect(err.kind).toBe('not_initialised')
    expect(err.retriable).toBe(false)
  })

  /**
   * Regression for FIX 2: `errors.ts` used to map `['StoreCorrupt',
   * 'store_corrupt']`, a Rust variant that has never existed --
   * `MachineFfiError`'s real variant is `Store` (see the generated
   * `MachineFfiError_Tags` in src/generated/matrix_crypto.ts), so a genuine
   * store failure fell through `KIND_BY_NAME` to `kind: 'unknown'`. `Store`
   * is a fielded variant (it carries `.inner.detail`), but its `.message` is
   * still exactly "MachineFfiError.Store" with no ": <message>" suffix: the
   * generated `Store_` constructor calls `super("MachineFfiError", "Store")`
   * with no third argument, matching `NotInitialised` above.
   */
  it('maps a real UniFFI-shaped MachineFfiError.Store to kind store_unavailable, not store_corrupt', () => {
    const raw = new Error('MachineFfiError.Store')
    expect(raw.name).toBe('Error')

    const err = toCryptoError(raw)
    expect(err.kind).toBe('store_unavailable')
    expect(err.kind).not.toBe('store_corrupt')
    expect(err.retriable).toBe(false)
  })

  /**
   * A parked finding from Task 2's review, addressed in Task 6: opening a
   * store that belongs to a different account is a recoverable
   * configuration mistake, not a storage failure like a full disk --
   * conflating the two under 'store_unavailable' would send a product
   * down the wrong recovery path. `MismatchedAccount` is a fieldless
   * variant, like `NotInitialised` above, so `.message` carries no
   * ": <message>" suffix either.
   */
  it('maps a real UniFFI-shaped MachineFfiError.MismatchedAccount to kind mismatched_account, not store_unavailable', () => {
    const raw = new Error('MachineFfiError.MismatchedAccount')
    expect(raw.name).toBe('Error')

    const err = toCryptoError(raw)
    expect(err.kind).toBe('mismatched_account')
    expect(err.kind).not.toBe('store_unavailable')
    expect(err.retriable).toBe(false)
  })

  it('recovers the variant from the "<Type>.<Variant>" prefix of .message when .name is not a recognized kind', () => {
    const err = toCryptoError({ name: 'Error', message: 'ProbeFfiError.Rejected' })
    expect(err.kind).toBe('rejected')
  })

  it('reads the payload from .inner rather than the top level', () => {
    const err = toCryptoError({
      name: 'MissingKey',
      inner: { reason: 'no room key for this session', sender: '@b:server2' },
    })
    expect(err.kind).toBe('missing_key')
    expect(err.message).toContain('no room key for this session')
    expect(err.sender).toBe('@b:server2')
  })

  /**
   * The three `SessionFfiError` variants Task 6 could not yet exercise
   * end to end (its own F9): `SessionError` had no FFI mirror at all, so
   * these were forward scaffolding, present in `KIND_BY_NAME` but
   * unreachable from a real generated error. Task 7 gives `SessionError`
   * that mirror; this proves the map entry was already correct, not that
   * it becomes correct now.
   */
  it('maps a real UniFFI-shaped SessionFfiError.MalformedPayload to kind malformed_payload', () => {
    const err = toCryptoError(new Error('SessionFfiError.MalformedPayload'))
    expect(err.kind).toBe('malformed_payload')
    expect(err.retriable).toBe(false)
  })

  it('maps a real UniFFI-shaped SessionFfiError.Failed to kind failed', () => {
    const err = toCryptoError(new Error('SessionFfiError.Failed'))
    expect(err.kind).toBe('failed')
    expect(err.retriable).toBe(false)
  })

  it('maps a real UniFFI-shaped SessionFfiError.UnknownRequest to kind unknown_request', () => {
    const err = toCryptoError(new Error('SessionFfiError.UnknownRequest'))
    expect(err.kind).toBe('unknown_request')
    expect(err.retriable).toBe(false)
  })

  /**
   * Regression for the `RevokedDevice` cleanup (flagged by Task 6's review,
   * finding F3, fixed here): `KIND_BY_NAME` used to map
   * `['RevokedDevice', 'revoked_device']`, a name that exists in neither
   * Rust crate -- confirmed by a whole-tree grep. Unlike the `StoreCorrupt`
   * bug it is modelled on, it shadowed no real condition, but it was dead
   * scaffolding and a trap for whoever next assumed the map was
   * authoritative. This asserts the entry is gone: an error naming that
   * variant now falls through to 'unknown' like any other unrecognised
   * name, rather than continuing to "work" by accident.
   */
  it('no longer maps RevokedDevice specially: it falls through to unknown', () => {
    const err = toCryptoError(new Error('MachineFfiError.RevokedDevice'))
    expect(err.kind).toBe('unknown')
  })

  it('still recovers the variant when .message carries a trailing ": <message>" suffix', () => {
    // `UniffiError`'s constructor (`node_modules/@ubjs/core/src/errors.ts`)
    // takes an optional third `message` argument and, when given one,
    // formats it as "<Type>.<Variant>: <message>". `ProbeFfiError.Rejected`
    // never takes this path (it is a fielded/tagged variant, generated by
    // ubrn's TaggedEnumTemplate.ts, which never passes a third argument) --
    // but ubrn's ErrorTemplate.ts `flat_error` macro does, for fieldless
    // ("flat") UniFFI error enums, so this is a real shape the same base
    // class produces elsewhere, not a hypothetical one.
    const err = toCryptoError({
      name: 'Error',
      message: 'ProbeFfiError.Rejected: probe rejected: input must not be empty',
    })
    expect(err.kind).toBe('rejected')
  })
})
