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
  // A payload this library was handed did not parse: `rawEvent`, a
  // `markRequestSent` response body, a sync delta. NOT a bad scope --
  // that is 'malformed_identifier' below, and telling the two apart is
  // the whole reason both exist. A malformed scope reported
  // 'malformed_payload' until the M2 final review, which sent a caller
  // whose payload was fine to go and inspect it.
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
  // An identifier this library was handed did not parse: a `CryptoScopeId`
  // (which `asCryptoScopeId` never validates), a user id, a device id.
  | 'malformed_identifier'
  // ---- verification ------------------------------------------------------
  // The first three cross the FFI boundary; the three after them are
  // synthesised in this file's `toCryptoError` or in facade.ts, the same way
  // 'not_implemented' is, and have no Rust variant.
  //
  // A verification identifier that names no flow this process is taking
  // part in. Either it never named one, or the flow it named finished and
  // the library has since released it -- which happens the next time a flow
  // is started, not on a timer. A caller holding an id across a later
  // `requestVerification` may see this for a flow it watched complete.
  | 'unknown_flow'
  // The call is one this flow supports, but not at the stage it is at.
  // `getVerificationStage` says which stage that is; `startVerification-
  // Comparison` reads it for you and reports the two conditions below
  // instead where they apply.
  | 'wrong_stage'
  // The keys are not exchanged, so there is no string to show yet. **In
  // practice this almost always means the outbound pump was drained and
  // never resolved**: the underlying state machine advances on
  // `markRequestSent`, so a caller that skips it parks the flow here
  // permanently. Deliberately absent from RETRIABLE below: retrying the
  // same call changes nothing at all, and pumping is what fixes it.
  | 'material_not_ready'
  // `startVerificationComparison` on a flow the *other* side already
  // started. Not a failure of the verification -- carry on, wait for the
  // string. Split out from 'wrong_stage' because the sentence a product
  // shows for it is the opposite of the one below.
  | 'comparison_already_started'
  // `startVerificationComparison` on a flow that is over, whether finished
  // or refused. Nothing to carry on with; start a new one.
  | 'verification_ended'
  // `confirmVerification` was handed material that is not the material the
  // flow currently holds. See that function's own doc comment: the argument
  // exists so a product cannot confirm a comparison it never showed.
  | 'material_mismatch'
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
  // Reached from two enums, like `MalformedIdentifier` below.
  // `SessionFfiError::UnknownDevice` is a device that did not meet the trust
  // level a decryption required; `MachineFfiError::UnknownDevice` is a
  // well-formed pair of identifiers naming a device this machine has never
  // been told about, which `requestVerification` reports. One entry serves
  // both because this map is keyed on the variant name alone, and what a
  // caller does about either is the same: query that user's devices through
  // the pump and try again.
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
  // Reached from two enums, not one. `MachineFfiError::MalformedIdentifier`
  // carries a `detail` and covers a bad user or device id at machine
  // creation; `SessionFfiError::MalformedIdentifier` is fieldless and
  // covers a `scope` (or a user id given to `shareScopeKey`) that does not
  // parse. This map is keyed on the variant name alone, so one entry
  // already served both the moment the second existed -- which is
  // convenient and easy to miss, since nothing in this file names either
  // enum. errors.test.ts asserts both, and asserts they agree.
  ['MalformedIdentifier', 'malformed_identifier'],
  ['NotInitialised', 'not_initialised'],
  ['AlreadyInitialised', 'already_initialised'],
  // The three `MachineFfiError` variants the verification surface added.
  // Without these entries every one of them arrives as kind 'unknown' with
  // the message "crypto error: unknown", which is the failure mode this map
  // exists to prevent and which no test on the Rust side can see: the core
  // proves the *right error* is produced, and this map is the only thing
  // that decides whether a product can tell it apart from any other. That
  // matters most for 'material_not_ready', which is the loud form of the one
  // way this flow can otherwise fail silently.
  ['UnknownFlow', 'unknown_flow'],
  ['WrongStage', 'wrong_stage'],
  ['MaterialNotReady', 'material_not_ready'],
  // Three more entries with no Rust variant, like 'NotImplemented' above,
  // synthesised in facade.ts. The first two are what
  // `startVerificationComparison` reports in place of the single
  // `WrongStage` the layer underneath can produce for three different
  // situations; the third is `confirmVerification` refusing material that
  // is not what the flow is showing. Named here rather than built inline so
  // there is one list of every kind this library can produce.
  ['ComparisonAlreadyStarted', 'comparison_already_started'],
  ['VerificationEnded', 'verification_ended'],
  ['MaterialMismatch', 'material_mismatch'],
])

// 'session_refused' is deliberately not here: see its own doc comment on
// CryptoErrorKind above. It is the one kind this set must never gain by a
// well-meaning edit that assumes every withheld-session kind belongs next
// to 'unshared_session'.
//
// 'material_not_ready' is deliberately not here either, and for the sharper
// version of the same reason. It reads transient -- "not ready *yet*" -- and
// a retry loop is the obvious thing to reach for. But the state it names
// does not resolve on its own: the flow advances when the caller resolves
// what it drained from the pump, so a caller that retries without doing that
// spins forever against a machine that will never move. Reporting it
// non-retriable is what sends a reader to the doc comment that says which
// call is missing.
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
