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
  // Forward scaffolding, not dead: nothing produces this. M3 landed device
  // verification and did not, because revoking a device is an identity
  // operation and identity waits on cross-signing, which is M4. **No
  // milestone is named here on purpose**, since the last one named came and
  // went with the comment unchanged: this kind stays declared and unproduced
  // until something produces it, and it stays in the union rather than being
  // silently dropped or silently absent -- the same treatment
  // 'not_implemented' gets in KIND_BY_NAME. If it turns out never to be
  // needed, remove it and say so; silence about which is not an option.
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
  // `markRequestFailed` was given a status that is not one a refused request
  // can carry. Accepted are 0, meaning nothing came back at all, and 300
  // through 599. The case this exists to catch is a **2xx**: it means
  // `markRequestFailed` and `markRequestSent` have been swapped, and since
  // reporting a refusal changes no state, saying nothing would let that
  // stand. It is the confusion this call can see in its own arguments, not
  // the only one the library catches: reporting a refused response through
  // `markRequestSent` is caught too whenever the body is not shaped like
  // that endpoint's answer. What neither can see is a refusal whose body is
  // shaped like one.
  | 'not_a_failure_status'
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
  // is *registered*, not on a timer. Registration is broader than starting
  // one: an inbound invitation announced down the signal channel registers,
  // and so does the first call made against a flow this process is not
  // already caching. A caller holding an id across any of those may see
  // this for a flow it watched complete.
  | 'unknown_flow'
  // The call is one this flow supports, but not at the stage it is at.
  // `getVerificationStage` says which stage that is; `startVerification-
  // Comparison` reads it for you and reports the two conditions below
  // instead where they apply.
  | 'wrong_stage'
  // The keys are not exchanged, so there is no string to show yet. **Two
  // causes, and they need opposite things done about them** -- read
  // `getVerificationStage`, which is what tells them apart:
  //
  //   - stage `'started'` and *the peer* opened the comparison: their start
  //     is a question this side has not answered. Answer it with a second
  //     `acceptVerification`. Pumping never fixes this one, and a product
  //     that only pumps waits forever.
  //   - otherwise, the outbound pump was drained and never resolved: the
  //     underlying state machine advances on `markRequestSent`, so a caller
  //     that skips it parks the flow here permanently.
  //
  // Deliberately absent from RETRIABLE below: retrying the same call
  // changes nothing at all under either cause.
  | 'material_not_ready'
  // `startVerificationComparison` on a flow the *other* side already
  // started. Not a failure of the verification -- but not nothing to do
  // either: their start is a question, so answer it with a second
  // `acceptVerification` and then wait for the string. Split out from
  // 'wrong_stage' because the sentence a product shows for it is the
  // opposite of the one below.
  | 'comparison_already_started'
  // `startVerificationComparison` on a flow that is over, whether finished
  // or refused. Nothing to carry on with; start a new one.
  | 'verification_ended'
  // `confirmVerification` was handed material that is not the material the
  // flow currently holds. See that function's own doc comment: the argument
  // exists so a product cannot confirm a comparison it never showed.
  | 'material_mismatch'
  // ---- the signing identity ----------------------------------------------
  // Both cross the FFI boundary, and both are `bootstrapCrossSigning`
  // refusing rather than failing. They are kept apart because their remedies
  // are opposite: one is a round of the ordinary pump loop, the other is a
  // thing this release cannot do at all.
  //
  // This library cannot yet say what identity this account has, so it cannot
  // know whether publishing would destroy one. The call queues a key query
  // as it refuses, so the usual remedy is drain, send, report sent, call
  // again. Deliberately absent from RETRIABLE below, for
  // 'material_not_ready''s reason: calling again without pumping in between
  // returns this forever.
  //
  // **That remedy has a case where it never terminates, and
  // `getIdentityStatus` is what says so.** This kind covers two situations:
  // nobody has asked, and the query was asked and answered by a server whose
  // answer settled nothing. The second is what a homeserver sends for a user
  // it does not know, which the Matrix specification prescribes, and what a
  // real Synapse sends when the server-name half of the account id differs
  // in case from its own. Read `accountKeysAnswerUnsettled`: false means
  // pump and call again, true means stop pumping and check the account id
  // against the canonical `user_id` your login returned. Nothing is
  // destroyed while it is true.
  | 'account_keys_not_fetched'
  // The account has a signing identity whose private keys this device does
  // not hold. There is no remedy through that call and there should not be:
  // this device joins that identity, it does not replace it, and replacing
  // it would reset the trust of everyone who had verified the old one.
  | 'identity_already_exists'
  // The mirror image of the kind above, and the third refusal on this
  // surface that turns on the same question: the server has been asked and
  // named no identity for this account. Deliberately absent from RETRIABLE
  // below: calling again changes nothing until an identity exists.
  //
  // **Two calls report it and they want the same thing done, which is a
  // decision rather than a retry.** `requestSelfVerification` reports it
  // because there is no identity to join. `bootstrapCrossSigning` reports it
  // because there is none to publish; it used to create one at this point,
  // and that is what an honest server plus ordinary two-device timing turned
  // into a creation over an identity another device had just published. The
  // answer to both is `createCrossSigningIdentity`, and it belongs where
  // your product has decided this account should be getting its first
  // identity, not in the handler that caught this.
  | 'identity_not_known'
  // ---- server-side recovery ----------------------------------------------
  // All four cross the FFI boundary. The pair in the middle is the one this
  // surface exists to keep apart, and the one a product's error message
  // turns on.
  //
  // `createRecovery` on a device that does not hold all three private
  // signing keys. There is nothing to write; `getIdentityStatus` says
  // whether the remedy is to create an identity or to join one.
  | 'private_keys_not_held'
  // The account data handed to `recoverIdentity` carries no complete
  // recovery. Either this account has none, or not all of it was fetched;
  // that call's own doc comment names the five events a complete one has.
  // This library sees only what it was given, so it cannot tell the two
  // apart, and says so rather than guessing.
  | 'recovery_not_set_up'
  // The passphrase or recovery key does not open the stored recovery, which
  // is otherwise intact. **The one refusal on this surface a user fixes by
  // typing again**, which is why it is not folded into the kind below.
  // Deliberately absent from RETRIABLE: retrying the same call with the same
  // secret fails the same way every time, and what resolves it is a
  // different secret rather than a repeat.
  | 'recovery_key_incorrect'
  // The stored recovery cannot be read, so no secret will open it: damaged
  // or unparseable account data, and also a recovery written for an identity
  // this account has since replaced. The remedy is to set recovery up again
  // from a device that still holds the keys.
  //
  // Folding this with 'recovery_key_incorrect' is the defect both exist to
  // prevent, and it goes wrong in both directions: a user with a typo told
  // their identity is destroyed does the one thing that destroys it, and a
  // user whose recovery really is unreadable retypes a correct passphrase
  // forever.
  | 'recovery_data_malformed'
  // `createRecovery` was handed account data that already names a recovery.
  // It will not write over one, because it cannot tell a user replacing
  // their own passphrase from a product about to invalidate the recovery key
  // another Matrix client gave this user and told them to keep. See that
  // call for the remedy, which is a deliberate clear-then-write rather than
  // a retry.
  | 'recovery_already_exists'
  | 'not_implemented'
  | 'not_initialised'
  | 'already_initialised'
  | 'unknown'
  | (string & {})

export interface CryptoError extends Error {
  kind: CryptoErrorKind
  /**
   * **Always `undefined` in every release so far.** Declared, and never
   * populated: every `SessionFfiError` variant is fieldless by
   * construction, so nothing on the decryption path can carry a scope
   * across the FFI boundary for `toCryptoError` to find. See `sender` below
   * for why the fields stay.
   *
   * A product handling a failed `decryptEvent` must therefore take the
   * scope from the call it made, not from the error it caught.
   */
  scope?: CryptoScopeId
  /**
   * Fully qualified `@user:server`, verbatim. Spec section 10.
   *
   * **Always `undefined` in every release so far**, for the same reason as
   * `scope` above: `SessionFfiError` is fieldless throughout,
   * `MachineFfiError` carries only `detail` and `ProbeFfiError` only
   * `reason`, so no FFI error variant can carry a sender. Both fields are optional and both are read
   * defensively by `toCryptoError`, so a later milestone that starts
   * populating them is additive rather than breaking. That is why they are
   * declared now and said to be empty, rather than removed and re-added.
   *
   * Note that a sender would not become authoritative merely by appearing
   * here. Spec section 7.1 applies to it exactly as it applies to
   * `EventEnvelope.sender` in `types.ts`: a sender is unauthenticated transport
   * metadata, and **completing a device verification does not change
   * that.** This used to say "until device verification lands", which
   * named a condition that has since been met and is not the one that
   * matters: a short string comparison sets *local* trust in a device, and
   * the path that decides what an event says about its sender consults
   * cross-signing, which nothing here publishes yet. The README retracts
   * the same claim in the same terms; cross-signing is M4.
   */
  sender?: string
  /** The bridge reports transience. The product layer decides what to do. */
  retriable: boolean
}

const BRAND = Symbol.for('react-native-matrix-crypto.CryptoError')

const KIND_BY_NAME = new Map<string, CryptoErrorKind>([
  ['Rejected', 'rejected'],
  // The one entry with no Rust variant, and never will have one: synthesised
  // in TypeScript by facade.ts's `notImplemented` helper for every
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
  // `markRequestFailed` handed a status that is not a refusal. See the
  // kind's own comment in the union above for why a 2xx is the case that
  // matters.
  ['NotAFailureStatus', 'not_a_failure_status'],
  // `MachineError::Store` means the store could not be opened -- often a
  // wrong passphrase or a permissions problem, not damaged data. Mapping it
  // to 'store_corrupt' would send a product down a destructive recovery path
  // over what might just be a typo'd passphrase. 'store_corrupt' stays in
  // the CryptoErrorKind union for genuine corruption, which decryption work
  // could detect; nothing maps to it yet, and nothing in M2 or M3 came to.
  // It stays declared rather than removed, on the same rule as
  // 'revoked_device' above.
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
  // The two `MachineFfiError` variants the signing identity added. They were
  // declared on the Rust side one task before anything returned them, so
  // until `bootstrapCrossSigning` was bridged there was no way to notice
  // they were missing here -- and the symptom would have been the one this
  // map exists to prevent: both refusals arriving as kind 'unknown' with the
  // message "crypto error: unknown", indistinguishable from each other and
  // from every unmapped failure, on the one call whose two refusals need
  // opposite things done about them.
  ['AccountKeysNotFetched', 'account_keys_not_fetched'],
  ['IdentityAlreadyExists', 'identity_already_exists'],
  // The third of that group, added with self-verification. It completes a
  // triangle rather than a pair: `identity_already_exists` says the account
  // has an identity this device is not part of, and this says the account has
  // none at all. A product told the wrong one either waits for an identity
  // that does not exist or refuses to create the one that is missing.
  ['IdentityNotKnown', 'identity_not_known'],
  // The four `MachineFfiError` variants server-side recovery added. Without
  // these entries every one of them arrives as kind 'unknown' with the
  // message "crypto error: unknown", which is the failure mode this map
  // exists to prevent and which no test on the Rust side can see. It matters
  // most for the middle pair: the Rust side proves a wrong passphrase and an
  // unreadable recovery are told apart, and this map is the only thing that
  // decides whether a product can act on the difference.
  ['PrivateKeysNotHeld', 'private_keys_not_held'],
  ['RecoveryNotSetUp', 'recovery_not_set_up'],
  ['RecoveryKeyIncorrect', 'recovery_key_incorrect'],
  ['RecoveryDataMalformed', 'recovery_data_malformed'],
  // The fifth, added when `createRecovery` stopped writing over a recovery
  // the account already had. Without this entry a product would be told
  // 'unknown' on the one refusal whose whole purpose is to make it stop and
  // look.
  ['RecoveryAlreadyExists', 'recovery_already_exists'],
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
