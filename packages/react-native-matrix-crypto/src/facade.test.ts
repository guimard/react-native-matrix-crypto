import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { CryptoScopeId, SasMaterial, SyncDelta, VerificationStage } from './types'
import { asCryptoScopeId } from './types'
import { isCryptoError } from './errors'
import {
  acceptVerification,
  bootstrapCrossSigning,
  cancelVerification,
  confirmVerification,
  createCryptoMachine,
  decryptEvent,
  encryptEvent,
  encryptionSlice,
  exportSecrets,
  getDeviceIdentityKeys,
  getDeviceStatuses,
  getIdentityStatus,
  getVerificationMaterial,
  getVerificationStage,
  markRequestFailed,
  markRequestSent,
  openCryptoStore,
  receiveSyncChanges,
  requestVerification,
  shareScopeKey,
  startVerificationComparison,
  takeOutgoingRequests,
} from './facade'
import {
  acceptVerification as nativeAcceptVerification,
  bootstrapIdentity as nativeBootstrapIdentity,
  cancelVerification as nativeCancelVerification,
  confirmVerification as nativeConfirmVerification,
  createCryptoMachine as nativeCreateCryptoMachine,
  decryptEvent as nativeDecryptEvent,
  deviceIdentityKeys as nativeDeviceIdentityKeys,
  deviceStatuses as nativeDeviceStatuses,
  encryptEvent as nativeEncryptEvent,
  identityStatus as nativeIdentityStatus,
  MachineFfiError,
  markRequestFailed as nativeMarkRequestFailed,
  markRequestSent as nativeMarkRequestSent,
  openCryptoStore as nativeOpenCryptoStore,
  receiveSyncChanges as nativeReceiveSyncChanges,
  requestVerification as nativeRequestVerification,
  SenderVerification as NativeSenderVerification,
  SessionFfiError,
  shareScopeKey as nativeShareScopeKey,
  startVerificationComparison as nativeStartVerificationComparison,
  takeOutgoingRequests as nativeTakeOutgoingRequests,
  TrustState as NativeTrustState,
  verificationMaterial as nativeVerificationMaterial,
  verificationStage as nativeVerificationStage,
  VerificationStage as NativeVerificationStage,
} from './generated/matrix_crypto'

const scope = asCryptoScopeId('!scope:example.org')

/**
 * The generated binding speaks `ArrayBuffer` for `Vec<u8>` fields (see
 * `Envelope.ciphertext` in `./generated/matrix_crypto`); this builds a fake
 * native response's ciphertext the same way a real one would arrive.
 */
function toArrayBuffer(text: string): ArrayBuffer {
  return new TextEncoder().encode(text).buffer as ArrayBuffer
}

// Only the native call itself is mocked -- there is no JSI host object under
// vitest (Node), so `deviceIdentityKeys` can never actually run here. Every
// other export, including the real generated `MachineFfiError` class, comes
// through `importOriginal` untouched, and `getDeviceIdentityKeys` /
// `toCryptoError` below run completely unmocked. This is FIX 2's real
// failure path: rust/matrix-crypto-core/src/identity.rs rejects a user id
// that fails `OwnedUserId` parsing with `MachineError::MalformedIdentifier
// { detail: "user id" }`, which rust/matrix-crypto-ffi/src/lib.rs mirrors as
// `MachineFfiError::MalformedIdentifier { detail }` -- the exact shape
// mocked below, not a hand-typed `{ name, reason }` fixture. (Renamed from
// `IdentityFfiError` in Task 2/3: `device_identity_keys` now reads the live,
// store-backed machine, so its error is the machine's, not a throwaway
// identity-only one.)
vi.mock('./generated/matrix_crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./generated/matrix_crypto')>()
  return {
    ...actual,
    // Stateless: both resolve to void on any input, so FIX 1's tests below
    // can inspect what reached them via vi.mocked(...).mock.calls without
    // this mock throwing or needing per-test setup.
    createCryptoMachine: vi.fn(async () => undefined),
    openCryptoStore: vi.fn(async () => undefined),
    deviceIdentityKeys: vi.fn(async (userId: string) => {
      if (userId !== 'bad-id') throw new Error('unexpected call in this fixture')
      throw new actual.MachineFfiError.MalformedIdentifier({ detail: 'user id' })
    }),
    // Task 7: session, encrypt/decrypt and the outbound pump. Stateless
    // defaults, distinguishable from any input, so a test that forgets to
    // assert on `.mock.calls` would still notice values it did not supply
    // flowing back out.
    receiveSyncChanges: vi.fn(async () => ({ toDeviceEventCount: 0, newSessionCount: 0 })),
    encryptEvent: vi.fn(async () => ({
      scope: '!native-scope:example.org',
      algorithm: 'm.native.algorithm',
      eventType: 'm.native.event',
      ciphertext: toArrayBuffer('native-ciphertext'),
      sender: '@native-sender:example.org',
    })),
    decryptEvent: vi.fn(async () => ({
      scope: '!native-scope:example.org',
      algorithm: 'm.native.algorithm',
      eventType: 'm.native.event',
      ciphertext: toArrayBuffer('native-plaintext'),
      sender: '@native-sender:example.org',
      // `actual.SenderVerification`, the real generated enum, not a
      // hand-typed number: a fixture that guessed the ordinal would keep
      // passing after a regeneration renumbered it. Not `Verified`, here
      // or anywhere else in this file -- see the distinguishing tests
      // below for why that is a rule rather than an accident.
      senderVerification: actual.SenderVerification.UnsignedDevice,
    })),
    shareScopeKey: vi.fn(async () => undefined),
    takeOutgoingRequests: vi.fn(async () => [{ id: 'req-1', kind: 'keys_upload', body: '{}' }]),
    markRequestFailed: vi.fn(async () => undefined),
    markRequestSent: vi.fn(async () => undefined),
    // Task 3: the verification surface. Stateless defaults again, and
    // deliberately distinguishable from anything a facade test supplies, so
    // a test that forgot to assert on `.mock.calls` would still notice
    // values it never provided coming back out. `actual.MachineFfiError`,
    // `actual.TrustState` and `actual.VerificationStage` all come through
    // `importOriginal` untouched, so every test below that throws or
    // returns one is using the real generated shape rather than a fixture
    // that happens to satisfy the facade's reader.
    deviceStatuses: vi.fn(async () => [
      { deviceId: 'NATIVEDEVICE', trust: actual.TrustState.Unverified },
    ]),
    requestVerification: vi.fn(async () => 'native-flow-id'),
    acceptVerification: vi.fn(async () => undefined),
    startVerificationComparison: vi.fn(async () => undefined),
    verificationStage: vi.fn(async () => actual.VerificationStage.Requested),
    verificationMaterial: vi.fn(async () => ({
      emoji: [{ symbol: 'native-symbol', description: 'native-word' }],
      decimalOne: 1111,
      decimalTwo: 2222,
      decimalThree: 3333,
    })),
    confirmVerification: vi.fn(async () => undefined),
    cancelVerification: vi.fn(async () => undefined),
    // The signing identity. Stateless defaults, and deliberately the
    // "nobody has asked" row rather than a served one: a test that forgot
    // to install the chain fake below gets the refusal the real core would
    // give it, not a bootstrap that silently succeeds.
    identityStatus: vi.fn(async () => ({
      accountKeysFetched: false,
      identityKnown: false,
      privateKeysHeld: false,
    })),
    bootstrapIdentity: vi.fn(async () => {
      throw new actual.MachineFfiError.AccountKeysNotFetched()
    }),
  }
})

describe('facade before implementation', () => {
  it('rejects exportSecrets with a typed not_implemented error rather than undefined', async () => {
    await expect(exportSecrets('passphrase')).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'not_implemented',
    )
  })
})

/**
 * Task 7. Each test proves the wiring, not just that the call compiles: it
 * inspects what actually reached `vi.mocked(native*).mock.calls`, and/or
 * that the facade's own return value is rebuilt field-by-field from the
 * native response rather than passed through. This is the same shape as
 * the `storePassphrase` regression above, which was verified by severing
 * the wiring and watching the matching test fail -- done again here for
 * `encryptEvent`'s `eventType` forwarding and its `ciphertext`
 * ArrayBuffer->Uint8Array conversion (see task-7-report.md).
 */
describe('receiveSyncChanges wiring to the native layer', () => {
  /**
   * The top-level shape of a real homeserver's `/sync` response. Trimmed of
   * payload, complete in its *keys*, because it is the key names that decide
   * whether the guard fires. A given homeserver may omit some of these --
   * the Continuwuity instance the level 2 interoperability test runs against
   * omits `device_one_time_keys_count` entirely -- but every one of them is
   * included here so the rename table the doc comment publishes is exercised
   * in full.
   */
  const SYNC_RESPONSE = {
    next_batch: 's72595_4483_1934',
    rooms: { join: {}, invite: {}, leave: {} },
    presence: { events: [] },
    account_data: { events: [] },
    to_device: {
      events: [{ sender: '@bob:example.org', type: 'm.room.encrypted', content: {} }],
    },
    device_lists: { changed: ['@bob:example.org'], left: [] },
    device_one_time_keys_count: { signed_curve25519: 50 },
    device_unused_fallback_key_types: ['signed_curve25519'],
  }

  it('forwards the sync delta as JSON and resolves void, discarding the native counts', async () => {
    // snake_case, matching the core's own `SyncChangesPayload` field names
    // exactly -- see the regression test below for why this is load-bearing,
    // not a style choice.
    const delta = {
      to_device_events: [],
      changed_devices: { changed: [], left: [] },
      one_time_keys_counts: {},
    }

    await expect(receiveSyncChanges(delta)).resolves.toBeUndefined()

    expect(vi.mocked(nativeReceiveSyncChanges).mock.calls.at(-1)?.[0]).toBe(JSON.stringify(delta))
  })

  it('accepts an empty object -- the shape an ordinary, uneventful sync sends', async () => {
    await expect(receiveSyncChanges({})).resolves.toBeUndefined()

    expect(vi.mocked(nativeReceiveSyncChanges).mock.calls.at(-1)?.[0]).toBe('{}')
  })

  it('accepts a payload naming at least one recognised field alongside an unrecognised one, tolerating a homeserver-added field', async () => {
    const delta = { changed_devices: { changed: [], left: [] }, some_future_sync_field: 'value' }

    await expect(receiveSyncChanges(delta)).resolves.toBeUndefined()

    expect(vi.mocked(nativeReceiveSyncChanges).mock.calls.at(-1)?.[0]).toBe(JSON.stringify(delta))
  })

  /**
   * Regression for F2 (Task 7 fix round 1): this file's own fixture above
   * used to be camelCase (`{ toDeviceEvents: [...] }`), which the core
   * silently accepts as an all-default, no-op payload -- every field
   * defaults independently and unknown keys are ignored -- so the one
   * worked example a reader would copy out of this repo was the silent
   * no-op the whole surface exists to catch. This proves a payload naming
   * none of the recognised fields is now rejected before it ever gets the
   * chance to silently do nothing.
   */
  it('rejects with malformed_payload before ever calling native, when the payload names none of the recognised fields', async () => {
    vi.mocked(nativeReceiveSyncChanges).mockClear()

    // Cast, deliberately: this is how a JavaScript consumer with no types
    // reaches this function, and the guard exists for exactly them -- see
    // the `encryptionSlice` describe block below for the same pattern.
    await expect(
      receiveSyncChanges({ toDeviceEvents: [] } as unknown as SyncDelta),
    ).rejects.toSatisfy((e: unknown) => isCryptoError(e) && e.kind === 'malformed_payload')
    await expect(
      receiveSyncChanges({ nonsense: true } as unknown as SyncDelta),
    ).rejects.toSatisfy((e: unknown) => isCryptoError(e) && e.kind === 'malformed_payload')

    expect(nativeReceiveSyncChanges).not.toHaveBeenCalled()
  })

  /**
   * Regression for F1 (Task 12 review). This function's own documentation
   * used to say a `/sync` response could be handed over "verbatim". It
   * cannot: the eight top-level keys above have no member in common with
   * the five this function reads, so the guard rejects the whole response.
   * The documentation said one thing and the code eleven lines above it
   * said another, for four tasks, because nothing fed this function a real
   * homeserver's body until level 2 did.
   */
  it('rejects a raw /sync response, which names none of the recognised fields', async () => {
    vi.mocked(nativeReceiveSyncChanges).mockClear()

    // Cast, deliberately: SYNC_RESPONSE's keys and SyncDelta's have no
    // member in common (the whole point of this test), and TypeScript's own
    // weak-type check (every SyncDelta field is optional) refuses that
    // assignment on sight -- this is the compile-time half of the same
    // rejection the runtime guard proves below. A JavaScript caller with no
    // types reaches this shape without a cast, which is why the guard, not
    // the type, has to be the one that actually stops it.
    await expect(
      receiveSyncChanges(SYNC_RESPONSE as unknown as SyncDelta),
    ).rejects.toSatisfy((e: unknown) => isCryptoError(e) && e.kind === 'malformed_payload')

    expect(nativeReceiveSyncChanges).not.toHaveBeenCalled()
  })

  /**
   * The other half of the same regression, and the half that makes it
   * actionable. A test proving only that the raw body is rejected leaves a
   * reader knowing what not to do and not what to do; this applies the
   * five-way rename the doc comment publishes, to the same fixture, and
   * requires it through. If the doc comment's table and this test ever
   * disagree, one of them fails.
   */
  it('accepts the same /sync response once the five documented fields are renamed', async () => {
    const syncDelta = {
      to_device_events: SYNC_RESPONSE.to_device.events,
      changed_devices: SYNC_RESPONSE.device_lists,
      one_time_keys_counts: SYNC_RESPONSE.device_one_time_keys_count,
      unused_fallback_keys: SYNC_RESPONSE.device_unused_fallback_key_types,
      next_batch_token: SYNC_RESPONSE.next_batch,
    }

    await expect(receiveSyncChanges(syncDelta)).resolves.toBeUndefined()

    expect(vi.mocked(nativeReceiveSyncChanges).mock.calls.at(-1)?.[0]).toBe(
      JSON.stringify(syncDelta),
    )

    // Each renamed field on its own, so a typo in any single row of the
    // published table fails here. Asserting only the five together would
    // pass with four correct names and one wrong one, since the guard asks
    // for *some* recognised field rather than all of them.
    for (const [field, value] of Object.entries(syncDelta)) {
      vi.mocked(nativeReceiveSyncChanges).mockClear()

      await expect(receiveSyncChanges({ [field]: value })).resolves.toBeUndefined()

      expect(nativeReceiveSyncChanges).toHaveBeenCalledOnce()
    }
  })

  /**
   * Regression for F6 (Task 7 fix round 1): `JSON.stringify(undefined)` is
   * the *value* `undefined`, not a string. `syncDelta` is now typed
   * `SyncDelta` rather than `unknown`, which is exactly why the call below
   * needs the cast: a typed caller cannot reach this path at all any more,
   * but an untyped JavaScript one still can, and the guard has to catch it
   * for them. This proves it is rejected before native is ever called,
   * rather than forwarded as the four-character string `"undefined"` or the
   * bare value `undefined`.
   */
  it('rejects with malformed_payload before ever calling native, when syncDelta stringifies to undefined', async () => {
    vi.mocked(nativeReceiveSyncChanges).mockClear()

    await expect(receiveSyncChanges(undefined as unknown as SyncDelta)).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'malformed_payload',
    )

    expect(nativeReceiveSyncChanges).not.toHaveBeenCalled()
  })
})

describe('encryptionSlice', () => {
  it('renames all five fields a sync response carries', () => {
    const slice = encryptionSlice({
      to_device: { events: [{ type: 'm.room.encrypted' }] },
      device_lists: { changed: ['@a:example.org'], left: [] },
      device_one_time_keys_count: { signed_curve25519: 42 },
      device_unused_fallback_key_types: ['signed_curve25519'],
      next_batch: 's72595_4483_1934',
      rooms: { join: {} },
      presence: { events: [] },
    })
    expect(slice).toEqual({
      to_device_events: [{ type: 'm.room.encrypted' }],
      changed_devices: { changed: ['@a:example.org'], left: [] },
      one_time_keys_counts: { signed_curve25519: 42 },
      unused_fallback_keys: ['signed_curve25519'],
      next_batch_token: 's72595_4483_1934',
    })
  })

  it('omits absent fields rather than passing undefined', () => {
    expect(encryptionSlice({ next_batch: 'x' })).toEqual({ next_batch_token: 'x' })
    expect(Object.keys(encryptionSlice({ next_batch: 'x' }))).toEqual(['next_batch_token'])
  })

  // The two tests below pin the behaviour that separates this helper from the
  // hand-written copies it replaces. Those tested each field for truthiness;
  // this one tests for presence, matching `encryption_slice` in
  // `rust/matrix-crypto-core/tests/level_two_interop.rs`, which is the version
  // exercised against a real homeserver.
  //
  // The difference is not cosmetic. A truthiness test silently drops a field a
  // homeserver did send, which is indistinguishable downstream from a field it
  // never sent -- and this is the one call whose failure mode is a library that
  // appears to work and encrypts to nobody. The correction arrived untested;
  // these are what stop it regressing back to `if (sync.device_lists)`.
  //
  // Both were verified by reverting the two presence checks to truthiness
  // checks and watching each test go red for its own field, then reverting.
  // Doing that is also what caught the first draft's overclaim, recorded in
  // the comment inside the first test.

  it('forwards a field that is present but empty', () => {
    // A first draft of this test claimed every value here was dropped by a
    // truthiness test. That was false and the sabotage run proved it: `{}` and
    // `[]` are truthy in JavaScript, so those three fields were never at risk
    // from the old form. Only `next_batch: ''` is, and it is what makes this
    // test fail against `if (sync.next_batch)` -- verified by making exactly
    // that change and watching it go red.
    //
    // The other four stay because they pin the semantics rather than the
    // divergence: an empty payload from the homeserver is forwarded as an
    // empty payload, not silently turned into an absent one.
    expect(
      encryptionSlice({
        to_device: { events: [] },
        device_lists: {},
        device_one_time_keys_count: {},
        device_unused_fallback_key_types: [],
        next_batch: '',
      }),
    ).toEqual({
      to_device_events: [],
      changed_devices: {},
      one_time_keys_counts: {},
      unused_fallback_keys: [],
      next_batch_token: '',
    })
  })

  it('forwards a field explicitly set to null rather than dropping it', () => {
    // `null` is present. Whether native then rejects it is native's business;
    // silently deciding here that the homeserver meant to omit it is not.
    const slice = encryptionSlice({ device_lists: null, next_batch: null })
    expect(Object.keys(slice).sort()).toEqual(['changed_devices', 'next_batch_token'])
    expect(slice.changed_devices).toBeNull()
  })

  it('produces something the guard accepts, for an uneventful sync', async () => {
    // The point of this test: the helper and the guard must agree. An empty
    // sync is the shape most syncs have, and a helper that produced a payload
    // its own library rejects would fail here rather than in a product.
    await expect(receiveSyncChanges(encryptionSlice({ rooms: {} }))).resolves.toBeUndefined()
  })

  it('still rejects a camelCase payload', async () => {
    // The guard is what makes the wrong shape loud. Typing the parameter must
    // not weaken it: this is the assertion that proves the runtime half
    // survived the compile-time half being added.
    await expect(
      receiveSyncChanges({ toDeviceEvents: [] } as unknown as SyncDelta),
    ).rejects.toThrow(/malformed_payload/)
  })
})

describe('encryptEvent wiring to the native layer', () => {
  it('forwards scope, eventType and a JSON-stringified payload, and rebuilds every field of the returned envelope', async () => {
    const payload = { body: 'hello', msgtype: 'm.text' }

    const envelope = await encryptEvent(scope, 'm.room.message', payload)

    const call = vi.mocked(nativeEncryptEvent).mock.calls.at(-1)
    expect(call?.[0]).toBe(scope)
    expect(call?.[1]).toBe('m.room.message')
    expect(call?.[2]).toBe(JSON.stringify(payload))

    expect(envelope.scope).toBe('!native-scope:example.org')
    expect(envelope.algorithm).toBe('m.native.algorithm')
    expect(envelope.eventType).toBe('m.native.event')
    expect(envelope.sender).toBe('@native-sender:example.org')
    // ArrayBuffer -> Uint8Array, the shape EventEnvelope promises.
    expect(envelope.ciphertext).toBeInstanceOf(Uint8Array)
    expect(new TextDecoder().decode(envelope.ciphertext)).toBe('native-ciphertext')
  })

  /**
   * Regression for F4 (Task 7 fix round 1): the per-field `toBe`
   * assertions above cannot see an extra key -- a review proved that
   * adding one to the mocked native `Envelope` and replacing the
   * destructuring with a pass-through spread left every test in this file
   * green. `toEqual` against the whole returned object does fail on an
   * extra key, the same shape `getDeviceIdentityKeys`'s own
   * leak-prevention test above uses.
   */
  it('does not leak a field the generated Envelope carries that this function does not name', async () => {
    vi.mocked(nativeEncryptEvent).mockResolvedValueOnce({
      scope: '!native-scope:example.org',
      algorithm: 'm.native.algorithm',
      eventType: 'm.native.event',
      ciphertext: toArrayBuffer('native-ciphertext'),
      sender: '@native-sender:example.org',
      ...({ internalDebugFlag: true } as Record<string, unknown>),
    })

    const envelope = await encryptEvent(scope, 'm.room.message', { body: 'hi' })

    expect(envelope).toEqual({
      scope: asCryptoScopeId('!native-scope:example.org'),
      algorithm: 'm.native.algorithm',
      eventType: 'm.native.event',
      ciphertext: new TextEncoder().encode('native-ciphertext'),
      sender: '@native-sender:example.org',
    })
  })

  /**
   * The encrypt direction has no verification state, and says so by not
   * carrying one. `toEqual` above already fails on an extra key, so this
   * asserts the same thing a second way and for a different reason: what
   * would be wrong is not an unexpected field but an *invented claim*, and
   * the tempting invention is `'verified'` -- true of this device as a
   * device, meaningless about an event nobody decrypted. See
   * `EventEnvelope.senderVerification`.
   */
  it('carries no authenticity on the encrypt path, because there is none to carry', async () => {
    const envelope = await encryptEvent(scope, 'm.room.message', { body: 'hi' })

    expect(envelope.senderVerification).toBeUndefined()
    expect('senderVerification' in envelope).toBe(false)
  })

  /**
   * Regression for F6 (Task 7 fix round 1): `JSON.stringify(undefined)` is
   * the *value* `undefined`, not a string, and `payload: unknown` lets it
   * through the type system. This proves it is rejected before native is
   * ever called, rather than forwarded as `undefined`.
   */
  it('rejects with malformed_payload before ever calling native, when payload stringifies to undefined', async () => {
    vi.mocked(nativeEncryptEvent).mockClear()

    await expect(encryptEvent(scope, 'm.room.message', undefined)).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'malformed_payload',
    )

    expect(nativeEncryptEvent).not.toHaveBeenCalled()
  })
})

describe('decryptEvent wiring to the native layer', () => {
  it('forwards scope and the JSON-stringified rawEvent verbatim, and rebuilds every field of the returned envelope', async () => {
    const event = { type: 'm.room.encrypted', sender: '@bob:example.org', content: { algorithm: 'm.native.algorithm' } }

    const envelope = await decryptEvent(scope, event)

    const call = vi.mocked(nativeDecryptEvent).mock.calls.at(-1)
    expect(call?.[0]).toBe(scope)
    expect(call?.[1]).toBe(JSON.stringify(event))

    expect(envelope.ciphertext).toBeInstanceOf(Uint8Array)
    expect(new TextDecoder().decode(envelope.ciphertext)).toBe('native-plaintext')
  })

  /**
   * `CryptoScopeId` performs no runtime validation (see types.ts): it is
   * enforced by the type system for a caller that goes through
   * `asCryptoScopeId`, but a caller that bypasses it (plain JS, or
   * `as any`) can still reach this function with a non-string value. This
   * proves that is rejected before ever reaching native, rather than
   * forwarded as `undefined`/`"[object Object]"`.
   *
   * The kind is `malformed_identifier`, matching what the core reports for
   * a scope that is a string but not a parseable identifier: both ways of
   * getting the scope wrong must name the scope, not the payload.
   */
  it('rejects with malformed_identifier before ever calling native, when scope is not actually a string at runtime', async () => {
    vi.mocked(nativeDecryptEvent).mockClear()

    await expect(decryptEvent(undefined as unknown as CryptoScopeId, {})).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'malformed_identifier',
    )

    expect(nativeDecryptEvent).not.toHaveBeenCalled()
  })

  /**
   * Regression for F4 (Task 7 fix round 1): see the identical test on
   * `encryptEvent` above for why the per-field assertions alone do not
   * catch this.
   */
  it('does not leak a field the generated Envelope carries that this function does not name', async () => {
    vi.mocked(nativeDecryptEvent).mockResolvedValueOnce({
      scope: '!native-scope:example.org',
      algorithm: 'm.native.algorithm',
      eventType: 'm.native.event',
      ciphertext: toArrayBuffer('native-plaintext'),
      sender: '@native-sender:example.org',
      senderVerification: NativeSenderVerification.UnsignedDevice,
      ...({ internalDebugFlag: true } as Record<string, unknown>),
    })

    const envelope = await decryptEvent(scope, { type: 'm.room.encrypted' })

    expect(envelope).toEqual({
      scope: asCryptoScopeId('!native-scope:example.org'),
      algorithm: 'm.native.algorithm',
      eventType: 'm.native.event',
      ciphertext: new TextEncoder().encode('native-plaintext'),
      sender: '@native-sender:example.org',
      senderVerification: { state: 'unverified', reason: 'unsigned_device' },
    })
  })

  /**
   * Regression for F6 (Task 7 fix round 1): see the identical test on
   * `encryptEvent` above.
   */
  it('rejects with malformed_payload before ever calling native, when rawEvent stringifies to undefined', async () => {
    vi.mocked(nativeDecryptEvent).mockClear()

    await expect(decryptEvent(scope, undefined)).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'malformed_payload',
    )

    expect(nativeDecryptEvent).not.toHaveBeenCalled()
  })

  /**
   * The distinguishing test, at the public surface.
   *
   * Two decryptions whose native verification state genuinely differs must
   * come out as two different public values. `mismatched_sender` is an
   * impersonation signal and `unsigned_device` is the ordinary case for
   * every peer in this release; a surface that folded the first into the
   * second would hide the case a product must react to, and -- section
   * 2.5's lesson -- the fold would also disable the test that would have
   * caught it.
   *
   * Both decryptions are handed identical everything else, so the only
   * thing the returned values can be differing on is the field under test.
   */
  it('surfaces two genuinely different native verification states as two different public values', async () => {
    const sameEverythingElse = {
      scope: '!native-scope:example.org',
      algorithm: 'm.native.algorithm',
      eventType: 'm.native.event',
      ciphertext: toArrayBuffer('native-plaintext'),
      sender: '@native-sender:example.org',
    }

    vi.mocked(nativeDecryptEvent).mockResolvedValueOnce({
      ...sameEverythingElse,
      senderVerification: NativeSenderVerification.UnsignedDevice,
    })
    const ordinary = await decryptEvent(scope, { type: 'm.room.encrypted' })

    vi.mocked(nativeDecryptEvent).mockResolvedValueOnce({
      ...sameEverythingElse,
      senderVerification: NativeSenderVerification.MismatchedSender,
    })
    const impersonated = await decryptEvent(scope, { type: 'm.room.encrypted' })

    expect(ordinary.senderVerification).toEqual({
      state: 'unverified',
      reason: 'unsigned_device',
    })
    expect(impersonated.senderVerification).toEqual({
      state: 'unverified',
      reason: 'mismatched_sender',
    })
    expect(impersonated.senderVerification).not.toEqual(ordinary.senderVerification)

    // Every other field is identical, so the difference above is the field
    // under test and not something that leaked in beside it.
    expect(impersonated.ciphertext).toEqual(ordinary.ciphertext)
    expect(impersonated.sender).toBe(ordinary.sender)
    expect(impersonated.algorithm).toBe(ordinary.algorithm)
  })

  /**
   * The two reasons behind `no_device` stay apart.
   *
   * They are one union member with a `problem` discriminator rather than
   * two members, which is exactly the shape in which a mapping quietly
   * collapses them: "the device is missing" and "the key came from an
   * unauthenticated source" are different facts and different product
   * responses.
   */
  it('keeps the two no_device reasons apart', async () => {
    const base = {
      scope: '!native-scope:example.org',
      algorithm: 'm.native.algorithm',
      eventType: 'm.native.event',
      ciphertext: toArrayBuffer('native-plaintext'),
      sender: '@native-sender:example.org',
    }

    vi.mocked(nativeDecryptEvent).mockResolvedValueOnce({
      ...base,
      senderVerification: NativeSenderVerification.NoDeviceMissing,
    })
    expect((await decryptEvent(scope, {})).senderVerification).toEqual({
      state: 'unverified',
      reason: 'no_device',
      problem: 'missing',
    })

    vi.mocked(nativeDecryptEvent).mockResolvedValueOnce({
      ...base,
      senderVerification: NativeSenderVerification.NoDeviceInsecureSource,
    })
    expect((await decryptEvent(scope, {})).senderVerification).toEqual({
      state: 'unverified',
      reason: 'no_device',
      problem: 'insecure_source',
    })
  })

  /**
   * **`'verified'` comes from the native `Verified` and from nothing
   * else.**
   *
   * ## What this test used to be called, and why the name had to change
   *
   * It was `never reports verified for any native value this release can
   * produce`, and it listed the six native values that were not `Verified`
   * because those were the only ones the library could produce. The M3
   * design ruling bound the suite to hold no case that appeared to produce
   * `'verified'`: a fixture faking it would teach exactly the belief the
   * ruling existed to prevent.
   *
   * M4 gives the core a cross-signing identity, and
   * `matrix-crypto-core/tests/verified_sender.rs` now reaches `Verified`
   * through the whole chain against a counterparty that process does not
   * control. So the native layer can hand this facade a `Verified`, and
   * the old name became a false statement about the library while the body
   * stayed green: nothing here was ever going to force the correction,
   * which is what makes this shape the dangerous one rather than the
   * merely untidy one.
   *
   * The ruling was replaced rather than dropped, and the replacement is
   * stricter: **nothing except the real chain produces `verified`.** It is
   * written at the type, on `matrix_crypto_core::SenderVerification`. What
   * this file holds is the boundary half of the complement, in both
   * directions at once. Something else arriving *as* `'verified'` (an
   * unsigned device, or worse a mismatched sender, presented to a product
   * as authentic) is still the failure that hurts most. Since M4 there is
   * a second one: a `Verified` the chain really did earn being quietly
   * downgraded on the way through this mapping, which a product would read
   * as a verification that simply never took effect.
   *
   * ## What the compiler covers, and a claim this file once got wrong
   *
   * `senderVerificationOf` used to return `SenderVerification | undefined`,
   * so a missing `case` fell off the end and compiled; review deleted the
   * `Verified` arm and `tsc` exited 0 with every test here green. The
   * function now takes and returns non-optional values, with the absent
   * case handled at its call site, so falling off the end is `TS2366`,
   * confirmed by deleting an arm and reading the error rather than
   * assumed. Two more checks stand behind the Rust half: the core's own
   * `match` and the FFI `From` are exhaustive over upstream enums that are
   * not `#[non_exhaustive]`, so an upstream addition fails the Rust build
   * before it can reach this file.
   */
  it('reports verified for the native verified value and for nothing else', async () => {
    const everyNativeValue = [
      // Reachable in the core since M4, through the chain
      // `matrix-crypto-core/tests/verified_sender.rs` drives end to end.
      // It is an input here for that reason and not as a fixture inventing
      // an authenticity claim, which is what the M3 ruling forbade and the
      // replacement still forbids.
      NativeSenderVerification.Verified,
      NativeSenderVerification.UnsignedDevice,
      NativeSenderVerification.NoDeviceMissing,
      NativeSenderVerification.NoDeviceInsecureSource,
      NativeSenderVerification.MismatchedSender,
      // Producible since before 0.1.0, and this list said otherwise until
      // then. It depends on the sender's cross-signing identity rather than
      // on ours, so any peer whose client has cross-signing set up produces
      // it. The most important entry here for that reason: "cross-signed"
      // read as "trusted" is how it would end up mapped to `verified`.
      NativeSenderVerification.UnverifiedIdentity,
      // Reachable only past `Verified`, for a sender whose chain completed
      // and whose identity then changed. No fixture in this repository
      // builds that situation; this entry is what holds the mapping on the
      // day one does.
      NativeSenderVerification.VerificationViolation,
    ]

    for (const value of everyNativeValue) {
      vi.mocked(nativeDecryptEvent).mockResolvedValueOnce({
        scope: '!native-scope:example.org',
        algorithm: 'm.native.algorithm',
        eventType: 'm.native.event',
        ciphertext: toArrayBuffer('native-plaintext'),
        sender: '@native-sender:example.org',
        senderVerification: value,
      })

      const envelope = await decryptEvent(scope, { type: 'm.room.encrypted' })

      // A single two-sided expectation rather than two loops: the failure
      // that invents `'verified'` and the failure that drops it are the
      // same defect seen from opposite sides, and one assertion that names
      // both is what stops either being added back without the other.
      expect(envelope.senderVerification?.state).toBe(
        value === NativeSenderVerification.Verified ? 'verified' : 'unverified',
      )
    }
  })
})

describe('shareScopeKey wiring to the native layer', () => {
  it('forwards scope and userIds verbatim', async () => {
    await expect(shareScopeKey(scope, ['@bob:example.org', '@carol:example.org'])).resolves.toBeUndefined()

    const call = vi.mocked(nativeShareScopeKey).mock.calls.at(-1)
    expect(call?.[0]).toBe(scope)
    expect(call?.[1]).toEqual(['@bob:example.org', '@carol:example.org'])
  })
})

describe('takeOutgoingRequests wiring to the native layer', () => {
  it('rebuilds every field of every returned request', async () => {
    const requests = await takeOutgoingRequests()

    expect(requests).toEqual([{ id: 'req-1', kind: 'keys_upload', body: '{}' }])
  })
})

describe('markRequestSent wiring to the native layer', () => {
  it('forwards id and responseJson verbatim', async () => {
    await expect(markRequestSent('req-1', '{"ok":true}')).resolves.toBeUndefined()

    const call = vi.mocked(nativeMarkRequestSent).mock.calls.at(-1)
    expect(call?.[0]).toBe('req-1')
    expect(call?.[1]).toBe('{"ok":true}')
  })
})

/**
 * The counterpart added so a refusal has somewhere to go. The status must
 * arrive as a number and unaltered: the core is what decides which values
 * are a refusal, and a facade that clamped, defaulted or stringified one
 * would take that decision away from it silently.
 */
describe('markRequestFailed wiring to the native layer', () => {
  it('forwards id and status verbatim', async () => {
    await expect(markRequestFailed('req-1', 502)).resolves.toBeUndefined()

    const call = vi.mocked(nativeMarkRequestFailed).mock.calls.at(-1)
    expect(call?.[0]).toBe('req-1')
    expect(call?.[1]).toBe(502)
  })

  it('forwards 0, which means no response arrived at all, rather than treating it as absent', async () => {
    await expect(markRequestFailed('req-1', 0)).resolves.toBeUndefined()

    const call = vi.mocked(nativeMarkRequestFailed).mock.calls.at(-1)
    expect(call?.[1]).toBe(0)
  })

  it('surfaces a native rejection as a CryptoError rather than the raw value', async () => {
    vi.mocked(nativeMarkRequestFailed).mockRejectedValueOnce(
      new Error('SessionFfiError.NotAFailureStatus'),
    )

    await expect(markRequestFailed('req-1', 200)).rejects.toMatchObject({
      kind: 'not_a_failure_status',
    })
  })
})

/**
 * Happy-path regression for the M1 final review's deferred item, fixed in
 * this task at `getDeviceIdentityKeys`: it used to return the native
 * result directly rather than destructuring it, so a field the generated
 * record gains later would cross this boundary unreviewed rather than
 * being a deliberate choice to expose. This proves both halves of that:
 * the two real fields still arrive correctly now that they are rebuilt
 * field by field, and a field this function does not name is dropped, not
 * forwarded -- not merely that the malformed-input error path still works
 * (already covered above).
 */
describe('getDeviceIdentityKeys happy path', () => {
  it('rebuilds curve25519 and ed25519 from the native response, and drops a field it does not name', async () => {
    vi.mocked(nativeDeviceIdentityKeys).mockResolvedValueOnce({
      curve25519: 'curve-key-value',
      ed25519: 'ed-key-value',
      // A field this function's own `IdentityKeys` type does not declare --
      // structurally compatible with it regardless, so only destructuring
      // (not the type system) keeps this out of the returned value.
      ...({ internalDebugFlag: true } as Record<string, unknown>),
    })

    const keys = await getDeviceIdentityKeys('@alice:example.org', 'DEVICE1')

    expect(keys).toEqual({
      curve25519: 'curve-key-value',
      ed25519: 'ed-key-value',
    })
    expect(keys).not.toHaveProperty('internalDebugFlag')
  })
})

/**
 * Regression for FIX 2: `getDeviceIdentityKeys('bad-id', ...)` used to yield
 * `kind: 'unknown'` with the Rust side's `detail` diagnostic silently
 * dropped, because `errors.ts` had no `KIND_BY_NAME` entry for
 * `MalformedIdentifier` and its field reader never looked at `.detail`.
 */
describe('getDeviceIdentityKeys against a real MalformedIdentifier failure', () => {
  it('maps it to kind malformed_identifier and keeps the Rust diagnostic, not unknown', async () => {
    const err = await getDeviceIdentityKeys('bad-id', 'DEVICE1').catch((e: unknown) => e)
    expect(isCryptoError(err)).toBe(true)
    if (!isCryptoError(err)) throw err
    expect(err.kind).toBe('malformed_identifier')
    expect(err.kind).not.toBe('unknown')
    expect(err.message).toContain('user id')
  })
})

/**
 * Regression for FIX 1: `CryptoMachineConfig` had no `storePassphrase`
 * field, so the native call never received one and every store this library
 * created held key material unencrypted at rest, with no way for a caller
 * to say otherwise. `storePassphrase` is required (`string | null`, not
 * optional) precisely so a caller cannot omit it by accident; these tests
 * cover both the real-passphrase path and the deliberate-`null` path,
 * neither of which may throw.
 */
describe('storePassphrase wiring to the native layer', () => {
  it('createCryptoMachine forwards a real passphrase, and translates an explicit null to undefined rather than throwing', async () => {
    await expect(
      createCryptoMachine({
        userId: '@alice:example.org',
        deviceId: 'DEVICE1',
        storePath: '/tmp/store-a',
        storePassphrase: 'correct horse battery staple',
      }),
    ).resolves.toBeUndefined()
    expect(vi.mocked(nativeCreateCryptoMachine).mock.calls.at(-1)?.[0].storePassphrase).toBe(
      'correct horse battery staple',
    )

    await expect(
      createCryptoMachine({
        userId: '@alice:example.org',
        deviceId: 'DEVICE1',
        storePath: '/tmp/store-a',
        storePassphrase: null,
      }),
    ).resolves.toBeUndefined()
    // The generated binding's optional field is spelled with `undefined`
    // (UniFFI's `Option<String>`), never the literal `null` -- asserted
    // explicitly so a future regression that forwards `null` verbatim fails
    // here rather than at the native boundary this test cannot reach.
    expect(vi.mocked(nativeCreateCryptoMachine).mock.calls.at(-1)?.[0].storePassphrase).toBeUndefined()
  })

  it('openCryptoStore forwards a real passphrase, and translates an explicit null to undefined rather than throwing', async () => {
    await expect(
      openCryptoStore({
        userId: '@alice:example.org',
        deviceId: 'DEVICE1',
        storePath: '/tmp/store-b',
        storePassphrase: 'correct horse battery staple',
      }),
    ).resolves.toBeUndefined()
    expect(vi.mocked(nativeOpenCryptoStore).mock.calls.at(-1)?.[0].storePassphrase).toBe(
      'correct horse battery staple',
    )

    await expect(
      openCryptoStore({
        userId: '@alice:example.org',
        deviceId: 'DEVICE1',
        storePath: '/tmp/store-b',
        storePassphrase: null,
      }),
    ).resolves.toBeUndefined()
    expect(vi.mocked(nativeOpenCryptoStore).mock.calls.at(-1)?.[0].storePassphrase).toBeUndefined()
  })
})

/**
 * Task 3: the verification surface.
 *
 * **What this file can and cannot prove, stated once rather than implied.**
 * There is no JSI host object under vitest, so nothing here performs any
 * cryptography and no verification actually happens. What is proven here is
 * the *bridge*: that each facade call reaches the native function it claims
 * to, forwards what it was given, rebuilds what it got back field by field,
 * and turns each native error into the kind its own doc comment promises.
 *
 * The cryptography, and the claim that a real comparison changes what
 * `getDeviceStatuses` reports, is proven in
 * `rust/matrix-crypto-core/tests/sas_two_party.rs`, against a machine this
 * library does not control, with the before and after values both asserted
 * and the change between them asserted separately.
 */

const FLOW = 'a-verification-id'

/** The material `verificationMaterial` is mocked to return, as the facade rebuilds it. */
const NATIVE_MATERIAL: SasMaterial = {
  emoji: [{ symbol: 'native-symbol', description: 'native-word' }],
  decimals: [1111, 2222, 3333],
}

/**
 * Restores every verification mock to the stateless default declared at the
 * top of this file, so a test that installs its own implementation cannot
 * leak it into the next one. Vitest's mocks are module-level and shared.
 */
beforeEach(() => {
  vi.mocked(nativeDeviceStatuses).mockReset()
  vi.mocked(nativeDeviceStatuses).mockResolvedValue([
    { deviceId: 'NATIVEDEVICE', trust: NativeTrustState.Unverified },
  ])
  vi.mocked(nativeRequestVerification).mockReset()
  vi.mocked(nativeRequestVerification).mockResolvedValue('native-flow-id')
  vi.mocked(nativeAcceptVerification).mockReset()
  vi.mocked(nativeAcceptVerification).mockResolvedValue(undefined)
  vi.mocked(nativeStartVerificationComparison).mockReset()
  vi.mocked(nativeStartVerificationComparison).mockResolvedValue(undefined)
  vi.mocked(nativeVerificationStage).mockReset()
  vi.mocked(nativeVerificationStage).mockResolvedValue(NativeVerificationStage.Requested)
  vi.mocked(nativeVerificationMaterial).mockReset()
  vi.mocked(nativeVerificationMaterial).mockResolvedValue({
    emoji: [{ symbol: 'native-symbol', description: 'native-word' }],
    decimalOne: 1111,
    decimalTwo: 2222,
    decimalThree: 3333,
  })
  vi.mocked(nativeConfirmVerification).mockReset()
  vi.mocked(nativeConfirmVerification).mockResolvedValue(undefined)
  vi.mocked(nativeCancelVerification).mockReset()
  vi.mocked(nativeCancelVerification).mockResolvedValue(undefined)
})

describe('getDeviceStatuses', () => {
  it('rebuilds each status from the native record, mapping the trust enum onto the string union', async () => {
    vi.mocked(nativeDeviceStatuses).mockResolvedValue([
      { deviceId: 'DEVICE-A', trust: NativeTrustState.Unverified },
      { deviceId: 'DEVICE-B', trust: NativeTrustState.Recognized },
      { deviceId: 'DEVICE-C', trust: NativeTrustState.Verified },
    ])

    await expect(getDeviceStatuses('@bob:example.org')).resolves.toEqual([
      { deviceId: 'DEVICE-A', trust: 'unverified' },
      { deviceId: 'DEVICE-B', trust: 'recognized' },
      { deviceId: 'DEVICE-C', trust: 'verified' },
    ])
    expect(vi.mocked(nativeDeviceStatuses).mock.calls.at(-1)?.[0]).toBe('@bob:example.org')
  })

  /**
   * All three values in one call, above, rather than three calls each
   * returning one: a mapping that answered a constant would satisfy any
   * single-value assertion, and asserting the three together is what rules
   * that out. This second test is the other half -- that the user id is
   * forwarded rather than ignored -- because a `getDeviceStatuses` that
   * always asked about the same user would pass everything above.
   */
  it('forwards the user id it was given', async () => {
    await getDeviceStatuses('@carol:example.org')
    expect(vi.mocked(nativeDeviceStatuses).mock.calls.at(-1)?.[0]).toBe('@carol:example.org')
  })

  it('reports an empty list as an empty list rather than as an error', async () => {
    vi.mocked(nativeDeviceStatuses).mockResolvedValue([])
    await expect(getDeviceStatuses('@nobody:example.org')).resolves.toEqual([])
  })

  it('turns a native machine error into a typed CryptoError', async () => {
    vi.mocked(nativeDeviceStatuses).mockRejectedValue(
      new MachineFfiError.MalformedIdentifier({ detail: 'user id' }),
    )
    await expect(getDeviceStatuses('not-a-user-id')).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'malformed_identifier',
    )
  })
})

describe('requestVerification, acceptVerification and cancelVerification', () => {
  it('forwards both identifiers and returns the flow id native minted', async () => {
    await expect(requestVerification('@bob:example.org', 'BOBDEVICE')).resolves.toBe(
      'native-flow-id',
    )
    expect(vi.mocked(nativeRequestVerification).mock.calls.at(-1)).toEqual([
      '@bob:example.org',
      'BOBDEVICE',
    ])
  })

  /**
   * The condition a product recovers from by querying that user's devices
   * and calling again. It arrives as its own kind rather than as
   * `malformed_identifier`, which no retry fixes, and rather than as
   * `unknown` -- which is what it would be if `errors.ts` had no entry for
   * the variant. That entry is invisible to every Rust test.
   */
  it('reports a device this library has never been told about as unknown_device', async () => {
    vi.mocked(nativeRequestVerification).mockRejectedValue(new MachineFfiError.UnknownDevice())
    await expect(requestVerification('@bob:example.org', 'NOSUCHDEVICE')).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'unknown_device',
    )
  })

  it('forwards the flow id to accept and to cancel', async () => {
    await expect(acceptVerification(FLOW)).resolves.toBeUndefined()
    expect(vi.mocked(nativeAcceptVerification).mock.calls.at(-1)?.[0]).toBe(FLOW)

    await expect(cancelVerification(FLOW)).resolves.toBeUndefined()
    expect(vi.mocked(nativeCancelVerification).mock.calls.at(-1)?.[0]).toBe(FLOW)
  })

  it('reports an identifier that names no flow as unknown_flow rather than unknown', async () => {
    vi.mocked(nativeAcceptVerification).mockRejectedValue(new MachineFfiError.UnknownFlow())
    await expect(acceptVerification('never-a-flow')).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'unknown_flow',
    )
  })

  it('reports cancelling an already-cancelled flow as wrong_stage rather than resolving', async () => {
    vi.mocked(nativeCancelVerification).mockRejectedValue(new MachineFfiError.WrongStage())
    await expect(cancelVerification(FLOW)).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'wrong_stage',
    )
  })
})

describe('getVerificationStage', () => {
  it('maps every native stage onto its own string, and forwards the flow id', async () => {
    const expected: [NativeVerificationStage, VerificationStage][] = [
      [NativeVerificationStage.Requested, 'requested'],
      [NativeVerificationStage.Ready, 'ready'],
      [NativeVerificationStage.Started, 'started'],
      [NativeVerificationStage.KeysExchanged, 'keys-exchanged'],
      [NativeVerificationStage.Confirmed, 'confirmed'],
      [NativeVerificationStage.Done, 'done'],
      [NativeVerificationStage.Cancelled, 'cancelled'],
    ]

    // Every stage, in one test, and the results collected before they are
    // compared: seven separate assertions each covering one value would
    // still all pass against a mapping that returned whatever it was given
    // as a string, and the pair `done`/`cancelled` is the one where a swap
    // presents a refusal as a success.
    const observed: VerificationStage[] = []
    for (const [native] of expected) {
      vi.mocked(nativeVerificationStage).mockResolvedValue(native)
      observed.push(await getVerificationStage(FLOW))
    }

    expect(observed).toEqual(expected.map(([, stage]) => stage))
    expect(vi.mocked(nativeVerificationStage).mock.calls.at(-1)?.[0]).toBe(FLOW)
  })

  it('reports an identifier that names no flow as unknown_flow', async () => {
    vi.mocked(nativeVerificationStage).mockRejectedValue(new MachineFfiError.UnknownFlow())
    await expect(getVerificationStage('never-a-flow')).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'unknown_flow',
    )
  })
})

describe('getVerificationMaterial', () => {
  it('rebuilds the string from the native record, three separate decimals back into one tuple', async () => {
    await expect(getVerificationMaterial(FLOW)).resolves.toEqual(NATIVE_MATERIAL)
    expect(vi.mocked(nativeVerificationMaterial).mock.calls.at(-1)?.[0]).toBe(FLOW)
  })

  it('keeps an absent symbol form absent rather than turning it into an empty list', async () => {
    vi.mocked(nativeVerificationMaterial).mockResolvedValue({
      decimalOne: 4444,
      decimalTwo: 5555,
      decimalThree: 6666,
    })

    const material = await getVerificationMaterial(FLOW)
    expect(material).toEqual({ decimals: [4444, 5555, 6666] })
    // Asserted separately: `toEqual` above treats an absent key and an
    // explicit `undefined` as the same, and a screen that renders
    // `material.emoji` as a list would show seven blanks for one and fall
    // back to the digits for the other.
    expect('emoji' in material).toBe(false)
  })

  /**
   * **The silent-stall problem, at the bridge.** The underlying state
   * machine advances from "accepted" to "keys exchanged" only when the
   * caller reports the key message sent, so a caller that drains the pump
   * and never calls `markRequestSent` parks the flow forever with no error
   * and no timeout. The core turns that into `MaterialNotReady`; the whole
   * question here is whether it survives as something a product can act on.
   *
   * Without the `['MaterialNotReady', 'material_not_ready']` entry in
   * `errors.ts` it arrives as kind `'unknown'` with the message "crypto
   * error: unknown" -- which no Rust test can see, because the core proves
   * only that the right *variant* is produced.
   *
   * Three things are asserted, not one: the kind, that the call rejects
   * rather than resolving with an empty record, and that it is not reported
   * retriable -- because retrying this call alone never resolves it, and a
   * product that reads `retriable` as permission to loop would spin against
   * a machine that will never move.
   */
  it('rejects with material_not_ready, and not retriably, when the pump was never resolved', async () => {
    vi.mocked(nativeVerificationMaterial).mockRejectedValue(new MachineFfiError.MaterialNotReady())

    const rejection = await getVerificationMaterial(FLOW).then(
      (material) => ({ resolved: material }),
      (e: unknown) => ({ rejected: e }),
    )

    expect(rejection).not.toHaveProperty('resolved')
    const error = (rejection as { rejected: unknown }).rejected
    expect(isCryptoError(error) && error.kind).toBe('material_not_ready')
    expect(isCryptoError(error) && error.retriable).toBe(false)
  })

  it('reports a flow that is over as wrong_stage, which is the kind that means it never will be ready', async () => {
    vi.mocked(nativeVerificationMaterial).mockRejectedValue(new MachineFfiError.WrongStage())
    await expect(getVerificationMaterial(FLOW)).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'wrong_stage',
    )
  })
})

describe('confirmVerification', () => {
  it('confirms when the material offered is the material the flow is showing', async () => {
    await expect(confirmVerification(FLOW, NATIVE_MATERIAL)).resolves.toBeUndefined()
    expect(vi.mocked(nativeConfirmVerification).mock.calls.at(-1)?.[0]).toBe(FLOW)
  })

  /**
   * The argument's whole purpose. Without the check, a product could
   * confirm a comparison it never displayed -- the layer underneath only
   * checks that a string exists, not that anybody saw it -- and "verified"
   * would then mean nothing.
   *
   * `nativeConfirmVerification` is asserted *not* to have been called: a
   * check that rejected after confirming would be reporting on something it
   * could no longer prevent.
   */
  it('refuses material that is not what the flow is showing, without confirming anything', async () => {
    await expect(
      confirmVerification(FLOW, { ...NATIVE_MATERIAL, decimals: [1111, 2222, 9999] }),
    ).rejects.toSatisfy((e: unknown) => isCryptoError(e) && e.kind === 'material_mismatch')
    expect(nativeConfirmVerification).not.toHaveBeenCalled()
  })

  it('refuses material whose digits are the right ones in the wrong order', async () => {
    await expect(
      confirmVerification(FLOW, { ...NATIVE_MATERIAL, decimals: [2222, 1111, 3333] }),
    ).rejects.toSatisfy((e: unknown) => isCryptoError(e) && e.kind === 'material_mismatch')
    expect(nativeConfirmVerification).not.toHaveBeenCalled()
  })

  it('refuses material whose symbols differ, even when the digits agree', async () => {
    await expect(
      confirmVerification(FLOW, {
        decimals: [1111, 2222, 3333],
        emoji: [{ symbol: 'a-different-symbol', description: 'native-word' }],
      }),
    ).rejects.toSatisfy((e: unknown) => isCryptoError(e) && e.kind === 'material_mismatch')
    expect(nativeConfirmVerification).not.toHaveBeenCalled()
  })

  it('accepts a translated description, which is a label rather than part of the string', async () => {
    await expect(
      confirmVerification(FLOW, {
        decimals: [1111, 2222, 3333],
        emoji: [{ symbol: 'native-symbol', description: 'un-mot-traduit' }],
      }),
    ).resolves.toBeUndefined()
    expect(nativeConfirmVerification).toHaveBeenCalledOnce()
  })

  /**
   * The same silent-stall problem seen from the other call. A caller that
   * skipped the pump and confirmed anyway must be told which of its own
   * steps is missing, not have the confirmation go through on a flow with
   * nothing to show.
   */
  it('rejects with material_not_ready, and confirms nothing, when the pump was never resolved', async () => {
    vi.mocked(nativeVerificationMaterial).mockRejectedValue(new MachineFfiError.MaterialNotReady())

    await expect(confirmVerification(FLOW, NATIVE_MATERIAL)).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'material_not_ready',
    )
    expect(nativeConfirmVerification).not.toHaveBeenCalled()
  })

  it('passes a native rejection from the confirmation itself through as its own kind', async () => {
    vi.mocked(nativeConfirmVerification).mockRejectedValue(new MachineFfiError.WrongStage())
    await expect(confirmVerification(FLOW, NATIVE_MATERIAL)).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'wrong_stage',
    )
  })
})

/**
 * The two conditions the core folds into one `WrongStage`, told apart again.
 *
 * The core's own `begin_comparison` documents the fold and says why it is
 * deliberate -- both mean *this call* has nothing to do -- and points at
 * `flow_stage` as the free discriminator. A screen that shows a person one
 * sentence for both is showing the wrong one about half the time: "they
 * started it, wait for the string" and "this is over, ask again" call for
 * opposite behaviour.
 */
describe('startVerificationComparison, and the conditions its one native error folds', () => {
  it('starts the comparison and forwards the flow id when nothing is wrong', async () => {
    await expect(startVerificationComparison(FLOW)).resolves.toBeUndefined()
    expect(vi.mocked(nativeStartVerificationComparison).mock.calls.at(-1)?.[0]).toBe(FLOW)
    // The stage is not read on the success path: it costs a native call,
    // and there is nothing to tell apart.
    expect(nativeVerificationStage).not.toHaveBeenCalled()
  })

  it.each([
    [NativeVerificationStage.Started],
    [NativeVerificationStage.KeysExchanged],
    [NativeVerificationStage.Confirmed],
  ])('reports comparison_already_started when the peer got there first (stage %i)', async (stage) => {
    vi.mocked(nativeStartVerificationComparison).mockRejectedValue(new MachineFfiError.WrongStage())
    vi.mocked(nativeVerificationStage).mockResolvedValue(stage)

    await expect(startVerificationComparison(FLOW)).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'comparison_already_started',
    )
  })

  it.each([[NativeVerificationStage.Done], [NativeVerificationStage.Cancelled]])(
    'reports verification_ended when the flow is over (stage %i)',
    async (stage) => {
      vi.mocked(nativeStartVerificationComparison).mockRejectedValue(
        new MachineFfiError.WrongStage(),
      )
      vi.mocked(nativeVerificationStage).mockResolvedValue(stage)

      await expect(startVerificationComparison(FLOW)).rejects.toSatisfy(
        (e: unknown) => isCryptoError(e) && e.kind === 'verification_ended',
      )
    },
  )

  /**
   * The remainder, kept as `wrong_stage` rather than given a name of its
   * own: at `requested` the flow has simply not been agreed to yet, which
   * is what "not at a stage where this call applies" already says.
   */
  it.each([[NativeVerificationStage.Requested], [NativeVerificationStage.Ready]])(
    'leaves the rejection as wrong_stage for a flow that is neither under way nor over (stage %i)',
    async (stage) => {
      vi.mocked(nativeStartVerificationComparison).mockRejectedValue(
        new MachineFfiError.WrongStage(),
      )
      vi.mocked(nativeVerificationStage).mockResolvedValue(stage)

      await expect(startVerificationComparison(FLOW)).rejects.toSatisfy(
        (e: unknown) => isCryptoError(e) && e.kind === 'wrong_stage',
      )
    },
  )

  /**
   * Only `wrong_stage` is unfolded. An `unknown_flow` rejection already
   * says exactly what it means, and reading the stage of a flow that does
   * not exist would only produce a second error to swallow.
   */
  it('passes a rejection that is not wrong_stage through untouched, without reading the stage', async () => {
    vi.mocked(nativeStartVerificationComparison).mockRejectedValue(new MachineFfiError.UnknownFlow())

    await expect(startVerificationComparison('never-a-flow')).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'unknown_flow',
    )
    expect(nativeVerificationStage).not.toHaveBeenCalled()
  })

  /**
   * The diagnosis is allowed to fail. A flow released between the two calls
   * would make the stage read throw, and an error about the diagnosis would
   * be worse than the one it replaced.
   */
  it('keeps the original rejection when the stage cannot be read either', async () => {
    vi.mocked(nativeStartVerificationComparison).mockRejectedValue(new MachineFfiError.WrongStage())
    vi.mocked(nativeVerificationStage).mockRejectedValue(new MachineFfiError.UnknownFlow())

    await expect(startVerificationComparison(FLOW)).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'wrong_stage',
    )
  })
})

/**
 * The whole arc, driven through the public surface in the order the
 * documentation publishes, against a fake that models the one ordering rule
 * this bridge cannot enforce for the caller.
 *
 * **What this proves and what it does not.** The fake performs no
 * cryptography: the comparison it "reaches" is a constant. What it does
 * model is the sequencing -- a flow that is not accepted cannot start a
 * comparison, and a comparison whose key message was never reported sent
 * never produces a string -- so this test proves the six public calls
 * compose in the documented order, that each one's output is what the next
 * one needs, and that skipping the pump is reported rather than hung on.
 * Whether the string two devices reach is the *same* string is the Rust
 * two-party test's claim, not this one's.
 */
describe('a verification driven end to end through the public surface', () => {
  interface FakeFlow {
    stage: NativeVerificationStage
    keyReported: boolean
  }

  function installFake(): FakeFlow {
    const flow: FakeFlow = { stage: NativeVerificationStage.Requested, keyReported: false }

    vi.mocked(nativeRequestVerification).mockImplementation(async () => {
      flow.stage = NativeVerificationStage.Requested
      return FLOW
    })
    vi.mocked(nativeAcceptVerification).mockImplementation(async () => {
      if (flow.stage !== NativeVerificationStage.Requested) throw new MachineFfiError.WrongStage()
      flow.stage = NativeVerificationStage.Ready
    })
    vi.mocked(nativeStartVerificationComparison).mockImplementation(async () => {
      if (flow.stage !== NativeVerificationStage.Ready) throw new MachineFfiError.WrongStage()
      flow.stage = NativeVerificationStage.Started
    })
    vi.mocked(nativeVerificationStage).mockImplementation(async () => flow.stage)
    vi.mocked(nativeVerificationMaterial).mockImplementation(async () => {
      // The rule the whole surface turns on: no report, no string.
      if (flow.stage === NativeVerificationStage.Started && !flow.keyReported) {
        throw new MachineFfiError.MaterialNotReady()
      }
      if (flow.stage !== NativeVerificationStage.KeysExchanged) {
        throw new MachineFfiError.WrongStage()
      }
      return { emoji: undefined, decimalOne: 1111, decimalTwo: 2222, decimalThree: 3333 }
    })
    vi.mocked(nativeConfirmVerification).mockImplementation(async () => {
      if (flow.stage !== NativeVerificationStage.KeysExchanged) {
        throw new MachineFfiError.WrongStage()
      }
      flow.stage = NativeVerificationStage.Confirmed
    })
    vi.mocked(nativeDeviceStatuses).mockImplementation(async () => [
      {
        deviceId: 'BOBDEVICE',
        trust:
          flow.stage === NativeVerificationStage.Done
            ? NativeTrustState.Verified
            : NativeTrustState.Unverified,
      },
    ])

    return flow
  }

  /** What the product does after sending what the pump handed it. */
  function reportTheKeySent(flow: FakeFlow): void {
    flow.keyReported = true
    flow.stage = NativeVerificationStage.KeysExchanged
  }

  it('runs request, accept, start, read and confirm in order, and the device reads verified only at the end', async () => {
    const flow = installFake()

    // Before anything: the far device is not verified, and that is the
    // value the last assertion in this test has to differ from.
    expect(await getDeviceStatuses('@bob:example.org')).toEqual([
      { deviceId: 'BOBDEVICE', trust: 'unverified' },
    ])

    const id = await requestVerification('@bob:example.org', 'BOBDEVICE')
    expect(await getVerificationStage(id)).toBe('requested')

    // Starting before both sides have agreed is refused, and refused as the
    // stage-shaped error rather than as one of the two split-out kinds.
    await expect(startVerificationComparison(id)).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'wrong_stage',
    )

    await acceptVerification(id)
    expect(await getVerificationStage(id)).toBe('ready')

    await startVerificationComparison(id)
    expect(await getVerificationStage(id)).toBe('started')

    // The pump has not been resolved, so there is no string -- named,
    // rather than an empty record or a promise that never settles.
    await expect(getVerificationMaterial(id)).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'material_not_ready',
    )
    // And confirming is refused for the same reason, so a product cannot
    // skip the string and confirm anyway.
    await expect(confirmVerification(id, { decimals: [1111, 2222, 3333] })).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'material_not_ready',
    )

    reportTheKeySent(flow)
    expect(await getVerificationStage(id)).toBe('keys-exchanged')

    const material = await getVerificationMaterial(id)
    expect(material).toEqual({ decimals: [1111, 2222, 3333] })

    await confirmVerification(id, material)
    expect(await getVerificationStage(id)).toBe('confirmed')

    // Confirmed is not done. The device is still unverified here, which is
    // the sentence this milestone exists to stop being told early.
    expect(await getDeviceStatuses('@bob:example.org')).toEqual([
      { deviceId: 'BOBDEVICE', trust: 'unverified' },
    ])

    // The peer's acknowledgement arrives and the flow closes.
    flow.stage = NativeVerificationStage.Done
    expect(await getVerificationStage(id)).toBe('done')
    expect(await getDeviceStatuses('@bob:example.org')).toEqual([
      { deviceId: 'BOBDEVICE', trust: 'verified' },
    ])
  })
})

/**
 * The seven-step chain that makes a decrypted event read `'verified'`,
 * driven through the functions this package publishes and through nothing
 * else, against a hand-written model of the core.
 *
 * # The line falls in an unobvious place, so read this before the tick
 *
 * **The boundary is exactly one module: `./generated/matrix_crypto`.**
 * Everything above it runs for real. Everything below it is this file's
 * model. A green run here is evidence about the first and no evidence at
 * all about the second, and the two halves are set out separately below so
 * that nobody has to infer which is which.
 *
 * ## What a green run does prove
 *
 * * **Every published call in the chain exists, and composes in this
 *   order.** `bootstrapCrossSigning`, `getIdentityStatus`,
 *   `takeOutgoingRequests`, `markRequestSent`, `markRequestFailed`,
 *   `receiveSyncChanges`, `requestVerification`, `acceptVerification`,
 *   `startVerificationComparison`, `getVerificationStage`,
 *   `getVerificationMaterial`, `confirmVerification`, `decryptEvent` and
 *   `getDeviceStatuses`, each taking what the one before it returns. That
 *   is the milestone's actual claim about TypeScript, and it is what was
 *   missing: the core has reached `Verified` since M4's second task and no
 *   product could get there, because the call that creates this account's
 *   identity stopped at the FFI crate.
 * * **Error translation, unmocked.** `vi.mock` wraps `importOriginal`, so
 *   the real generated `MachineFfiError` and `SessionFfiError` classes
 *   cross this boundary and `errors.ts` runs on them untouched. The
 *   `'account_keys_not_fetched'`, `'identity_already_exists'` and
 *   `'material_not_ready'` assertions are real assertions about that map;
 *   any of the three reverting to `'unknown'` fails here.
 * * **Value translation, unmocked, against the real enums.**
 *   `senderVerificationOf`, `trustStateOf` and `flowStageOf` run on genuine
 *   generated enum members carrying the real wire ordinals, not hand-typed
 *   numbers. The `{ state: 'verified' }` at the end is the first time that
 *   value has been read off an `EventEnvelope` anywhere in this repository.
 * * **Argument forwarding.** The model throws `UnknownRequest` for an id it
 *   did not hand out, so a facade that dropped or mangled an id fails.
 *
 * ## What a green run does not prove, and where that proof lives instead
 *
 * **Not one line of Rust executes.** There is no JSI host object under
 * vitest, so no test in this directory has ever run any. The cryptography
 * is proved in `rust/matrix-crypto-core/tests/verified_sender.rs`, by
 * `the_whole_chain_makes_an_event_read_verified` against a
 * counterparty that process does not control, and that test is the only
 * thing entitled to say the value is earned.
 *
 * **Every outcome below is decided by `installFake`, not by the library.**
 * The refusal and the key query it queues, the batch and its order, the
 * `401` leaving the id alive, the device moving, and `'verified'` itself
 * are all the model's five-boolean conjunction agreeing with the model's
 * own `queue()` calls. So the three interleaved negative assertions do not
 * fail on a library defect. What they do catch is narrower and still worth
 * having: they fail if the facade stops driving the published call that
 * flips a given boolean, which is a real regression guard on the order
 * above. **Do not read them as evidence that an incomplete chain is unsafe
 * in the library.** `verified_sender.rs`'s
 * `omitting_the_second_key_fetch_leaves_the_sender_below_verified` is what
 * holds that, against real cryptography.
 *
 * # Why the model is a model and not a constant
 *
 * The M3 ruling this file already carries -- restated at
 * `matrix_crypto_core::SenderVerification` as **nothing except the real
 * chain produces `verified`** -- forbids a fixture that simply hands back
 * the value, because such a fixture teaches the belief the ruling exists to
 * prevent. So the model does not. It holds the five facts the real gate
 * holds, each set by a different published call resolving a different
 * request, and reports `Verified` only when all five are true. That keeps
 * the fixture honest about the *shape* of the rule even though it can
 * prove nothing about the rule's implementation.
 *
 * The sharpest of the five is step six. Nothing caches the signature a
 * comparison produces, so uploading it and not fetching it back leaves
 * every event reading `'unverified_identity'` while every call in the flow
 * returned success and the device reads `'verified'`. The model reproduces
 * that shape so this file's reader meets it; `verified_sender.rs` is what
 * proves it.
 *
 * # What the model deliberately does not reproduce at all
 *
 * Response-body validation, which `markRequestSent` performs in Rust over
 * each endpoint's declared fields and which the core's own tests cover
 * (this file reports `'{}'` for a `keys_upload`, which the real core
 * rejects); the within-a-batch ordering rule, which the verification arc
 * above covers; and the eviction rule, which is documented at
 * `takeOutgoingRequests` and belongs to the pump rather than to this
 * chain. A model that reproduced everything would be the thing under test.
 */
describe('the signing identity chain, driven through the public surface', () => {
  const PEER = '@bob:example.org'

  interface Chain {
    /** Step 1a: a key query naming our own account was reported sent. */
    accountKeysFetched: boolean
    /** Steps 1 and 2: we hold the private identity, and published it. */
    identityPublished: boolean
    /** Step 5: a comparison completed, which is what makes the signature. */
    comparisonDone: boolean
    /** Step 6: that signature reached the server. */
    signatureUploaded: boolean
    /** Step 7: and came back into our own store on a later key query. */
    signatureFetchedBack: boolean
  }

  interface Fake {
    chain: Chain
    /** The peer's acknowledgement arrives and the flow closes. */
    finishTheFlow(): void
    /** A later `/sync` says the peer's devices changed. */
    peerDevicesChanged(): Promise<void>
  }

  function installFake(): Fake {
    const chain: Chain = {
      accountKeysFetched: false,
      identityPublished: false,
      comparisonDone: false,
      signatureUploaded: false,
      signatureFetchedBack: false,
    }
    // Everything the library owes the product right now, and everything it
    // is waiting to hear back about. Ids are opaque and the facade parses
    // nothing out of one, so a counter is enough.
    let owed: Array<{ id: string; kind: string; body: string }> = []
    const pending = new Map<string, string>()
    let nextId = 0
    let identityKnown = false
    let privateKeysHeld = false
    let stage = NativeVerificationStage.Requested
    let keyReported = false

    const queue = (kind: string, body = '{}'): void => {
      owed.push({ id: `request-${++nextId}`, kind, body })
    }

    vi.mocked(nativeIdentityStatus).mockImplementation(async () => ({
      accountKeysFetched: chain.accountKeysFetched,
      identityKnown,
      privateKeysHeld,
    }))

    vi.mocked(nativeBootstrapIdentity).mockImplementation(async () => {
      if (!chain.accountKeysFetched) {
        // Queued *by* the refusal, exactly as the core does it, so the
        // refusal is recoverable rather than a dead end.
        queue('keys_query')
        throw new MachineFfiError.AccountKeysNotFetched()
      }
      if (identityKnown && !privateKeysHeld) throw new MachineFfiError.IdentityAlreadyExists()
      identityKnown = true
      privateKeysHeld = true
      // Upstream's order, and the batch is longer than the four requests
      // that belong to the bootstrap. See `bootstrapCrossSigning`.
      queue('keys_upload', '{"device_keys":{}}')
      queue('signing_keys_upload', '{"master_key":{}}')
      queue('signature_upload', '{"signed_keys":{}}')
      queue('keys_upload', '{"device_keys":{}}')
      queue('keys_query')
    })

    vi.mocked(nativeTakeOutgoingRequests).mockImplementation(async () => {
      const batch = owed
      owed = []
      for (const request of batch) pending.set(request.id, request.kind)
      return batch
    })

    vi.mocked(nativeMarkRequestSent).mockImplementation(async (id: string) => {
      const kind = pending.get(id)
      if (kind === undefined) throw new SessionFfiError.UnknownRequest()
      pending.delete(id)
      if (kind === 'keys_query') {
        // The first answered query is about our own account and is what
        // lifts the bootstrap gate. Every later one is about the peer, and
        // one of those is step seven -- but only once there is a signature
        // of ours for it to bring back.
        if (!chain.accountKeysFetched) chain.accountKeysFetched = true
        else if (chain.signatureUploaded) chain.signatureFetchedBack = true
      }
      if (kind === 'signing_keys_upload') chain.identityPublished = true
      if (kind === 'signature_upload' && chain.comparisonDone) chain.signatureUploaded = true
      if (kind === 'to_device' && stage === NativeVerificationStage.Started) {
        keyReported = true
        stage = NativeVerificationStage.KeysExchanged
      }
    })

    vi.mocked(nativeMarkRequestFailed).mockImplementation(async (id: string) => {
      if (!pending.has(id)) throw new SessionFfiError.UnknownRequest()
      // A refusal teaches the library nothing and consumes nothing: the
      // entry stays, which is what lets a product loop on a 401.
    })

    vi.mocked(nativeReceiveSyncChanges).mockImplementation(async () => {
      queue('keys_query')
      return { toDeviceEventCount: 0, newSessionCount: 0 }
    })

    const chainComplete = (): boolean =>
      chain.accountKeysFetched &&
      chain.identityPublished &&
      chain.comparisonDone &&
      chain.signatureUploaded &&
      chain.signatureFetchedBack

    vi.mocked(nativeDecryptEvent).mockImplementation(async () => ({
      scope: '!native-scope:example.org',
      algorithm: 'm.native.algorithm',
      eventType: 'm.native.event',
      ciphertext: toArrayBuffer('native-plaintext'),
      sender: PEER,
      // The peer runs a mainstream client, so their device carries their
      // own identity's signature from the start. What our side has to earn
      // is the second gate, and until every step of the chain is done the
      // value sits one rung below it.
      senderVerification: chainComplete()
        ? NativeSenderVerification.Verified
        : NativeSenderVerification.UnverifiedIdentity,
    }))

    vi.mocked(nativeDeviceStatuses).mockImplementation(async () => [
      {
        // The device a person actually compared a string with. Locally
        // trusted the moment the flow closes, with no signature round trip
        // needed for that half.
        deviceId: 'BOBDEVICE',
        trust:
          stage === NativeVerificationStage.Done
            ? NativeTrustState.Verified
            : NativeTrustState.Unverified,
      },
      {
        // A second device of the same person. Nobody has compared anything
        // with it and nobody ever will; it moves when their *identity*
        // becomes trusted, which is the point of cross-signing and the
        // behaviour change this release ships.
        deviceId: 'BOBPHONE',
        trust: chainComplete() ? NativeTrustState.Verified : NativeTrustState.Unverified,
      },
    ])

    vi.mocked(nativeRequestVerification).mockImplementation(async () => {
      stage = NativeVerificationStage.Requested
      return 'chain-flow-id'
    })
    vi.mocked(nativeAcceptVerification).mockImplementation(async () => {
      if (stage !== NativeVerificationStage.Requested) throw new MachineFfiError.WrongStage()
      stage = NativeVerificationStage.Ready
    })
    vi.mocked(nativeStartVerificationComparison).mockImplementation(async () => {
      if (stage !== NativeVerificationStage.Ready) throw new MachineFfiError.WrongStage()
      stage = NativeVerificationStage.Started
      // The key message. Reporting it sent is what produces a string, and
      // reporting is the only thing that advances this flow.
      queue('to_device')
    })
    vi.mocked(nativeVerificationStage).mockImplementation(async () => stage)
    vi.mocked(nativeVerificationMaterial).mockImplementation(async () => {
      if (stage === NativeVerificationStage.Started && !keyReported) {
        throw new MachineFfiError.MaterialNotReady()
      }
      if (stage !== NativeVerificationStage.KeysExchanged) throw new MachineFfiError.WrongStage()
      return { emoji: undefined, decimalOne: 4444, decimalTwo: 5555, decimalThree: 6666 }
    })
    vi.mocked(nativeConfirmVerification).mockImplementation(async () => {
      if (stage !== NativeVerificationStage.KeysExchanged) throw new MachineFfiError.WrongStage()
      stage = NativeVerificationStage.Confirmed
    })

    return {
      chain,
      finishTheFlow() {
        stage = NativeVerificationStage.Done
        chain.comparisonDone = true
        // Step 5's output. A completed comparison signs the peer's master
        // key with our user-signing key, and the resulting signature reaches
        // the pump as an ordinary outgoing request.
        queue('signature_upload', '{"signed_keys":{}}')
      },
      async peerDevicesChanged() {
        await receiveSyncChanges({ changed_devices: { changed: [PEER] } })
      },
    }
  }

  /** Sends and reports everything the pump is currently holding. */
  async function pump(): Promise<string[]> {
    const batch = await takeOutgoingRequests()
    for (const request of batch) await markRequestSent(request.id, '{}')
    return batch.map((request) => request.kind)
  }

  it('drives every published call of the chain, in order, and translates what it is handed', async () => {
    const fake = installFake()

    // ---- Step 1: nothing is known, and the refusal says which nothing ----
    expect(await getIdentityStatus()).toEqual({
      accountKeysFetched: false,
      identityKnown: false,
      privateKeysHeld: false,
    })

    // Refused, and refused as its own kind rather than as 'unknown'. Both
    // halves matter: a product told 'unknown' cannot tell this apart from a
    // failure, and this one has a remedy.
    await expect(bootstrapCrossSigning()).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'account_keys_not_fetched',
    )

    // The refusal queued the question that lifts it.
    expect(await pump()).toEqual(['keys_query'])
    expect((await getIdentityStatus()).accountKeysFetched).toBe(true)

    // ---- Step 2: now it is served, and the status says it took effect ----
    await expect(bootstrapCrossSigning()).resolves.toBeUndefined()
    expect(await getIdentityStatus()).toEqual({
      accountKeysFetched: true,
      identityKnown: true,
      privateKeysHeld: true,
    })

    // The batch is longer than the four requests the bootstrap owns, and
    // it is in the order that lets a signature follow the key it names.
    const batch = await takeOutgoingRequests()
    expect(batch.map((request) => request.kind)).toEqual([
      'keys_upload',
      'signing_keys_upload',
      'signature_upload',
      'keys_upload',
      'keys_query',
    ])

    // ---- The authentication loop this library refuses to run for you ----
    const signingKeys = batch.find((request) => request.kind === 'signing_keys_upload')
    if (signingKeys === undefined) throw new Error('the bootstrap queued no signing keys upload')

    // `bootstrapCrossSigning` takes no argument, and this is the assertion
    // that fails the day someone adds one: the challenge is only known
    // after this very request has been refused, so a credential parameter
    // would have to be guessed before the server had spoken.
    expect(bootstrapCrossSigning.length).toBe(0)

    // The server refuses the first attempt with a challenge. Reported as a
    // failure, which teaches the library nothing and consumes nothing.
    await markRequestFailed(signingKeys.id, 401)
    // No identity is published on the strength of a challenge.
    expect(fake.chain.identityPublished).toBe(false)
    // The same id, and the same body with an `auth` object merged into it
    // by the product, sent again. The id survived the refusal.
    await markRequestSent(signingKeys.id, '{}')
    expect(fake.chain.identityPublished).toBe(true)

    for (const request of batch.filter((r) => r.kind !== 'signing_keys_upload')) {
      await markRequestSent(request.id, '{}')
    }

    // ---- Steps 3 and 4: their identity, and our copy of their keys ----
    await fake.peerDevicesChanged()
    expect(await pump()).toEqual(['keys_query'])

    // We have an identity and they have one, and we have no opinion of
    // theirs. The ordinary value for a peer running a mainstream client,
    // and also where an incomplete chain lands.
    expect((await decryptEvent(scope, { type: 'm.room.encrypted' })).senderVerification).toEqual({
      state: 'unverified',
      reason: 'unverified_identity',
    })
    expect(await getDeviceStatuses(PEER)).toEqual([
      { deviceId: 'BOBDEVICE', trust: 'unverified' },
      { deviceId: 'BOBPHONE', trust: 'unverified' },
    ])

    // ---- Step 5: a person compares a string ----
    const id = await requestVerification(PEER, 'BOBDEVICE')
    await acceptVerification(id)
    await startVerificationComparison(id)
    // No report, no string: the state machine advances on markRequestSent
    // and on nothing else, and this is the one way the flow could fail
    // silently if it were not reported.
    await expect(getVerificationMaterial(id)).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'material_not_ready',
    )
    expect(await pump()).toEqual(['to_device'])
    expect(await getVerificationStage(id)).toBe('keys-exchanged')

    const material = await getVerificationMaterial(id)
    expect(material).toEqual({ decimals: [4444, 5555, 6666] })
    await confirmVerification(id, material)
    fake.finishTheFlow()
    expect(await getVerificationStage(id)).toBe('done')

    // The compared device is verified. The event is not, and that
    // combination is not a defect: it is a comparison whose signature has
    // not come back yet.
    expect(await getDeviceStatuses(PEER)).toEqual([
      { deviceId: 'BOBDEVICE', trust: 'verified' },
      { deviceId: 'BOBPHONE', trust: 'unverified' },
    ])
    expect((await decryptEvent(scope, { type: 'm.room.encrypted' })).senderVerification).toEqual({
      state: 'unverified',
      reason: 'unverified_identity',
    })

    // ---- Step 6: upload the signature the comparison produced ----
    expect(await pump()).toEqual(['signature_upload'])

    // **Still not verified.** Every call so far returned success, the
    // comparison finished, the device reads verified and the signature
    // really did reach the server; nothing anywhere reports a problem, and
    // the sender sits one rung below where a product would put it.
    //
    // Read this for what it is: the model reproducing that shape, so a
    // reader of this file meets it. It fails if the facade stops driving
    // the call that flips `signatureFetchedBack`, and it cannot fail on a
    // library defect, because the value it reads is this file's own
    // conjunction. What proves the library behaves this way is
    // `verified_sender.rs`'s
    // `omitting_the_second_key_fetch_leaves_the_sender_below_verified`.
    expect((await decryptEvent(scope, { type: 'm.room.encrypted' })).senderVerification).toEqual({
      state: 'unverified',
      reason: 'unverified_identity',
    })

    // ---- Step 7: fetch their keys again, so that our own signature is in
    // our own store, which is the only place the gate underneath reads ----
    await fake.peerDevicesChanged()
    expect(await pump()).toEqual(['keys_query'])

    // Only now.
    expect((await decryptEvent(scope, { type: 'm.room.encrypted' })).senderVerification).toEqual({
      state: 'verified',
    })

    // And the second device, which nobody compared anything with and
    // nobody ever will. This is the M4 design's section 3.2 item 1 arriving
    // in a product: verifying one device of a user moves every device of
    // that user, including ones that turn up afterwards. It is correct
    // rather than a defect, and it is why `getDeviceStatuses` now says so
    // at the call.
    expect(await getDeviceStatuses(PEER)).toEqual([
      { deviceId: 'BOBDEVICE', trust: 'verified' },
      { deviceId: 'BOBPHONE', trust: 'verified' },
    ])
  })
})
