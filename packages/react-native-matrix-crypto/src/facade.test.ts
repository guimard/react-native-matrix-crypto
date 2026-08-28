import { describe, expect, it, vi } from 'vitest'
import type { CryptoScopeId } from './types'
import { asCryptoScopeId } from './types'
import { isCryptoError } from './errors'
import {
  createCryptoMachine,
  decryptEvent,
  encryptEvent,
  exportSecrets,
  getDeviceIdentityKeys,
  markRequestSent,
  openCryptoStore,
  receiveSyncChanges,
  shareScopeKey,
  takeOutgoingRequests,
} from './facade'
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
    })),
    shareScopeKey: vi.fn(async () => undefined),
    takeOutgoingRequests: vi.fn(async () => [{ id: 'req-1', kind: 'keys_upload', body: '{}' }]),
    markRequestSent: vi.fn(async () => undefined),
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

    await expect(receiveSyncChanges({ toDeviceEvents: [] })).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'malformed_payload',
    )
    await expect(receiveSyncChanges({ nonsense: true })).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'malformed_payload',
    )

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

    await expect(receiveSyncChanges(SYNC_RESPONSE)).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'malformed_payload',
    )

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
   * the *value* `undefined`, not a string, and `syncDelta: unknown` lets
   * it through the type system. This proves it is rejected before native
   * is ever called, rather than forwarded as the four-character string
   * `"undefined"` or the bare value `undefined`.
   */
  it('rejects with malformed_payload before ever calling native, when syncDelta stringifies to undefined', async () => {
    vi.mocked(nativeReceiveSyncChanges).mockClear()

    await expect(receiveSyncChanges(undefined)).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'malformed_payload',
    )

    expect(nativeReceiveSyncChanges).not.toHaveBeenCalled()
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
   */
  it('rejects with malformed_payload before ever calling native, when scope is not actually a string at runtime', async () => {
    vi.mocked(nativeDecryptEvent).mockClear()

    await expect(decryptEvent(undefined as unknown as CryptoScopeId, {})).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'malformed_payload',
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
      ...({ internalDebugFlag: true } as Record<string, unknown>),
    })

    const envelope = await decryptEvent(scope, { type: 'm.room.encrypted' })

    expect(envelope).toEqual({
      scope: asCryptoScopeId('!native-scope:example.org'),
      algorithm: 'm.native.algorithm',
      eventType: 'm.native.event',
      ciphertext: new TextEncoder().encode('native-plaintext'),
      sender: '@native-sender:example.org',
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
