import { describe, expect, it, vi } from 'vitest'
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
  it('forwards the sync delta as JSON and resolves void, discarding the native counts', async () => {
    const delta = { toDeviceEvents: [], changedDevices: { changed: [], left: [] }, oneTimeKeysCounts: {} }

    await expect(receiveSyncChanges(delta)).resolves.toBeUndefined()

    expect(vi.mocked(nativeReceiveSyncChanges).mock.calls.at(-1)?.[0]).toBe(JSON.stringify(delta))
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
})

describe('decryptEvent wiring to the native layer', () => {
  it('extracts scope from rawEvent, forwards the event as JSON verbatim, and rebuilds every field of the returned envelope', async () => {
    const event = { type: 'm.room.encrypted', sender: '@bob:example.org', content: { algorithm: 'm.native.algorithm' } }

    const envelope = await decryptEvent({ scope: '!s:example.org', event })

    const call = vi.mocked(nativeDecryptEvent).mock.calls.at(-1)
    expect(call?.[0]).toBe('!s:example.org')
    expect(call?.[1]).toBe(JSON.stringify(event))

    expect(envelope.ciphertext).toBeInstanceOf(Uint8Array)
    expect(new TextDecoder().decode(envelope.ciphertext)).toBe('native-plaintext')
  })

  /**
   * `decryptEvent`'s frozen M1a signature -- `(rawEvent: unknown) =>
   * Promise<EventEnvelope>` -- has no separate scope parameter, so scope
   * travels inside `rawEvent` as `{ scope, event }`. This proves the
   * malformed-shape guard rejects before ever reaching native, rather
   * than forwarding `undefined`/`"undefined"` as if it were a scope.
   */
  it('rejects with malformed_payload before ever calling native, when rawEvent carries no string scope', async () => {
    vi.mocked(nativeDecryptEvent).mockClear()

    await expect(decryptEvent({ event: {} })).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'malformed_payload',
    )
    await expect(decryptEvent(null)).rejects.toSatisfy(
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
