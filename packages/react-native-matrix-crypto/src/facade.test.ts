import { describe, expect, it, vi } from 'vitest'
import { asCryptoScopeId } from './types'
import { isCryptoError } from './errors'
import { encryptEvent, decryptEvent, exportSecrets, getDeviceIdentityKeys } from './facade'

const scope = asCryptoScopeId('!scope:example.org')

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
    deviceIdentityKeys: vi.fn(async (userId: string) => {
      if (userId !== 'bad-id') throw new Error('unexpected call in this fixture')
      throw new actual.MachineFfiError.MalformedIdentifier({ detail: 'user id' })
    }),
  }
})

describe('facade before implementation', () => {
  it('rejects with a typed not_implemented error rather than undefined', async () => {
    await expect(encryptEvent(scope, 'm.room.message', { body: 'hi' }))
      .rejects.toSatisfy((e: unknown) => isCryptoError(e) && e.kind === 'not_implemented')
  })

  it('rejects decryptEvent the same way', async () => {
    await expect(decryptEvent({})).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'not_implemented',
    )
  })

  it('rejects exportSecrets the same way', async () => {
    await expect(exportSecrets('passphrase')).rejects.toSatisfy(
      (e: unknown) => isCryptoError(e) && e.kind === 'not_implemented',
    )
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
