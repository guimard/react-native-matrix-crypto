import { describe, expect, it } from 'vitest'
import { asCryptoScopeId } from './types'
import { isCryptoError } from './errors'
import { encryptEvent, decryptEvent, exportSecrets } from './facade'

const scope = asCryptoScopeId('!scope:example.org')

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
