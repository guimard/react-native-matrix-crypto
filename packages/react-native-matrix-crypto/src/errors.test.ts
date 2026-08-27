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
})
