import { describe, expect, it } from 'vitest'
import {
  CRYPTO_SUITE_STEPS,
  runCryptoSuite,
  type CryptoBinding,
  type CryptoBindingEnvelope,
} from './crypto-suite'

/**
 * A stand-in, not a reference binding, and the distinction matters enough to
 * keep it out of `reference.ts`: it performs no cryptography at all. Its
 * only job is to let this file exercise the suite's own reporting -- that
 * every step is reported on every run, that a failure is reported rather
 * than thrown, and that the steps after a failure are reported as failures
 * instead of vanishing from the count.
 *
 * The real proof that the cryptography works is the example app's probe on
 * an emulator and a simulator, against the shipped JSI binding. Nothing in
 * this file can substitute for that, which is the whole reason task 10
 * exists.
 */
function fakeBinding(overrides: Partial<CryptoBinding> = {}): CryptoBinding {
  let plaintext = ''
  const base: CryptoBinding = {
    createCryptoMachine: async () => {},
    takeOutgoingRequests: async () => [
      { id: 'a', kind: 'keys_upload', body: '{}' },
      { id: 'b', kind: 'keys_query', body: '{}' },
    ],
    markRequestSent: async () => {},
    shareScopeKey: async () => {},
    encryptEvent: async (_scope, eventType, payload): Promise<CryptoBindingEnvelope> => {
      plaintext = JSON.stringify(payload)
      // Shaped like the encrypted content the core returns: JSON, with the
      // payload nowhere inside it.
      const content = JSON.stringify({
        algorithm: 'a.made.up.tag',
        ciphertext: 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=',
        session_id: 'session',
      })
      return {
        algorithm: 'a.made.up.tag',
        eventType,
        ciphertext: Uint8Array.from(content, (c) => c.charCodeAt(0)),
        sender: '@probe:example.org',
      }
    },
    decryptEvent: async (_scope, _rawEvent): Promise<CryptoBindingEnvelope> => ({
      algorithm: 'a.made.up.tag',
      eventType: 'm.room.message',
      ciphertext: Uint8Array.from(plaintext, (c) => c.charCodeAt(0)),
      sender: '@probe:example.org',
    }),
    errorKind: (e) => (e instanceof Error && 'kind' in e ? String(e.kind) : undefined),
  }
  return { ...base, ...overrides }
}

const OPTIONS = {
  machine: {
    userId: '@probe:example.org',
    deviceId: 'PROBEDEVICE',
    storePath: '/somewhere/writable',
    storePassphrase: 'passphrase',
  },
  scope: '!probe:example.org',
}

describe('crypto interop suite', () => {
  it('reports every step, in order, on a clean run', async () => {
    const checks = await runCryptoSuite(fakeBinding(), OPTIONS)

    expect(checks.map((c) => c.name)).toEqual([...CRYPTO_SUITE_STEPS])
    const failed = checks.filter((c) => !c.ok)
    expect(failed, `failed: ${failed.map((c) => c.name).join(', ')}`).toHaveLength(0)
  })

  it('still reports every step when one of them fails', async () => {
    // Corrupting the recovered plaintext is the cleanest single break: the
    // encrypt call still succeeds, the decrypt call still resolves, and only
    // the byte-for-byte comparison notices.
    const checks = await runCryptoSuite(
      fakeBinding({
        decryptEvent: async () => ({
          algorithm: 'a.made.up.tag',
          eventType: 'm.room.message',
          ciphertext: new Uint8Array([0]),
          sender: '@probe:example.org',
        }),
      }),
      OPTIONS,
    )

    expect(checks.map((c) => c.name)).toEqual([...CRYPTO_SUITE_STEPS])
    expect(checks.find((c) => c.name === 'round_trip')?.ok).toBe(false)
    // The step after the failure is reported as a failure, not dropped:
    // a summary whose denominator shrinks with each failure is
    // indistinguishable from a pass.
    expect(checks.find((c) => c.name === 'ciphertext_opaque')).toEqual({
      name: 'ciphertext_opaque',
      ok: false,
      detail: 'not reached: an earlier step failed',
    })
  })

  it('fails the round trip when the ciphertext carries the plaintext', async () => {
    const checks = await runCryptoSuite(
      fakeBinding({
        encryptEvent: async (_scope, eventType, payload) => ({
          algorithm: 'a.made.up.tag',
          eventType,
          ciphertext: Uint8Array.from(JSON.stringify(payload), (c) => c.charCodeAt(0)),
          sender: '@probe:example.org',
        }),
      }),
      OPTIONS,
    )

    expect(checks.find((c) => c.name === 'ciphertext_opaque')?.ok).toBe(false)
  })

  it('resolves with failing checks rather than rejecting when a call throws', async () => {
    const checks = await runCryptoSuite(
      fakeBinding({
        createCryptoMachine: async () => {
          throw Object.assign(new Error('ProbeFfiError.Store'), { kind: 'store_unavailable' })
        },
      }),
      OPTIONS,
    )

    expect(checks).toHaveLength(CRYPTO_SUITE_STEPS.length)
    expect(checks.every((c) => !c.ok)).toBe(true)
    // The kind, and only the kind: the message is never copied into a
    // detail, so nothing a failure happens to be holding can reach a log.
    expect(checks[0].detail).toBe('rejected with kind "store_unavailable"')
  })

  it('fails rather than skipping when the host supplies no store path', async () => {
    const checks = await runCryptoSuite(fakeBinding(), {
      ...OPTIONS,
      machine: { ...OPTIONS.machine, storePath: '' },
    })

    expect(checks).toHaveLength(CRYPTO_SUITE_STEPS.length)
    expect(checks[0]).toEqual({
      name: 'machine_created',
      ok: false,
      detail: 'the host supplied no writable store path',
    })
  })
})
