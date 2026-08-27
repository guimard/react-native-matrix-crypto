import { describe, expect, it } from 'vitest'
import { runInteropSuite } from './suite'
import { referenceBinding } from './reference'

describe('interop suite', () => {
  it('passes every check against the reference binding', async () => {
    const checks = await runInteropSuite(referenceBinding())
    const failed = checks.filter((c) => !c.ok)
    expect(failed, `failed: ${failed.map((c) => c.name).join(', ')}`).toHaveLength(0)
    expect(checks).toHaveLength(5)
  })

  it('reports a failure rather than throwing when a binding misbehaves', async () => {
    const broken = referenceBinding()
    broken.runProbe = async () => ({ echoed: 'wrong', payload: new Uint8Array(), coreVersion: '' })

    const checks = await runInteropSuite(broken)
    expect(checks.find((c) => c.name === 'record')?.ok).toBe(false)
  })

  it('resolves rather than rejecting when onCryptoSignal throws synchronously', async () => {
    const broken = referenceBinding()
    broken.onCryptoSignal = () => {
      throw new Error('subscribe boom')
    }

    // A bare `const unsubscribe = binding.onCryptoSignal(...)` ahead of the
    // try block would let this reject before a single check was recorded.
    const result = runInteropSuite(broken)
    await expect(result).resolves.toBeDefined()

    const checks = await result
    expect(checks.length).toBeGreaterThan(0)
  })

  it('resolves and keeps the checks already collected when unsubscribe throws', async () => {
    const broken = referenceBinding()
    const originalSubscribe = broken.onCryptoSignal
    broken.onCryptoSignal = (cb) => {
      originalSubscribe(cb)
      return () => {
        throw new Error('unsubscribe boom')
      }
    }

    // A throw from `finally { unsubscribe() }` would replace whatever the
    // try/catch was about to return, discarding every check already
    // collected. All five must survive teardown, not just "some array".
    const result = runInteropSuite(broken)
    await expect(result).resolves.toBeDefined()

    const checks = await result
    expect(checks).toHaveLength(5)
    expect(checks.every((c) => c.ok)).toBe(true)
  })
})
