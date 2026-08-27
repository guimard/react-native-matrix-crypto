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

  it('resolves with a fatal check rather than rejecting when runProbe throws synchronously', async () => {
    const broken = referenceBinding()
    broken.runProbe = () => {
      throw new Error('boom')
    }

    // binding.runProbe(...) throws while evaluating the first `await`,
    // still inside the suite's own try block -- no separate guard needed,
    // but worth locking down: this is the only step left in the suite, so
    // there is nowhere else for such a throw to hide.
    const result = runInteropSuite(broken)
    await expect(result).resolves.toBeDefined()

    const checks = await result
    expect(checks).toEqual([{ name: 'fatal', ok: false, detail: expect.stringContaining('boom') }])
  })

  it("does not leak one caller's probe signal into a concurrent, independent caller", async () => {
    // This is the defect this suite exists to catch: two independent
    // callers of the same binding (e.g. the example app's guided walkthrough
    // and its diagnostics panel, mounted as siblings) must each see only
    // their own call's signal -- never "probe_started,probe_started".
    const binding = referenceBinding()

    const [checksA, checksB] = await Promise.all([runInteropSuite(binding), runInteropSuite(binding)])

    for (const checks of [checksA, checksB]) {
      const signal = checks.find((c) => c.name === 'signal')
      expect(signal?.ok).toBe(true)
      expect(signal?.detail).toBe('probe_started')
    }
  })
})
