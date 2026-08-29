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

    // This binding never signals either, so it would otherwise sit out the
    // whole `signal` budget on the way to the assertion below.
    const checks = await runInteropSuite(broken, { signalWaitMs: 100 })
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

  it('sees a signal the binding delivers after runProbe has already resolved', async () => {
    // The failure this pins is not hypothetical. A release build of the
    // example app on emulator-5554 reported `signal FAIL (none)` on 5 of 8
    // launches while the callback was working perfectly -- it simply reached
    // the JS thread after the promise did. The reference binding calls its
    // observer synchronously, so nothing in Node had ever exercised the other
    // order.
    const binding = referenceBinding()
    const direct = binding.runProbe
    binding.runProbe = async (input, payload, onSignal) => {
      const report = await direct(input, payload, undefined)
      if (onSignal) setTimeout(() => onSignal('probe_started'), 50)
      return report
    }

    const checks = await runInteropSuite(binding)
    const signal = checks.find((c) => c.name === 'signal')
    expect(signal?.ok).toBe(true)
    expect(signal?.detail).toBe('probe_started')
  })

  it('still fails when the binding never signals at all', async () => {
    // The other half of the check above: waiting for a late callback must not
    // turn `signal` into something that can only pass. A binding that never
    // calls the observer has to fail, bounded wait or not.
    //
    // `signalWaitMs` is shortened because this test is about the branch, not
    // about the budget -- the shipped default carries a margin for a slower
    // emulator than this one and would spend ten seconds here proving nothing
    // extra.
    //
    // Written as words rather than as a figure on purpose: this line said
    // "3 seconds" for one commit after `SIGNAL_WAIT_MS` moved to 10000, in the
    // very commit whose subject was about sizing that constant. A duplicated
    // number goes stale silently; a description of what the default is for
    // does not.
    const binding = referenceBinding()
    const direct = binding.runProbe
    binding.runProbe = (input, payload) => direct(input, payload, undefined)

    const checks = await runInteropSuite(binding, { signalWaitMs: 100 })
    const signal = checks.find((c) => c.name === 'signal')
    expect(signal?.ok).toBe(false)
    expect(signal?.detail).toBe('(none)')
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
