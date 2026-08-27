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
})
