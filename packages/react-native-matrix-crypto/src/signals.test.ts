import { afterEach, describe, expect, it } from 'vitest'
import { emitCryptoSignal, onCryptoSignal } from './signals'
import type { CryptoSignal } from './signals'

const SIGNAL: CryptoSignal = { kind: 'trust_changed', user: '@alice:example.org', state: 'verified' }

describe('emitCryptoSignal', () => {
  // Every listener registered by a test is tracked here and torn down in
  // afterEach, so tests never leak listeners into one another through the
  // module-level `listeners` Set.
  const unsubs: Array<() => void> = []
  afterEach(() => {
    for (const unsubscribe of unsubs.splice(0)) unsubscribe()
  })

  it('does not let a throwing listener block a later-registered listener', () => {
    unsubs.push(
      onCryptoSignal(() => {
        throw new Error('boom')
      }),
    )
    const received: CryptoSignal[] = []
    unsubs.push(onCryptoSignal((s) => received.push(s)))

    emitCryptoSignal(SIGNAL)

    expect(received).toEqual([SIGNAL])
  })

  it('unsubscribe removes only the listener it belongs to', () => {
    const a: CryptoSignal[] = []
    const b: CryptoSignal[] = []
    const unsubscribeA = onCryptoSignal((s) => a.push(s))
    unsubs.push(onCryptoSignal((s) => b.push(s)))

    unsubscribeA()
    emitCryptoSignal(SIGNAL)

    expect(a).toEqual([])
    expect(b).toEqual([SIGNAL])
  })

  it('a listener registered during dispatch does not receive the signal in progress', () => {
    const lateReceived: CryptoSignal[] = []
    unsubs.push(
      onCryptoSignal(() => {
        unsubs.push(onCryptoSignal((s) => lateReceived.push(s)))
      }),
    )

    emitCryptoSignal(SIGNAL)

    expect(lateReceived).toEqual([])
  })
})
