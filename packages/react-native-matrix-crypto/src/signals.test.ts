import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  CryptoSignal as NativeCryptoSignal,
  TrustState as NativeTrustState,
} from './generated/matrix_crypto'
import type { CryptoSignal } from './signals'

/**
 * Every observer `signals.ts` handed to the native side, in order.
 *
 * `vi.hoisted` because `vi.mock`'s factory is hoisted above the imports and
 * cannot close over an ordinary module-level `const`.
 */
const { installed } = vi.hoisted(() => ({
  installed: [] as Array<{ onSignal: (signal: NativeCryptoSignal) => void }>,
}))

// Only `setCryptoObserver` is mocked -- there is no JSI host object under
// vitest (Node), so it can never actually run here. Everything else in the
// generated module comes through `importOriginal` untouched, including
// `CryptoSignal`'s own tagged classes and the `TrustState` enum. That is
// load-bearing: the signals these tests feed the observer are built with
// the real generated constructors, so a reader that only works against a
// hand-typed `{ tag, inner }` fixture fails here rather than in production.
vi.mock('./generated/matrix_crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./generated/matrix_crypto')>()
  return {
    ...actual,
    setCryptoObserver: vi.fn((observer: { onSignal: (signal: NativeCryptoSignal) => void }) => {
      installed.push(observer)
    }),
  }
})

/**
 * A fresh copy of the module under test.
 *
 * `signals.ts` keeps two pieces of module state -- the listener set and
 * whether the native observer has been installed -- and both have to start
 * empty for each test, so the module is re-evaluated rather than reset by
 * hand. That also means each test's listeners are discarded with the module
 * copy that held them, which is why nothing here unsubscribes in teardown.
 */
async function freshSignals() {
  vi.resetModules()
  installed.length = 0
  return import('./signals')
}

const TRUST_CHANGED: CryptoSignal = {
  kind: 'trust_changed',
  user: '@alice:example.org',
  state: 'verified',
}

describe('onCryptoSignal', () => {
  beforeEach(() => {
    installed.length = 0
  })

  it('installs nothing until something subscribes', async () => {
    await freshSignals()

    expect(installed).toEqual([])
  })

  it('installs the native observer exactly once, however many listeners subscribe', async () => {
    const { onCryptoSignal } = await freshSignals()

    const first = onCryptoSignal(() => {})
    onCryptoSignal(() => {})
    first()
    onCryptoSignal(() => {})

    // One observer, not one per listener: the fan-out to listeners happens
    // on this side of the boundary, and a second registration would replace
    // the first native-side rather than add to it.
    expect(installed).toHaveLength(1)
  })
})

describe('the native producer', () => {
  beforeEach(() => {
    installed.length = 0
  })

  it('delivers a trust change as the public signal', async () => {
    const { onCryptoSignal } = await freshSignals()
    const received: CryptoSignal[] = []
    onCryptoSignal((s) => received.push(s))

    installed[0].onSignal(
      new NativeCryptoSignal.TrustChanged({
        user: '@alice:example.org',
        state: NativeTrustState.Verified,
      }),
    )

    expect(received).toEqual([TRUST_CHANGED])
  })

  it('delivers an inbound announcement with the identifier that accepts it', async () => {
    const { onCryptoSignal } = await freshSignals()
    const received: CryptoSignal[] = []
    onCryptoSignal((s) => received.push(s))

    installed[0].onSignal(
      new NativeCryptoSignal.VerificationRequested({
        user: '@bob:example.org',
        deviceId: 'BOBDEVICE',
        verificationId: 'the-transaction-id',
      }),
    )

    // The three strings are deliberately distinguishable from one another:
    // they all cross the boundary as `string`, so a reader that paired them
    // up wrongly would satisfy any assertion that only checked the shape.
    // `verificationId` is the one that matters most -- it is what a product
    // hands to `acceptVerification`, and getting it from here is the whole
    // reason this variant exists.
    expect(received).toEqual([
      {
        kind: 'verification_requested',
        user: '@bob:example.org',
        device: 'BOBDEVICE',
        verificationId: 'the-transaction-id',
      },
    ])
  })

  it('does not let a throwing listener starve a later-registered one', async () => {
    const { onCryptoSignal } = await freshSignals()
    onCryptoSignal(() => {
      throw new Error('boom')
    })
    const received: CryptoSignal[] = []
    onCryptoSignal((s) => received.push(s))

    // Driven through the installed observer rather than through
    // `emitCryptoSignal`, which is what this test used to do. The
    // isolation guarantee was written and tested against a channel with no
    // producer; now that one exists, what has to survive a throwing
    // listener is a real inbound announcement, because the listener behind
    // the broken one is the one that opens the verification screen.
    installed[0].onSignal(
      new NativeCryptoSignal.VerificationRequested({
        user: '@bob:example.org',
        deviceId: 'BOBDEVICE',
        verificationId: 'the-transaction-id',
      }),
    )

    expect(received).toEqual([
      {
        kind: 'verification_requested',
        user: '@bob:example.org',
        device: 'BOBDEVICE',
        verificationId: 'the-transaction-id',
      },
    ])
  })

  it('stops delivering to a listener that has unsubscribed', async () => {
    const { onCryptoSignal } = await freshSignals()
    const a: CryptoSignal[] = []
    const b: CryptoSignal[] = []
    const unsubscribeA = onCryptoSignal((s) => a.push(s))
    onCryptoSignal((s) => b.push(s))

    unsubscribeA()
    installed[0].onSignal(
      new NativeCryptoSignal.TrustChanged({
        user: '@alice:example.org',
        state: NativeTrustState.Verified,
      }),
    )

    expect(a).toEqual([])
    expect(b).toEqual([TRUST_CHANGED])
  })

  it('does not deliver the signal in progress to a listener registered during dispatch', async () => {
    const { onCryptoSignal } = await freshSignals()
    const lateReceived: CryptoSignal[] = []
    onCryptoSignal(() => {
      onCryptoSignal((s) => lateReceived.push(s))
    })

    installed[0].onSignal(
      new NativeCryptoSignal.TrustChanged({
        user: '@alice:example.org',
        state: NativeTrustState.Verified,
      }),
    )

    expect(lateReceived).toEqual([])
  })
})
