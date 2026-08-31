import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  CryptoSignal as NativeCryptoSignal,
  CryptoSignal_Tags as NativeCryptoSignalTag,
  TrustState as NativeTrustState,
} from './generated/matrix_crypto'
import type { CryptoSignal } from './signals'

/**
 * Every observer `signals.ts` handed to the native side, in order.
 *
 * `vi.hoisted` because `vi.mock`'s factory is hoisted above the imports and
 * cannot close over an ordinary module-level `const`.
 */
const { installed, cleared, failNextInstall, failNextClear } = vi.hoisted(() => ({
  installed: [] as Array<{ onSignal: (signal: NativeCryptoSignal) => void }>,
  cleared: { count: 0 },
  // Armed by a test, disarmed by the call it fires on, so a test that arms
  // one is describing a single failing call rather than a broken module.
  failNextInstall: { pending: false },
  failNextClear: { pending: false },
}))

/**
 * What the generated wrapper actually throws when the bootstrap has not run.
 *
 * Both registry wrappers in `./generated/matrix_crypto` reach the JSI host
 * object through `nativeModule()` and read a function off it. With no host
 * object there is nothing to read from, and the shape of the failure is a
 * `TypeError` naming the symbol, which is exactly what `index.ts`'s own
 * comment records hitting on a real device build. Built here rather than
 * thrown as a bare `Error` so the assertions below can key on the symbol
 * name and cannot pass against some other throw.
 */
function nativeModuleMissing(symbol: string): TypeError {
  return new TypeError(`Cannot read property '${symbol}' of undefined`)
}

// Only the two observer-registry calls are mocked -- there is no JSI host
// object under vitest (Node), so neither can actually run here. Everything
// else in the generated module comes through `importOriginal` untouched,
// including `CryptoSignal`'s own tagged classes and the `TrustState` enum.
// That is load-bearing: the signals these tests feed the observer are built
// with the real generated constructors, so a reader that only works against
// a hand-typed `{ tag, inner }` fixture fails here rather than in
// production.
vi.mock('./generated/matrix_crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./generated/matrix_crypto')>()
  return {
    ...actual,
    setCryptoObserver: vi.fn((observer: { onSignal: (signal: NativeCryptoSignal) => void }) => {
      if (failNextInstall.pending) {
        failNextInstall.pending = false
        throw nativeModuleMissing('ubrn_uniffi_matrix_crypto_ffi_fn_func_set_crypto_observer')
      }
      // Recorded only on the way out, so `installed` counts registrations
      // the native side actually took, not attempts.
      installed.push(observer)
    }),
    clearCryptoObserver: vi.fn(() => {
      if (failNextClear.pending) {
        failNextClear.pending = false
        throw nativeModuleMissing('ubrn_uniffi_matrix_crypto_ffi_fn_func_clear_crypto_observer')
      }
      cleared.count += 1
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
  cleared.count = 0
  failNextInstall.pending = false
  failNextClear.pending = false
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
    cleared.count = 0
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

  it('keeps the native observer while any listener is still subscribed', async () => {
    const { onCryptoSignal } = await freshSignals()

    const first = onCryptoSignal(() => {})
    onCryptoSignal(() => {})
    first()

    expect(cleared.count).toBe(0)
  })

  it('uninstalls the native observer when the last listener unsubscribes', async () => {
    const { onCryptoSignal } = await freshSignals()

    const only = onCryptoSignal(() => {})
    expect(cleared.count).toBe(0)
    only()

    // Not tidiness. While an observer is installed the Rust side does its
    // full pass, registers an inbound invitation, marks it announced and
    // delivers it into a listener set that is now empty -- and then refuses
    // to announce it again for the life of the flow. Nothing lists inbound
    // flows, so the invitation is lost until it expires. See
    // `clear_crypto_observer` in the core.
    expect(cleared.count).toBe(1)
  })

  it('installs again, and delivers again, when something resubscribes', async () => {
    const { onCryptoSignal } = await freshSignals()

    onCryptoSignal(() => {})()

    const received: CryptoSignal[] = []
    onCryptoSignal((s) => received.push(s))

    // A second registration, not the first one reused: the resubscribe has
    // to reach the native side, or the Rust observer stays cleared and the
    // channel is silent from here on.
    expect(installed).toHaveLength(2)
    installed[1].onSignal(
      new NativeCryptoSignal.TrustChanged({
        user: '@alice:example.org',
        state: NativeTrustState.Verified,
      }),
    )
    expect(received).toEqual([TRUST_CHANGED])
  })
})

describe('the native producer', () => {
  beforeEach(() => {
    installed.length = 0
    cleared.count = 0
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

  it('delivers a completed code verification, naming the flow and nothing else', async () => {
    const { onCryptoSignal } = await freshSignals()
    const received: CryptoSignal[] = []
    onCryptoSignal((s) => received.push(s))

    installed[0].onSignal(
      new NativeCryptoSignal.VerificationCompleted({
        verificationId: 'the-transaction-id',
      }),
    )

    // The whole value, not its `kind`. This variant deliberately carries no
    // user and no trust state: what changed at that moment is not the same
    // in all three of the protocol's modes, and a field carrying one of them
    // would be right in one mode and misleading in the others. A reader that
    // helpfully filled one in would satisfy a `kind` check and fail here.
    expect(received).toEqual([
      { kind: 'verification_completed', verificationId: 'the-transaction-id' },
    ])
  })

  // Every variant the generated enum can deliver, not merely the ones this
  // file happens to feed the observer. `cryptoSignalOf` is exhaustive by
  // compile error, so an unhandled variant cannot ship -- but nothing made
  // one reach these tests, and a producer suite that silently covers less
  // than the enum it stands for is the shape this repository keeps finding.
  it('has a test above for every variant the native producer can deliver', () => {
    expect(Object.keys(NativeCryptoSignalTag).filter((key) => Number.isNaN(Number(key)))).toEqual([
      'TrustChanged',
      'VerificationRequested',
      'VerificationCompleted',
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
    // The control. Without it this test passes against an implementation
    // with no fan-out at all: the outer listener would never run, no late
    // listener would ever be registered, and `lateReceived` would be empty
    // for the wrong reason. Its sibling above has the same shape for the
    // same reason.
    const outerReceived: CryptoSignal[] = []
    onCryptoSignal((s) => {
      outerReceived.push(s)
      onCryptoSignal((late) => lateReceived.push(late))
    })

    installed[0].onSignal(
      new NativeCryptoSignal.TrustChanged({
        user: '@alice:example.org',
        state: NativeTrustState.Verified,
      }),
    )

    expect(outerReceived).toEqual([TRUST_CHANGED])
    expect(lateReceived).toEqual([])
  })
})

/**
 * The channel's one way to fail without saying so.
 *
 * `setCryptoObserver` is the only call `onCryptoSignal` makes that can
 * fail, and what it fails at is the whole subscription: a listener added
 * behind a registry call that did not happen is a listener nothing will
 * ever reach. So the question every test here asks is not whether the
 * module recovers, but whether the caller is told.
 */
describe('an install that throws', () => {
  it('reports the failure to the subscriber that asked for it', async () => {
    const { onCryptoSignal } = await freshSignals()
    failNextInstall.pending = true

    // Not caught and turned into a quiet no-op. `onCryptoSignal` returning
    // normally has one meaning, and it is that the channel is live.
    expect(() => onCryptoSignal(() => {})).toThrow(/set_crypto_observer/)
  })

  it('reports it to the next subscriber too, rather than handing out a dead channel', async () => {
    const { onCryptoSignal } = await freshSignals()
    failNextInstall.pending = true
    expect(() => onCryptoSignal(() => {})).toThrow()

    // The regression this file exists to keep out. `nativeInstalled` was
    // set before the call it describes, so a throw left the module
    // believing the observer was installed. Every later subscribe then took
    // the early return and handed back an unsubscribe function for a
    // channel that would never deliver: nothing thrown, nothing logged, and
    // an inbound verification request expiring ten minutes later with a
    // product still waiting for it.
    failNextInstall.pending = true
    expect(() => onCryptoSignal(() => {})).toThrow(/set_crypto_observer/)
  })

  it('installs on the next subscribe once the native module is there', async () => {
    const { onCryptoSignal } = await freshSignals()
    failNextInstall.pending = true
    expect(() => onCryptoSignal(() => {})).toThrow()

    // Retried, not remembered as broken. The condition behind a real
    // failure here is a bootstrap that has not run against this runtime
    // yet, which is true at one moment and false at the next; a flag that
    // recorded the failure permanently would be this same defect with the
    // sign reversed, and just as quiet.
    const received: CryptoSignal[] = []
    onCryptoSignal((s) => received.push(s))

    expect(installed).toHaveLength(1)
    installed[0].onSignal(
      new NativeCryptoSignal.TrustChanged({
        user: '@alice:example.org',
        state: NativeTrustState.Verified,
      }),
    )
    expect(received).toEqual([TRUST_CHANGED])
  })

  it('registers no listener for a subscribe that threw', async () => {
    const { onCryptoSignal } = await freshSignals()
    failNextInstall.pending = true
    const orphan: CryptoSignal[] = []
    expect(() => onCryptoSignal((s) => orphan.push(s))).toThrow()

    const received: CryptoSignal[] = []
    const unsubscribe = onCryptoSignal((s) => received.push(s))
    installed[0].onSignal(
      new NativeCryptoSignal.TrustChanged({
        user: '@alice:example.org',
        state: NativeTrustState.Verified,
      }),
    )

    // A caller that caught an exception holds no unsubscribe function and
    // has every right to believe it is not subscribed, so it must not start
    // receiving the moment somebody else installs the observer.
    expect(orphan).toEqual([])
    expect(received).toEqual([TRUST_CHANGED])

    // And it must not hold the set non-empty behind the last real listener,
    // which would leave the observer installed over nobody: the state
    // `uninstallNativeObserver` exists to prevent, and the one that
    // consumes an invitation irrecoverably.
    unsubscribe()
    expect(cleared.count).toBe(1)
  })
})

describe('an uninstall that throws', () => {
  it('reports the failure to the caller that unsubscribed', async () => {
    const { onCryptoSignal } = await freshSignals()
    const only = onCryptoSignal(() => {})
    failNextClear.pending = true

    // The listener is gone either way: `listeners` is this module's own
    // state and the delete had already happened. What is reported is that
    // the native side was not told, which is the condition that leaves an
    // observer running over an empty set.
    expect(only).toThrow(/clear_crypto_observer/)
  })

  it('leaves the observer recorded as installed, because it still is', async () => {
    const { onCryptoSignal } = await freshSignals()
    const only = onCryptoSignal(() => {})
    failNextClear.pending = true
    expect(only).toThrow()

    // The clear did not happen, so the native side still holds the observer
    // this module built, and that observer dispatches to `listeners`, which
    // is module state the failed unsubscribe left intact. Recording it as
    // gone would lay a second registration over a first that never left,
    // and would make the next empty set skip the clear rather than retry
    // it.
    const received: CryptoSignal[] = []
    const second = onCryptoSignal((s) => received.push(s))
    expect(installed).toHaveLength(1)

    installed[0].onSignal(
      new NativeCryptoSignal.TrustChanged({
        user: '@alice:example.org',
        state: NativeTrustState.Verified,
      }),
    )
    expect(received).toEqual([TRUST_CHANGED])

    // What the accurate flag buys: the next time the set empties, the clear
    // is attempted again instead of being skipped as already done.
    second()
    expect(cleared.count).toBe(1)
  })
})
