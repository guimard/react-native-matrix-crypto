/**
 * The guided walkthrough's own step functions, run on a host machine.
 *
 * WHY THIS FILE EXISTS AT ALL. Until today `packages/example-app` had no test
 * runner. Two defects reached a device because of it. Step 3 reported "no
 * signal received" on a real phone while the same launch logged
 * `PROBE_SUMMARY 12/12`, because step 2 returned before its own observer
 * callback had landed and step 3 read the array anyway. The `notYet` card
 * reported "unexpected" on every launch because it asserted that a library
 * function was unimplemented after the library had implemented it. This
 * paragraph called that one "step 6" until the walkthrough renumbered and
 * the sentence did not; cards are named by id here now. Neither
 * is exotic. Both are the kind of thing a test catches in a second, and
 * nothing in this package could run a test.
 *
 * These are the REAL functions, imported from `./flowRunners`, not a
 * transcription of them. The first attempt at reproducing the step 3 defect
 * copied `runCall` and `runSignal` into a test file, which passes happily
 * while the original is broken and is exactly the failure this package has
 * just spent a day paying for.
 *
 * WHAT IS FAKED, AND WHERE. Exactly one thing: the generated binding's
 * `probeWithObserver`, which is the single function in the chain that
 * actually reaches Rust. Everything above it is real, including
 * `runProbe`'s conversion and `toCryptoError`'s normalisation, so step 4's
 * typed error is normalised by the code that normalises it on a device.
 * Reaching into the library's generated module rather than stubbing its
 * public `runProbe` is deliberate: the seam belongs at the native boundary,
 * which is the only place a host machine genuinely cannot follow, and it is
 * the same seam `src/facade.test.ts` uses inside the library.
 *
 * WHAT THIS FILE CANNOT ESTABLISH. There is no JSI host object in Node, so
 * nothing here proves the bridge works. Three steps are not stubbed and are
 * asserted to fail here for that reason, and the list is
 * `UNREACHABLE_IN_NODE` rather than this sentence: it held two ids when
 * this was written and holds three now, and the package README already said
 * three.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { FLOW_STEPS, type FlowStep } from './steps'
import {
  runCall,
  runFlow,
  runSignal,
  runSigningIdentity,
  type Outcome,
  type RunContext,
} from './flowRunners'

/**
 * How long after `probeWithObserver` resolves the fake observer callback is
 * delivered. Larger than `interop/suite.ts`'s 20 ms poll interval so the
 * bounded wait genuinely has to poll, and far smaller than its 10 s budget
 * so a passing run costs about a tenth of a second.
 */
const SIGNAL_DELAY_MS = 60

/**
 * Set by the fake binding just before it resolves, read by the tests.
 *
 * It records the precondition every step 3 assertion below rests on: at the
 * instant `probeWithObserver`'s promise resolved, the observer callback had
 * NOT been delivered. Without that, a green step 3 would prove nothing,
 * because a callback that had already arrived would be read correctly by a
 * step that waits and by a step that does not.
 */
let signalDeliveredBeforeResolve = true
let signalFired = false

/**
 * Whether the faked native `bootstrapIdentity` refuses, and with what.
 *
 * Step 6's card asserts that the library refuses to mint a signing identity
 * before any key query has been answered, and reports the refusal by kind.
 * That is a claim about the *facade*, the same class as step 4's typed
 * error, so it is faked at the same seam and in the same way: the mock
 * throws the real generated error class and the real `toCryptoError` decides
 * what kind reaches the runner.
 *
 * Settable so the card can be made to face the outcome it must reject: a
 * bootstrap that is served when nothing has asked the server. See the second
 * test in that block.
 */
let bootstrapRefuses = true

vi.mock('react-native-matrix-crypto/src/generated/matrix_crypto', async importOriginal => {
  const actual =
    await importOriginal<typeof import('react-native-matrix-crypto/src/generated/matrix_crypto')>()
  return {
    ...actual,
    // The three facts the machine reports about the account, in the state
    // this app is really in: it has no homeserver, so nothing has been
    // asked and nothing is known.
    identityStatus: vi.fn(async () => ({
      accountKeysFetched: false,
      identityKnown: false,
      privateKeysHeld: false,
    })),
    bootstrapIdentity: vi.fn(async () => {
      if (bootstrapRefuses) {
        throw new actual.MachineFfiError.AccountKeysNotFetched()
      }
    }),
    probeWithObserver: vi.fn(
      async (input: string, payload: ArrayBuffer, observer: { onSignal(s: { kind: string; detail: string }): void }) => {
        // The real core rejects empty input with `ProbeError::Rejected`
        // (rust/matrix-crypto-core/src/probe.rs). Thrown here as the real
        // generated error class, so the facade's own normalisation decides
        // the kind rather than this file asserting one.
        if (input === '') {
          throw new actual.ProbeFfiError.Rejected({ reason: 'input was empty' })
        }
        // Scheduled, not called: this is the race the bounded wait in step 2
        // exists to absorb. On Android release builds the observer loses it
        // about half the time.
        signalFired = false
        setTimeout(() => {
          signalFired = true
          observer.onSignal({ kind: 'probe_started', detail: 'fake binding' })
        }, SIGNAL_DELAY_MS)
        signalDeliveredBeforeResolve = signalFired
        return {
          echoed: input,
          payload: new Uint8Array(new Uint8Array(payload)).reverse().buffer,
          coreVersion: '0.0.0-host-fake',
        }
      },
    ),
  }
})

function freshContext(): RunContext {
  return { unsubscribe: null, probeSignals: [], storeDir: '/tmp/example-app-host-test' }
}

function recorder() {
  const outcomes: Partial<Record<FlowStep['id'], Outcome>> = {}
  return {
    outcomes,
    commit: (id: FlowStep['id'], outcome: Outcome) => {
      outcomes[id] = outcome
    },
  }
}

beforeEach(() => {
  signalDeliveredBeforeResolve = true
  signalFired = false
  bootstrapRefuses = true
})

describe('step 3 reads a value step 2 has finished writing', () => {
  it('reports the signal when the observer lands after step 2 resolved', async () => {
    const ctx = freshContext()
    const { outcomes, commit } = recorder()

    await runCall(ctx, commit)
    await runSignal(ctx, commit)

    // The precondition. If this is ever true, the test below has stopped
    // testing anything.
    expect(signalDeliveredBeforeResolve).toBe(false)
    expect(outcomes.call?.status).toBe('ok')
    expect(outcomes.signal).toEqual({ status: 'ok', headline: 'Received signal: probe_started' })
  })

  it('reports no signal when there is genuinely none, and does so without waiting', async () => {
    // The negative control for the test above, and the proof that step 3
    // does no waiting of its own. `runSignal` is called on a context no
    // `runCall` has touched, so nothing is outstanding and nothing is
    // coming. If it had a bounded wait of its own it would sit out
    // `interop/suite.ts`'s 10 s budget and blow vitest's 5 s per-test
    // timeout instead of returning here.
    const ctx = freshContext()
    const { outcomes, commit } = recorder()

    await runSignal(ctx, commit)

    expect(outcomes.signal).toEqual({ status: 'unexpected', headline: 'Unexpected: no signal received' })
  })

  it('deduplicates a kind delivered twice into one row', async () => {
    // A dev-mode double mount can leave an earlier instance's call resolving
    // into the current context. Harmless, but it must not print the kind
    // twice.
    const ctx = freshContext()
    ctx.probeSignals = ['probe_started', 'probe_started']
    const { outcomes, commit } = recorder()

    await runSignal(ctx, commit)

    expect(outcomes.signal).toEqual({ status: 'ok', headline: 'Received signal: probe_started' })
  })
})

describe('step 2 reports its own round trip', () => {
  it('echoes the input back and reverses the bytes', async () => {
    const ctx = freshContext()
    const { outcomes, commit } = recorder()

    await runCall(ctx, commit)

    expect(outcomes.call?.status).toBe('ok')
    expect(outcomes.call?.headline).toContain('Echoed "hello"')
    expect(outcomes.call?.detail).toContain('[3, 2, 1]')
  })

  it('starts each run from an empty log rather than accumulating', async () => {
    const ctx = freshContext()
    ctx.probeSignals = ['probe_started', 'probe_started', 'probe_started']
    const { commit } = recorder()

    await runCall(ctx, commit)

    expect(ctx.probeSignals).toEqual(['probe_started'])
  })
})

/**
 * The steps this runner cannot reach, and why.
 *
 * Step 1 subscribes, and the first subscriber installs this process's native
 * observer across the boundary. Step 5 creates a crypto machine and reads
 * its identity keys. Step 7 creates a group session, encrypts one payload
 * and decrypts the result. All three need the JSI host object, which no Node
 * process has, so all three report `unexpected` here.
 *
 * Asserted rather than skipped. A hole nobody names is how a suite comes to
 * look like it covers a screen it does not, and the whole reason this file
 * exists is that this package looked covered while covering nothing. If any
 * of these ever passes here, something has stubbed the native boundary and
 * this file's claim about what it proves has to be rewritten.
 */
const UNREACHABLE_IN_NODE: FlowStep['id'][] = [
  'subscribe',
  'identity',
  // Step 7 creates a real group session, encrypts one payload with it and
  // decrypts the result. There is no crypto machine here, so it reports
  // `unexpected`.
  //
  // **Deliberately not faked, unlike step 6 above it.** Stubbing the native
  // encrypt and decrypt would make this file report a `senderVerification`
  // this file itself wrote, and that is precisely the shape
  // `cardClaims.test.ts` opens by refusing: a claim about the library
  // checked against a fake of the library is not checked at all. Worse here
  // than anywhere, because the value in question is the one the library's
  // own documentation spends pages warning must never be manufactured. What
  // the card actually reports is proven where a real event exists: on a
  // device, and in
  // `rust/matrix-crypto-core/tests/level_two_identity.rs` against a real
  // homeserver.
  'senderCheck',
]

describe('the whole flow, in the order the screen runs it', () => {
  it('settles every step, and only the ones that need a device report unexpected', async () => {
    const ctx = freshContext()
    const { outcomes, commit } = recorder()

    await runFlow(ctx, commit)

    expect(signalDeliveredBeforeResolve).toBe(false)
    for (const step of FLOW_STEPS) {
      const expected = UNREACHABLE_IN_NODE.includes(step.id) ? 'unexpected' : 'ok'
      expect(outcomes[step.id], `step "${step.id}"`).toBeDefined()
      expect(outcomes[step.id]?.status, `step "${step.id}": ${outcomes[step.id]?.headline}`).toBe(expected)
    }
  })

  it('runs the steps in the order the cards are shown in', async () => {
    const seen: FlowStep['id'][] = []
    await runFlow(freshContext(), id => {
      seen.push(id)
    })

    expect(seen).toEqual(FLOW_STEPS.map(step => step.id))
  })
})

describe('step 6 reports the signing-identity gate refusing', () => {
  it('reports ok, and names the three facts the refusal only means anything beside', async () => {
    const { outcomes, commit } = recorder()

    await runSigningIdentity(freshContext(), commit)

    expect(outcomes.signingIdentity?.status, outcomes.signingIdentity?.headline).toBe('ok')
    expect(outcomes.signingIdentity?.headline).toContain('"account_keys_not_fetched"')
    // With `accountKeysFetched` false, `identityKnown` false means "nobody
    // has asked", not "the account has none". A card that printed only the
    // second would be printing the one reading that authorises minting.
    expect(outcomes.signingIdentity?.detail).toContain('accountKeysFetched: false')
    expect(outcomes.signingIdentity?.detail).toContain('identityKnown: false')
    expect(outcomes.signingIdentity?.detail).toContain('privateKeysHeld: false')
  })

  it('reports unexpected when the bootstrap is served with nothing having asked the server', async () => {
    // The outcome the card exists to notice. A library that minted here
    // would replace whatever identity the account already had, and the
    // damage is to other people's trust rather than to anything this
    // process can afterwards detect. Without this test, a card that had
    // silently started passing on a served bootstrap would look identical
    // to one reporting a refusal.
    bootstrapRefuses = false
    const { outcomes, commit } = recorder()

    await runSigningIdentity(freshContext(), commit)

    expect(outcomes.signingIdentity?.status).toBe('unexpected')
    expect(outcomes.signingIdentity?.headline).toContain('minted')
  })
})

describe('step 4 makes a bad call on purpose', () => {
  it('normalises the core rejection into kind "rejected"', async () => {
    const ctx = freshContext()
    const { outcomes, commit } = recorder()

    await runFlow(ctx, commit)

    expect(outcomes.typedError?.status).toBe('ok')
    expect(outcomes.typedError?.headline).toContain('"rejected"')
  })
})
