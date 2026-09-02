/**
 * The camera walkthrough's own arc, run on a host machine.
 *
 * WHAT THIS ESTABLISHES. That the screen a person holds a phone in front of
 * drives the published surface in the right order, draws the grid that
 * surface handed it, asks for a confirmation at the one moment the protocol
 * asks for one, and reports a refusal as a refusal. Those are the parts of
 * the walkthrough a person could get wrong by reading them, and until this
 * file the only way to check any of them was to hold a phone.
 *
 * WHAT IS FAKED, AND WHERE. Exactly one thing: the generated binding, which
 * is the single layer in the chain that reaches Rust. `facade.ts` is the
 * shipped one, so the payload this test sees as a `Uint8Array` was converted
 * from an `ArrayBuffer` by the same line that converts it on a device, and
 * the module array is passed through the same destructuring. The seam is at
 * the native boundary for `flowRunners.test.ts`'s reason: it is the only
 * place a host genuinely cannot follow.
 *
 * WHAT THIS FILE CANNOT ESTABLISH, AND IT IS THE WHOLE POINT OF THE
 * WALKTHROUGH. That a camera reads what gets drawn. No test can: it needs a
 * person, a second client and a lens. `level-two/run_camera_proof.py` sets
 * that up and then stops. What this file rules out is everything else going
 * wrong first.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import * as generated from 'react-native-matrix-crypto/src/generated/matrix_crypto'
import { startScannedCodeRun, type HttpResult, type ScannedCodeState } from './scannedCodeRunner'

/** The mode byte a self-verification from an established device carries. */
const MODE_SELF_TRUSTED = 0x01

/**
 * A payload shaped exactly as the protocol fixes it, so the assertions below
 * are about a real layout rather than about a blob this file invented: six
 * header bytes, the version, the mode, a big-endian identifier length, the
 * identifier, two keys and a shared secret.
 */
function samplePayload(flowId: string): ArrayBuffer {
  const id = new TextEncoder().encode(flowId)
  const bytes = new Uint8Array(6 + 1 + 1 + 2 + id.length + 32 + 32 + 16)
  bytes.set(new TextEncoder().encode('MATRIX'), 0)
  bytes[6] = 0x02
  bytes[7] = MODE_SELF_TRUSTED
  bytes[8] = (id.length >> 8) & 0xff
  bytes[9] = id.length & 0xff
  bytes.set(id, 10)
  for (let at = 10 + id.length; at < bytes.length; at += 1) bytes[at] = at & 0xff
  return bytes.buffer
}

/** A tiny, honest symbol: the finder pattern in the top row, `true` is dark. */
function sampleModules(width: number): boolean[] {
  const modules = new Array<boolean>(width * width).fill(false)
  for (let x = 0; x < 7; x += 1) modules[x] = true
  for (let x = width - 7; x < width; x += 1) modules[x] = true
  return modules
}

const FLOW = 'flow-under-test'
const PEER_FLOW = 'flow-from-peer'
const CODE_WIDTH = 45

/**
 * The native side, faked: a verification that advances one stage each time
 * it is asked, exactly as a real one advances as syncs arrive.
 */
const native = {
  stages: [] as string[],
  codeThrows: null as Error | null,
  confirmed: false,
  capabilitiesOffered: null as { canShow: boolean; canScan: boolean } | null,
  requests: [] as Array<{ id: string; kind: string; body: string }>,
  syncsReceived: 0,
  accepted: [] as string[],
  cancelled: [] as string[],
  cancelCalls: 0,
  // How long each stage read parks, in real milliseconds. Zero for every
  // test but the unanswered-ask race, whose deadline must have certainly
  // passed by the loop's first read; a real sync's news arrives no faster.
  readDelayMs: 0,
  observer: null as { onSignal: (signal: unknown) => void } | null,
}

vi.mock('react-native-matrix-crypto/src/generated/matrix_crypto', async importOriginal => {
  const original =
    await importOriginal<typeof import('react-native-matrix-crypto/src/generated/matrix_crypto')>()
  return {
    ...original,
    createCryptoMachine: vi.fn(async () => undefined),
    offerCodes: vi.fn((capabilities: { canShow: boolean; canScan: boolean }) => {
      native.capabilitiesOffered = capabilities
    }),
    requestSelfVerification: vi.fn(async () => FLOW),
    acceptVerification: vi.fn(async (id: string) => {
      // The real library refuses a flow this side opened: it is already
      // agreed to, and the call would end the run. Model that refusal so
      // the runner's `!openedHere` guard cannot be dropped without a test
      // failing; any other id is a peer's flow, accepted as the real
      // library accepts it.
      if (id === FLOW) throw new original.MachineFfiError.WrongStage()
      native.accepted.push(id)
    }),
    cancelVerification: vi.fn(async (id: string) => {
      native.cancelCalls += 1
      // The real library refuses to cancel a flow whose stage has moved on
      // from `requested`: by the time a deadline cancel lands, the peer may
      // already have answered. Model that refusal so the runner's
      // `wrong_stage` re-read cannot be dropped without a test failing; a
      // flow genuinely still waiting at `requested` is cancelled, as the
      // real library cancels it.
      if (native.stages[0] !== 'Requested') throw new original.MachineFfiError.WrongStage()
      native.cancelled.push(id)
    }),
    verificationStage: vi.fn(async () => {
      // A test that needs the wall clock to have moved before this read
      // returns parks a real delay here (see `native.readDelayMs`); the
      // suite runs on real timers, and the deadline it underpins is the
      // same one a real 180 s budget drives.
      if (native.readDelayMs > 0) {
        await new Promise<void>(resolve => setTimeout(resolve, native.readDelayMs))
      }
      // The last stage repeats once the list runs out, which is what a flow
      // parked at `done` or `cancelled` really does.
      const next = native.stages.length > 1 ? native.stages.shift() : native.stages[0]
      // The REAL generated enum member, never the string the surface
      // publishes. Returning the string looks right and is not: the facade
      // maps the enum to the union, an unmapped value comes back
      // `undefined`, and the walkthrough then waits for a stage it can
      // never see. That is what the first version of this file did, and it
      // exhausted the heap rather than failing an assertion.
      return original.VerificationStage[
        next as keyof typeof original.VerificationStage
      ] as never
    }),
    verificationCode: vi.fn(async (id: string) => {
      if (native.codeThrows) throw native.codeThrows
      return { payload: samplePayload(id), width: CODE_WIDTH, modules: sampleModules(CODE_WIDTH) }
    }),
    confirmScan: vi.fn(async () => {
      native.confirmed = true
    }),
    takeOutgoingRequests: vi.fn(async () => {
      const batch = native.requests
      native.requests = []
      return batch
    }),
    markRequestSent: vi.fn(async () => undefined),
    markRequestFailed: vi.fn(async () => undefined),
    receiveSyncChanges: vi.fn(async () => {
      native.syncsReceived += 1
    }),
    setCryptoObserver: vi.fn((installed: { onSignal: (signal: unknown) => void }) => {
      native.observer = installed
    }),
    clearCryptoObserver: vi.fn(() => {
      native.observer = null
    }),
  }
})

/** A homeserver that answers a sync and accepts anything posted to it. */
const http = vi.fn(async (method: string, url: string): Promise<HttpResult> => {
  if (method === 'GET' && url.includes('/sync')) {
    return { status: 200, text: JSON.stringify({ next_batch: 's1', to_device: { events: [] } }) }
  }
  return { status: 200, text: '{}' }
})

const plan = {
  homeserver: 'http://127.0.0.1:1',
  userId: '@somebody:example.org',
  deviceId: 'DEVICE1',
  accessToken: 'not-a-real-token',
}

/** Runs with no real delay, so a whole arc costs milliseconds. */
const noSleep = () => Promise.resolve()

async function drive(stages: string[]): Promise<{
  states: ScannedCodeState[]
  final: ScannedCodeState
}> {
  native.stages = [...stages]
  const states: ScannedCodeState[] = []
  const run = startScannedCodeRun(plan, '/tmp/store', http, state => states.push({ ...state }), {
    sleep: noSleep,
  })
  // The person's two decisions, made immediately: nothing here is testing
  // how long a human takes.
  run.askOtherDevices()
  run.confirm()
  await run.finished
  return { states, final: states[states.length - 1] }
}

beforeEach(() => {
  native.stages = []
  native.codeThrows = null
  native.confirmed = false
  native.capabilitiesOffered = null
  native.requests = []
  native.syncsReceived = 0
  native.accepted = []
  native.cancelled = []
  native.cancelCalls = 0
  native.readDelayMs = 0
  native.observer = null
  http.mockClear()
})

/**
 * Delivers a peer's verification request through the installed observer,
 * exactly as a sync would: the runner subscribes on its first await, a few
 * microtasks after start, and this returns once it is listening.
 */
async function firePeerRequest(flowId: string): Promise<void> {
  while (native.observer === null) await Promise.resolve()
  native.observer.onSignal(
    new generated.CryptoSignal.VerificationRequested({
      user: '@peer:example.org',
      deviceId: 'PEERDEVICE',
      verificationId: flowId,
    }),
  )
}

describe('the camera walkthrough', () => {
  // The assertion is the exact record, not that a call happened. This app
  // draws a code and has no camera: `canScan: true` here would be a lie told
  // to the other client, and it is the lie the camera run actually hit. A
  // real Element was told this side could read a code, chose the mode where
  // it shows one and this side reads it, and the flow died waiting for a
  // camera that does not exist. Asserting only that codes were offered would
  // pass on that.
  it('announces that it can show a code and cannot scan one', async () => {
    await drive(['Requested', 'Ready', 'CodeScanned', 'Done'])
    expect(native.capabilitiesOffered).toEqual({ canShow: true, canScan: false })
  })

  it('draws the grid the published surface handed it, not a re-encoding', async () => {
    const { states } = await drive(['Requested', 'Ready', 'CodeScanned', 'Done'])
    const withCode = states.find(state => state.code !== undefined)
    expect(withCode).toBeDefined()
    const code = withCode!.code!
    expect(code.width).toBe(CODE_WIDTH)
    expect(code.modules).toHaveLength(CODE_WIDTH * CODE_WIDTH)
    // The conversion under test is the facade's, not this file's: the
    // generated binding speaks ArrayBuffer and the surface speaks
    // Uint8Array.
    expect(code.payload).toBeInstanceOf(Uint8Array)
    expect(Array.from(code.payload.slice(0, 6))).toEqual(
      Array.from(new TextEncoder().encode('MATRIX')),
    )
    expect(code.payload[7]).toBe(MODE_SELF_TRUSTED)
    // `true` is dark, and the finder pattern is where the protocol puts it.
    // A screen that drew the negative of this would hand a camera a symbol
    // no scanner reads, which is the defect the core's own tests caught.
    expect(code.modules.slice(0, 7)).toEqual([true, true, true, true, true, true, true])
    expect(code.modules[7]).toBe(false)
  })

  it('asks the person only at the moment the protocol asks, and then confirms', async () => {
    const { states, final } = await drive(['Requested', 'Ready', 'CodeScanned', 'Done'])
    // Asked for at that stage and at no other. Written this way round on
    // purpose: an earlier version asked only whether the states at `ready`
    // were free of it, which a screen that offered the button at every
    // stage still passed. Sabotaging the condition to `if (true)` is what
    // showed that, and this is the assertion that catches it.
    const asking = states.filter(state => state.awaitingConfirmation)
    expect(asking.length).toBeGreaterThan(0)
    expect(asking.every(state => state.stage === 'code-scanned')).toBe(true)
    expect(native.confirmed).toBe(true)
    expect(final.headline).toBe('Verified.')
    expect(final.finished).toBe(true)
    expect(final.failed).toBe(false)
    // A finished run stops drawing the code: leaving a used one on screen
    // invites a second scan of a flow that is over.
    expect(final.code).toBeUndefined()
  })

  it('reports a refused flow as a refusal rather than as a success', async () => {
    const { final } = await drive(['Requested', 'Ready', 'CodeScanned', 'Cancelled'])
    expect(final.finished).toBe(true)
    expect(final.failed).toBe(true)
    expect(final.headline).toContain('called off')
    expect(final.code).toBeUndefined()
  })

  it('names the refusal when this device cannot show a code at all', async () => {
    // The kind a product actually meets first: an account with no published
    // signing identity has nothing to put in a code.
    const refusal = Object.assign(new Error('identity not known'), { name: 'IdentityNotKnown' })
    native.codeThrows = refusal
    const { final } = await drive(['Requested', 'Ready', 'Ready', 'Ready'])
    expect(final.failed).toBe(true)
    expect(final.headline).toContain('cannot show a code')
  })

  it('drives the pump, so nothing the library handed over is dropped', async () => {
    native.requests = [
      { id: 'r1', kind: 'keys_upload', body: '{}' },
      { id: 'r2', kind: 'to_device', body: JSON.stringify({ event_type: 'm.key.verification.ready' }) },
    ]
    await drive(['Requested', 'Ready', 'CodeScanned', 'Done'])
    const posted = http.mock.calls.filter(call => call[0] !== 'GET').map(call => String(call[1]))
    expect(posted.some(url => url.endsWith('/_matrix/client/v3/keys/upload'))).toBe(true)
    expect(
      posted.some(url => url.includes('/sendToDevice/m.key.verification.ready/r2')),
    ).toBe(true)
  })

  it('feeds every sync it performs to the library', async () => {
    await drive(['Requested', 'Ready', 'CodeScanned', 'Done'])
    expect(native.syncsReceived).toBeGreaterThan(0)
  })

  // Every test above drives the ask branch. This one drives the accept
  // branch, which no test reached before: the observer never fired and
  // `native.accepted` was never asserted.
  it('accepts a verification the peer opened, with no ask from this side', async () => {
    native.stages = ['Requested', 'Ready', 'CodeScanned', 'Done']
    const states: ScannedCodeState[] = []
    const run = startScannedCodeRun(plan, '/tmp/store', http, state => states.push({ ...state }), {
      sleep: noSleep,
    })
    await firePeerRequest(PEER_FLOW)
    await run.finished
    // Accepted with the peer's own flow id, and only the peer's.
    expect(native.accepted).toEqual([PEER_FLOW])
    // The run then reaches the code/ready stage per the existing fake.
    const withCode = states.find(state => state.stage === 'ready' && state.code !== undefined)
    expect(withCode).toBeDefined()
    const final = states[states.length - 1]
    expect(final.finished).toBe(true)
    expect(final.failed).toBe(false)
  })

  it('fails the run on a deadline rather than wait on an unanswered ask forever', async () => {
    native.stages = ['Requested']
    const states: ScannedCodeState[] = []
    const run = startScannedCodeRun(plan, '/tmp/store', http, state => states.push({ ...state }), {
      sleep: noSleep,
      // A budget nobody could answer in, injected rather than faked: the
      // suite runs on real timers, and the check this proves is the same
      // one a real 180 s budget drives.
      unansweredRequestMs: 10,
    })
    run.askOtherDevices()
    await run.finished
    const final = states[states.length - 1]
    expect(final.finished).toBe(true)
    expect(final.failed).toBe(true)
    expect(final.headline).toContain('unanswered')
    // The flow this side opened is called off, so the peer's banner does
    // not outlive the run.
    expect(native.cancelled).toEqual([FLOW])
  })

  // The race the deadline's `wrong_stage` handling exists for: the stage is
  // read at `requested`, and between that read and the cancel the peer
  // answers, so the cancel is refused and the flow must not be reported as
  // unanswered. Two `Requested` entries feed the phase-2 preamble read and
  // the loop's first read; the script then moves to `ready`, exactly as the
  // flow does once the peer accepts.
  it('rides out the peer answering in the gap the deadline cancel targets', async () => {
    native.stages = ['Requested', 'Requested', 'Ready', 'Ready', 'CodeScanned', 'Done']
    // The accept takes real time to arrive, as a sync would: park each
    // stage read so the deadline has certainly passed by the loop's first
    // read, and the race lands on that read rather than on whichever later
    // one the wall clock happens to reach.
    native.readDelayMs = 20
    const states: ScannedCodeState[] = []
    const run = startScannedCodeRun(plan, '/tmp/store', http, state => states.push({ ...state }), {
      sleep: noSleep,
      // A budget nobody could answer in, injected rather than faked: the
      // suite runs on real timers, and the check this proves is the same
      // one a real 180 s budget drives.
      unansweredRequestMs: 10,
    })
    run.askOtherDevices()
    await run.finished
    const final = states[states.length - 1]
    // The cancel was attempted, and refused with the real `WrongStage`
    // because the scripted flow had moved on since the read above.
    expect(native.cancelCalls).toBe(1)
    expect(native.cancelled).toEqual([])
    // The runner took the refusal as the race it is: no unanswered failure
    // was published, and the loop's ordinary stage handling carried the run
    // to `ready` with a code and on to a success.
    expect(states.some(state => state.headline.includes('unanswered'))).toBe(false)
    expect(states.some(state => state.stage === 'ready' && state.code !== undefined)).toBe(true)
    expect(final.finished).toBe(true)
    expect(final.failed).toBe(false)
    expect(final.headline).toBe('Verified.')
  })
})
