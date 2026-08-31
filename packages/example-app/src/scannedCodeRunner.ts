/**
 * The one claim no in-process test can make: that a foreign scanner reads
 * the symbol this library renders, and that the flow then completes.
 *
 * # What this drives, and why it is not a fixture
 *
 * Every call below is the published TypeScript surface, and the squares this
 * produces come from `getVerificationCode`'s own `modules`. Nothing here
 * draws a picture of a code; it draws the code. That matters more than it
 * sounds: as of this milestone **no test anywhere in `packages/` had ever
 * carried a real payload byte across the boundary.** The QR surface's twelve
 * TypeScript cases all talk to a mock, so the join between a well-driven core
 * and a well-tested facade had never been exercised on real bytes. A person
 * holding a phone in front of this screen is the first thing that does.
 *
 * # Deliberately free of `react` and `react-native`
 *
 * For `flowRunners.ts`'s reason, at more length in its header: a module that
 * imports either cannot be loaded by a Node process, and the only way anyone
 * checks it is then by holding a phone. `ScannedCodeWalkthrough.tsx` keeps
 * every line that touches a component, and `scannedCodeRunner.test.ts` calls
 * these exact functions on a host.
 *
 * # The transport is injected; nothing else is
 *
 * The library performs no request, by design, so a run needs the product's
 * own HTTP. That one function arrives as a parameter, which is also what
 * lets the host test drive a whole verification against a fake homeserver
 * without a device. Everything else -- the machine, the pump, the code, the
 * stage -- is the shipped library.
 */
import {
  acceptVerification,
  confirmScan,
  createCryptoMachine,
  encryptionSlice,
  getVerificationCode,
  getVerificationStage,
  isCryptoError,
  markRequestFailed,
  markRequestSent,
  offerScannableCodes,
  onCryptoSignal,
  receiveSyncChanges,
  requestSelfVerification,
  takeOutgoingRequests,
  type CryptoSignal,
  type ScannableCode,
  type Unsubscribe,
  type VerificationStage,
} from 'react-native-matrix-crypto'

/**
 * Where a run has got to, in the words a person on the screen needs.
 *
 * One flat shape rather than a discriminated union: every field is drawn by
 * the same component, and a union would make the renderer branch on states
 * whose only difference is which line of prose to show.
 */
export interface ScannedCodeState {
  /** What the person should be doing, in one line. */
  headline: string
  /** The longer explanation under it, when there is one. */
  detail?: string
  /** The code to draw, once there is one. `undefined` means draw nothing. */
  code?: ScannableCode
  /** The flow, once one exists. Shown so a log line can be matched to it. */
  verificationId?: string
  /** The stage the library reports, verbatim. */
  stage?: VerificationStage
  /** Whether the person is being asked to confirm a scan right now. */
  awaitingConfirmation: boolean
  /** Whether the run is over, either way. */
  finished: boolean
  /** True when it is over and did not verify anything. */
  failed: boolean
}

export interface ScannedCodePlan {
  homeserver: string
  userId: string
  deviceId: string
  accessToken: string
}

export interface HttpResult {
  status: number
  text: string
}

export type HttpJson = (
  method: string,
  url: string,
  options?: { token?: string; body?: string; timeoutMs?: number },
) => Promise<HttpResult>

export type Publish = (state: ScannedCodeState) => void

/**
 * How long between polls of the flow's stage while a code is on screen.
 *
 * Short enough that the person does not wonder whether the screen is alive,
 * long enough that a phone showing a code for a minute is not doing anything
 * hot. The stage is read after every sync anyway; this only bounds the gap
 * when a sync returns early.
 */
const STAGE_POLL_MS = 400

/** How long a single long-polled `/sync` asks the homeserver to wait. */
const SYNC_TIMEOUT_MS = 5_000

/**
 * The endpoint each `kind` of outgoing request belongs to.
 *
 * The product owns transport, so the product owns this mapping, and a `kind`
 * with no endpoint is a finding rather than something to skip: skipping one
 * silently is how the whole "the library hands you requests and you must
 * send them" rule was got wrong the first time. `levelTwoTransport.ts` says
 * the same thing at more length for the suite's own copy.
 */
export function endpointFor(kind: string): { method: string; path: string } {
  switch (kind) {
    case 'keys_upload':
      return { method: 'POST', path: '/_matrix/client/v3/keys/upload' }
    case 'keys_query':
      return { method: 'POST', path: '/_matrix/client/v3/keys/query' }
    case 'keys_claim':
      return { method: 'POST', path: '/_matrix/client/v3/keys/claim' }
    case 'signature_upload':
      return { method: 'POST', path: '/_matrix/client/v3/keys/signatures/upload' }
    case 'signing_keys_upload':
      return { method: 'POST', path: '/_matrix/client/v3/keys/device_signing/upload' }
    // `to_device` is deliberately absent: its path carries the event type and
    // the transaction id, both of which live in the request the library
    // handed over, so `pump` builds it there rather than passing them in
    // here for this function to reassemble.
    default:
      throw new Error(`no endpoint for an outgoing request of kind ${kind}`)
  }
}

/**
 * Drains the pump once and posts everything it handed over.
 *
 * Every request is reported back, success or failure: a request the library
 * handed out and never heard about again parks the flow it belongs to, which
 * is the failure this call exists to prevent.
 */
export async function pump(plan: ScannedCodePlan, http: HttpJson): Promise<number> {
  const requests = await takeOutgoingRequests()
  for (const request of requests) {
    let path: string
    let method: string
    if (request.kind === 'to_device') {
      // The event type lives in the body the library built, which is also
      // the only place it is written down.
      const body = JSON.parse(request.body) as { event_type?: string }
      const eventType = body.event_type ?? 'm.room.encrypted'
      method = 'PUT'
      path = `/_matrix/client/v3/sendToDevice/${encodeURIComponent(eventType)}/${encodeURIComponent(request.id)}`
    } else {
      const endpoint = endpointFor(request.kind)
      method = endpoint.method
      path = endpoint.path
    }
    const response = await http(method, `${plan.homeserver}${path}`, {
      token: plan.accessToken,
      body: request.body,
    })
    if (response.status >= 200 && response.status < 300) {
      await markRequestSent(request.id, response.text)
    } else {
      await markRequestFailed(request.id, response.status)
    }
  }
  return requests.length
}

/** One `/sync`, fed to the library, returning the next batch token. */
export async function syncOnce(
  plan: ScannedCodePlan,
  http: HttpJson,
  since: string,
): Promise<string> {
  const query = since === '' ? `timeout=${SYNC_TIMEOUT_MS}` : `timeout=${SYNC_TIMEOUT_MS}&since=${encodeURIComponent(since)}`
  const response = await http('GET', `${plan.homeserver}/_matrix/client/v3/sync?${query}`, {
    token: plan.accessToken,
    timeoutMs: SYNC_TIMEOUT_MS + 10_000,
  })
  if (response.status !== 200) throw new Error(`sync returned HTTP ${response.status}`)
  const body = JSON.parse(response.text) as Record<string, unknown>
  await receiveSyncChanges(encryptionSlice(body))
  await pump(plan, http)
  return typeof body.next_batch === 'string' ? body.next_batch : since
}

/**
 * A run, from a cold machine to a completed verification, with the person's
 * two decisions in the middle.
 *
 * Returns a handle rather than a promise of the end: the screen has to stay
 * responsive, and the one thing the person does -- saying that the other
 * device really did scan -- arrives from a button rather than from here.
 */
export interface ScannedCodeRun {
  /** Resolves when the run is over, either way. */
  finished: Promise<void>
  /**
   * Called by the confirm button. Safe to call when nothing is waiting.
   *
   * A confirmation set before anyone has scanned is **held**, not dropped,
   * and acted on the moment the flow reaches that stage. On the screen that
   * cannot happen, because the button is only rendered while a confirmation
   * is being asked for; it is written this way so the host test can make the
   * person's decision without racing the flow.
   */
  confirm: () => void
  /** Asks this account's other devices to verify, from this side. */
  askOtherDevices: () => void
  /** Stops the loop and drops the signal subscription. */
  stop: () => void
}

export function startScannedCodeRun(
  plan: ScannedCodePlan,
  storeDir: string,
  http: HttpJson,
  publish: Publish,
  options: { sleep?: (ms: number) => Promise<void> } = {},
): ScannedCodeRun {
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms)))

  let state: ScannedCodeState = {
    headline: 'Starting…',
    awaitingConfirmation: false,
    finished: false,
    failed: false,
  }
  const update = (next: Partial<ScannedCodeState>) => {
    state = { ...state, ...next }
    publish(state)
  }

  let stopped = false
  let confirmRequested = false
  let askRequested = false
  let unsubscribe: Unsubscribe | null = null
  let announced: string | null = null

  const finished = (async () => {
    try {
      await createCryptoMachine({
        userId: plan.userId,
        deviceId: plan.deviceId,
        storePath: `${storeDir}/scanned-code`,
        storePassphrase: 'scanned-code-walkthrough',
      })

      // THE SWITCH. Without it this build announces the short string alone,
      // no code is ever negotiated, and the other client offers no scanner.
      offerScannableCodes(true)

      unsubscribe = onCryptoSignal((signal: CryptoSignal) => {
        if (signal.kind === 'verification_requested' && announced === null) {
          announced = signal.verificationId
        }
      })

      update({ headline: 'Publishing this device’s keys…' })
      await pump(plan, http)

      update({
        headline: 'Waiting for your other client to start a verification.',
        detail:
          'In Element, open Settings, Sessions, this session, and choose to verify it. ' +
          'Or press the button below to ask from this side instead.',
      })

      let since = ''
      // ---- phase 1: a flow exists ------------------------------------
      while (!stopped && announced === null) {
        if (askRequested) {
          askRequested = false
          announced = await requestSelfVerification()
          await pump(plan, http)
          update({
            headline: 'Asked your other devices to verify.',
            detail: 'Accept it there; this screen will show the code once it does.',
          })
          break
        }
        since = await syncOnce(plan, http, since)
      }
      if (stopped || announced === null) return

      const flow = announced
      update({ verificationId: flow })

      // ---- phase 2: agree to it, and show the code -------------------
      // `acceptVerification` is the call that answers a flow the other side
      // opened. A flow this side opened is already agreed to, and the call
      // would refuse it, so it is made only for the first case.
      let stage = await getVerificationStage(flow)
      if (stage === 'requested') {
        await acceptVerification(flow)
        await pump(plan, http)
      }

      let code: ScannableCode | undefined
      while (!stopped && code === undefined) {
        stage = await getVerificationStage(flow)
        update({ stage })
        // Every stage that is over ends the loop, not just the refusal.
        // A loop that waits only for the one ending it expects spins for
        // ever on any other, and this one runs on a phone in a person's
        // hand.
        if (stage === 'cancelled' || stage === 'done') {
          update({
            headline:
              stage === 'done'
                ? 'The verification finished before this device showed a code.'
                : 'The verification was called off.',
            detail: 'Start again from the other client.',
            finished: true,
            failed: true,
          })
          return
        }
        if (stage === 'ready' || stage === 'started') {
          try {
            code = await getVerificationCode(flow)
          } catch (error) {
            if (!isCryptoError(error)) throw error
            // `wrong_stage` here is the ordinary case: both sides have
            // agreed but the code is not built yet. Anything else is a
            // refusal a person needs to read, and its `kind` is the whole
            // of what this screen can honestly say about it.
            if (error.kind !== 'wrong_stage') {
              update({
                headline: `This device cannot show a code: ${error.kind}.`,
                detail:
                  'Both accounts need a published signing identity and each side needs ' +
                  'to know the other’s device before a code exists.',
                finished: true,
                failed: true,
              })
              return
            }
          }
        }
        if (code === undefined) since = await syncOnce(plan, http, since)
      }
      if (stopped || code === undefined) return

      update({
        code,
        headline: 'Point the other client’s camera at this code.',
        detail:
          'It is drawn from the bytes this library produced, at the size the ' +
          'protocol fixes. Hold the screen still and fill the viewfinder.',
      })

      // ---- phase 3: the person's one decision ------------------------
      while (!stopped) {
        stage = await getVerificationStage(flow)
        update({ stage })
        if (stage === 'code-scanned') {
          update({
            awaitingConfirmation: true,
            headline: 'The other device says it scanned this code.',
            detail: 'Was that really your other device? Confirm only if it was.',
          })
          if (confirmRequested) {
            confirmRequested = false
            await confirmScan(flow)
            await pump(plan, http)
            update({
              awaitingConfirmation: false,
              headline: 'Confirmed. Waiting for the other device to finish.',
              detail: undefined,
            })
          }
        }
        if (stage === 'done') {
          update({
            headline: 'Verified.',
            detail: 'A camera read what this library drew and the flow completed.',
            awaitingConfirmation: false,
            finished: true,
            failed: false,
            code: undefined,
          })
          return
        }
        if (stage === 'cancelled') {
          update({
            headline: 'The verification was called off.',
            detail: 'Nothing was verified. Start again from the other client.',
            awaitingConfirmation: false,
            finished: true,
            failed: true,
            code: undefined,
          })
          return
        }
        since = await syncOnce(plan, http, since)
        await sleep(STAGE_POLL_MS)
      }
    } catch (error) {
      update({
        headline: 'The run stopped on an error.',
        detail: isCryptoError(error) ? `kind: ${error.kind}` : String(error),
        finished: true,
        failed: true,
      })
    } finally {
      unsubscribe?.()
      unsubscribe = null
    }
  })()

  return {
    finished,
    confirm: () => {
      confirmRequested = true
    },
    askOtherDevices: () => {
      askRequested = true
    },
    stop: () => {
      stopped = true
      unsubscribe?.()
      unsubscribe = null
    },
  }
}
