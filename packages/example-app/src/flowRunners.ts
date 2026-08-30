/**
 * The seven steps of the guided walkthrough, and nothing else.
 *
 * Split out of `GuidedFlow.tsx` so that these functions, the real ones the
 * screen runs, can be run by a test on a host machine. They were private to
 * a file that imports `react-native`, which no Node process can load, so the
 * only way anyone had checked them was by holding a phone. Two defects lived
 * here because of that, and one of them, step 6's, had been on screen since
 * M3 telling every reader that a working function was unimplemented.
 *
 * `flowRunners.test.ts` and `cardClaims.test.ts` import this module and call
 * these exact functions. A transcription of them into a test file was written
 * first and thrown away: a copy passes while the original is broken, which is
 * the failure mode the whole exercise exists to close.
 *
 * Deliberately free of `react` and `react-native` imports. That is not a
 * style preference, it is what makes the module loadable outside a device,
 * and `GuidedFlow.tsx` keeps every line that touches a component.
 */
import {
  asCryptoScopeId,
  bootstrapCrossSigning,
  createCryptoMachine,
  decryptEvent,
  encryptEvent,
  exportSecrets,
  getDeviceIdentityKeys,
  getIdentityStatus,
  isCryptoError,
  onCryptoSignal,
  runProbe,
  shareScopeKey,
  type SenderVerification,
  type Unsubscribe,
} from 'react-native-matrix-crypto'
// The bounded wait only, not the suite: this screen explains the bridge to a
// person and deliberately runs none of the CI-scraped checks. It shares the
// wait because the race it absorbs is a property of the binding rather than
// of the caller. See `awaitSignalDelivery` for what happened when the two
// had separate copies.
import { awaitSignalDelivery } from 'react-native-matrix-crypto/interop/suite'
import {
  DEMO_DEVICE_ID,
  DEMO_SENDER_SCOPE,
  DEMO_USER_ID,
  demoMachineConfig,
} from './cryptoConfig'
import { FLOW_STEPS, type FlowStep } from './steps'
import { nthSignal } from './signalOrder'

export type OutcomeStatus = 'pending' | 'ok' | 'unexpected'

export interface Outcome {
  status: OutcomeStatus
  headline: string
  detail?: string
}

export type Commit = (id: FlowStep['id'], outcome: Outcome) => void

/**
 * Mutable state shared across steps within one run, and carried forward
 * between runs.
 *
 * `unsubscribe` is step 1's subscription to the real, product-facing
 * `onCryptoSignal` channel (spec section 7.3). Its union is open to
 * additions, so this comment names none of the variants: it used to list
 * three, and M3 added a fourth without touching this file.
 * `probeSignals` is unrelated: it is
 * fed only by step 2's own call to `runProbe`, via the per-call callback
 * `runProbe` accepts directly -- never by step 1's listener. The two are
 * deliberately different channels; step 3 explains why.
 *
 * Re-running step 1 replaces the previous subscription rather than
 * stacking a second one on top of it. Re-running step 2 replaces
 * `probeSignals` with that call's own result rather than accumulating
 * across calls -- a fresh call only ever reports its own signal.
 *
 * `probeSignals` is settled by step 2 before step 2 reports, not left to
 * settle on its own afterwards: the observer callback and `runProbe`'s
 * promise reach JavaScript independently, so step 2 waits, bounded, for
 * its own signal before committing its row. Every reader of this array
 * therefore sees a value that is finished being written, which is what
 * lets step 3 read it with no wait of its own.
 */
export interface RunContext {
  unsubscribe: Unsubscribe | null
  probeSignals: string[]
  /**
   * The writable directory this app's own native code supplied (see
   * App.tsx). Step 5 needs it: the crypto machine is what holds this
   * device's identity keys, and creating one needs somewhere to put its
   * store.
   */
  storeDir: string
}

function bytesToText(bytes: Uint8Array): string {
  return `[${Array.from(bytes).join(', ')}]`
}

// Step 1: subscribe to the real crypto-signal channel. Registered before any
// call is made, the way a real consumer would. Nothing arrives on it during
// this walkthrough, and the reason is no longer the one this comment used to
// give. It said no trust logic existed yet; M3 landed it, and the channel
// carries `trust_changed` and `verification_requested` today. What keeps this
// walkthrough silent is that both are produced while a sync is applied
// (`receiveSyncChanges`), and this walkthrough applies none. Step 3
// demonstrates a different channel entirely, not this one.
export async function runSubscribe(ctx: RunContext, commit: Commit): Promise<void> {
  try {
    ctx.unsubscribe?.()
    ctx.unsubscribe = onCryptoSignal(() => {
      // Never invoked today: see the comment above. Kept as a real,
      // running subscription rather than removed, so this step continues
      // to prove `onCryptoSignal` itself works, independent of runProbe.
    })
    commit('subscribe', { status: 'ok', headline: 'Listening for signals' })
  } catch (e) {
    commit('subscribe', { status: 'unexpected', headline: `Unexpected: ${String(e)}` })
  }
}

// Step 2: the round trip. Also captures this call's own diagnostic signal,
// via the callback runProbe accepts directly -- not via step 1's listener --
// and does not report until that signal has settled, so step 3 can be the
// plain read it says it is.
export async function runCall(ctx: RunContext, commit: Commit): Promise<void> {
  try {
    ctx.probeSignals = []
    const report = await runProbe('hello', new Uint8Array([1, 2, 3]), signal => {
      // Counted, not used here: this screen races ProbeHarness's own call on
      // every cold launch, and the count is how ProbeHarness's row says which
      // delivery it timed. See src/signalOrder.ts.
      nthSignal()
      ctx.probeSignals = [...ctx.probeSignals, signal.kind]
    })
    // The promise above and the observer callback reach JavaScript
    // independently, and which lands first is a dispatch detail of the
    // binding rather than something the API promises. On Android release
    // builds the callback loses that race about half the time (see
    // `SIGNAL_WAIT_MS` for the measurement), so a step that read
    // `probeSignals` the moment this promise resolved was reading a value
    // that had not settled yet.
    //
    // The wait belongs here, in the step that made the call, and not in
    // step 3. It is this call's own callback: step 2 is the only step that
    // knows one is outstanding, and waiting here is what lets step 3 stay a
    // step that makes no call and does no waiting. Re-running step 3 alone
    // therefore stays instant and still reports the previous call's settled
    // result, instead of sitting out a budget for a signal nobody asked for.
    //
    // Nothing here adds, removes or moves an emitting call. This screen's
    // one observed `runProbe` is still issued at the same point in the mount
    // sequence and the wait is entirely after it, so the emissions racing on
    // a cold launch are exactly the ones that raced before. `PROBE_SIGNAL_NTH`
    // therefore still measures what it measured: which delivery of the
    // process ProbeHarness's timed callback turned out to be. That is settled
    // by the race and not by this file, which is the whole reason it is a
    // counter that gets reported rather than an order anyone reasons about.
    // See src/signalOrder.ts.
    //
    // Deliberately not judged here. Step 2's claim is that a call reaches
    // Rust and comes back, and that is already settled by this point; the
    // callback is step 3's claim, and step 3 is where a missing one is
    // reported.
    await awaitSignalDelivery(() => ctx.probeSignals.includes('probe_started'))
    commit('call', {
      status: 'ok',
      headline: `Echoed "${report.echoed}" -- core v${report.coreVersion}`,
      detail: `bytes came back reversed: [1, 2, 3] -> ${bytesToText(report.payload)}`,
    })
  } catch (e) {
    commit('call', { status: 'unexpected', headline: `Unexpected: ${String(e)}` })
  }
}

// Step 3: reports whatever step 2's own callback has captured. Making no
// call of its own is the point -- re-running this step in isolation only
// re-reads the current log; it takes a fresh call (step 2) to change what
// it finds. Deliberately NOT step 1's channel: see this step's `why` text
// on screen for what that separation proves.
//
// Reads immediately, and correctly, because step 2 does not return until
// its own signal has landed or run out of budget. That is the whole reason
// the bounded wait lives in step 2: a wait here would have to be spent on
// every isolated re-run, where no call is outstanding and no signal is
// coming, turning an instant true answer into a slow identical one. What
// this step reads is already settled by the time it runs, on every path
// that reaches it: the mount run, "Run all", a step 2 re-run, and a re-run
// of this step on its own.
export async function runSignal(ctx: RunContext, commit: Commit): Promise<void> {
  // Deduplicated for display: a dev-mode double-mount (React or Fast
  // Refresh remounting this screen) can leave an earlier instance's
  // in-flight call still resolving into the current context, which is
  // harmless -- the check below only asks whether the expected kind
  // arrived -- but would otherwise print the same kind twice.
  const seen = [...new Set(ctx.probeSignals)]
  commit(
    'signal',
    seen.includes('probe_started')
      ? { status: 'ok', headline: `Received signal: ${seen.join(', ')}` }
      : { status: 'unexpected', headline: 'Unexpected: no signal received' },
  )
}

// Step 4: deliberately triggers the typed-error path.
export async function runTypedError(_ctx: RunContext, commit: Commit): Promise<void> {
  try {
    await runProbe('', new Uint8Array())
    commit('typedError', { status: 'unexpected', headline: 'Unexpected: resolved instead of rejecting' })
  } catch (e) {
    const kind = isCryptoError(e) ? e.kind : undefined
    commit(
      'typedError',
      kind === 'rejected'
        ? {
            status: 'ok',
            headline: 'Expected error received -- kind: "rejected"',
            detail: 'This is success: it proves a typed error survived the FFI boundary intact.',
          }
        : { status: 'unexpected', headline: `Unexpected error shape: ${String(e)}` },
    )
  }
}

// Step 5: real cryptography.
//
// `createCryptoMachine` first, and with the identity `cryptoConfig` holds
// for the whole app: M2 changed what `getDeviceIdentityKeys` reads. It used
// to mint a throwaway machine per call; it now reports the live machine's
// own keys, and refuses a caller who names a different user or device than
// that machine holds. Creating the machine here is safe alongside
// ProbeHarness doing the same: the library holds one machine per process
// and documents a second create with a matching configuration as resolving
// against the existing one.
export async function runIdentity(ctx: RunContext, commit: Commit): Promise<void> {
  try {
    await createCryptoMachine(demoMachineConfig(ctx.storeDir))
    const keys = await getDeviceIdentityKeys(DEMO_USER_ID, DEMO_DEVICE_ID)
    const wellFormed = keys.curve25519.length === 43 && keys.ed25519.length === 43
    commit('identity', {
      status: wellFormed ? 'ok' : 'unexpected',
      headline: wellFormed
        ? 'Received real Curve25519 and Ed25519 keys (43 characters each)'
        : `Unexpected key length: curve25519=${keys.curve25519.length}, ed25519=${keys.ed25519.length}`,
      detail: `curve25519: ${keys.curve25519}\ned25519: ${keys.ed25519}`,
    })
  } catch (e) {
    commit('identity', { status: 'unexpected', headline: `Unexpected: ${String(e)}` })
  }
}

/**
 * UTF-8, written out: React Native ships no `TextDecoder`.
 *
 * A third copy in this repository, and the reason is the same one
 * `levelTwoSuite.ts` gives for its own: this module must stay free of
 * imports the library does not publish, and neither of the other two is on
 * the published surface. Six lines of decoding is a smaller cost than a
 * dependency that would make this file unloadable outside a device.
 */
function utf8Decode(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) {
    // Every payload this card decodes is JSON this same process encoded, so
    // it is ASCII by construction. Anything outside that range is reported
    // rather than guessed at.
    out += byte < 0x80 ? String.fromCharCode(byte) : '�'
  }
  return out
}

/** How a `SenderVerification` reads on one line. */
function describeSender(verification: SenderVerification | undefined): string {
  if (verification === undefined) return 'absent'
  return verification.state === 'unverified'
    ? `${verification.state} / ${verification.reason}`
    : verification.state
}

// Step 6: the signing-identity gate, observed refusing.
//
// The refusal IS the demonstration, and the card says so. This app has no
// homeserver, so no key query naming the account has been answered, and
// `bootstrapCrossSigning` will not mint an identity on a question nobody has
// answered. A walkthrough that got past this would have to invent a key
// query response, which is the exact mistake `markRequestSent`'s own
// documentation spends a page on.
//
// `getIdentityStatus` is called first and its three fields are reported,
// because the refusal only means what it means alongside them: with
// `accountKeysFetched` false, `identityKnown` false says "nobody has asked",
// not "the account has none".
export async function runSigningIdentity(_ctx: RunContext, commit: Commit): Promise<void> {
  try {
    const status = await getIdentityStatus()
    const shape =
      `accountKeysFetched: ${status.accountKeysFetched}, ` +
      `identityKnown: ${status.identityKnown}, ` +
      `privateKeysHeld: ${status.privateKeysHeld}`
    try {
      await bootstrapCrossSigning()
      commit('signingIdentity', {
        status: 'unexpected',
        headline: 'Unexpected: an identity was minted with no server ever asked',
        detail: shape,
      })
    } catch (e) {
      const kind = isCryptoError(e) ? e.kind : undefined
      commit(
        'signingIdentity',
        kind === 'account_keys_not_fetched'
          ? {
              status: 'ok',
              headline: 'Refused, as it must be, with kind "account_keys_not_fetched"',
              detail: `${shape}\nThe key query that lifts this refusal is already queued: drain takeOutgoingRequests, send it, report it, call again.`,
            }
          : { status: 'unexpected', headline: `Unexpected error shape: ${String(e)}`, detail: shape },
      )
    }
  } catch (e) {
    commit('signingIdentity', { status: 'unexpected', headline: `Unexpected: ${String(e)}` })
  }
}

// Step 7: one real event, decrypted, and what it says about who sent it.
//
// The event is this device's own, which is the only sender a walkthrough
// with no homeserver and no counterparty has. That is enough for the claim
// the card makes: the value is produced by the same code path that reads a
// stranger's event, and the reason it reports is the one every product meets
// first. What it cannot show is a value above `unsigned_device`; those need
// a peer whose client published a cross-signing identity, which is what
// rust/matrix-crypto-core/tests/level_two_identity.rs drives.
export async function runSenderCheck(_ctx: RunContext, commit: Commit): Promise<void> {
  try {
    const scope = asCryptoScopeId(DEMO_SENDER_SCOPE)
    // One share is what creates the group session this card then uses. It
    // delivers nothing to anybody -- there is no homeserver to carry it --
    // and the card does not claim it does.
    await shareScopeKey(scope, [DEMO_USER_ID])

    const sealed = await encryptEvent(scope, 'm.room.message', {
      msgtype: 'm.text',
      body: 'who sent this?',
    })
    // `encryptEvent` hands back the encrypted *content*. `decryptEvent`
    // takes the whole event a homeserver would have delivered, so the
    // envelope around it is built here.
    const opened = await decryptEvent(scope, {
      sender: sealed.sender,
      event_id: '$sender-demo:example.org',
      origin_server_ts: 1700000000000,
      content: JSON.parse(utf8Decode(sealed.ciphertext)) as unknown,
    })

    const verification = opened.senderVerification
    const expected =
      verification !== undefined &&
      verification.state === 'unverified' &&
      verification.reason === 'unsigned_device'
    commit('senderCheck', {
      status: expected ? 'ok' : 'unexpected',
      headline: expected
        ? 'Decrypted, and the sender reads: unverified / unsigned_device'
        : `Unexpected sender verification: ${describeSender(verification)}`,
      detail: expected
        ? 'Not a placeholder. Step 6 refused to publish an identity, so no signature exists for this device and the library says exactly that.'
        : 'This card expects unsigned_device, because nothing in this walkthrough publishes a signing identity.',
    })
  } catch (e) {
    commit('senderCheck', { status: 'unexpected', headline: `Unexpected: ${String(e)}` })
  }
}

// Step 8: deliberately triggers the not-implemented path.
//
// THIS STEP HAS NOW GONE STALE TWICE, and the reason is structural rather
// than careless. The card asserts an implementation detail of the library,
// so every milestone that improves the library can falsify it, and until
// today nothing in this package ran on a machine that could notice. It
// pointed at `encryptEvent` until M2 implemented encryption, then at
// `getDeviceStatuses` until M3 implemented that, and the M3 breakage sat on
// screen reporting "unexpected" on every launch of a library that was
// working correctly.
//
// The card is not what is wrong. A walkthrough that ends honestly on what is
// not built yet is worth having, and it can only do that by naming a
// function. What was wrong is that the naming was unchecked. So the call
// below is now pinned by `cardClaims.test.ts`, which mocks nothing and runs
// this very function against the real facade on every CI run: the next time
// the library implements what this card points at, the build goes red before
// a developer ever sees the card go red on a phone.
//
// `exportSecrets` is the current choice out of the three the facade still
// rejects in JavaScript before any native call (`restoreCryptoMachine`,
// `exportSecrets`, `importSecrets`). Do not repoint it without moving the
// card in `steps.ts` with it; the test asserts the two agree.
export async function runNotYet(_ctx: RunContext, commit: Commit): Promise<void> {
  try {
    // Not a secret and not protecting anything: the facade rejects this call
    // before it reads the argument, which is the whole point of the step.
    await exportSecrets('example-app-not-implemented-probe')
    commit('notYet', { status: 'unexpected', headline: 'Unexpected: resolved instead of rejecting' })
  } catch (e) {
    const kind = isCryptoError(e) ? e.kind : undefined
    commit(
      'notYet',
      kind === 'not_implemented'
        ? {
            status: 'ok',
            headline: 'Expected error received -- kind: "not_implemented"',
            detail: 'Not a bug: the type is final today, and the behavior is scheduled, not missing.',
          }
        : { status: 'unexpected', headline: `Unexpected error shape: ${String(e)}` },
    )
  }
}

// Step 9: closing tally. Purely local -- everything above already crossed
// all five layers; this just names them.
export async function runLayers(_ctx: RunContext, commit: Commit): Promise<void> {
  commit('layers', {
    status: 'ok',
    headline: 'TypeScript facade -> generated bindings -> JSI Turbo Module -> UniFFI scaffolding -> Rust core',
  })
}

export const STEP_RUNNERS: Record<FlowStep['id'], (ctx: RunContext, commit: Commit) => Promise<void>> = {
  subscribe: runSubscribe,
  call: runCall,
  signal: runSignal,
  typedError: runTypedError,
  identity: runIdentity,
  signingIdentity: runSigningIdentity,
  senderCheck: runSenderCheck,
  notYet: runNotYet,
  layers: runLayers,
}

// The order FLOW_STEPS itself declares, not a second, hand-maintained list
// that could drift from it.
export const STEP_ORDER: FlowStep['id'][] = FLOW_STEPS.map(step => step.id)

/** Runs every step once, in order -- exactly what the mount effect below does, and exactly what "Run all" repeats. There is only one implementation of the sequence. */
export async function runFlow(ctx: RunContext, commit: Commit): Promise<void> {
  for (const id of STEP_ORDER) {
    await STEP_RUNNERS[id](ctx, commit)
  }
}
