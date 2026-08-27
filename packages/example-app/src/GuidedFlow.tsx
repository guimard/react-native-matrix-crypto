import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Pressable, StyleSheet, Text, View } from 'react-native'
import {
  asCryptoScopeId,
  encryptEvent,
  getDeviceIdentityKeys,
  isCryptoError,
  onCryptoSignal,
  runProbe,
  type Unsubscribe,
} from 'react-native-matrix-crypto'
import { FLOW_STEPS, type FlowStep } from './steps'

/**
 * A human-readable walkthrough of the public API, run live against the real
 * native binding every time this screen mounts. Nothing below is a canned
 * example: every result is computed on this device, right now.
 *
 * This is separate from ProbeHarness, which is the automated, CI-scraped
 * check. This component exists to explain the bridge to a person; it must
 * never become the thing CI depends on, and it must never gate ProbeHarness
 * behind its own mount -- see App.tsx for how the two are kept independent.
 *
 * The mount effect below always runs the full flow automatically and
 * unconditionally -- that first run is never gated behind a tap, and never
 * becomes conditional on one. "Run all" and each card's "Re-run this step"
 * only ever repeat a run that has already happened once on its own; neither
 * control is required for a single line of this screen's own output to
 * exist. Removing every button from this file would not change what
 * appears on first launch.
 */

// Deliberately fictional Matrix identifiers, `example.org`-shaped, so they
// read as illustrative rather than as configuration for any real server.
const DEMO_USER_ID = '@alice:example.org'
const DEMO_DEVICE_ID = 'DEVICE1'
const DEMO_SCOPE = '!crypto-demo:example.org'

type OutcomeStatus = 'pending' | 'ok' | 'unexpected'

interface Outcome {
  status: OutcomeStatus
  headline: string
  detail?: string
}

type Commit = (id: FlowStep['id'], outcome: Outcome) => void

/**
 * Mutable state shared across steps within one run, and carried forward
 * between runs.
 *
 * `unsubscribe` is step 1's subscription to the real, product-facing
 * `onCryptoSignal` channel (spec section 7.3: `trust_changed`,
 * `unexpected_device`, `key_missing`). `probeSignals` is unrelated: it is
 * fed only by step 2's own call to `runProbe`, via the per-call callback
 * `runProbe` accepts directly -- never by step 1's listener. The two are
 * deliberately different channels; step 3 explains why.
 *
 * Re-running step 1 replaces the previous subscription rather than
 * stacking a second one on top of it. Re-running step 2 replaces
 * `probeSignals` with that call's own result rather than accumulating
 * across calls -- a fresh call only ever reports its own signal.
 */
interface RunContext {
  unsubscribe: Unsubscribe | null
  probeSignals: string[]
}

function bytesToText(bytes: Uint8Array): string {
  return `[${Array.from(bytes).join(', ')}]`
}

// Step 1: subscribe to the real crypto-signal channel. Registered before any
// call is made, the way a real consumer would. Nothing arrives on it during
// this walkthrough -- no trust logic exists yet in this milestone -- so this
// step is left running to show the API's shape; step 3 demonstrates a
// different channel entirely, not this one.
async function runSubscribe(ctx: RunContext, commit: Commit): Promise<void> {
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
// for step 3 to report.
async function runCall(ctx: RunContext, commit: Commit): Promise<void> {
  try {
    ctx.probeSignals = []
    const report = await runProbe('hello', new Uint8Array([1, 2, 3]), signal => {
      ctx.probeSignals = [...ctx.probeSignals, signal.kind]
    })
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
async function runSignal(ctx: RunContext, commit: Commit): Promise<void> {
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
async function runTypedError(_ctx: RunContext, commit: Commit): Promise<void> {
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
async function runIdentity(_ctx: RunContext, commit: Commit): Promise<void> {
  try {
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

// Step 6: deliberately triggers the not-implemented path.
async function runNotYet(_ctx: RunContext, commit: Commit): Promise<void> {
  try {
    await encryptEvent(asCryptoScopeId(DEMO_SCOPE), 'm.room.message', { body: 'hello' })
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

// Step 7: closing tally. Purely local -- everything above already crossed
// all five layers; this just names them.
async function runLayers(_ctx: RunContext, commit: Commit): Promise<void> {
  commit('layers', {
    status: 'ok',
    headline: 'TypeScript facade -> generated bindings -> JSI Turbo Module -> UniFFI scaffolding -> Rust core',
  })
}

const STEP_RUNNERS: Record<FlowStep['id'], (ctx: RunContext, commit: Commit) => Promise<void>> = {
  subscribe: runSubscribe,
  call: runCall,
  signal: runSignal,
  typedError: runTypedError,
  identity: runIdentity,
  notYet: runNotYet,
  layers: runLayers,
}

// The order FLOW_STEPS itself declares, not a second, hand-maintained list
// that could drift from it.
const STEP_ORDER: FlowStep['id'][] = FLOW_STEPS.map(step => step.id)

/** Runs every step once, in order -- exactly what the mount effect below does, and exactly what "Run all" repeats. There is only one implementation of the sequence. */
async function runFlow(ctx: RunContext, commit: Commit): Promise<void> {
  for (const id of STEP_ORDER) {
    await STEP_RUNNERS[id](ctx, commit)
  }
}

function pillStyle(status: OutcomeStatus) {
  switch (status) {
    case 'ok':
      return styles.pill_ok
    case 'unexpected':
      return styles.pill_unexpected
    default:
      return styles.pill_pending
  }
}

function StatusPill({ status }: { status: OutcomeStatus }) {
  const label = status === 'pending' ? 'running' : status === 'ok' ? 'done' : 'unexpected'
  return (
    <View style={[styles.pill, pillStyle(status)]}>
      <Text style={styles.pillText}>{label}</Text>
    </View>
  )
}

function StepCard({
  step,
  outcome,
  disabled,
  onRerun,
}: {
  step: FlowStep
  outcome: Outcome | undefined
  disabled: boolean
  onRerun: () => void
}) {
  const resolved: Outcome = outcome ?? { status: 'pending', headline: 'running…' }
  return (
    <View style={styles.card}>
      <View style={styles.cardHeader}>
        <Text style={styles.cardTitle}>{step.title}</Text>
        <StatusPill status={resolved.status} />
      </View>
      <Text style={styles.narrative}>{step.why}</Text>
      <View style={styles.codeBlock}>
        <Text style={styles.codeText}>{step.call}</Text>
      </View>
      <Text style={styles.label}>Crosses the boundary</Text>
      <Text style={styles.boundary}>{step.crosses}</Text>
      <Text style={styles.label}>Result</Text>
      <Text style={resolved.status === 'unexpected' ? styles.headlineBad : styles.headlineGood}>
        {resolved.headline}
      </Text>
      {resolved.detail ? <Text style={styles.detail}>{resolved.detail}</Text> : null}
      <Pressable
        accessibilityRole="button"
        disabled={disabled}
        onPress={onRerun}
        style={[styles.rerunButton, disabled && styles.buttonDisabled]}
      >
        <Text style={styles.rerunText}>Re-run this step</Text>
      </Pressable>
    </View>
  )
}

export function GuidedFlow() {
  const [outcomes, setOutcomes] = useState<Partial<Record<FlowStep['id'], Outcome>>>({})
  // Starts true: the automatic run below begins the instant this component
  // mounts, before any button could possibly be pressed. This flag only
  // ever disables controls while a run -- automatic or manual -- is
  // in flight, so two runs can never overlap and race on the shared
  // subscription in ctxRef.
  const [busy, setBusy] = useState(true)
  const mountedRef = useRef(true)
  const ctxRef = useRef<RunContext>({ unsubscribe: null, probeSignals: [] })

  const commit = useCallback<Commit>((id, outcome) => {
    if (!mountedRef.current) return
    setOutcomes(prev => ({ ...prev, [id]: outcome }))
  }, [])

  // Automatic, unconditional run on mount -- never gated behind a tap, and
  // not affected by anything below. This is what makes PROBE-style
  // unattended verification possible for this screen too: every result a
  // cold launch needs is already produced here, before a person could
  // touch anything.
  useEffect(() => {
    const ctx = ctxRef.current
    runFlow(ctx, commit).finally(() => {
      if (mountedRef.current) setBusy(false)
    })
    return () => {
      mountedRef.current = false
      ctx.unsubscribe?.()
    }
  }, [commit])

  const handleRunAll = useCallback(() => {
    if (busy) return
    setOutcomes({})
    setBusy(true)
    runFlow(ctxRef.current, commit).finally(() => {
      if (mountedRef.current) setBusy(false)
    })
  }, [busy, commit])

  const handleRerunStep = useCallback(
    (id: FlowStep['id']) => {
      if (busy) return
      setOutcomes(prev => ({ ...prev, [id]: undefined }))
      setBusy(true)
      STEP_RUNNERS[id](ctxRef.current, commit).finally(() => {
        if (mountedRef.current) setBusy(false)
      })
    },
    [busy, commit],
  )

  return (
    <View style={styles.container}>
      <Text style={styles.intro}>
        Seven steps through this library's public API, from a bare connectivity check to real cryptography, ending
        honestly on what is not built yet. Every result below is live: computed by this build, on this device, right
        now -- not a canned example. The steps below already ran once, automatically, when this screen opened;
        "Run all" and each card's own re-run button only repeat that.
      </Text>
      <Pressable
        accessibilityRole="button"
        disabled={busy}
        onPress={handleRunAll}
        style={[styles.runAllButton, busy && styles.buttonDisabled]}
      >
        <Text style={styles.runAllText}>{busy ? 'Running…' : 'Run all'}</Text>
      </Pressable>
      {FLOW_STEPS.map(step => (
        <StepCard
          key={step.id}
          step={step}
          outcome={outcomes[step.id]}
          disabled={busy}
          onRerun={() => handleRerunStep(step.id)}
        />
      ))}
    </View>
  )
}

const styles = StyleSheet.create({
  container: {
    padding: 16,
  },
  intro: {
    fontSize: 14,
    lineHeight: 20,
    marginBottom: 16,
    opacity: 0.8,
  },
  runAllButton: {
    alignSelf: 'flex-start',
    backgroundColor: '#0969da',
    borderRadius: 6,
    marginBottom: 16,
    paddingHorizontal: 16,
    paddingVertical: 10,
  },
  runAllText: {
    color: '#fff',
    fontSize: 14,
    fontWeight: '600',
  },
  card: {
    borderWidth: StyleSheet.hairlineWidth,
    borderColor: '#8888',
    borderRadius: 8,
    padding: 12,
    marginBottom: 12,
  },
  cardHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 6,
  },
  cardTitle: {
    fontSize: 15,
    fontWeight: '600',
    flexShrink: 1,
    marginRight: 8,
  },
  narrative: {
    fontSize: 13,
    lineHeight: 18,
    opacity: 0.85,
    marginBottom: 8,
  },
  codeBlock: {
    backgroundColor: '#0002',
    borderRadius: 6,
    padding: 8,
    marginBottom: 8,
  },
  codeText: {
    fontFamily: 'Courier',
    fontSize: 12,
    lineHeight: 17,
  },
  label: {
    fontSize: 11,
    fontWeight: '700',
    textTransform: 'uppercase',
    opacity: 0.6,
    marginTop: 4,
  },
  boundary: {
    fontSize: 13,
    lineHeight: 18,
    marginBottom: 4,
  },
  headlineGood: {
    fontSize: 13,
    fontWeight: '600',
    color: '#1a7f37',
  },
  headlineBad: {
    fontSize: 13,
    fontWeight: '600',
    color: '#cf222e',
  },
  detail: {
    fontSize: 12,
    lineHeight: 17,
    opacity: 0.7,
    marginTop: 2,
  },
  pill: {
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 10,
  },
  pill_pending: {
    backgroundColor: '#8888',
  },
  pill_ok: {
    backgroundColor: '#1a7f3733',
  },
  pill_unexpected: {
    backgroundColor: '#cf222e33',
  },
  pillText: {
    fontSize: 11,
    fontWeight: '600',
  },
  rerunButton: {
    alignSelf: 'flex-start',
    borderColor: '#8888',
    borderRadius: 6,
    borderWidth: StyleSheet.hairlineWidth,
    marginTop: 10,
    paddingHorizontal: 10,
    paddingVertical: 6,
  },
  rerunText: {
    fontSize: 12,
    fontWeight: '600',
    opacity: 0.8,
  },
  buttonDisabled: {
    opacity: 0.4,
  },
})
