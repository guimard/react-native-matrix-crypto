import React, { useEffect, useState } from 'react'
import { StyleSheet, Text, View } from 'react-native'
import {
  asCryptoScopeId,
  encryptEvent,
  getDeviceIdentityKeys,
  isCryptoError,
  onCryptoSignal,
  runProbe,
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

function bytesToText(bytes: Uint8Array): string {
  return `[${Array.from(bytes).join(', ')}]`
}

async function runFlow(commit: (id: FlowStep['id'], outcome: Outcome) => void): Promise<void> {
  const signals: string[] = []

  // Step 1: subscribe. Registered before any call is made, the way a real
  // consumer would -- step 3 reads whatever this listener catches.
  try {
    onCryptoSignal((s) => {
      signals.push(s.kind)
    })
    commit('subscribe', { status: 'ok', headline: 'Listening for signals' })
  } catch (e) {
    commit('subscribe', { status: 'unexpected', headline: `Unexpected: ${String(e)}` })
  }

  // Step 2: the round trip.
  try {
    const report = await runProbe('hello', new Uint8Array([1, 2, 3]))
    commit('call', {
      status: 'ok',
      headline: `Echoed "${report.echoed}" -- core v${report.coreVersion}`,
      detail: `bytes came back reversed: [1, 2, 3] -> ${bytesToText(report.payload)}`,
    })
  } catch (e) {
    commit('call', { status: 'unexpected', headline: `Unexpected: ${String(e)}` })
  }

  // Step 3: the signal from step 2 has already arrived, since Rust invokes
  // the step 1 observer callback before the awaited call resolves.
  // Deduplicated for display: a dev-mode double-mount (React or Fast
  // Refresh remounting this screen) can leave an earlier instance's
  // in-flight call still delivering to the current listener, which is
  // harmless -- the check below only asks whether the expected kind
  // arrived -- but would otherwise print the same kind twice.
  const seen = [...new Set(signals)]
  commit(
    'signal',
    seen.includes('probe_started')
      ? { status: 'ok', headline: `Received signal: ${seen.join(', ')}` }
      : { status: 'unexpected', headline: 'Unexpected: no signal received' },
  )

  // Step 4: deliberately triggers the typed-error path.
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

  // Step 5: real cryptography.
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

  // Step 6: deliberately triggers the not-implemented path.
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

  // Step 7: closing tally. Purely local -- everything above already
  // crossed all five layers; this just names them.
  commit('layers', {
    status: 'ok',
    headline: 'TypeScript facade -> generated bindings -> JSI Turbo Module -> UniFFI scaffolding -> Rust core',
  })
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

function StepCard({ step, outcome }: { step: FlowStep; outcome: Outcome | undefined }) {
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
    </View>
  )
}

export function GuidedFlow() {
  const [outcomes, setOutcomes] = useState<Partial<Record<FlowStep['id'], Outcome>>>({})

  useEffect(() => {
    let cancelled = false

    function commit(id: FlowStep['id'], outcome: Outcome) {
      if (cancelled) return
      setOutcomes((prev) => ({ ...prev, [id]: outcome }))
    }

    runFlow(commit)

    return () => {
      cancelled = true
    }
  }, [])

  return (
    <View style={styles.container}>
      <Text style={styles.intro}>
        Seven steps through this library's public API, from a bare connectivity check to real cryptography, ending
        honestly on what is not built yet. Every result below is live: computed by this build, on this device, right
        now -- not a canned example.
      </Text>
      {FLOW_STEPS.map((step) => (
        <StepCard key={step.id} step={step} outcome={outcomes[step.id]} />
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
})
