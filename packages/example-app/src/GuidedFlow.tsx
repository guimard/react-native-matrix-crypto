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

import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Pressable, StyleSheet, Text, View } from 'react-native'
import { FLOW_STEPS, type FlowStep } from './steps'
// The steps themselves live in a module of their own, with no `react`
// or `react-native` import anywhere in it, so `flowRunners.test.ts` can call
// these exact functions on a host machine. Nothing here re-implements a step
// and nothing here decides what a step reports; this file renders what they
// commit and offers the two controls that repeat them.
import {
  runFlow,
  STEP_RUNNERS,
  type Commit,
  type Outcome,
  type OutcomeStatus,
  type RunContext,
} from './flowRunners'

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

export function GuidedFlow({ storeDir }: { storeDir: string }) {
  const [outcomes, setOutcomes] = useState<Partial<Record<FlowStep['id'], Outcome>>>({})
  // Starts true: the automatic run below begins the instant this component
  // mounts, before any button could possibly be pressed. This flag only
  // ever disables controls while a run -- automatic or manual -- is
  // in flight, so two runs can never overlap and race on the shared
  // subscription in ctxRef.
  const [busy, setBusy] = useState(true)
  const mountedRef = useRef(true)
  const ctxRef = useRef<RunContext>({ unsubscribe: null, probeSignals: [], storeDir })

  // Declared before the run effect below, so a `storeDir` that changed
  // between renders reaches the context before anything reads it. The ref's
  // initial value already carries the mount-time one; this only keeps a
  // later change from being missed, without mutating a ref during render.
  useEffect(() => {
    ctxRef.current.storeDir = storeDir
  }, [storeDir])

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
        {FLOW_STEPS.length} steps through this library's public API, from a bare connectivity check to real
        cryptography, ending
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
