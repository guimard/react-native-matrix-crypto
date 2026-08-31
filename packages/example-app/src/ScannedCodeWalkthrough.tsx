/**
 * The screen a person holds a phone in front of.
 *
 * Everything it shows comes from `scannedCodeRunner.ts`, which imports the
 * published TypeScript surface and no component. This file draws squares and
 * offers two buttons; it decides nothing.
 *
 * # The library never sees a camera, and neither does this
 *
 * No camera, no image decoder, no permission prompt, here or anywhere in
 * `react-native-matrix-crypto`. The product owns the scanner and the screen.
 * What this draws is `getVerificationCode`'s own `modules`: a row-major
 * boolean grid where `true` is a dark square, at the width the protocol
 * fixes. It is not a re-encoding of the payload and there is no honest
 * string to hand a code-drawing component instead, which is why the grid
 * crosses the boundary rather than the bytes alone.
 *
 * # Why plain views and not an image
 *
 * A `<View>` per square, sized so the whole symbol fills the width. That is
 * about two thousand views for a 45-square code, which is more than a
 * production app should draw and exactly what this one should: it adds no
 * dependency, and every square on screen is one entry of the array the
 * library handed over, so what a camera reads is what crossed the boundary
 * rather than what an encoder made of it.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Pressable, ScrollView, StyleSheet, Text, View, useWindowDimensions } from 'react-native'
import type { ScannableCode } from 'react-native-matrix-crypto'
import { httpJson } from './levelTwoTransport'
import type { LevelTwoPlan } from './levelTwoTransport'
import { startScannedCodeRun, type ScannedCodeRun, type ScannedCodeState } from './scannedCodeRunner'

/**
 * The pale border every QR symbol needs around it.
 *
 * Four squares rather than the specification's minimum, because the thing
 * pointed at this screen is a phone held by a person rather than a scanner
 * in a jig, and a symbol that reaches the edge of a bright screen is the
 * commonest reason a scan fails.
 */
const QUIET_ZONE_SQUARES = 4

function CodeMatrix({ code }: { code: ScannableCode }) {
  const { width: screenWidth } = useWindowDimensions()
  const side = Math.min(screenWidth - 32, 360)
  const squares = code.width + QUIET_ZONE_SQUARES * 2
  // Floored, so rounding never makes the drawn symbol wider than the space
  // it was given; the remainder becomes extra quiet zone rather than a
  // clipped final column.
  const squareSize = Math.floor((side / squares) * 100) / 100

  const rows = []
  for (let y = 0; y < code.width; y += 1) {
    const cells = []
    for (let x = 0; x < code.width; x += 1) {
      // Row-major, exactly as the surface documents it. Reading this the
      // other way round transposes the symbol, which for most codes still
      // decodes, to different bytes.
      const dark = code.modules[y * code.width + x]
      cells.push(
        <View
          key={x}
          style={{
            width: squareSize,
            height: squareSize,
            backgroundColor: dark ? '#000000' : '#ffffff',
          }}
        />,
      )
    }
    rows.push(
      <View key={y} style={styles.matrixRow}>
        {cells}
      </View>,
    )
  }

  return (
    <View style={[styles.matrixFrame, { padding: squareSize * QUIET_ZONE_SQUARES }]}>{rows}</View>
  )
}

export function ScannedCodeWalkthrough({
  plan,
  storeDir,
}: {
  plan: LevelTwoPlan
  storeDir: string
}) {
  const [state, setState] = useState<ScannedCodeState>({
    headline: 'Starting…',
    awaitingConfirmation: false,
    finished: false,
    failed: false,
  })
  const runRef = useRef<ScannedCodeRun | null>(null)
  const lastHeadlineRef = useRef<string>("")
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    const run = startScannedCodeRun(
      {
        homeserver: plan.homeserver,
        userId: plan.userId,
        deviceId: plan.deviceId,
        accessToken: plan.accessToken,
      },
      storeDir,
      httpJson,
      next => {
        // One line per change of headline, so the operator running the
        // host-side program sees the same story without holding the phone up
        // to their face. Headline and stage only: never an identifier, never
        // a payload byte, never a module. The payload is authentication
        // material and the modules are the same secret drawn as squares.
        if (next.headline !== lastHeadlineRef.current) {
          lastHeadlineRef.current = next.headline
          console.log(`SCANNED_CODE ${next.stage ?? 'no-stage'} ${next.headline}`)
        }
        if (mountedRef.current) setState(next)
      },
    )
    runRef.current = run
    return () => {
      mountedRef.current = false
      run.stop()
    }
  }, [plan, storeDir])

  const onConfirm = useCallback(() => runRef.current?.confirm(), [])
  const onAsk = useCallback(() => runRef.current?.askOtherDevices(), [])

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.title}>Verify by scanning a code</Text>
      <Text style={styles.intro}>
        This screen shows a real code for a real verification, produced by this build on this
        device. Point another Matrix client's camera at it. Nothing here decodes anything: this
        library never sees a camera, and the squares below are the grid it handed over.
      </Text>

      <Text style={state.failed ? styles.headlineBad : styles.headlineGood}>{state.headline}</Text>
      {state.detail ? <Text style={styles.detail}>{state.detail}</Text> : null}

      {state.code ? <CodeMatrix code={state.code} /> : null}

      {state.awaitingConfirmation ? (
        <Pressable accessibilityRole="button" onPress={onConfirm} style={styles.confirmButton}>
          <Text style={styles.confirmText}>Yes, that was my other device</Text>
        </Pressable>
      ) : null}

      {!state.finished && state.code === undefined ? (
        <Pressable accessibilityRole="button" onPress={onAsk} style={styles.askButton}>
          <Text style={styles.askText}>Ask my other devices to verify</Text>
        </Pressable>
      ) : null}

      <Text style={styles.label}>Stage</Text>
      <Text style={styles.mono}>{state.stage ?? 'not started'}</Text>
      {state.code ? (
        <>
          <Text style={styles.label}>Symbol</Text>
          <Text style={styles.mono}>
            {state.code.width} squares a side, {state.code.payload.length} bytes of payload
          </Text>
        </>
      ) : null}
    </ScrollView>
  )
}

const styles = StyleSheet.create({
  container: {
    padding: 16,
  },
  title: {
    fontSize: 20,
    fontWeight: '700',
    marginBottom: 8,
  },
  intro: {
    fontSize: 13,
    lineHeight: 19,
    opacity: 0.8,
    marginBottom: 16,
  },
  headlineGood: {
    fontSize: 15,
    fontWeight: '600',
    color: '#1a7f37',
  },
  headlineBad: {
    fontSize: 15,
    fontWeight: '600',
    color: '#cf222e',
  },
  detail: {
    fontSize: 13,
    lineHeight: 18,
    opacity: 0.75,
    marginTop: 4,
    marginBottom: 12,
  },
  matrixFrame: {
    alignSelf: 'center',
    backgroundColor: '#ffffff',
    marginVertical: 16,
  },
  matrixRow: {
    flexDirection: 'row',
  },
  confirmButton: {
    alignSelf: 'flex-start',
    backgroundColor: '#1a7f37',
    borderRadius: 6,
    marginTop: 8,
    paddingHorizontal: 16,
    paddingVertical: 12,
  },
  confirmText: {
    color: '#ffffff',
    fontSize: 15,
    fontWeight: '700',
  },
  askButton: {
    alignSelf: 'flex-start',
    borderColor: '#8888',
    borderRadius: 6,
    borderWidth: StyleSheet.hairlineWidth,
    marginTop: 8,
    paddingHorizontal: 12,
    paddingVertical: 8,
  },
  askText: {
    fontSize: 13,
    fontWeight: '600',
    opacity: 0.8,
  },
  label: {
    fontSize: 11,
    fontWeight: '700',
    textTransform: 'uppercase',
    opacity: 0.6,
    marginTop: 12,
  },
  mono: {
    fontFamily: 'Courier',
    fontSize: 12,
  },
})
