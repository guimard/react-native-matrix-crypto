/**
 * The shared QR-symbol renderer: `getVerificationCode`'s own `modules` drawn
 * as squares, nothing re-encoded. Extracted from ScannedCodeWalkthrough so the
 * camera-proof harness draws the same symbol the walkthrough does, from the
 * same code path, with only its size different -- a second hand-written copy
 * of the row-major drawing loop would be a second thing to keep correct, and
 * a transposed or resized-wrong symbol is exactly the defect this render path
 * exists to surface (see ScannedCodeWalkthrough's own header for why plain
 * views and not an image).
 *
 * Every decision about WHERE the squares go now lives in
 * `codeMatrixLayout.ts`, which is host-tested by encoding a payload, laying
 * it out, painting it and decoding the paint back. What is left here is the
 * mapping to views, which is the part a renderer is needed for and the part
 * that cannot be wrong about the bytes.
 *
 * `maxSide` is the only parameter: the walkthrough caps the symbol because a
 * person holds a phone at it, the camera-proof harness passes the smaller of
 * the two screen dimensions because a fixed mount holds the scanner at it.
 * The quiet zone is part of the symbol, not of the screen: it scales with the
 * squares either way.
 */

import React from 'react'
import { StyleSheet, View, useWindowDimensions } from 'react-native'
import type { ScannableCode } from 'react-native-matrix-crypto'
import { codeMatrixLayout } from './codeMatrixLayout'

export function CodeMatrix({ code, maxSide = 360 }: { code: ScannableCode; maxSide?: number }) {
  const { width: screenWidth } = useWindowDimensions()
  const { squareSize, quietZone, rows } = codeMatrixLayout(code, Math.min(screenWidth - 32, maxSide))

  return (
    <View style={[styles.matrixFrame, { padding: quietZone }]}>
      {rows.map((cells, y) => (
        <View key={y} style={styles.matrixRow}>
          {cells.map((dark, x) => (
            <View
              key={x}
              style={{
                width: squareSize,
                height: squareSize,
                backgroundColor: dark ? '#000000' : '#ffffff',
              }}
            />
          ))}
        </View>
      ))}
    </View>
  )
}

const styles = StyleSheet.create({
  matrixFrame: {
    alignSelf: 'center',
    backgroundColor: '#ffffff',
    marginVertical: 16,
  },
  matrixRow: {
    flexDirection: 'row',
  },
})
