/**
 * The camera proof, minus the camera.
 *
 * `scripts/run-camera-proof.sh` proves the strong thing -- an unmodified
 * Element on a real phone reads a symbol this library drew -- and it needs a
 * person to aim the phone, so it runs when somebody is at the rig. Between
 * those runs nothing watches the drawing. That is issue #29, and this file
 * is its cheap half.
 *
 * WHICH ASSERTION CATCHES WHAT, MEASURED RATHER THAN ASSUMED. The obvious
 * design -- draw it, decode it, compare -- was written first and is kept,
 * but it is NOT the guard here, because a QR decoder is built to succeed
 * through exactly the damage this test wants to notice. Measured with jsQR
 * 1.4 against a 126-byte payload:
 *
 *   corruption            decoder      caught by
 *   --------------------  -----------  --------------------------------
 *   drawn correctly       the payload  -
 *   transposed            the payload  the cell-for-cell assertion
 *   one module flipped    the payload  the cell-for-cell assertion
 *   no quiet zone at all  the payload  the quiet-zone assertion
 *   shifted one place     NO DECODE    the round trip
 *
 * A transposed symbol decodes to the SAME bytes, because decoders read
 * mirrored symbols on purpose and a transpose is a mirror. A single flipped
 * module decodes because error correction repairs it. A symbol with no quiet
 * zone decodes because jsQR is reading a buffer rather than a photograph of
 * a bright screen. So the cell-for-cell assertion is the guard, the
 * quiet-zone assertion stands for an optical need no decoder expresses, and
 * the round trip covers the structural damage that leaves nothing readable
 * at all.
 *
 * WHAT THIS DOES NOT PROVE: anything optical. No lens, no light, no
 * distance, no phone. Squares here are exact pixels, and a symbol that
 * decodes perfectly at 4 px per square can still be unreadable on a real
 * screen at a real distance. That claim belongs to the rig and is made
 * there.
 */

import jsQR from 'jsqr'
import qrcode from 'qrcode-generator'
import { describe, expect, it } from 'vitest'
import type { ScannableCode } from 'react-native-matrix-crypto'
import { QUIET_ZONE_SQUARES, codeMatrixLayout } from './codeMatrixLayout'

/**
 * A stand-in for `getVerificationCode`'s output, built by a real QR encoder.
 *
 * Not a recorded fixture: a blob checked in beside a test says nothing about
 * where it came from and cannot be re-derived when somebody doubts it. This
 * builds one, in Byte mode, from bytes chosen to be binary rather than text
 * -- which is what the real payload is (`ScannableCode.payload` is about 126
 * bytes carrying two signing keys and a shared secret, and the surface
 * documentation is emphatic that it is not a string).
 */
function encode(payload: Uint8Array): ScannableCode {
  const qr = qrcode(0, 'M')
  qr.addData(
    Array.from(payload, byte => String.fromCharCode(byte)).join(''),
    'Byte',
  )
  qr.make()
  const width = qr.getModuleCount()
  const modules: boolean[] = []
  for (let y = 0; y < width; y += 1) {
    for (let x = 0; x < width; x += 1) modules.push(qr.isDark(y, x))
  }
  return { payload, width, modules }
}

/** A payload with every byte value in it, so no encoding can round-trip by luck. */
function payloadOf(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (index * 7 + 13) % 256)
}

/**
 * Paints a layout the way the component does -- dark squares black, light
 * squares white, the quiet zone the same white -- into the RGBA buffer a
 * decoder takes.
 *
 * `scale` is px per square, and it is the one number here that is not the
 * layout's: a decoder needs whole pixels, and `squareSize` is a float
 * because a screen's width is not a multiple of a symbol's. Painting at a
 * whole-pixel scale is what lets this test isolate the drawing from the
 * rounding, and `it('never overflows...')` below covers the rounding
 * separately.
 */
function paint(
  rows: boolean[][],
  scale: number,
): { data: Uint8ClampedArray; size: number } {
  const squares = rows.length + QUIET_ZONE_SQUARES * 2
  const size = squares * scale
  const data = new Uint8ClampedArray(size * size * 4).fill(255)
  for (let y = 0; y < rows.length; y += 1) {
    for (let x = 0; x < rows.length; x += 1) {
      if (!rows[y][x]) continue
      for (let dy = 0; dy < scale; dy += 1) {
        for (let dx = 0; dx < scale; dx += 1) {
          const px =
            ((y + QUIET_ZONE_SQUARES) * scale + dy) * size +
            (x + QUIET_ZONE_SQUARES) * scale +
            dx
          data[px * 4] = 0
          data[px * 4 + 1] = 0
          data[px * 4 + 2] = 0
        }
      }
    }
  }
  return { data, size }
}

function decode(rows: boolean[][]): number[] | null {
  const { data, size } = paint(rows, 4)
  return jsQR(data, size, size)?.binaryData ?? null
}

describe('codeMatrixLayout', () => {
  it('draws a symbol a decoder reads back as the payload it was given', () => {
    const payload = payloadOf(126)
    const code = encode(payload)
    const { rows } = codeMatrixLayout(code, 360)
    expect(decode(rows)).toEqual(Array.from(payload))
  })

  it('catches a transposed symbol, which no decoder will', () => {
    // The risk CodeMatrix's comment names. MEASURED: a decoder is no use
    // here -- it reads the transposed symbol back as the same payload,
    // because decoders read mirrored symbols on purpose and a transpose is a
    // mirror. So this asserts through the cells, and asserts the decoder's
    // uselessness too, so that nobody re-writes this test as a round trip.
    const payload = payloadOf(126)
    const code = encode(payload)
    const { rows } = codeMatrixLayout(code, 360)
    const transposed = rows.map((_, y) => rows.map(row => row[y]))
    expect(transposed).not.toEqual(rows)
    expect(decode(transposed)).toEqual(Array.from(payload))
  })

  it('catches a symbol shifted one place, which a decoder cannot read at all', () => {
    // The other half of the same measurement: structural damage that moves
    // every module leaves nothing a decoder can lock onto, so the round trip
    // is what covers this one.
    const code = encode(payloadOf(126))
    const { rows } = codeMatrixLayout(code, 360)
    const flat = rows.flat()
    const shifted = rows.map((row, y) =>
      row.map((_, x) => flat[(y * rows.length + x + 1) % flat.length]),
    )
    expect(decode(shifted)).toBeNull()
  })

  it('reads modules row-major, cell for cell', () => {
    const code = encode(payloadOf(64))
    const { rows } = codeMatrixLayout(code, 360)
    expect(rows).toHaveLength(code.width)
    for (let y = 0; y < code.width; y += 1) {
      expect(rows[y]).toHaveLength(code.width)
      for (let x = 0; x < code.width; x += 1) {
        expect(rows[y][x]).toBe(code.modules[y * code.width + x])
      }
    }
  })

  it('keeps a quiet zone of four squares on every side', () => {
    // Asserted structurally because no decoder will assert it for us:
    // MEASURED, jsQR reads a symbol painted with no quiet zone at all. It is
    // reading a buffer; a camera reads a bright screen, and a symbol that
    // runs to the edge of one is the commonest reason a scan fails. This is
    // the assertion standing in for that.
    const { squareSize, quietZone } = codeMatrixLayout(
      encode(payloadOf(126)),
      360,
    )
    expect(QUIET_ZONE_SQUARES).toBe(4)
    expect(quietZone).toBe(squareSize * QUIET_ZONE_SQUARES)
  })

  it('never overflows the space it was given, at any width', () => {
    // Floored square sizes are the reason: the remainder has to become quiet
    // zone rather than a clipped final column, and "never wider" is the
    // property that says so for every size rather than for one.
    for (const available of [120, 197, 240, 360, 361, 1080, 2400]) {
      const { side } = codeMatrixLayout(encode(payloadOf(126)), available)
      expect(side).toBeLessThanOrEqual(available)
    }
  })

  it('refuses a code whose modules do not match its width', () => {
    const code = encode(payloadOf(126))
    expect(() =>
      codeMatrixLayout({ ...code, modules: code.modules.slice(0, -1) }, 360),
    ).toThrow(/refusing to draw a symbol/)
  })
})
