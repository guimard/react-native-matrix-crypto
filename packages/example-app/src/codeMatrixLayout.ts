/**
 * Where every square of a scannable code goes, as numbers rather than views.
 *
 * Extracted from `CodeMatrix.tsx` for the reason `cameraProofLog.ts` was
 * extracted from `CameraProofHarness.tsx`: the decisions worth testing are
 * arithmetic and indexing, and neither needs a renderer. The component keeps
 * exactly one job, mapping `rows` to `View`s, so there is no second copy of
 * the row-major loop to keep correct.
 *
 * WHAT THE TEST BESIDE THIS FILE PROVES, AND WHAT IT DOES NOT. It asserts
 * the drawing cell for cell against `modules`, because that is the only
 * assertion that catches every way the drawing can be wrong: a decoder is
 * built to succeed through a transposed symbol and through a flipped module,
 * and it needs no quiet zone at all when it is reading a buffer rather than
 * a photograph. The test's own header carries that measurement.
 *
 * It never touches a lens. Whether a real camera reads this at a real
 * distance under real light is `scripts/run-camera-proof.sh`'s claim, made
 * once against an unmodified Element on a real phone, and it needs a person
 * to aim. That is the split issue #29 exists to name: this file's test is
 * what watches for regressions between those runs.
 */

import type { ScannableCode } from 'react-native-matrix-crypto'

/**
 * The pale border every QR symbol needs around it.
 *
 * Four squares rather than the specification's minimum, because the thing
 * pointed at this screen is a phone held by a person -- or fixed in a mount,
 * at a distance nobody re-measures per run -- rather than a scanner in a jig,
 * and a symbol that reaches the edge of a bright screen is the commonest
 * reason a scan fails.
 */
export const QUIET_ZONE_SQUARES = 4

export interface CodeMatrixLayout {
  /** The side of one square, in px. */
  squareSize: number
  /** The pale border, in px, on each of the four sides. */
  quietZone: number
  /** `rows[y][x]` is true where the square is dark. Row-major, like `modules`. */
  rows: boolean[][]
  /** The whole symbol including its quiet zone, in px. */
  side: number
}

/**
 * Lays `code` out inside `available` px.
 *
 * `available` is what the caller has room for; how it decided that is the
 * caller's business (the walkthrough caps it because a person holds a phone
 * at it, the camera-proof harness passes the smaller screen dimension
 * because a mount holds the scanner at it).
 */
export function codeMatrixLayout(
  code: ScannableCode,
  available: number,
): CodeMatrixLayout {
  // Refused rather than drawn wrong. A `modules` array that does not match
  // `width` would index past its end, and JavaScript answers `undefined`
  // there, which is falsy, which is white -- so the symbol would come out
  // silently truncated and a camera would read a code that is not this one.
  // The far side reports that as `scanned_code_refused`, an error about the
  // wrong thing entirely. Nothing downstream can recover a symbol that was
  // never drawn, so this fails where the fact is known.
  if (code.modules.length !== code.width * code.width) {
    throw new Error(
      `a scannable code of width ${code.width} needs ${code.width * code.width} ` +
        `modules and this one has ${code.modules.length}; refusing to draw a ` +
        'symbol that would decode to something other than this code',
    )
  }

  const squares = code.width + QUIET_ZONE_SQUARES * 2
  // Floored, so rounding never makes the drawn symbol wider than the space
  // it was given; the remainder becomes extra quiet zone rather than a
  // clipped final column.
  const squareSize = Math.floor((available / squares) * 100) / 100

  const rows: boolean[][] = []
  for (let y = 0; y < code.width; y += 1) {
    const cells: boolean[] = []
    for (let x = 0; x < code.width; x += 1) {
      // Row-major, exactly as the surface documents it. Reading this the
      // other way round transposes the symbol, and MEASURED (see the test
      // beside this file), that does NOT produce different bytes: a decoder
      // reads the transposed symbol back as the same payload, because
      // decoders read mirrored symbols on purpose and a transpose is a
      // mirror. An earlier revision of this comment said "to different
      // bytes", which would have made a wrong drawing invisible AND
      // harmless, and it is neither -- another client's decoder need not
      // mirror.
      cells.push(code.modules[y * code.width + x])
    }
    rows.push(cells)
  }

  return {
    squareSize,
    quietZone: squareSize * QUIET_ZONE_SQUARES,
    rows,
    side: squareSize * squares,
  }
}
