import { probeWithObserver } from './generated/matrix_crypto'
import { toCryptoError } from './errors'

export interface ProbeResult {
  echoed: string
  payload: Uint8Array
  coreVersion: string
}

/**
 * A single diagnostic emitted by one `runProbe` call. Not a `CryptoSignal`:
 * it carries no product decision and belongs to no crypto state -- it is
 * proof that the UniFFI callback interface crosses JSI in the reverse
 * direction (Rust calling back into JS), scoped to the call that asked for
 * it. See `runProbe`'s own comment for why this is not broadcast.
 */
export interface ProbeSignal {
  kind: string
  detail: string
}

/**
 * The generated binding speaks `ArrayBuffer`; the public API speaks
 * `Uint8Array`, which is the idiomatic React Native shape for binary data and
 * what `EventEnvelope.ciphertext` uses. The shim converts in both directions.
 *
 * Slicing when the view is not the whole buffer is load-bearing: a bare
 * `.buffer` would hand the native side the entire backing store rather than
 * the caller's window onto it.
 *
 * Exported for `facade.ts`'s `submitScannedCode`, which has the same trap to
 * avoid on a value that is even likelier to arrive as a view: the bytes a
 * scanner library hands a product. Not part of the package's public surface
 * -- `index.ts` decides that, and does not export it.
 */
export function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  const isWholeBuffer =
    view.byteOffset === 0 && view.byteLength === view.buffer.byteLength
  return isWholeBuffer ? (view.buffer as ArrayBuffer) : view.slice().buffer
}

/**
 * Round-trips a string and bytes through the whole chain. Exists to prove
 * the binding chain works, including in reverse: Rust invokes the observer
 * passed to `probeWithObserver` back across JSI while the call is still in
 * flight. It has no cryptographic meaning.
 *
 * `onProbeSignal`, if given, receives that one call's own diagnostic and
 * nothing else. It is deliberately NOT routed through
 * `emitCryptoSignal`/`onCryptoSignal`: that channel is spec section 7.3's
 * broadcast for genuine crypto state changes (`verification_requested`,
 * `trust_changed`, `unexpected_device`, `key_missing`), which every
 * subscriber should learn about. This list named three of the four and left
 * out the only one of them that hands a caller something no other call
 * will. A probe's signal is a per-call diagnostic of this function, not a
 * crypto state change, so it must reach only the caller that asked for it --
 * broadcasting it made two independent callers of `runProbe` (e.g. the
 * example app's guided walkthrough and its diagnostics panel, mounted as
 * siblings) each see the other's signal too.
 */
export async function runProbe(
  input: string,
  payload: Uint8Array,
  onProbeSignal?: (signal: ProbeSignal) => void,
): Promise<ProbeResult> {
  try {
    const report = await probeWithObserver(input, toArrayBuffer(payload), {
      onSignal(signal: ProbeSignal) {
        onProbeSignal?.(signal)
      },
    })
    return {
      echoed: report.echoed,
      payload: new Uint8Array(report.payload),
      coreVersion: report.coreVersion,
    }
  } catch (e) {
    throw toCryptoError(e)
  }
}
