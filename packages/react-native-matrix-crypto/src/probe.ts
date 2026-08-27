import { probeWithObserver } from './generated/matrix_crypto'
import { toCryptoError } from './errors'
import { emitCryptoSignal } from './signals'

export interface ProbeResult {
  echoed: string
  payload: Uint8Array
  coreVersion: string
}

/**
 * Round-trips a string and bytes through the whole chain, emitting one signal.
 * Exists to prove the binding chain works. It has no cryptographic meaning.
 */
/**
 * The generated binding speaks `ArrayBuffer`; the public API speaks
 * `Uint8Array`, which is the idiomatic React Native shape for binary data and
 * what `EventEnvelope.ciphertext` uses. The shim converts in both directions.
 *
 * Slicing when the view is not the whole buffer is load-bearing: a bare
 * `.buffer` would hand the native side the entire backing store rather than
 * the caller's window onto it.
 */
function toArrayBuffer(view: Uint8Array): ArrayBuffer {
  const isWholeBuffer =
    view.byteOffset === 0 && view.byteLength === view.buffer.byteLength
  return isWholeBuffer ? (view.buffer as ArrayBuffer) : view.slice().buffer
}

export async function runProbe(input: string, payload: Uint8Array): Promise<ProbeResult> {
  try {
    const report = await probeWithObserver(input, toArrayBuffer(payload), {
      onSignal(signal: { kind: string; detail: string }) {
        emitCryptoSignal({ kind: 'probe_started', detail: signal.detail })
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
