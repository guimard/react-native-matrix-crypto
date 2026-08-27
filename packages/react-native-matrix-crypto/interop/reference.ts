import type { BridgeBinding } from './suite'
import { isCryptoError, toCryptoError } from '../src/errors'

/**
 * Pure-TypeScript restatement of the contract, used to exercise the suite in
 * Node where the JSI module cannot load. It doubles as executable
 * documentation of what a binding must do.
 */
export function referenceBinding(): BridgeBinding {
  const listeners = new Set<(s: { kind: string }) => void>()

  return {
    async runProbe(input, payload) {
      if (input === '') {
        throw toCryptoError({ name: 'Rejected', reason: 'input must not be empty' })
      }
      for (const l of listeners) l({ kind: 'probe_started' })
      return {
        echoed: input,
        payload: new Uint8Array(Array.from(payload).reverse()),
        coreVersion: '0.1.0',
      }
    },
    onCryptoSignal(cb) {
      listeners.add(cb)
      return () => listeners.delete(cb)
    },
    isCryptoError,
    errorKind: (e) => (isCryptoError(e) ? e.kind : undefined),
  }
}
