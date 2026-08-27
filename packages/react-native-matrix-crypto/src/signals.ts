import type { CryptoScopeId, TrustState } from './types'

/** Typed, silent by default. Takes no product decision. Spec sections 7, 11. */
export type CryptoSignal =
  | { kind: 'trust_changed'; user: string; state: TrustState }
  | { kind: 'unexpected_device'; scope: CryptoScopeId; user: string }
  | { kind: 'key_missing'; scope: CryptoScopeId }
  | { kind: 'probe_started'; detail: string }

export type Unsubscribe = () => void

const listeners = new Set<(s: CryptoSignal) => void>()

export function onCryptoSignal(cb: (s: CryptoSignal) => void): Unsubscribe {
  listeners.add(cb)
  return () => {
    listeners.delete(cb)
  }
}

/** Internal. Called by the shim when the native observer fires. */
export function emitCryptoSignal(signal: CryptoSignal): void {
  // Snapshot before dispatch: a listener that subscribes while we are
  // iterating must not receive the signal that triggered its own
  // registration. Unsubscribing mid-dispatch remains safe either way.
  for (const listener of [...listeners]) {
    try {
      listener(signal)
    } catch {
      // Isolate. One throwing listener must never starve the others: this
      // channel carries trust_changed, unexpected_device and key_missing,
      // and a buggy UI listener must not be able to suppress them.
      // Deliberately silent - the bridge has no logger.
    }
  }
}
