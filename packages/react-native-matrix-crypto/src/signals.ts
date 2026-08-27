import type { CryptoScopeId, TrustState } from './types'

/**
 * Typed, silent by default. Takes no product decision. Spec sections 7, 11.
 *
 * Exactly the three variants spec section 7.3 defines: state changes that
 * belong to no call in flight and every subscriber should learn about.
 * `runProbe`'s own diagnostic (`probe_started`) is not one of these -- it is
 * a per-call result of that function, not a crypto state change, so it
 * never reaches this union or this channel. See `probe.ts`'s `ProbeSignal`
 * and its `runProbe` comment.
 */
export type CryptoSignal =
  | { kind: 'trust_changed'; user: string; state: TrustState }
  | { kind: 'unexpected_device'; scope: CryptoScopeId; user: string }
  | { kind: 'key_missing'; scope: CryptoScopeId }

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
