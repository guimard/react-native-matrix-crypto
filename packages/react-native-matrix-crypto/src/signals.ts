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

/**
 * Subscribes to the crypto signal channel. Returns an unsubscribe function.
 *
 * **Nothing emits a signal in M2, so a listener registered here never
 * fires.** The channel itself is real -- subscribing, unsubscribing,
 * fan-out and listener isolation all work and are tested -- but
 * `emitCryptoSignal`, the only thing that can deliver to it, has no caller
 * in the shipped library. No native path routes into it, and `runProbe`'s
 * `onProbeSignal` is a deliberately separate per-call channel that never
 * reaches this one (see `probe.ts`).
 *
 * This is stated rather than left to be discovered because M2 is the
 * milestone that starts producing the *conditions* these variants name.
 * A `missing_key` decryption failure is now an ordinary occurrence and it
 * arrives as a rejected promise from `decryptEvent`, never as a
 * `key_missing` signal here. A product that wires a UI to this channel and
 * waits gets silence, not an error.
 *
 * **When that changes is not yet settled.** The earliest producer would be
 * the device verification work in M3, whose `trust_changed` state has an
 * obvious home in this union -- but the M3 design leaves it an open
 * question (§7, Q8) whether verification state rides this channel at all
 * or gets a call-shaped surface instead, because turning this into a real
 * event stream makes its per-signal thread and its latency
 * product-visible at the same moment. So subscribe if it costs nothing to
 * be ready; do not build a flow that depends on being told.
 */
export function onCryptoSignal(cb: (s: CryptoSignal) => void): Unsubscribe {
  listeners.add(cb)
  return () => {
    listeners.delete(cb)
  }
}

/**
 * Internal. Called by the shim when the native observer fires.
 *
 * Nothing calls it in M2 outside this module's own tests: no native path
 * produces a `CryptoSignal` yet. That is why `onCryptoSignal` documents
 * itself as never firing. Kept, and kept tested, so the channel is proven
 * before the first producer needs it rather than after.
 */
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
