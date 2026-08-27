import type { BridgeBinding } from './suite'
import { isCryptoError, toCryptoError } from '../src/errors'

/**
 * Pure-TypeScript restatement of the contract, used to exercise the suite in
 * Node where the JSI module cannot load. It doubles as executable
 * documentation of what a binding must do.
 */
export function referenceBinding(): BridgeBinding {
  return {
    async runProbe(input, payload, onSignal) {
      if (input === '') {
        // UniFFI-shaped, not a convenient fiction: `@ubjs/core`'s `UniffiError`
        // base class (confirmed by reading its source) never sets `.name` --
        // it stays the inherited "Error" -- and always sets `.message` to
        // exactly "<EnumTypeName>.<VariantName>", with the variant's payload
        // nested under `.inner`. A `{ name: 'Rejected', reason: '...' }`
        // fixture here once satisfied `toCryptoError`'s old, wrong reading of
        // that shape and hid a real production bug (Task 11) from every Node
        // test. See src/errors.ts's `variantNameFromMessage`/`stringField`.
        const uniffiShapedError = Object.assign(new Error('ProbeFfiError.Rejected'), {
          inner: { reason: 'input must not be empty' },
        })
        throw toCryptoError(uniffiShapedError)
      }
      // Called directly, on this call's own callback -- not dispatched to a
      // shared registry. Two concurrent `runProbe` calls against this same
      // binding each get their own closure and never see each other's kind.
      onSignal?.('probe_started')
      return {
        echoed: input,
        payload: new Uint8Array(Array.from(payload).reverse()),
        coreVersion: '0.1.0',
      }
    },
    isCryptoError,
    errorKind: (e) => (isCryptoError(e) ? e.kind : undefined),
  }
}
