// The public API. Consumers import from here and nowhere else.
// Nothing from ./generated is re-exported: spec section 5 forbids leaking
// internal Rust structure.

export type { CryptoAlgorithm, CryptoScopeId, EventEnvelope, TrustState } from './types'
export { asCryptoScopeId } from './types'

export type { CryptoError, CryptoErrorKind } from './errors'
export { isCryptoError } from './errors'

export type { CryptoSignal, Unsubscribe } from './signals'
export { onCryptoSignal } from './signals'

export type { ProbeResult } from './probe'
export { runProbe } from './probe'

export type { CryptoMachineConfig, DeviceStatus } from './facade'
export {
  confirmVerification,
  createCryptoMachine,
  decryptEvent,
  encryptEvent,
  exportSecrets,
  getDeviceStatuses,
  getSupportedAlgorithms,
  importSecrets,
  openCryptoStore,
  receiveSyncChanges,
  requestVerification,
  restoreCryptoMachine,
} from './facade'
