import type { CryptoAlgorithm, CryptoScopeId, EventEnvelope, TrustState } from './types'
import { toCryptoError } from './errors'

function notImplemented(name: string): Promise<never> {
  return Promise.reject(toCryptoError({ name: 'NotImplemented', reason: `${name} is not implemented yet` }))
}

// Spec section 5's surface, re-typed onto the branded scope and the open
// algorithm tag. Types are real so consumers can compile today; runtime
// arrives in M2.

export interface CryptoMachineConfig {
  userId: string
  deviceId: string
  storePath: string
}

export interface DeviceStatus {
  deviceId: string
  trust: TrustState
}

export function createCryptoMachine(_config: CryptoMachineConfig): Promise<void> {
  return notImplemented('createCryptoMachine')
}

export function openCryptoStore(_config: CryptoMachineConfig): Promise<void> {
  return notImplemented('openCryptoStore')
}

export function restoreCryptoMachine(_bundle: Uint8Array): Promise<void> {
  return notImplemented('restoreCryptoMachine')
}

export function receiveSyncChanges(_syncDelta: unknown): Promise<void> {
  return notImplemented('receiveSyncChanges')
}

export function encryptEvent(
  _scope: CryptoScopeId,
  _eventType: string,
  _payload: unknown,
): Promise<EventEnvelope> {
  return notImplemented('encryptEvent')
}

export function decryptEvent(_rawEvent: unknown): Promise<EventEnvelope> {
  return notImplemented('decryptEvent')
}

export function getDeviceStatuses(_userId: string): Promise<DeviceStatus[]> {
  return notImplemented('getDeviceStatuses')
}

export function requestVerification(_userId: string, _deviceId: string): Promise<string> {
  return notImplemented('requestVerification')
}

export function confirmVerification(_verificationId: string, _data: unknown): Promise<void> {
  return notImplemented('confirmVerification')
}

export function exportSecrets(_passphrase: string): Promise<Uint8Array> {
  return notImplemented('exportSecrets')
}

export function importSecrets(_bundle: Uint8Array, _passphrase: string): Promise<void> {
  return notImplemented('importSecrets')
}

/** Algorithms this build can carry. Open by design; see spec section 6. */
export function getSupportedAlgorithms(): CryptoAlgorithm[] {
  return ['megolm', 'olm']
}
