import { asCryptoScopeId } from './types'
import type { CryptoAlgorithm, CryptoScopeId, EventEnvelope } from './types'

// A bare string must NOT be assignable to CryptoScopeId.
// @ts-expect-error bare strings must go through asCryptoScopeId
const bad: CryptoScopeId = '!room:example.org'

// The branded constructor is the only way in.
const good: CryptoScopeId = asCryptoScopeId('!room:example.org')

// The algorithm union must stay open: an unknown algorithm is assignable,
// so adding MLS later is an additive change, not a breaking one.
const known: CryptoAlgorithm = 'megolm'
const future: CryptoAlgorithm = 'mls'
const fabricated: CryptoAlgorithm = 'x-fabricated-suite'

const envelope: EventEnvelope = {
  scope: good,
  algorithm: fabricated,
  eventType: 'm.room.message',
  ciphertext: new Uint8Array([1, 2, 3]),
  sender: '@a:server1',
}

void bad; void known; void future; void envelope
