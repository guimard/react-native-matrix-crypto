import { asCryptoScopeId } from './types'
import type {
  CryptoAlgorithm,
  CryptoScopeId,
  EventEnvelope,
  SasMaterial,
  TrustState,
  VerificationStage,
} from './types'

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

// `TrustState` and `VerificationStage` are CLOSED, unlike `CryptoAlgorithm`
// above. That is the opposite property and it needs the opposite assertion:
// a value outside the union must be a compile error, so a product can switch
// on either exhaustively and be told by the compiler when a later version
// adds a case.
// @ts-expect-error TrustState is closed: a value outside the union is not assignable
const fabricatedTrust: TrustState = 'x-fabricated-trust'
// @ts-expect-error VerificationStage is closed: a value outside the union is not assignable
const fabricatedStage: VerificationStage = 'x-fabricated-stage'

const trust: TrustState = 'verified'
const stage: VerificationStage = 'keys-exchanged'

// The digits are a fixed-length tuple, not an array: a caller cannot index
// past the end of something it believed had three entries, and a record
// carrying the wrong number of them does not compile.
// @ts-expect-error the short authentication string has exactly three digits
const shortMaterial: SasMaterial = { decimals: [1, 2] }

// The symbol form is optional, because the protocol only produces it when
// both sides negotiated it. A screen offering only symbols has a live path
// with nothing to show, and this is where that is visible.
const digitsOnly: SasMaterial = { decimals: [1, 2, 3] }
const withSymbols: SasMaterial = {
  decimals: [1, 2, 3],
  emoji: [{ symbol: 'x', description: 'a word' }],
}

void bad; void known; void future; void envelope
void fabricatedTrust; void fabricatedStage; void trust; void stage
void shortMaterial; void digitsOnly; void withSymbols
