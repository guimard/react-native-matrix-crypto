import { asCryptoScopeId } from './types'
import type {
  CryptoAlgorithm,
  CryptoScopeId,
  EventEnvelope,
  SasMaterial,
  SenderVerification,
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

// The authenticity field is optional, because one type describes both
// directions and only one of them has a value for it. An envelope without
// it is the encrypt direction and must still compile.
const envelope: EventEnvelope = {
  scope: good,
  algorithm: fabricated,
  eventType: 'm.room.message',
  ciphertext: new Uint8Array([1, 2, 3]),
  sender: '@a:server1',
}

const decrypted: EventEnvelope = {
  ...envelope,
  senderVerification: { state: 'unverified', reason: 'mismatched_sender' },
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

// `SenderVerification` is CLOSED too, and closed in two places at once: the
// `state` tag and the `reason` behind it. A product switching on both
// exhaustively must be told by the compiler when a later version adds a
// case, which is the entire argument for declaring the three values this
// release cannot produce rather than adding them later.
// @ts-expect-error SenderVerification is closed: a fabricated state is not assignable
const fabricatedState: SenderVerification = { state: 'x-fabricated-state' }
// @ts-expect-error SenderVerification is closed: a fabricated reason is not assignable
const fabricatedReason: SenderVerification = { state: 'unverified', reason: 'x-fabricated' }
// `no_device` is the one member carrying a third field, and it is required:
// "we could not link this event to a device" is not a complete answer
// without which of the two reasons it was.
// @ts-expect-error no_device must say which problem it is
const problemless: SenderVerification = { state: 'unverified', reason: 'no_device' }
// And `verified` carries no reason, because there is nothing to explain.
// @ts-expect-error a verified sender has no reason to give
const reasoned: SenderVerification = { state: 'verified', reason: 'unsigned_device' }

// The values this release can actually produce.
const unsigned: SenderVerification = { state: 'unverified', reason: 'unsigned_device' }
const impersonated: SenderVerification = { state: 'unverified', reason: 'mismatched_sender' }
const undeliverable: SenderVerification = {
  state: 'unverified',
  reason: 'no_device',
  problem: 'insecure_source',
}

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

void bad; void known; void future; void envelope; void decrypted
void fabricatedTrust; void fabricatedStage; void trust; void stage
void shortMaterial; void digitsOnly; void withSymbols
void fabricatedState; void fabricatedReason; void problemless; void reasoned
void unsigned; void impersonated; void undeliverable
