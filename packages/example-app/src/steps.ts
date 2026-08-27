/**
 * Static description of each step in the guided flow: the exact call, what
 * physically crosses the JS/native boundary, and why the step exists.
 *
 * Execution lives in GuidedFlow.tsx, not here: several steps depend on
 * state an earlier one produced (step 3 reads a signal that step 1's
 * listener caught and step 2's call caused Rust to emit), which a purely
 * static list cannot express on its own.
 */
export interface FlowStep {
  id: 'subscribe' | 'call' | 'signal' | 'typedError' | 'identity' | 'notYet' | 'layers'
  title: string
  /** The exact TypeScript a consumer would write. */
  call: string
  /** What physically crosses the JS/native boundary, in one line. */
  crosses: string
  /** Why this step exists -- the property it demonstrates. */
  why: string
}

export const FLOW_STEPS: FlowStep[] = [
  {
    id: 'subscribe',
    title: '1. Subscribe to signals',
    call: "import { onCryptoSignal } from 'react-native-matrix-crypto';\n\nconst unsubscribe = onCryptoSignal(signal => {\n  console.log(signal.kind);\n});",
    crosses:
      'Nothing yet. This registers a listener for events that belong to no call in flight -- a real consumer subscribes before making calls, not after.',
    why: 'Sets up the channel step 3 reads from. In production this same channel carries trust changes and key gaps, not just this probe.',
  },
  {
    id: 'call',
    title: '2. Round-trip a record and bytes',
    call: "import { runProbe } from 'react-native-matrix-crypto';\n\nconst result = await runProbe('hello', new Uint8Array([1, 2, 3]));",
    crosses:
      'A string and three bytes cross via JSI into the Rust core, which reverses the bytes and reports its own crate version -- proof this is the real crate replying, not a mock echoing its input back unread.',
    why: 'The most basic proof this library does anything at all: a call reaches Rust and comes back.',
  },
  {
    id: 'signal',
    title: '3. Observe the signal that arrived',
    call: '// No call here -- this reads what step 2 already caused Rust to\n// emit back across the boundary, through the listener from step 1.',
    crosses:
      'Rust invoked the step 1 callback across the boundary while the step 2 call was still running; the binding turned it into a typed signal and dispatched it to every subscriber.',
    why: "Requests aren't the only channel. This is the same push mechanism that carries trust changes and key gaps in production, proven here with the probe's own signal.",
  },
  {
    id: 'typedError',
    title: '4. A typed error, on purpose',
    call: "import { isCryptoError, runProbe } from 'react-native-matrix-crypto';\n\ntry {\n  await runProbe('', new Uint8Array());\n} catch (e) {\n  if (isCryptoError(e)) {\n    console.log(e.kind); // 'rejected'\n  }\n}",
    crosses:
      "Rust rejects the empty input and returns a typed error variant; the library normalizes it into a CryptoError with a stable .kind field. Only the reason string is ever copied in -- payload content and ciphertext are never read, so they can't reach a crash report.",
    why: 'This step deliberately makes a bad call, to prove the failure path works, not the success path.',
  },
  {
    id: 'identity',
    title: '5. Real cryptography',
    call: "import { getDeviceIdentityKeys } from 'react-native-matrix-crypto';\n\nconst keys = await getDeviceIdentityKeys(\n  '@alice:example.org',\n  'DEVICE1',\n);",
    crosses:
      'Rust builds a real device crypto machine in memory for this user and device, and returns its actual public Curve25519 and Ed25519 identity keys -- 32 raw bytes each, base64-encoded. Not placeholders.',
    why: 'Everything before this line was plumbing. This is the first genuine cryptographic value in the flow.',
  },
  {
    id: 'notYet',
    title: '6. Not implemented yet -- on purpose',
    call: "import { asCryptoScopeId, encryptEvent } from 'react-native-matrix-crypto';\n\nawait encryptEvent(\n  asCryptoScopeId('!crypto-demo:example.org'),\n  'm.room.message',\n  { body: 'hello' },\n);",
    crosses:
      'Nothing crosses to native code at all. The facade rejects before making a call, with a typed not_implemented error.',
    why: "Ten more functions in this library's product surface share this shape: final, compiling types with the implementation still to come. Shown as a feature, not a gap -- product code can be written against the real shape today, and starts working the moment the native side lands.",
  },
  {
    id: 'layers',
    title: '7. Where the layers are',
    call: '// No call -- everything above already crossed all five.',
    crosses: 'Nothing new here. A summary of what every step above actually passed through.',
    why: 'Five layers, each doing one job: the TypeScript facade (types the public surface), generated bindings (translate types), the JSI Turbo Module (crosses the JS/native boundary), UniFFI scaffolding (matches Rust to JavaScript), and the Rust core (the cryptography itself).',
  },
]
