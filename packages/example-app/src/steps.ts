/**
 * Static description of each step in the guided flow: the exact call, what
 * physically crosses the JS/native boundary, and why the step exists.
 *
 * Execution lives in GuidedFlow.tsx, not here: some steps depend on state
 * an earlier one produced (step 3 reads the signal step 2's own call
 * caught, via the callback runProbe accepts directly -- not step 1's
 * listener, which is a separate channel demonstrated for its own sake),
 * which a purely static list cannot express on its own.
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
      'Nothing yet. This registers a listener for state changes that belong to no call in flight -- a real consumer subscribes before making calls, not after.',
    why: "The channel that will carry trust changes and key gaps once that logic lands. Nothing arrives on it in this walkthrough -- this milestone has no trust logic yet -- and it never carries a single call's own diagnostic either: step 3 uses a different channel, on purpose.",
  },
  {
    id: 'call',
    title: '2. Round-trip a record and bytes',
    call: "import { runProbe } from 'react-native-matrix-crypto';\n\nconst result = await runProbe(\n  'hello',\n  new Uint8Array([1, 2, 3]),\n  signal => console.log(signal.kind),\n);",
    crosses:
      "A string and three bytes cross via JSI into the Rust core, which reverses the bytes and reports its own crate version -- proof this is the real crate replying, not a mock echoing its input back unread. The third argument also receives a callback invocation from Rust while the call is still running. That callback and the call's own result travel back independently, so this step is not finished until both have settled: the result is back, and the callback has either arrived or used up the time this library allows it. Step 3 then reports what it caught, waiting for nothing itself.",
    why: 'The most basic proof this library does anything at all: a call reaches Rust and comes back.',
  },
  {
    id: 'signal',
    title: '3. Observe the signal that arrived',
    call: "// No call here -- this reads what step 2's own callback\n// already caught while that call was still running.",
    crosses:
      "Rust invoked the callback passed into step 2's runProbe call, directly across the boundary, while that call was still in flight -- scoped to that one call, never dispatched anywhere else.",
    why: "Requests aren't the only direction data crosses this boundary -- this proves the UniFFI callback interface works in reverse too (native code calling back into JS). Deliberately not step 1's channel: broadcasting a single call's own diagnostic to every subscriber is exactly what would make two independent screens see each other's signal.",
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
    call: "import { createCryptoMachine, getDeviceIdentityKeys } from 'react-native-matrix-crypto';\n\nawait createCryptoMachine({\n  userId: '@alice:example.org',\n  deviceId: 'DEVICE1',\n  storePath, // from this app's own native code\n  storePassphrase,\n});\n\nconst keys = await getDeviceIdentityKeys(\n  '@alice:example.org',\n  'DEVICE1',\n);",
    crosses:
      "Rust opens a real, passphrase-encrypted crypto store on disk, builds this device's crypto machine on top of it, and returns that machine's actual public Curve25519 and Ed25519 identity keys -- 32 raw bytes each, base64-encoded. Not placeholders, and not a throwaway machine either: these are the keys everything else on this screen encrypts and decrypts with.",
    why: "Everything before this line was plumbing. This is the first genuine cryptographic value in the flow. The store path comes from this app's own native code, not from the library: a crypto library that picks its own on-disk location writes somewhere the product did not agree to.",
  },
  {
    id: 'notYet',
    title: '6. Not implemented yet -- on purpose',
    call: "import { getDeviceStatuses } from 'react-native-matrix-crypto';\n\nawait getDeviceStatuses('@alice:example.org');",
    crosses:
      'Nothing crosses to native code at all. The facade rejects before making a call, with a typed not_implemented error.',
    why: "Five more functions in this library's product surface share this shape: final, compiling types with the implementation still to come. Shown as a feature, not a gap -- product code can be written against the real shape today, and starts working the moment the native side lands. This card used to demonstrate encryptEvent; that one now works, which the diagnostics below prove on this device, so the example moved to a function still genuinely waiting on trust establishment.",
  },
  {
    id: 'layers',
    title: '7. Where the layers are',
    call: '// No call -- everything above already crossed all five.',
    crosses: 'Nothing new here. A summary of what every step above actually passed through.',
    why: 'Five layers, each doing one job: the TypeScript facade (types the public surface), generated bindings (translate types), the JSI Turbo Module (crosses the JS/native boundary), UniFFI scaffolding (matches Rust to JavaScript), and the Rust core (the cryptography itself).',
  },
]
