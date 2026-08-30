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
  id:
    | 'subscribe'
    | 'call'
    | 'signal'
    | 'typedError'
    | 'identity'
    | 'signingIdentity'
    | 'senderCheck'
    | 'notYet'
    | 'layers'
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
      "The first subscriber installs this process's one native observer across the boundary, so the native side has somewhere to deliver to. No signal is in flight yet: this registers a listener for state changes that belong to no call, which is what a real consumer does before making calls, not after.",
    why: "The channel that carries trust changes and verification invitations. It is live: that logic landed, and this card said otherwise for a milestone after it did. Nothing arrives on it during this walkthrough for a narrower reason, which is that every signal on it is produced while sync changes are applied, and this walkthrough applies none. It never carries a single call's own diagnostic either: step 3 uses a different channel, on purpose.",
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
    id: 'signingIdentity',
    title: "6. Publish this account's signing identity",
    call: "import { bootstrapCrossSigning, getIdentityStatus, isCryptoError } from 'react-native-matrix-crypto';\n\nconst status = await getIdentityStatus();\n\ntry {\n  await bootstrapCrossSigning();\n} catch (e) {\n  if (isCryptoError(e) && e.kind === 'account_keys_not_fetched') {\n    // Ask the homeserver first: drain takeOutgoingRequests, send the\n    // key query this refusal already queued, report it with\n    // markRequestSent, then call bootstrapCrossSigning again.\n  }\n}",
    crosses:
      "Rust reads three separate facts about the account out of the live machine: whether a key query naming it has been answered in this process, whether this machine holds a public signing identity for it, and whether it holds the private half. Then it is asked to mint one, and refuses. The refusal crosses back as a typed error whose kind names the remedy. Nothing is minted and nothing is published.",
    why: "A signing identity is what lets one device vouch for another without a person comparing anything. Minting a second one over an account's existing identity resets the trust of every device and every person who ever verified that account, and there is no warning and nothing this process can afterwards detect. So the call refuses until the server has actually been asked. This walkthrough stops at the refusal on purpose: finishing the bootstrap means answering that key query, and answering it with a body this app invented is precisely the mistake the gate exists to prevent.",
  },
  {
    id: 'senderCheck',
    title: '7. What a decrypted event says about its sender',
    call: "import { asCryptoScopeId, decryptEvent, encryptEvent, shareScopeKey } from 'react-native-matrix-crypto';\n// utf8Decode is this app's own helper: React Native ships no TextDecoder.\n\nconst scope = asCryptoScopeId('!sender-demo:example.org');\nawait shareScopeKey(scope, ['@alice:example.org']);\n\nconst sealed = await encryptEvent(scope, 'm.room.message', {\n  msgtype: 'm.text',\n  body: 'who sent this?',\n});\nconst opened = await decryptEvent(scope, {\n  sender: sealed.sender,\n  event_id: '$sender-demo:example.org',\n  origin_server_ts: 1700000000000,\n  content: JSON.parse(utf8Decode(sealed.ciphertext)),\n});\n\nconsole.log(opened.senderVerification);\n// { state: 'unverified', reason: 'unsigned_device' }",
    crosses:
      'A group session is created, one payload is encrypted with it, and the resulting event is handed straight back to be decrypted. What comes back alongside the plaintext is this library reporting what it knew about the sending device at the moment it decrypted: a value with a stable state and, when the state is unverified, a reason.',
    why: "The reason is 'unsigned_device' here, and it is the honest answer rather than a placeholder. The device that sent this event carries no signature from an identity its owner published, because step 6 refused to publish one. This value never asks whether you trust the sender; it says what evidence exists. A product decides what to show from that, and the branch above is the one every product meets first.",
  },
  {
    id: 'notYet',
    title: '8. Not implemented yet -- on purpose',
    call: "import { exportSecrets } from 'react-native-matrix-crypto';\n\nawait exportSecrets(passphrase);",
    crosses:
      'Nothing crosses to native code at all. The facade rejects before making a call, with a typed not_implemented error.',
    why: "A few functions in this library's product surface are final, compiling types with the implementation still to come. Shown as a feature, not a gap: product code can be written against the real shape today, and starts working the moment the native side lands. This card has pointed at two other functions before this one, encryptEvent and then getDeviceStatuses, and each time the library implemented what the card called missing and this card went on claiming it for a milestone. What has changed is not the wording, which had been corrected before and rotted anyway: a host-side test now calls this exact function on every CI run, so the next time it stops rejecting the build turns red before anyone sees this card turn red on a phone.",
  },
  {
    id: 'layers',
    title: '9. Where the layers are',
    call: '// No call -- everything above already crossed all five.',
    crosses: 'Nothing new here. A summary of what every step above actually passed through.',
    why: 'Five layers, each doing one job: the TypeScript facade (types the public surface), generated bindings (translate types), the JSI Turbo Module (crosses the JS/native boundary), UniFFI scaffolding (matches Rust to JavaScript), and the Rust core (the cryptography itself).',
  },
]
