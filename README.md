# react-native-matrix-crypto

A React Native bridge for Matrix cryptography.

It exposes the modern Matrix end-to-end encryption stack, [`matrix-sdk-crypto`](https://github.com/matrix-org/matrix-rust-sdk/tree/main/crates/matrix-sdk-crypto), which is the same Rust implementation Element uses, to a React Native application through a small, typed TypeScript surface.

## Architecture

Six layers, each doing one job. A call travels down and its result travels back up.

```
┌───────────────────────────────────────────────────────────┐
│ Your application                                          │
│   import { encryptEvent } from 'react-native-matrix-crypto'
└──────────────────────────┬────────────────────────────────┘
                           │
┌──────────────────────────▼────────────────────────────────┐
│ TypeScript facade                    src/*.ts             │
│   branded types, error normalisation, the public API      │
└──────────────────────────┬────────────────────────────────┘
                           │
┌──────────────────────────▼────────────────────────────────┐
│ Generated bindings                   src/generated/       │
│   emitted by uniffi-bindgen-react-native, never edited    │
└──────────────────────────┬────────────────────────────────┘
                           │
┌──────────────────────────▼────────────────────────────────┐
│ JSI Turbo Module                     cpp/generated/       │
│   the JavaScript / native boundary                        │
└──────────────────────────┬────────────────────────────────┘
                           │
┌──────────────────────────▼────────────────────────────────┐
│ UniFFI scaffolding                   matrix-crypto-ffi    │
│   type mirroring and delegation only, no logic            │
└──────────────────────────┬────────────────────────────────┘
                           │
┌──────────────────────────▼────────────────────────────────┐
│ Rust core                            matrix-crypto-core   │
│   all logic, wrapping matrix-sdk-crypto                   │
└───────────────────────────────────────────────────────────┘
```

## What this is not

This matters more than what it is, and it is the first thing worth knowing.

**This library does not talk to a homeserver.** There is no login, no `/sync`, no sending, no room state, no timeline. It is a cryptographic engine: you hand it an event, it hands you back an encrypted one, and the reverse. Transport is your application's job.

That boundary is deliberate and enforced. The same separation exists upstream between `matrix-sdk-crypto` and the full `matrix-sdk`, for the same reason: a crypto engine that also owns networking is far harder to audit, reuse and reason about.

So this library is **not**:

* a Matrix client SDK. See [`matrix-js-sdk`](https://github.com/matrix-org/matrix-js-sdk) if that is what you need.
* a replacement for a homeserver connection.
* tied to any particular product, backend or deployment.

It is a reusable component. Any React Native project can consume it without carrying configuration that belongs to someone else's product.

## Status

**The bridge chain is complete and proven. Encryption works, and a third-party Matrix client decrypts what this library produces over a real homeserver.**

Being precise about that, because a cryptographic library that oversells itself is worse than one that admits its state.

| Capability | State |
|---|---|
| Rust to UniFFI to JSI to TypeScript chain | working, verified on an iOS simulator and an Android emulator |
| Byte-accurate marshalling across the boundary | verified |
| Typed errors crossing the FFI boundary | verified |
| Callback interface, Rust to JavaScript | verified |
| Real `OlmMachine` identity keys | working |
| Persistent encrypted store, surviving restart | working |
| Encryption and decryption | working, proven between two crypto machines |
| Interoperability with a third-party Matrix client | proven both directions against `matrix-nio`, over a real homeserver |
| Crypto signal channel (`onCryptoSignal`) | working for verification: inbound invitations and completed comparisons emit; the other two variants still have no producer, see below |
| Sender authenticity, per event | **not provided, and not coming in M3**, see below |
| Device verification by short string comparison (SAS) | working, proven against a bare `matrix-sdk-crypto` machine driven directly -- upstream's own, not a third-party implementation; a third-party proof is still to come |
| Device verification by QR code | **deferred**, see the roadmap |
| Secret export and import | **not implemented**, see the roadmap |

The unimplemented functions exist today as final types that compile, and reject at runtime with a typed `not_implemented` error. That is intentional: a consuming team can build against the real shape while the cryptography underneath is written.

`onCryptoSignal` had no producer for the whole of M1 and M2, and now has two, both belonging to device verification. `verification_requested` says another device has asked to verify itself against this one, and carries the `verificationId` that `acceptVerification` takes -- it is the only way *this library* hands a receiving side that identifier, since no call lists inbound flows. `trust_changed` says a comparison finished and a device belonging to that user moved; `getDeviceStatuses` for that user says which. The other two variants, `unexpected_device` and `key_missing`, still have no producer, and the conditions they name reach you elsewhere: a missing key arrives as a rejected `decryptEvent` with kind `missing_key`, not as a `key_missing` signal. **Subscribe before your first sync**, and keep the subscription. Both producers run inside `receiveSyncChanges`, and nothing is consumed while nobody is subscribed -- so an invitation that arrives while you are away is announced on the first sync after you come back, and the ordinary `useEffect(() => onCryptoSignal(h), [])` does not lose invitations.

**Two limits worth knowing before you build on this.**

Decryption does not authenticate the sender. `EventEnvelope.sender` is the value the homeserver delivered, and a successfully decrypted event does not prove who sent it. **Verifying a device does not change this**, and it is worth being blunt about that, because "verification landed" is exactly the sentence that would make a reader assume otherwise: a short string comparison establishes *local* trust in a device, and the path that decides what a decrypted event says about its sender consults *cross-signing*, which nothing here publishes yet. So a device can read `verified` from `getDeviceStatuses` while an event from that same device still carries an unauthenticated sender. Treat `sender` and `algorithm` as unauthenticated transport metadata until cross-signing lands.

What a decrypted event *does* now carry is how little it is claiming. `EventEnvelope.senderVerification` reports what this library knew about the sender at the moment it decrypted, in its own vocabulary rather than folded into `TrustState` -- two subjects, so two types. **It cannot read `verified` in this release**, for the reason the paragraph above gives, and that is documented at the type rather than left for you to discover; three of its six values need cross-signing and are marked unreachable at the type and at each member. What it can do is tell an ordinary unsigned device apart from `mismatched_sender`, which says the sender the event claims is not the owner of the session that encrypted it -- decryption succeeded and the `sender` field is still false. That is an impersonation signal and it is the one value here worth reacting to on its own. It is also a **snapshot taken at decryption time**: upstream defines it as the state of the sending device then, and tells callers who persist it to mark it dirty when a device change arrives down the sync -- `device_lists.changed`, which you are already passing to `receiveSyncChanges`. Nothing re-derives a stored value for you.

**This section used to say that authentication "comes from device verification", and that was wrong.** The claim is retracted rather than quietly edited, because it shipped in `0.1.0-rc.2` and a reader who saw it needs to know which half changed. Upstream's `SenderData::from_device` branches on whether the sending device is cross-signed and then on whether that signature is trusted; it never consults local trust, which is all a string comparison sets. Established against `matrix-sdk-crypto` 0.18.0 rather than assumed, and reasoned through in the M3 design, section 7, question 6.

The interoperability proof has a floor, and it is the ratchet. `matrix-nio`, a Matrix client written in Python by people who have never seen this code, decrypts what this library encrypts and this library decrypts what it sends, over a real homeserver, in two tests anyone can run: one driving the Rust core, one driving the published TypeScript API on an emulator. What neither proves is the ratchet itself. `matrix-nio` 0.26 and this library both call `vodozemac 0.10.0`, so a defect inside that crate, or a misreading shared below the protocol line, would pass both sides. What is genuinely tested by two independent implementations is everything above it: event shapes, the `/keys/*` payloads a real homeserver accepts and answers, to-device routing, and the order a session key has to travel in. That is where this library's own code lives.

Verified end to end on an iOS simulator and on an Android emulator: a record round trip, a byte array returned reversed to prove Rust genuinely read it, an async call resolving as a Promise, a typed error reaching a JavaScript `catch`, one callback signal travelling back from Rust, and a real Curve25519 and Ed25519 key pair.

## Installation

```sh
yarn add react-native-matrix-crypto
```

A plain `yarn add` always resolves npm's `latest` tag, and a prerelease is published under its own tag, so `yarn add react-native-matrix-crypto@rc` is how you ask for one on purpose.

**While this package is pre-1.0, that is not yet enough to keep one away by accident.** npm assigns `latest` to the *first* version published to a new package whatever `--tag` says, because a package must always have a `latest`. `0.1.0-rc.2` was that first version, so today `latest` and `rc` point at the same prerelease and a bare `yarn add` gets it. npm does not allow the `latest` tag to be deleted, so this resolves when the first stable version is published and takes `latest` over -- not before. `scripts/assert-published-tags.sh` reads the tags back off the registry after every publish and says which state you are in, because the pre-publish check could only ever verify the tag npm was *told*, never the one npm *applied*.

**No Rust toolchain is required.** The published package ships prebuilt binaries: an `.xcframework` for iOS, and for Android a prebuilt Rust library per ABI under `android/src/main/jniLibs/`, which this module's `CMakeLists.txt` links when your app autolinks it and builds its C++ from source. `yarn add` is all you need.

Two different checks stand behind that sentence, and they establish different things.

**On every pull request,** a job packs this repository, installs the result on a machine with every directory carrying `cargo` or `rustc` scrubbed out of `PATH`, and asserts that the installed package declares no `preinstall`, `install`, `postinstall` or `prepare` script and ships no `binding.gyp` — so nothing in it can reach for a compiler on your machine either. It does not check the binaries, and cannot: they are build outputs, ignored by git, so the tarball a pull request is able to pack contains none of them.

**At publication,** the release workflow does. It builds both platforms in full, packs one tarball, and then opens that tarball and reads what is inside: every slice the `.xcframework` advertises and a prebuilt Rust library for every ABI `android/build.gradle` declares — each large enough and with the right magic number to be real compiled code rather than a placeholder. Only then does it install those exact bytes on a machine with `cargo` and `rustc` unreachable, bundle and run the entry point out of the installed package the way your app's bundler would, and publish the tarball it checked, with [npm provenance](https://docs.npmjs.com/generating-provenance-statements) so the registry can show which workflow run produced what you downloaded.

Neither of those runs the cryptography. Loading the module in a plain Node process stops where it calls into the native library, because a JSI turbo module needs a React Native runtime. Running the shipped chain end to end is the Android emulator job's business, and the interoperability proof below is where a third party client checks the result.

A prebuilt `react-native-matrix-crypto-release.aar` used to sit at the package root too, and nothing ever consumed it: autolinking builds `android/build.gradle` as a Gradle subproject from source, and no gradle file, podspec or `CMakeLists.txt` in this repository ever named that archive. It duplicated the per-ABI libraries above at thirteen percent of the unpacked package, so it was dropped from `package.json`'s `files` rather than kept as a feature nobody could reach.

### Requirements

* React Native 0.87 or later, with the New Architecture enabled. This is a JSI Turbo Module.
* React 19.2 or later
* iOS 13 or later, Android API 24 or later

### Platform support

| Platform | Architectures |
|---|---|
| iOS | `arm64` device, `arm64` simulator, `x86_64` simulator |
| Android | `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86` |

## Usage

What works today:

```ts
import { getDeviceIdentityKeys } from 'react-native-matrix-crypto'

// Real cryptography. Creates an OlmMachine and returns its public identity keys.
const keys = await getDeviceIdentityKeys('@alice:example.org', 'DEVICE1')
// { curve25519: '...', ed25519: '...' }  43-character base64 each
```

### Encrypting, and the one ordering rule you cannot skip

This library performs no network requests. It hands you a list of requests to send and
expects you to tell it when you have sent them. That is not a detail: **a key reaches
another device only through requests you send**, so a product that never drains the
queue encrypts to nobody, silently and with no error.

```ts
import {
  createCryptoMachine, shareScopeKey, takeOutgoingRequests, markRequestSent,
  encryptEvent, decryptEvent, asCryptoScopeId,
} from 'react-native-matrix-crypto'

await createCryptoMachine({
  userId: '@alice:example.org',
  deviceId: 'DEVICE1',
  storePath: `${documentsDir}/crypto`,
  storePassphrase: secret,   // null is allowed, and means unencrypted at rest
})

const scope = asCryptoScopeId('!s:example.org')

// Drain and send. Do this after every call that changes crypto state.
// One drain at a time: see the note below before you make this concurrent.
async function pump() {
  for (const request of await takeOutgoingRequests()) {
    const response = await yourHomeserverClient.send(request)  // your transport
    await markRequestSent(request.id, response)
  }
}

await pump()                                   // publishes this device's keys
await shareScopeKey(scope, ['@bob:example.org'])
await pump()                                   // asks the server about Bob's devices
await shareScopeKey(scope, ['@bob:example.org'])
await pump()                                   // now the key actually travels
```

**The first `shareScopeKey` for a user you have never encrypted to delivers nothing,
and that is correct.** It starts tracking them and queues a query about their devices.
That query only reaches your homeserver when you drain the queue, so nobody is known to
share with yet. Call it again after pumping. The library cannot collapse these steps,
because it sends nothing itself and therefore cannot wait for a reply.

**Do not let a second drain overlap an unfinished one.** `takeOutgoingRequests` hands
out three kinds that describe a standing need rather than one message, `keys_upload`,
`keys_query` and `keys_claim`, and a later call that hands out a fresh request of one
of those kinds retires the older id: `markRequestSent` then rejects it with
`unknown_request`. That is deliberate, because the machine mints a new id for the same
need each time and forgets the old one, but it means two pumps racing, or a pump on a
timer alongside a pump after a write, will fail on ids you are legitimately holding. If
you do see `unknown_request` for an id from an earlier batch, discard that response and
pump again rather than retrying it; nothing is lost, because the need was re-derived
rather than dropped. `takeOutgoingRequests`' own doc comment carries the full rule.

**Send the requests within one batch in the order you were given them**, one at a time:
each has to reach your homeserver before you send the next. *Marking* them is a different
matter and is not ordered at all -- `markRequestSent` is a lookup by id, so you may mark
them in whatever order the responses come back, and you need not wait for one to be marked
before sending the next.

Up to and including `0.1.0-rc.2` this section said the opposite: that sending and marking
within one batch could both be concurrent. That was true of every request the library
could then produce, and it stopped being true when device verification arrived. A
verification ends with a confirmation followed by an acknowledgement, and the other
device **silently discards** an acknowledgement that reaches it before the
confirmation it acknowledges: it then waits for one that has already been sent, while
your side completes and records the other device as verified. Neither side is told. The
library orders the batch it hands you correctly, across both of the places those requests
come from, but it never sees your requests leave, so preserving that order is yours to
do.

### Verifying a device

Two people compare a seven-symbol string, read off their two screens, over a channel this
library did not establish -- in person, or on a call they already trust. If it matches, each
side records the other's device as verified. If it does not, the flow is cancelled and
nothing is recorded. That refusal is the point: a comparison that can only ever agree proves
nothing.

A flow is named by an opaque id. Hand it back verbatim; parse nothing out of it.

**Both sides must already know each other's devices before any of this.** A verification
cannot be started against, or accepted from, a device this library has never been told
about: track the user, drain the `keys_query` and report it with `markRequestSent`, and
check that `getDeviceStatuses` for that user answers non-empty. On the receiving side this
is not merely a precondition that errors -- see the warning after the second listing.

The side that asks:

```ts
const id = await requestVerification('@bob:example.org', 'BOBDEVICE')
// pump: takeOutgoingRequests -> send in order -> markRequestSent each

// Wait for the other side to agree. Their answer arrives in a later /sync,
// which you feed to receiveSyncChanges as usual; then this reads 'ready':
await getVerificationStage(id)

await startVerificationComparison(id) // either side may; pump again
// Keep pumping until the stage reads 'keys-exchanged'.

const material = await getVerificationMaterial(id)
// Show material.emoji (or material.decimals) to a person and ask.

await confirmVerification(id, material) // or cancelVerification(id)
// Pump once more. The stage reaches 'done', and only then:
await getDeviceStatuses('@bob:example.org') // BOBDEVICE reads 'verified'
```

**The side that is asked is a different application, in a different process, and the signal
channel is what hands it an id.** Subscribe once, at start-up, and forward your syncs as
usual:

```ts
onCryptoSignal((signal) => {
  if (signal.kind !== 'verification_requested') return
  // signal.user and signal.device say who is asking.
  // Ask the person. Then:
  acceptVerification(signal.verificationId) // or cancelVerification to refuse
  // pump, and carry on from `startVerificationComparison` above.
})

// Forward the sync. This is what makes the flow exist, and what announces it.
await receiveSyncChanges(encryptionSlice(sync))
```

**Subscribe before your first sync, and keep the subscription.** Nothing is queued for a
subscriber that is not there -- and nothing is consumed either, because the layer underneath
does no work at all with nobody subscribed. An invitation that arrives while you are
unsubscribed is still `requested` when you come back, and the first `receiveSyncChanges`
after you resubscribe announces it, so subscribing on mount and unsubscribing on unmount
does not lose invitations. A completed comparison's `trust_changed` is not re-offered that
way; `getDeviceStatuses` is the durable answer to that question and always was.

This section used to tell you to filter your own `to_device_events` for
`m.key.verification.request` and read `content.transaction_id` out of one. That was a seam --
a field of protocol JSON this library otherwise keeps to itself -- and the announcement
closes it. The identifier still *is* that transaction id on the wire; you no longer have to
know that.

**An invitation from a device you have never been told about is discarded on arrival, and
is not announced.** The layer underneath needs the sender's device keys to build the flow;
without them it drops the event. `receiveSyncChanges` still resolves successfully, no flow
exists, nothing is announced, and `acceptVerification` would reject that transaction id with
`unknown_flow`. The silence is the channel refusing to hand you an identifier no call here
answers to, rather than a gap in it.

**Keep the events you could not act on, because nothing here does.** What was discarded is
that arrival, not the invitation: feeding the same event to `receiveSyncChanges` a second
time, once you have queried the sender's devices, does create the flow -- and announces it,
exactly as a first-time arrival would. You never open the event: what you keep is an opaque
blob and what you get back is the announcement. Promptly, though -- an invitation expires ten
minutes after it was sent. A product that throws away to-device events it could not act on
has no way back, which is why the device-knowledge step is listed before the flow rather
than inside it.

**Keep the ones you did act on, too, until their flow finishes.** Flows live in memory on
both sides of this boundary, so a process that restarts mid-verification holds a
`verificationId` that now rejects with `unknown_flow`, and nothing is announced for it
because there is nothing left to announce. The recovery is the same one: feed the kept
invitation in again and be told the flow's name as though it had just arrived. The
ten-minute expiry is still running while you do.

**Every step goes through the queue.** Nothing reaches the other device until you send what
`takeOutgoingRequests` hands you and report each one with `markRequestSent`. Skipping the
report is the one way this flow could fail silently: the state machine advances on that
report and on nothing else, so the string is simply never produced. It is reported instead --
`getVerificationMaterial` rejects with kind `material_not_ready` rather than resolving with
an empty record or hanging. That kind is deliberately **not** retriable: retrying the same
call never resolves it, and pumping does.

**`getDeviceStatuses` is the only place a verification becomes visible.** A decrypted event's
sender does not become authenticated by it, and will not until cross-signing lands: the event
path consults cross-signing, and a string comparison sets local trust. Note also that your own
device reads `verified` from the moment it exists, because this process holds its private
keys -- so "some device in this list reads verified" says nothing. What carries a claim is
another user's device changing.

**`startVerificationComparison` reports three different things.** `comparison_already_started`
means the other side got there first, which is not a failure: carry on and wait for the
string. `verification_ended` means the flow is over and you need a new one.
`wrong_stage` means it has not been agreed to yet. `getVerificationStage` is free to call and
tells you which at any point.

Once a key has travelled, encryption and decryption are ordinary:

```ts
const envelope = await encryptEvent(scope, 'm.room.message', { body: 'hi' })
// send envelope.ciphertext as the content of an m.room.encrypted event

const recovered = await decryptEvent(scope, incomingEvent)
// recovered.ciphertext is the PLAINTEXT. One type serves both directions, so the
// field name describes the encrypt path and is wrong here. Handle it as plaintext:
// no logging, no unencrypted persistence, no crash report.
```

### Design notes worth knowing

**Scopes are opaque.** `CryptoScopeId` is a branded type, not a room id. Nothing in the public API says "room". The encryption algorithm travels as an open tag rather than an assumption, so a later move to MLS, or a hybrid post-quantum layer, can land without breaking this surface. A build gate rejects any Megolm, Olm or room specific identifier reaching the public declarations. Those three words are the whole denylist, and the boundary is worth stating rather than implying: `curve25519` and `ed25519` are in the public surface today, on `IdentityKeys`, because that is what the Matrix protocol calls those keys and hiding the name would buy nothing. The gate defends the design decision that a scope is not a room and an algorithm is a tag, not the broader claim that no primitive is ever named.

**The library writes no diagnostics of its own.** No `println!`, no `console.*`, no file writes, no `tracing` subscriber. Errors return identifiers to their caller. Diagnostics, if you need them, belong in a sink your application owns. A cryptographic library that logs by default is how cleartext reaches a crash report.

`gate:logger` enforces that in every language this package ships, and it is worth saying what "enforces" means, because for a while it meant less than this sentence did. The reach is enumerated rather than counted, because the count is what drifted: this paragraph and the gate table below it once disagreed about it, in a repository where a number in prose has no way to be wrong out loud. In Rust it rejects the print macros, `dbg!`, an import of `log` or `tracing` and a fully qualified `log::`/`tracing::` call, and — in the library sources, not the tests — `fs::write`, `File::create`, `io::stdout()` and `write_all`. In TypeScript it rejects reaching for `console` by property, by bracket index or by handing the object to something, and any `fs` import or file-writing call. In C, C++ and Objective-C it rejects every stream and every `printf` family member, plus `fwrite`, `write`, `putchar`, `ofstream`, `fopen` and the platform loggers. In Kotlin it rejects `android.util.Log`, `println`, `System.out`, `System.err` and the file writers. In Swift it rejects `print`, `debugPrint`, `dump`, `NSLog`, `os_log`, `OSLog`, `Logger`, the standard file handles and the file writers, and it does so before this package contains a line of Swift, because the podspec already compiles `ios/**/*.swift` into your app. In the podspec itself, which is Ruby that CocoaPods executes on your machine, it rejects `puts` and its family, the standard streams, the file writers, and both `script_phase` and `prepare_command`, which are the two ways a podspec can run shell inside your build. What it does not claim to stop is a reference laundered past a regex — `globalThis["con" + "sole"]` and its equivalents. The rule is that this bridge's own source does not reach for a log, not that a determined author could not.

There is one exception, and it is worth stating precisely rather than claiming an absolute that is not true. The UniFFI to JSI boundary code that `uniffi-bindgen-react-native` generates writes to `std::cout` when a JavaScript callback throws back across the boundary. There are eight such sites in `cpp/generated/matrix_crypto.cpp`, one per callback trampoline, and on iOS the file compiles into your app. There were five until the crypto signal channel got a native producer, which added a second callback interface and with it three more trampolines — its own method, plus the free and clone every vtable carries. Four of the original five survived into the shipped `libreact-native-matrix-crypto.so`; that count has not been re-measured since the three were added. Each site writes a fixed string naming the callback, then `jsi::JSError::what()`, which is the JavaScript exception's message and its stack.

No call argument, ciphertext, key or identifier is interpolated into that stream. The JavaScript functions reached at those eight sites are the generator's own, not yours. A callback you pass in runs inside the generated trampoline's TypeScript `try`/`catch`, which lowers a throw into a Rust call status before it can reach the C++ frame; `onCryptoSignal` listeners sit behind a second `try`/`catch` in `emitCryptoSignal` on top of that. What is left to reach the stream is the generator's own fixed-message internal errors, such as a stale handle after a hot reload.

It cannot be switched off. The generator's C++ backend takes no configuration at all, the write is unconditional in a template compiled into the tool, and hand-editing generated code is forbidden here and caught by `gate:drift`. So `gate:logger` reads that file instead of skipping it and tolerates exactly that one three-line shape and nothing else anywhere in the shipped C, C++ or Objective-C. Arrangement alone is not enough to earn the exemption: the name in the message must be one the generator emits, and the `try` block the `catch` closes must construct no error of its own, so a site that manufactures a `jsi::JSError` out of a key and prints it is rejected rather than tolerated. The number of tolerated sites is asserted to be exactly eight, not merely printed, so a ninth fails the build instead of moving a digit in a log nobody reads. That is what happened when `CryptoObserver` was added: the build failed, the three new sites were read, and only then was the number raised.

**Errors carry no payload content.** `toCryptoError` reads a small set of known fields and never copies ciphertext, plaintext or arbitrary properties into a message.

**Federation is invisible here.** No primitive distinguishes a local participant from a federated one. A `sender` carries its fully qualified `@user:server` verbatim, untransformed.

## Roadmap

The milestones below turn this from a proven chain into a usable encryption library. Each item names what does not work today and what has to happen for it to work.

### M2, the encryption core, landed

| Item | State |
|---|---|
| `encryptEvent`, `decryptEvent` | done, group sessions backed by `matrix-sdk-crypto` |
| `createCryptoMachine`, `openCryptoStore` | done, persistent storage through `matrix-sdk-sqlite`, surviving restart |
| `receiveSyncChanges` | done |
| `shareScopeKey`, `takeOutgoingRequests`, `markRequestSent` | done, the outbound queue described above |
| Two crypto machines exchanging a key and decrypting each other | done, in one test process, with the key travelling through the queue rather than handed over in test code |
| A third-party Matrix client decrypting what this library produces | done, both directions, against `matrix-nio` over a real homeserver |
| The same proof through the published TypeScript surface | done, on an emulator, with a second Matrix user as the counterparty |

Both obstacles named when this milestone was planned turned out real, and both were resolved rather than absorbed:

* **A tokio runtime became mandatory**, because group key sharing reaches `tokio::task::spawn`. The core now owns one, and signal delivery is non blocking, so no callback holds a lock or waits on JavaScript.
* **Binary size** went the other way from expected. Linking the Rust as a shared library instead of a static archive cut the published tarball by 74 percent, from 263 MB to 68 MB, which is 44 percent of its budget. Splitting into per platform packages was not needed.

**Why the last two rows exist.** Two of our own crypto machines agreeing proves the implementation is self consistent. It cannot prove the wire format is right, because a consistent misreading of the protocol passes it cleanly on both sides. Only a third party client decrypting a real message answers that, so both proofs run against `matrix-nio` over a real homeserver, and either can be run by anyone: `./scripts/run-level-two-interop.sh` for the core, and the level two harness in `packages/example-app` for the published surface.

What those proofs still cannot reach is stated under Status: `matrix-nio` and this library both call `vodozemac`, so the ratchet is the floor, and sender authenticity waits on cross-signing -- not on device verification, which has now landed and does not provide it.

### M3, device verification, in progress

Four items, scoped against one test: verification, plus whatever would obstruct a team building on `0.1.0`.

| Item | State |
|---|---|
| A typed `SyncDelta`, and one shared mapping instead of four | done |
| Device verification by short string comparison, in the Rust core | done, two machines completing a comparison and a genuine disagreement refusing |
| The same, reachable from TypeScript, with `getDeviceStatuses` reporting a verified device | done |
| `verification_state` on a decrypted event | done, as `EventEnvelope.senderVerification`; it cannot read `verified` before cross-signing, which is stated at the type |
| Trust changes emitted on the signal channel, and inbound invitations announced with their identifier | done |
| A third-party client participating in a verification | not started |
| Signal delivery no longer costing one operating system thread per signal | done |

QR verification is **deferred, not rejected**. It would add a dependency absent from `rust/Cargo.lock`, an off-by-default Cargo feature, and pressure on a size budget that has already been tripped once.

### M4 and beyond

* **cross-signing**, which is what turns a verified device into a verified *sender*. Named here rather than in M3 because M3 established that a string comparison alone cannot do it: the event path consults cross-signing, and a comparison sets local trust. This is the item that turns `sender` from transport metadata into a claim you can rely on
* device verification by QR code, alongside the string comparison that has landed
* secret export and import, for recovery
* multi participant scenarios and federation neutral test coverage
* cross implementation testing against both Synapse and Continuwuity
* a stabilised API, published documentation and multi platform CI for 1.0

## Contributing

Contributions are welcome. A few things about this repository are unusual and worth knowing before you start.

### Getting set up

```sh
yarn install
cargo test --manifest-path rust/Cargo.toml            # Rust
yarn --cwd packages/react-native-matrix-crypto test   # TypeScript
```

`packages/example-app` is a neutral React Native application that runs the full chain and explains it. It walks seven steps from a trivial call through to real cryptographic keys, showing at each step the exact TypeScript a consumer would write, what crosses the native boundary, and the result.

### Running the interoperability proof

The strongest claim this library makes is that a third party client decrypts what it encrypts, over a real homeserver. You can check that claim yourself, on your own machine, without an account anywhere:

```sh
./scripts/run-level-two-interop.sh
```

That starts a throwaway [Continuwuity](https://continuwuity.org) homeserver in a container, creates the one account the test needs inside it with a password generated for that run, installs a pinned `matrix-nio[e2e]` into a temporary virtualenv, runs the level 2 test, and destroys all of it. It needs Docker, a Rust toolchain and a Python 3, and nothing else. No credential is read from anywhere, and none is left behind. CI runs the same script, so what you run and what stands behind the claim are the same code path.

`matrix-nio` is a Matrix client written in Python by people who have never seen this code. The test has it decrypt an event this library encrypted, has this library decrypt an event it encrypted, and flips a single character of each ciphertext to watch both refusals happen. A run that never reaches those assertions fails: the script requires cargo's own output to name the test as passed, because `cargo test` exits successfully when it matches no test at all.

To point the same test at a homeserver you already have an account on, set the three variables it has always read and the script starts no container:

```sh
MATRIX_INTEROP_HOMESERVER=https://your.homeserver \
MATRIX_INTEROP_USER=@you:your.homeserver \
MATRIX_INTEROP_PASSWORD=... \
./scripts/run-level-two-interop.sh
```

### Running the same proof through the TypeScript API

The script above drives the Rust core. Between that core and your code sit the UniFFI scaffolding, the JSI binding, the generated TypeScript and the facade, and the same exchange runs through all of them on an Android emulator:

```sh
python3 packages/example-app/level-two/run_level_two.py
```

It needs Docker, an emulator `adb` can see, a release APK already built, and a Python with `matrix-nio[e2e]`, and no Rust toolchain. It stands up its own throwaway homeserver, creates two accounts and an encrypted room inside it, drives `matrix-nio` as the counterparty, installs and launches the example app, and reads the app's own `LEVEL2_SUMMARY 13/13` back out of the system log. Every call the app makes is the published API and nothing else. Everything the run creates lives inside the container, and the container is destroyed from a `finally`, an `atexit` hook and a signal handler, so a failed run leaves no more behind than a passing one.

`--mutation <name>` sabotages exactly one assertion, to check that assertion can fail: corrupting the event the counterparty is meant to read, or handing `receiveSyncChanges` a raw `/sync` response, among others. A mutated run prints a different summary line, so it can never be read as a clean one.

### Never hand edit a generated file

The TypeScript and C++ bindings are generated from the Rust by [`uniffi-bindgen-react-native`](https://github.com/jhugman/uniffi-bindgen-react-native) and committed to the repository. Change the Rust, then regenerate:

```sh
yarn --cwd packages/react-native-matrix-crypto codegen
```

A CI gate regenerates and fails on any difference, so drift between the Rust and the committed bindings cannot land.

### The crate layout, and why

* **`rust/matrix-crypto-core`** holds all logic. It knows nothing about UniFFI, JSI or React Native, and is testable with plain `cargo test`.
* **`rust/matrix-crypto-ffi`** holds the `#[uniffi::export]` surface. Type mirroring, conversion and delegation only, no logic.

A CI gate asserts the core never gains a direct `uniffi` dependency, so that separation is a property of the repository rather than a convention someone can quietly break.

### Build gates

Every one of these runs in CI. Each has been observed rejecting a real violation, not merely passing.

| Gate | Enforces |
|---|---|
| `gate:workspaces` | the Cargo and yarn workspaces resolve |
| `gate:boundary` | the core takes no direct `uniffi` dependency |
| `gate:drift` | committed bindings match the Rust source |
| `gate:logger` | the bridge contains no logger, in every language it ships: Rust, TypeScript, C/C++/Objective-C, Kotlin, Swift and the podspec |
| `gate:agility` | no Megolm, Olm or room specific identifier reaches the public API |
| `gate:stubs` | the committed turbo module is really wired up, not an empty shell |
| `gate:readme` | the README npm shows is the README GitHub shows |
| `gate:measure-guards` | the B2 measurement harness still refuses the runs it documents refusing |

`gate:stubs` exists because of a specific near miss. `ubrn build --and-generate` can emit a turbo module that exports nothing, with exit code zero and no warning, when it reads an Android shared library whose symbol table was stripped. Nothing downstream noticed, and the build went green. `gate:drift` cannot catch it either: drift regenerates and compares, so two equally empty generations agree with each other perfectly.

If you add a gate, add the step that proves it fails on a real violation. A gate nobody has watched fail is not known to work.

### Releasing

A release is a git tag. Pushing `v0.1.0-rc.1` runs `.github/workflows/release.yml`, which calls the entire pull request workflow first — every gate above, both build legs, the emulator probe and the interoperability proof — then builds the full cross compile matrix for both platforms, checks that the binaries really landed in the tree it is about to pack from and that npm's own file list names them, packs one tarball, asserts that tarball really contains the prebuilt binaries, installs those same bytes with `cargo` and `rustc` scrubbed out of `PATH` and loads the module out of them, and only then publishes, with provenance and under the correct npm distribution tag. It publishes the exact tarball it checked rather than repacking, so there is no gap between what was verified and what is uploaded. Afterwards it runs `scripts/assert-published-tags.sh`, which reads the distribution tags back off the registry: every check before the publish can only verify the tag npm was *told*, and the first release proved that is a different thing from the tag npm *applied*.

The two binary checks are deliberately separate. Only the one that reads the packed tarball can authorise a publish, but on its own it reports every fault as "the tarball has no xcframework", which is the same sentence whether the untar misfired, npm declined to pack what was sitting right there, or something deleted it in between. `scripts/assert-tree-ships-binaries.sh` runs first and tells those apart, because the first release attempt was the middle one and nothing in the run log said so.

Four things stop the run before anything is built: a tag that disagrees with the version in `packages/react-native-matrix-crypto/package.json`, an npm distribution tag that disagrees with what that version implies (a prerelease reaching `latest`, or a plain version reaching anything else), a version already on the registry, and a missing `NPM_TOKEN` repository secret. Each says so by name.

You can rehearse the publish without publishing and without a token:

```sh
./scripts/rehearse-publish.sh
```

That runs the same tree check the release workflow runs, packs the package exactly as the release workflow packs it, runs the same assertion on the packed bytes, and finishes with `npm publish --dry-run --tag <tag>`, which prints the file list npm would upload and the distribution tag it would publish under, and uploads nothing. It needs the binaries on disk; its header carries the two `ubrn build` invocations that produce them, and if any are missing it names precisely which. It also prints the npm version it used, because a rehearsal is only predictive of CI to the extent the two agree about what `npm pack` includes, and once they did not. To rehearse the other half, `./scripts/assert-release-ready.sh v0.1.0-rc.1 rc`.

The release assertions are deliberately not `gate:*` scripts. `gate:readme` requires every `gate:*` to run as a step in `ci.yml`, and these two need an artifact with binaries in it, which a pull request never has.

### Conventions

* Conventional Commits, imperative mood, one subject per commit.
* A manifest change and its lockfile update belong in the same commit.
* Every core to FFI type conversion destructures its source, so a field added later fails the build instead of being silently dropped.
* Tests assert, they do not print, and `gate:logger` reads `rust/*/tests` to make sure of it. The one thing a test may do that the library may not is write a file: the level 2 proof passes a marker through the filesystem to a spawned child process, which is how the cross-process restore is proved at all.

## Security

This library has not been independently audited. It wraps `matrix-sdk-crypto`, which is widely deployed, but the bridge layer around it is new.

If you believe you have found a security issue, please report it privately through GitHub's security advisory feature on this repository rather than opening a public issue.

## License

Apache-2.0. The same license as `matrix-sdk-crypto`, which this library is built on, and which carries the patent grant that matters for cryptographic work.
