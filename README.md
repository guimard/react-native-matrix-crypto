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

**The bridge chain is complete and proven. Encryption works between two crypto machines. It has not yet been proven against a third-party Matrix client.**

Being precise about that, because a cryptographic library that oversells itself is worse than one that admits its state.

| Capability | State |
|---|---|
| Rust to UniFFI to JSI to TypeScript chain | working, verified on real hardware |
| Byte-accurate marshalling across the boundary | verified |
| Typed errors crossing the FFI boundary | verified |
| Callback interface, Rust to JavaScript | verified |
| Real `OlmMachine` identity keys | working |
| Persistent encrypted store, surviving restart | working |
| Encryption and decryption | working, proven between two crypto machines |
| Interoperability with a third-party Matrix client | **not yet proven**, see the roadmap |
| Sender authenticity | **not provided**, see below |
| Device verification (SAS, QR) | **not implemented**, see the roadmap |
| Secret export and import | **not implemented**, see the roadmap |

The unimplemented functions exist today as final types that compile, and reject at runtime with a typed `not_implemented` error. That is intentional: a consuming team can build against the real shape while the cryptography underneath is written.

**Two limits worth knowing before you build on this.**

Decryption does not authenticate the sender. `EventEnvelope.sender` is the value the homeserver delivered, and a successfully decrypted event does not prove who sent it. That authentication comes from device verification, which is not implemented yet. Treat `sender` and `algorithm` as unauthenticated transport metadata until it is.

Interoperability is proven only against ourselves so far. Two of our own crypto machines exchange keys and decrypt each other's events, which catches most defects but cannot catch a consistent misreading of the protocol, because both sides would misread it the same way. Until a third-party client decrypts what this library produces, treat the wire format as unverified.

Verified end to end on an iOS simulator and on a physical Android device: a record round trip, a byte array returned reversed to prove Rust genuinely read it, an async call resolving as a Promise, a typed error reaching a JavaScript `catch`, one callback signal travelling back from Rust, and a real Curve25519 and Ed25519 key pair.

## Installation

```sh
yarn add react-native-matrix-crypto
```

**No Rust toolchain is required.** The published package ships prebuilt binaries, an `.xcframework` for iOS and an `.aar` for Android, so `yarn add` is all a consumer needs. This is verified in CI by a job that installs the real tarball on a machine with `cargo` and `rustc` removed from `PATH`.

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
import { getDeviceIdentityKeys, onCryptoSignal } from 'react-native-matrix-crypto'

// Real cryptography. Creates an OlmMachine and returns its public identity keys.
const keys = await getDeviceIdentityKeys('@alice:example.org', 'DEVICE1')
// { curve25519: '...', ed25519: '...' }  43-character base64 each

// Crypto state changes that belong to no call in flight.
const unsubscribe = onCryptoSignal((signal) => {
  switch (signal.kind) {
    case 'trust_changed':      break
    case 'unexpected_device':  break
    case 'key_missing':        break
  }
})
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

Once a key has travelled, encryption and decryption are ordinary:

```ts
const envelope = await encryptEvent(scope, 'm.room.message', { body: 'hi' })
// send envelope.ciphertext as the content of an m.room.encrypted event

const recovered = await decryptEvent(scope, incomingEvent)
```

### Design notes worth knowing

**Scopes are opaque.** `CryptoScopeId` is a branded type, not a room id. Nothing in the public API says "room". The encryption algorithm travels as an open tag rather than an assumption, so a later move to MLS, or a hybrid post-quantum layer, can land without breaking this surface. A build gate rejects any Megolm, Olm or room specific identifier reaching the public declarations.

**The library writes no diagnostics of its own.** No `println!`, no `console.*`, no file writes, no `tracing` subscriber. Errors return identifiers to their caller. Diagnostics, if you need them, belong in a sink your application owns. A cryptographic library that logs by default is how cleartext reaches a crash report.

There is one exception, and it is worth stating precisely rather than claiming an absolute that is not true. The UniFFI to JSI boundary code that `uniffi-bindgen-react-native` generates writes to `std::cout` when a JavaScript callback throws back across the boundary. There are five such sites in `cpp/generated/matrix_crypto.cpp`, one per callback trampoline; four survive into the shipped `libreact-native-matrix-crypto.so`, and on iOS the file compiles into your app. Each writes a fixed string naming the callback, then `jsi::JSError::what()`, which is the JavaScript exception's message and its stack.

No call argument, ciphertext, key or identifier is interpolated into that stream. The JavaScript functions reached at those five sites are the generator's own, not yours. A callback you pass in runs inside the generated trampoline's TypeScript `try`/`catch`, which lowers a throw into a Rust call status before it can reach the C++ frame; `onCryptoSignal` listeners sit behind a second `try`/`catch` in `emitCryptoSignal` on top of that. What is left to reach the stream is the generator's own fixed-message internal errors, such as a stale handle after a hot reload.

It cannot be switched off. The generator's C++ backend takes no configuration at all, the write is unconditional in a template compiled into the tool, and hand-editing generated code is forbidden here and caught by `gate:drift`. So `gate:logger` reads that file instead of skipping it, tolerates exactly that one three-line shape and nothing else anywhere in the shipped C, C++ or Objective-C, and prints how many sites it tolerated so the number is visible when it moves.

**Errors carry no payload content.** `toCryptoError` reads a small set of known fields and never copies ciphertext, plaintext or arbitrary properties into a message.

**Federation is invisible here.** No primitive distinguishes a local participant from a federated one. A `sender` carries its fully qualified `@user:server` verbatim, untransformed.

## Roadmap

The milestone below is what turns this from a proven chain into a usable encryption library. Each item names what does not work today and what has to happen for it to work.

### M2, the encryption core, mostly landed

| Item | State |
|---|---|
| `encryptEvent`, `decryptEvent` | done, group sessions backed by `matrix-sdk-crypto` |
| `createCryptoMachine`, `openCryptoStore` | done, persistent storage through `matrix-sdk-sqlite`, surviving restart |
| `receiveSyncChanges` | done |
| `shareScopeKey`, `takeOutgoingRequests`, `markRequestSent` | done, the outbound queue described above |
| Two crypto machines exchanging a key and decrypting each other | done, in one test process, with the key travelling through the queue rather than handed over in test code |
| A third-party Matrix client decrypting what this library produces | **the one thing left**, see below |

Both obstacles named when this milestone was planned turned out real, and both were resolved rather than absorbed:

* **A tokio runtime became mandatory**, because group key sharing reaches `tokio::task::spawn`. The core now owns one, and signal delivery is non blocking, so no callback holds a lock or waits on JavaScript.
* **Binary size** went the other way from expected. Linking the Rust as a shared library instead of a static archive cut the published tarball by 74 percent, from 263 MB to 68 MB, which is 44 percent of its budget. Splitting into per platform packages was not needed.

**What remains is the level that matters most.** Two of our own crypto machines agreeing proves the implementation is self consistent; it cannot prove the wire format is right, because a consistent misreading of the protocol passes it cleanly. Only a third party client decrypting a real message answers that, and until it does, the format is unverified.

### M3 and beyond

* device verification, SAS and QR
* **sender authenticity**, which arrives with verification and not before. Until a device is verified, a decrypted event's sender is what the server said it was, so this is the item that turns `sender` from transport metadata into a claim you can rely on
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
| `gate:logger` | the bridge contains no logger, in Rust, TypeScript and C++ alike |
| `gate:agility` | no algorithm specific identifier reaches the public API |
| `gate:stubs` | the committed turbo module is really wired up, not an empty shell |

`gate:stubs` exists because of a specific near miss. `ubrn build --and-generate` can emit a turbo module that exports nothing, with exit code zero and no warning, when it reads an Android shared library whose symbol table was stripped. Nothing downstream noticed, and the build went green. `gate:drift` cannot catch it either: drift regenerates and compares, so two equally empty generations agree with each other perfectly.

If you add a gate, add the step that proves it fails on a real violation. A gate nobody has watched fail is not known to work.

### Conventions

* Conventional Commits, imperative mood, one subject per commit.
* A manifest change and its lockfile update belong in the same commit.
* Every core to FFI type conversion destructures its source, so a field added later fails the build instead of being silently dropped.
* Tests assert, they do not print. The no logger rule has no test exemption.

## Security

This library has not been independently audited. It wraps `matrix-sdk-crypto`, which is widely deployed, but the bridge layer around it is new.

If you believe you have found a security issue, please report it privately through GitHub's security advisory feature on this repository rather than opening a public issue.

## License

Apache-2.0. The same license as `matrix-sdk-crypto`, which this library is built on, and which carries the patent grant that matters for cryptographic work.
