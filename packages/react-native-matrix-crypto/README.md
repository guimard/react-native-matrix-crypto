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

**The bridge chain is complete and proven. The cryptographic surface is not yet implemented.**

Being precise about that, because a cryptographic library that oversells itself is worse than one that admits its state.

| Capability | State |
|---|---|
| Rust to UniFFI to JSI to TypeScript chain | working, verified on real hardware |
| Byte-accurate marshalling across the boundary | verified |
| Typed errors crossing the FFI boundary | verified |
| Callback interface, Rust to JavaScript | verified |
| Real `OlmMachine` identity keys | working |
| Encryption and decryption | **not implemented**, see the roadmap |
| Device verification (SAS, QR) | **not implemented**, see the roadmap |
| Secret export and import | **not implemented**, see the roadmap |

The unimplemented functions exist today as final types that compile, and reject at runtime with a typed `not_implemented` error. That is intentional: a consuming team can build against the real shape while the cryptography underneath is written.

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

The rest of the surface is typed and compiles today:

```ts
import { encryptEvent, asCryptoScopeId, isCryptoError } from 'react-native-matrix-crypto'

try {
  await encryptEvent(asCryptoScopeId('!room:example.org'), 'm.room.message', { body: 'hi' })
} catch (e) {
  if (isCryptoError(e)) {
    console.log(e.kind) // 'not_implemented', for now
  }
}
```

### Design notes worth knowing

**Scopes are opaque.** `CryptoScopeId` is a branded type, not a room id. Nothing in the public API says "room". The encryption algorithm travels as an open tag rather than an assumption, so a later move to MLS, or a hybrid post-quantum layer, can land without breaking this surface. A build gate rejects any Megolm, Olm or room specific identifier reaching the public declarations.

**The library never logs.** Not sparingly, never. A cryptographic library that logs by default is how cleartext reaches a crash report. Errors return identifiers to their caller and are never written anywhere. Diagnostics, if you need them, belong in a sink your application owns. A build gate enforces this too.

**Errors carry no payload content.** `toCryptoError` reads a small set of known fields and never copies ciphertext, plaintext or arbitrary properties into a message.

**Federation is invisible here.** No primitive distinguishes a local participant from a federated one. A `sender` carries its fully qualified `@user:server` verbatim, untransformed.

## Roadmap

The milestone below is what turns this from a proven chain into a usable encryption library. Each item names what does not work today and what has to happen for it to work.

### M2, the encryption core

| Not working today | What lands it |
|---|---|
| `encryptEvent`, `decryptEvent` | Megolm group sessions backed by `matrix-sdk-crypto`, exercised by two crypto machines encrypting to each other in one test process |
| `createCryptoMachine`, `openCryptoStore` | persistent storage through `matrix-sdk-sqlite`, the store Element uses, so sessions survive an app restart |
| `receiveSyncChanges` | feeding a homeserver's `/sync` response into the crypto machine, which is how it learns about other devices |

Two known obstacles, both already diagnosed rather than discovered later:

* **A tokio runtime becomes mandatory.** `OlmMachine::share_room_key`, which is Megolm key sharing and therefore unavoidable for group encryption, reaches `tokio::task::spawn` through `matrix-sdk-common`. Adding that runtime makes every callback that returns a value a blocking cross thread round trip. The plan is to make signal delivery non blocking so the cost is removed rather than absorbed.
* **Binary size.** The published tarball is already a large fraction of its budget, and M2 retains more of `matrix-sdk-crypto` than the current single function does. Build profile optimisation comes first, and splitting into per platform packages is the fallback if that is not enough.

Interoperability is tested in two levels, in this order. First two party encryption in process, which is deterministic and catches most defects. Then a real homeserver and a third party client, which answers the question the first level cannot: whether a real Matrix client decrypts what we encrypt.

### M3 and beyond

* device verification, SAS and QR
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
| `gate:logger` | the bridge contains no logger |
| `gate:agility` | no algorithm specific identifier reaches the public API |

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
