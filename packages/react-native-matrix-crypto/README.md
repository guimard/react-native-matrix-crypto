# react-native-matrix-crypto

A React Native bridge for Matrix cryptography.

It exposes the modern Matrix end-to-end encryption stack — [`matrix-sdk-crypto`](https://github.com/matrix-org/matrix-rust-sdk/tree/main/crates/matrix-sdk-crypto), the same Rust implementation Element uses — to a React Native application, through a small, typed TypeScript surface.

```
your app  →  TypeScript facade  →  generated bindings  →  JSI Turbo Module
                                                              ↓
          matrix-sdk-crypto (Rust)  ←  UniFFI scaffolding  ←──┘
```

---

## What this is not

This matters more than what it is, and it is the first thing worth knowing.

**This library does not talk to a homeserver.** There is no login, no `/sync`, no sending, no room state, no timeline. It is a cryptographic engine: you hand it an event, it hands you back an encrypted one, and vice versa. Transport is your application's job.

That boundary is deliberate and enforced. The same separation exists upstream between `matrix-sdk-crypto` and the full `matrix-sdk`, and for the same reason: a crypto engine that also owns networking is far harder to audit, reuse, and reason about.

So this library is **not**:

- a Matrix client SDK — see [`matrix-js-sdk`](https://github.com/matrix-org/matrix-js-sdk) if that is what you need;
- a replacement for a homeserver connection;
- tied to any particular product, backend, or deployment.

It is a reusable component. Any React Native project can consume it without carrying configuration belonging to someone else's product.

---

## Status

**The bridge chain is complete and proven. The cryptographic surface is not yet implemented.**

Being precise about that, because a crypto library that oversells itself is worse than one that admits its state:

| | |
|---|---|
| Rust → UniFFI → JSI → TypeScript chain | ✅ working, verified on real hardware |
| Byte-accurate marshalling across the boundary | ✅ verified |
| Typed errors crossing the FFI boundary | ✅ verified |
| Callback interface, Rust → JavaScript | ✅ verified |
| Real `OlmMachine` identity keys | ✅ working |
| Encryption, decryption, verification, secrets | ⚠️ **typed, not implemented** |

The eleven remaining functions of the public API exist today as final types that compile, and reject at runtime with a typed `not_implemented` error. That is intentional: a consuming team can build against the real shape while the cryptography underneath is written.

Verified end to end on an iOS simulator and on a physical Android device (Pixel 10 Pro Fold): a record round-trip, a byte array returned reversed to prove Rust genuinely read it, an async call resolving as a Promise, a typed error reaching a JavaScript `catch`, one callback signal travelling back from Rust, and a real Curve25519 / Ed25519 key pair.

---

## Installation

```sh
yarn add react-native-matrix-crypto
```

**No Rust toolchain is required.** The published package ships prebuilt binaries — an `.xcframework` for iOS and an `.aar` for Android — so `yarn add` is all a consumer needs. This is verified in CI by a job that installs the real tarball on a machine with `cargo` and `rustc` removed from `PATH`.

### Requirements

- React Native 0.87+ with the New Architecture enabled (this is a JSI Turbo Module)
- React 19.2+
- iOS 13+ / Android API 24+

### Platform support

| Platform | Architectures |
|---|---|
| iOS | `arm64` device, `arm64` simulator, `x86_64` simulator |
| Android | `arm64-v8a`, `armeabi-v7a`, `x86_64` |

---

## Usage

What works today:

```ts
import { getDeviceIdentityKeys, onCryptoSignal } from 'react-native-matrix-crypto'

// Real cryptography: creates an OlmMachine and returns its public identity keys.
const keys = await getDeviceIdentityKeys('@alice:example.org', 'DEVICE1')
// → { curve25519: '…', ed25519: '…' }  (43-character base64 each)

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
    console.log(e.kind) // → 'not_implemented', for now
  }
}
```

### Design notes worth knowing

**Scopes are opaque.** `CryptoScopeId` is a branded type, not a room id. Nothing in the public API says "room". The encryption algorithm travels as an open tag rather than an assumption, so a later move to MLS, or a hybrid post-quantum layer, can land without breaking this surface. A build gate enforces that no Megolm-, Olm- or room-specific identifier reaches the public declarations.

**The library never logs.** Not sparingly — never. A cryptographic library that logs by default is how cleartext reaches a crash report. Errors return identifiers to their caller and are never written anywhere; diagnostics, if you need them, belong in a sink your application owns. A build gate enforces this too.

**Errors carry no payload content.** `toCryptoError` reads a small set of known fields and never copies ciphertext, plaintext, or arbitrary properties into a message.

**Federation is invisible here.** No primitive distinguishes a local participant from a federated one. A `sender` carries its fully qualified `@user:server` verbatim, untransformed.

---

## Development

This is a monorepo. The library is `packages/react-native-matrix-crypto`; the Rust lives in `rust/`.

```sh
yarn install
cargo test --manifest-path rust/Cargo.toml     # Rust
yarn --cwd packages/react-native-matrix-crypto test   # TypeScript
```

### Regenerating bindings

The TypeScript and C++ bindings are generated from the Rust by [`uniffi-bindgen-react-native`](https://github.com/jhugman/uniffi-bindgen-react-native) and committed. **Never hand-edit a generated file** — change the Rust and regenerate:

```sh
yarn --cwd packages/react-native-matrix-crypto codegen
```

A CI gate regenerates and fails on any diff, so drift between the Rust and the committed bindings cannot land.

### The crate layout, and why

- **`rust/matrix-crypto-core`** — all logic. Knows nothing about UniFFI, JSI or React Native, and is testable with plain `cargo test`.
- **`rust/matrix-crypto-ffi`** — the `#[uniffi::export]` surface. Type mirroring, conversion and delegation only; no logic.

A CI gate asserts that the core never gains a direct `uniffi` dependency, so that separation is a property of the repository rather than a convention.

### Build gates

Every one of these runs in CI, and each has been observed rejecting a real violation rather than merely passing:

| Gate | Enforces |
|---|---|
| `gate:workspaces` | the Cargo and yarn workspaces resolve |
| `gate:boundary` | the core takes no direct `uniffi` dependency |
| `gate:drift` | committed bindings match the Rust source |
| `gate:logger` | the bridge contains no logger |
| `gate:agility` | no algorithm-specific identifier reaches the public API |

---

## Example app

`packages/example-app` is a neutral React Native application that runs the full chain and explains it. It walks seven steps from a trivial call through to real cryptographic keys, showing at each step the exact TypeScript a consumer would write, what crosses the native boundary, and the result. It also runs the interoperability suite on every launch and logs machine-readable results for CI.

---

## Roadmap

- **M1 — walking skeleton** ✅ the chain, proven on both platforms
- **M2** — the cryptographic surface: encryption, decryption, verification, secret export and import; interoperability tested against a real homeserver and a third-party client
- **M3** — multi-participant scenarios, federation-neutral test coverage
- **V1.0** — stabilised API, published documentation, multi-platform CI

---

## License

Apache-2.0. The same license as `matrix-sdk-crypto`, which this library is built on, and which carries the patent grant that matters for cryptographic work.
