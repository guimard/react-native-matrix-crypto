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
| Rust to UniFFI to JSI to TypeScript chain | working, verified on real hardware |
| Byte-accurate marshalling across the boundary | verified |
| Typed errors crossing the FFI boundary | verified |
| Callback interface, Rust to JavaScript | verified |
| Real `OlmMachine` identity keys | working |
| Persistent encrypted store, surviving restart | working |
| Encryption and decryption | working, proven between two crypto machines |
| Interoperability with a third-party Matrix client | proven both directions against `matrix-nio`, over a real homeserver |
| Crypto signal channel (`onCryptoSignal`) | present and typed, but **nothing emits a signal yet**, see below |
| Sender authenticity | **not provided**, see below |
| Device verification (SAS, QR) | **not implemented**, see the roadmap |
| Secret export and import | **not implemented**, see the roadmap |

The unimplemented functions exist today as final types that compile, and reject at runtime with a typed `not_implemented` error. That is intentional: a consuming team can build against the real shape while the cryptography underneath is written.

`onCryptoSignal` is the quieter case, and worth stating plainly because it does not throw. The channel is real, subscribing and unsubscribing work, and a listener that throws cannot starve the others. What is missing is a producer: nothing in this milestone emits a `CryptoSignal`, so a listener registered today never fires. The conditions the three variants name do occur now, and reach you elsewhere: a missing key arrives as a rejected `decryptEvent` with kind `missing_key`, not as a `key_missing` signal. The earliest producer would be M3's device verification work, and whether trust changes ride this channel or get a call-shaped surface instead is still an open question in the M3 design. Subscribe if being ready costs you nothing; do not build a flow that waits to be told.

**Two limits worth knowing before you build on this.**

Decryption does not authenticate the sender. `EventEnvelope.sender` is the value the homeserver delivered, and a successfully decrypted event does not prove who sent it. That authentication comes from device verification, which is not implemented yet. Treat `sender` and `algorithm` as unauthenticated transport metadata until it is.

The interoperability proof has a floor, and it is the ratchet. `matrix-nio`, a Matrix client written in Python by people who have never seen this code, decrypts what this library encrypts and this library decrypts what it sends, over a real homeserver, in two tests anyone can run: one driving the Rust core, one driving the published TypeScript API on an emulator. What neither proves is the ratchet itself. `matrix-nio` 0.26 and this library both call `vodozemac 0.10.0`, so a defect inside that crate, or a misreading shared below the protocol line, would pass both sides. What is genuinely tested by two independent implementations is everything above it: event shapes, the `/keys/*` payloads a real homeserver accepts and answers, to-device routing, and the order a session key has to travel in. That is where this library's own code lives.

Verified end to end on an iOS simulator and on a physical Android device: a record round trip, a byte array returned reversed to prove Rust genuinely read it, an async call resolving as a Promise, a typed error reaching a JavaScript `catch`, one callback signal travelling back from Rust, and a real Curve25519 and Ed25519 key pair.

## Installation

```sh
yarn add react-native-matrix-crypto
```

**No Rust toolchain is required.** The published package ships prebuilt binaries: an `.xcframework` for iOS, and for Android a prebuilt Rust library per ABI under `android/src/main/jniLibs/`, which this module's `CMakeLists.txt` links when your app autolinks it and builds its C++ from source. A fully prebuilt, already linked `.aar` ships alongside those, for a consumer who would rather not build from source at all. `yarn add` is all you need.

Two different checks stand behind that sentence, and they establish different things.

**On every pull request,** a job packs this repository, installs the result on a machine with every directory carrying `cargo` or `rustc` scrubbed out of `PATH`, and asserts that the installed package declares no `preinstall`, `install`, `postinstall` or `prepare` script and ships no `binding.gyp` — so nothing in it can reach for a compiler on your machine either. It does not check the binaries, and cannot: they are build outputs, ignored by git, so the tarball a pull request is able to pack contains none of them.

**At publication,** the release workflow does. It builds both platforms in full, packs one tarball, and then opens that tarball and reads what is inside: every slice the `.xcframework` advertises, a prebuilt Rust library for every ABI `android/build.gradle` declares, an `.aar` carrying all of them — each large enough and with the right magic number to be real compiled code rather than a placeholder. Only then does it install those exact bytes on a machine with `cargo` and `rustc` unreachable, bundle and run the entry point out of the installed package the way your app's bundler would, and publish the tarball it checked, with [npm provenance](https://docs.npmjs.com/generating-provenance-statements) so the registry can show which workflow run produced what you downloaded.

Neither of those runs the cryptography. Loading the module in a plain Node process stops where it calls into the native library, because a JSI turbo module needs a React Native runtime. Running the shipped chain end to end is the Android emulator job's business, and the interoperability proof below is where a third party client checks the result.

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

**Scopes are opaque.** `CryptoScopeId` is a branded type, not a room id. Nothing in the public API says "room". The encryption algorithm travels as an open tag rather than an assumption, so a later move to MLS, or a hybrid post-quantum layer, can land without breaking this surface. A build gate rejects any Megolm, Olm or room specific identifier reaching the public declarations. Those three words are the whole denylist, and the boundary is worth stating rather than implying: `curve25519` and `ed25519` are in the public surface today, on `IdentityKeys`, because that is what the Matrix protocol calls those keys and hiding the name would buy nothing. The gate defends the design decision that a scope is not a room and an algorithm is a tag, not the broader claim that no primitive is ever named.

**The library writes no diagnostics of its own.** No `println!`, no `console.*`, no file writes, no `tracing` subscriber. Errors return identifiers to their caller. Diagnostics, if you need them, belong in a sink your application owns. A cryptographic library that logs by default is how cleartext reaches a crash report.

`gate:logger` enforces that in every language this package ships, and it is worth saying what "enforces" means, because for a while it meant less than this sentence did. The reach is enumerated rather than counted, because the count is what drifted: this paragraph and the gate table below it once disagreed about it, in a repository where a number in prose has no way to be wrong out loud. In Rust it rejects the print macros, `dbg!`, an import of `log` or `tracing` and a fully qualified `log::`/`tracing::` call, and — in the library sources, not the tests — `fs::write`, `File::create`, `io::stdout()` and `write_all`. In TypeScript it rejects reaching for `console` by property, by bracket index or by handing the object to something, and any `fs` import or file-writing call. In C, C++ and Objective-C it rejects every stream and every `printf` family member, plus `fwrite`, `write`, `putchar`, `ofstream`, `fopen` and the platform loggers. In Kotlin it rejects `android.util.Log`, `println`, `System.out`, `System.err` and the file writers. In Swift it rejects `print`, `debugPrint`, `dump`, `NSLog`, `os_log`, `OSLog`, `Logger`, the standard file handles and the file writers, and it does so before this package contains a line of Swift, because the podspec already compiles `ios/**/*.swift` into your app. In the podspec itself, which is Ruby that CocoaPods executes on your machine, it rejects `puts` and its family, the standard streams, the file writers, and both `script_phase` and `prepare_command`, which are the two ways a podspec can run shell inside your build. What it does not claim to stop is a reference laundered past a regex — `globalThis["con" + "sole"]` and its equivalents. The rule is that this bridge's own source does not reach for a log, not that a determined author could not.

There is one exception, and it is worth stating precisely rather than claiming an absolute that is not true. The UniFFI to JSI boundary code that `uniffi-bindgen-react-native` generates writes to `std::cout` when a JavaScript callback throws back across the boundary. There are five such sites in `cpp/generated/matrix_crypto.cpp`, one per callback trampoline; four survive into the shipped `libreact-native-matrix-crypto.so`, and on iOS the file compiles into your app. Each writes a fixed string naming the callback, then `jsi::JSError::what()`, which is the JavaScript exception's message and its stack.

No call argument, ciphertext, key or identifier is interpolated into that stream. The JavaScript functions reached at those five sites are the generator's own, not yours. A callback you pass in runs inside the generated trampoline's TypeScript `try`/`catch`, which lowers a throw into a Rust call status before it can reach the C++ frame; `onCryptoSignal` listeners sit behind a second `try`/`catch` in `emitCryptoSignal` on top of that. What is left to reach the stream is the generator's own fixed-message internal errors, such as a stale handle after a hot reload.

It cannot be switched off. The generator's C++ backend takes no configuration at all, the write is unconditional in a template compiled into the tool, and hand-editing generated code is forbidden here and caught by `gate:drift`. So `gate:logger` reads that file instead of skipping it and tolerates exactly that one three-line shape and nothing else anywhere in the shipped C, C++ or Objective-C. Arrangement alone is not enough to earn the exemption: the name in the message must be one the generator emits, and the `try` block the `catch` closes must construct no error of its own, so a site that manufactures a `jsi::JSError` out of a key and prints it is rejected rather than tolerated. The number of tolerated sites is asserted to be exactly five, not merely printed, so a sixth fails the build instead of moving a digit in a log nobody reads.

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
| A third-party Matrix client decrypting what this library produces | done, both directions, against `matrix-nio` over a real homeserver |
| The same proof through the published TypeScript surface | done, on an emulator, with a second Matrix user as the counterparty |

Both obstacles named when this milestone was planned turned out real, and both were resolved rather than absorbed:

* **A tokio runtime became mandatory**, because group key sharing reaches `tokio::task::spawn`. The core now owns one, and signal delivery is non blocking, so no callback holds a lock or waits on JavaScript.
* **Binary size** went the other way from expected. Linking the Rust as a shared library instead of a static archive cut the published tarball by 74 percent, from 263 MB to 68 MB, which is 44 percent of its budget. Splitting into per platform packages was not needed.

**Why the last two rows exist.** Two of our own crypto machines agreeing proves the implementation is self consistent. It cannot prove the wire format is right, because a consistent misreading of the protocol passes it cleanly on both sides. Only a third party client decrypting a real message answers that, so both proofs run against `matrix-nio` over a real homeserver, and either can be run by anyone: `./scripts/run-level-two-interop.sh` for the core, and the level two harness in `packages/example-app` for the published surface.

What those proofs still cannot reach is stated under Status: `matrix-nio` and this library both call `vodozemac`, so the ratchet is the floor, and sender authenticity waits on device verification in M3.

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

`gate:stubs` exists because of a specific near miss. `ubrn build --and-generate` can emit a turbo module that exports nothing, with exit code zero and no warning, when it reads an Android shared library whose symbol table was stripped. Nothing downstream noticed, and the build went green. `gate:drift` cannot catch it either: drift regenerates and compares, so two equally empty generations agree with each other perfectly.

If you add a gate, add the step that proves it fails on a real violation. A gate nobody has watched fail is not known to work.

### Releasing

A release is a git tag. Pushing `v0.1.0` runs `.github/workflows/release.yml`, which calls the entire pull request workflow first — every gate above, both build legs, the emulator probe and the interoperability proof — then builds the full cross compile matrix for both platforms, packs one tarball, asserts that tarball really contains the prebuilt binaries, installs those same bytes with `cargo` and `rustc` scrubbed out of `PATH` and loads the module out of them, and only then publishes, with provenance. It publishes the exact tarball it checked rather than repacking, so there is no gap between what was verified and what is uploaded.

Three things stop the run before anything is built: a tag that disagrees with the version in `packages/react-native-matrix-crypto/package.json`, a version already on the registry, and a missing `NPM_TOKEN` repository secret. Each says so by name.

You can rehearse the publish without publishing and without a token:

```sh
./scripts/rehearse-publish.sh
```

That packs the package exactly as the release workflow packs it, runs the same assertion on the packed bytes, and finishes with `npm publish --dry-run`, which prints the file list npm would upload and uploads nothing. It needs the binaries on disk; its header carries the three commands that produce them — two `ubrn build` invocations and the Gradle `assembleRelease` that produces the `.aar`, which `ubrn` does not — and if any are missing it names precisely which. To rehearse the other half, `./scripts/assert-release-ready.sh v0.1.0`.

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
