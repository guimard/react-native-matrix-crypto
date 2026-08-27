# react-native-matrix-crypto — Design

**Status:** Approved design. Supersedes conflicting details in the Messagr v2 specs where noted in §1.
**Date:** 2026-08-27
**Scope of this document:** the standalone generic React Native Matrix E2EE bridge, and the walking skeleton that de-risks it. Messagr product concerns are explicitly out of scope.

## 0. Source documents and authority

| Source | Authority |
|---|---|
| Messagr Bridge Layer Specification v2 | Normative for bridge scope, boundaries, and contract |
| Messagr Cryptographic Specification v2 | Normative for threat model, agility, metadata boundaries |
| Naming convention table (2026-08-27) | **Overrides** all names in both specs |

Where the naming table and the specs disagree, the naming table wins. Where this
document and the specs disagree, this document wins and states why in §1.

## 1. Corrections to the source specifications

These are errors or stale text in the v2 specs. They are recorded here so no
implementer rediscovers them at cost.

### 1.1 `matrix-sdk-crypto-ffi` is not a consumable dependency

Bridge spec §1 and §4 name `matrix_sdk_crypto_ffi` as the crate the bridge binds
against. On crates.io that name is a 1039-byte `0.0.1-reserved` placeholder
published 2022-05-12 and never republished. The real crate exists only as an
unpublished workspace member inside `matrix-org/matrix-rust-sdk`, where it backs
Element X's own bindings.

**Consequence:** we depend on `matrix-sdk-crypto` directly and author our own
`matrix-crypto-ffi`. This is what bridge spec §4bis.1 already describes, so
§4bis.1 is correct and §1 and §4 are stale.

### 1.2 Names are superseded

| Spec text | Actual name |
|---|---|
| `messagr-bridge-core` | `matrix-crypto-core` |
| `messagr-bridge-ffi` | `matrix-crypto-ffi` |
| `@messagr/bridge-native` | `react-native-matrix-crypto` |

The generalized names are consistent with bridge spec §0, which states the bridge
is independent of Messagr. The npm name `react-native-matrix-crypto` was verified
unclaimed on 2026-08-27.

### 1.3 `apps/messagr/` is dropped from the repository layout

Bridge spec §4 places `apps/messagr/` inside the monorepo. Bridge spec §0 calls
Messagr "its first consumer, not its exclusive purpose", and §12 requires the
bridge be "reusable by other RN projects without any Messagr-specific
configuration". Keeping the consumer in the repository makes that boundary social
rather than structural.

**Consequence:** this is a standalone library repository. Messagr consumes it as
an npm dependency from its own repository.

### 1.4 §5's `encryptEvent(roomId, ...)` contradicts §6

Bridge spec §5 names the first parameter `roomId`. Bridge spec §6 requires that
the TypeScript contract "must not hardwire the assumption that a `Channel` is
necessarily a Megolm room", and calls this "a normative requirement, not an
intention". A parameter named `roomId` is that assumption.

**Consequence:** the facade takes an opaque branded scope identifier. See §6.

### 1.5 Three tool facts corrected during planning

Established by inspecting `uniffi-bindgen-react-native@0.31.0-5` directly on
2026-08-27.

- Bridge spec §4bis.2 step 2 names `ubrn generate all`. **That command does not
  exist.** The real surface is `ubrn generate jsi turbo-module` and
  `ubrn generate jsi bindings`.
- ubrn's default output directories are `src/generated` for TypeScript and
  `cpp/generated` for C++, not a single `generated/`. §3 now matches the tool.
- `#[uniffi::export]` on a plain `async fn` already yields a Promise. The
  `async_runtime = "tokio"` attribute is only required when the future needs a
  specific reactor, so §5.1 no longer assumes it.
- ubrn compiles its own binary from Rust source on first invocation. It is
  therefore a `devDependency` only; in `dependencies` it would break the
  no-Rust-toolchain guarantee of §4bis.2.

## 2. Frozen decisions

Bridge spec §15 requires these be frozen early.

| Decision | Value |
|---|---|
| Library name | `react-native-matrix-crypto` |
| npm package | `react-native-matrix-crypto` (unscoped) |
| Reserved alternate | `@linagora/react-native-matrix-crypto`, unused |
| Rust crates | `matrix-crypto-core`, `matrix-crypto-ffi` |
| License | Apache-2.0 |
| Repository shape | Standalone library, no consumer app in-repo |
| Crypto agility mechanism | Opaque branded scope id + open `algorithm` tag |
| Binary distribution | Built in CI, packed into the npm tarball at publish |
| First milestone | Walking skeleton, sequenced chain-first then dependency |
| CI | GitHub Actions, macOS runners for the iOS leg |
| Logging policy | The bridge has no logger. See §7. |

Apache-2.0 matches `matrix-sdk-crypto`'s own license, so no compatibility question
arises on the dependency the bridge is built on, and it carries a patent grant,
which matters for cryptography and more so on the post-quantum trajectory of
crypto spec §12.

## 3. Repository layout

```
react-native-matrix-crypto/
├── LICENSE                        Apache-2.0
├── package.json                   yarn workspaces root, private: true
├── ubrn.config.yaml               single source of truth for codegen
├── rust-toolchain.toml            pinned toolchain and targets
├── .nvmrc
├── rust/
│   ├── Cargo.toml                 workspace: core + ffi
│   ├── matrix-crypto-core/        all logic; knows no UniFFI, no JSI
│   └── matrix-crypto-ffi/         #[uniffi::export] and type translation only
├── packages/
│   ├── react-native-matrix-crypto/
│   │   ├── src/                   hand-written facade: brands, error mapping
│   │   ├── src/generated/         ubrn TypeScript output, committed
│   │   ├── cpp/generated/         ubrn C++ output, committed
│   │   ├── ios/                   podspec and generated glue
│   │   ├── android/               build.gradle and generated glue
│   │   └── package.json
│   └── example-app/               neutral RN demo, nothing Messagr-shaped
├── docs/
└── .github/workflows/
```

`src/` is a real layer, not a re-export. UniFFI cannot emit branded types, so the
`CryptoScopeId` brand, error normalization, and bridge spec §5's "no internal Rust
structure is directly re-exported" all live in a thin hand-written TypeScript shim
over `generated/`. That shim is the public API. `generated/` is an implementation
detail that happens to be committed.

`generated/` is committed per bridge spec §4bis.2 step 5. CI therefore regenerates it and
fails on any diff, which is how §4bis.3's "CI must detect and reject drift" becomes
a property of the repository rather than a promise.

## 4. Version matrix

Every pin is exact, because the codegen tool is pre-1.0.

| Component | Pin | Rationale |
|---|---|---|
| `uniffi-bindgen-react-native` | `0.31.0-5` exact | Pre-release; no caret range |
| `uniffi` crate | `"0.31"` | Must exclude 0.32.0, which exists and would break ubrn |
| `matrix-sdk-crypto` | `0.18.0` (M1b onward) | Latest, 2026-06-02; MSRV 1.93 |
| Rust toolchain | `1.97.1` | Clears MSRV; pinned for CI reproducibility |
| React Native | `0.87.1` | New Architecture / Turbo Modules |
| Node | `22.22.3` | Matches development environment |
| Package manager | yarn 1.22 workspaces | What RN libraries and ubrn examples assume |

Rust targets required: `aarch64-apple-ios`, `aarch64-apple-ios-sim`,
`x86_64-apple-ios`, `aarch64-linux-android`, `armv7-linux-androideabi`,
`x86_64-linux-android`, plus `aarch64-apple-darwin` for desktop consumption.
`armv7-linux-androideabi` is not installed in the development environment and must
be added.

The yarn-classic choice is the weakest pin in this table. RN autolinking and
CocoaPods still assume a flat `node_modules`. It stays until it causes a problem.

## 5. Architecture: the binding chain

```
app code
  └─ src/index.ts            hand-written: brands, error mapping   <- public API
      └─ generated/*.ts      ubrn output, typed, unbranded
          └─ generated/*.cpp JSI HostObject (New Architecture Turbo Module)
              └─ extern "C"  UniFFI scaffolding, stable C ABI
                  └─ matrix-crypto-ffi    #[uniffi::export], translation only
                      └─ matrix-crypto-core     all logic
                          └─ matrix-sdk-crypto  (M1b onward)
```

C++ is entirely generated and must never be hand-edited, per bridge spec §4bis.1.

### 5.1 Everything crossing the boundary is async

`matrix-sdk-crypto`'s `OlmMachine` is async, and JSI HostObject methods execute on
the JS thread. A synchronous decrypt of a key backlog on that thread would block
the UI. Therefore:

- `matrix-crypto-core` exposes `async fn`;
- `matrix-crypto-ffi` re-exports under plain `#[uniffi::export]`; UniFFI maps the
  future to a Promise on its own, and no runtime attribute is required until the
  core's futures need a specific reactor;
- every generated TypeScript function returns a Promise, and accepts an optional
  `{ signal: AbortSignal }` final argument for cancellation;
- if `matrix-sdk-crypto` turns out to require a tokio reactor, the attribute
  becomes `#[uniffi::export(async_runtime = "tokio")]` and the runtime is owned by
  the FFI crate and nowhere else.

**M1b outcome.** M1b exercised exactly one function, `device_identity_keys`
(`OlmMachine::new` plus an in-memory store, no spawning). No `async_runtime`
attribute was needed for it — confirmed by reading the vendored source and by
clean runs on both the iOS simulator and a physical Android device, no reactor
panic.

That result is scoped to the one function tested, not a resolution for
`matrix-sdk-crypto` as a whole, and must not be read that way. `matrix-sdk-common`
— a mandatory, non-optional dependency of `matrix-sdk-crypto` — enables tokio's
`rt` feature on every native (non-wasm) target
(`matrix-sdk-common/Cargo.toml`, `[target.'cfg(not(target_family = "wasm"))'
.dependencies.tokio]`: `features = ["sync", "rt", "time", "macros"]`) and
re-exports `tokio::task::spawn` as `matrix_sdk_common::executor::spawn`
(`src/executor.rs:29-31`). `matrix-sdk-crypto` calls that spawn from production,
non-test code reachable from public APIs this crate does not yet expose:
`session_manager/group_sessions/mod.rs:355,502,902,963` and
`identities/manager.rs:318,387`. Most notably, `OlmMachine::share_room_key`
(`machine/mod.rs:1239`) — the Megolm key-sharing entry point a later milestone
needs — reaches the first of those as its normal, non-test path. Calling
`share_room_key` under the current no-`async_runtime` setup would panic with
"there is no reactor running".

The async-runtime question is therefore scoped to what M1b exercised, not closed
for the crate. It must be re-opened, not assumed closed, the moment a future
milestone exports `share_room_key` or anything else that reaches a `spawn` call —
at which point the `invokeBlocking` consequence below becomes live and the signal
channel must be re-examined deliberately, exactly as already written here.

**That attribute has a second consequence, discovered while building the signal
channel and not anticipated here.** UniFFI callback methods that must return a value
synchronously are dispatched through `UniffiCallInvoker::invokeBlocking`, which really
does block the calling native thread on a promise whenever that thread is not already
the JS thread. Today the cost is zero, because the exported functions carry no
`async_runtime` and therefore already run on the JS thread. The moment a tokio runtime
is introduced, every signal delivery becomes a genuine cross-thread blocking
round-trip.

For a crypto bridge this is not a micro-optimisation: signals fire on key events, and
§7.3 requires them to be silent and cheap. Whichever change first adds
`async_runtime = "tokio"` must re-examine the signal channel deliberately rather than
inheriting this by accident — the likely answer is a non-blocking delivery path for
callbacks whose return value nothing reads.

This is committed to in M1a deliberately. Retrofitting async through an established
UniFFI surface is a rewrite, not a change.

### 5.2 The core / FFI boundary is mechanically enforced

Bridge spec §4bis.3 requires all logic to live in the core. Two CI assertions make
this checkable:

1. `matrix-crypto-core`'s direct dependencies must not include `uniffi`, read from
   `cargo metadata`. A hit fails the build.
2. `cargo test -p matrix-crypto-core` must pass with no Node, no simulator, and no
   Turbo Module.

## 6. Public facade and crypto agility

The facade satisfies bridge spec §6 by construction rather than by convention.

```ts
// Branded: callers cannot pass a bare string, and no type says "room".
type CryptoScopeId = string & { readonly __brand: unique symbol }

// Open union: adding 'mls' is an additive change, a minor bump per §4bis.4.
type CryptoAlgorithm = 'megolm' | 'olm' | (string & {})

interface EventEnvelope {
  scope: CryptoScopeId
  algorithm: CryptoAlgorithm
  eventType: string
  ciphertext: Uint8Array
  sender: string              // @user:server, verbatim, per bridge spec §10
}

encryptEvent(scope: CryptoScopeId, type: string, payload: unknown)
  : Promise<EventEnvelope>
```

A later move to MLS adds an algorithm tag value and a scope-creation path. No
existing signature changes.

The full surface of bridge spec §5 is re-typed onto this shape and written as types
in M1a, throwing `NotImplemented` at runtime, so a consuming product team can
compile against the real shape while M1b is still linking.

The bridge remains federation-neutral per bridge spec §10: `sender` carries the
fully qualified `@user:server` without transformation, and no primitive
distinguishes a local from a federated participant.

## 7. Errors, signals, and the anonymity constraint

### 7.1 Returning is not emitting

Bridge spec §10 requires errors from a federated device to carry `@user:server`
without transformation. Bridge spec §8 forbids journaling device identifiers beyond
the strict minimum. Both hold once separated:

**The bridge returns identifiers to its caller. It never persists or emits them.**

The caller is the product layer, which already holds that data and is the only
layer §8 permits to own telemetry.

### 7.2 The bridge has no logger

No `println!`, no `eprintln!`, no `log::`, no `console.*`, no file writes, and no
`tracing` subscriber of its own. Diagnostics, if ever required, pass through a sink
the product injects and owns. CI greps the shipped surface for these tokens and
fails on a hit.

A crypto library that logs by default is how cleartext reaches a crash report.
This also satisfies crypto spec §6's rule that audit "must never silently become a
second cleartext content store".

### 7.3 Two channels

A failed decrypt belongs to a call. An unexpected device appearing in a group
belongs to no call. Bridge spec §7 and §11 require the second to be typed and
silent by default, taking no product decision.

```ts
// Channel 1: a call failed. Open union per §4bis.4, so consumers
// must handle an unknown kind.
type CryptoErrorKind =
  | 'missing_key' | 'unshared_session' | 'unknown_device'
  | 'revoked_device' | 'undecryptable' | 'store_corrupt'
  | 'not_implemented' | (string & {})

interface CryptoError extends Error {
  kind: CryptoErrorKind
  scope?: CryptoScopeId
  sender?: string        // @user:server verbatim, per §10
  retriable: boolean     // bridge reports; upper layer decides
}

// Channel 2: state changed, no call in flight. §7, §11.
type CryptoSignal =
  | { kind: 'trust_changed'; user: string; state: TrustState }
  | { kind: 'unexpected_device'; scope: CryptoScopeId; user: string }
  | { kind: 'key_missing'; scope: CryptoScopeId }

onCryptoSignal(cb: (s: CryptoSignal) => void): Unsubscribe
```

Channel 2 rides a UniFFI callback interface, which has its own threading rules
across JSI. M1a's probe therefore carries one trivial signal end-to-end, so broken
callback plumbing is found in M1a rather than M3.

`retriable` edges toward a product decision, which §11 says these surfaces must not
take. It is retained because transience is knowable only at the crypto layer. If
that trade is judged wrong, it is removed without affecting anything else.

## 8. Testing

Bridge spec §13 defines five levels. Three cannot be meaningful in a skeleton.

| §13 level | M1 status |
|---|---|
| Rust / crypto tests | Real: `cargo test -p matrix-crypto-core`, no Node, no simulator |
| RN integration | Real: probe on device and emulator |
| Multi-participant contract | Deferred to M3; requires real sessions |
| Binding interop | Harness real, suite trivial. §4bis.3 calls drift blocking, so the shared JS suite exists from day one and a second binding drops into it |
| Federation-neutral | Deferred; requires Synapse and Continuwuity, per crypto spec §14 |

### 8.1 The agility test is pulled forward

Crypto spec §14 requires a compatibility test proving a Megolm to MLS swap does not
break the facade. This does not require MLS. In M1a:

1. push a fabricated third algorithm tag through the facade and assert it survives
   untouched;
2. assert no Megolm-specific or Olm-specific identifier appears in the public
   `.d.ts`.

This verifies the normative requirement of bridge spec §6 on the only day the
facade is cheap to change.

### 8.2 The M1a probe

A trivial integer proves nothing, because integers never break. The probe exercises
the four things that do:

```rust
// matrix-crypto-core, no uniffi present
pub struct ProbeReport {
    pub echoed: String,
    pub payload: Vec<u8>,
    pub core_version: String,
}
pub enum ProbeError { Rejected { reason: String } }
pub async fn probe(input: String, payload: Vec<u8>)
    -> Result<ProbeReport, ProbeError>;
```

Record round-trip; `Vec<u8>` to `Uint8Array`, the classic JSI marshalling break and
exactly how ciphertext will travel; async to Promise; and a typed error reaching a
JS `catch`. Plus one callback signal, per §7.3.

If those five survive the chain on real hardware, the chain carries `EventEnvelope`.

## 9. CI and release

Every job is a gate. None are advisory.

| Job | Asserts |
|---|---|
| `core` | `cargo test -p matrix-crypto-core`; no direct `uniffi` dependency |
| `drift` | `ubrn generate jsi turbo-module` then `git diff --exit-code` |
| `no-logger` | Grep the shipped surface for logging tokens |
| `lint` | `cargo fmt --check`, `clippy -D warnings`, `tsc --noEmit`, eslint |
| `agility` | §8.1 |
| `build-ios` | `ubrn build ios`, produce xcframework, record artifact size |
| `build-android` | `ubrn build android`, produce aar, record artifact size |
| `e2e-ios` / `e2e-android` | Probe assertions on simulator and emulator |
| `cold-consume` | Fresh RN 0.87 app runs `yarn add` on a runner with **no Rust installed** |

`cold-consume` is the only real proof of bridge spec §4bis.2's "the RN consumer
installs no Rust toolchain".

macOS runners are the cost centre. The iOS legs run on pull requests; the full
cross-compile matrix runs on tag only.

Release, per bridge spec §4bis.2: tag triggers cross-compilation of all targets,
codegen, packaging, the interop suite, and `npm publish` of a tarball containing
prebundled binaries. Versioning is in lockstep with the Rust crates. A breaking
TypeScript change is a major bump documented in `CHANGELOG.md` with explicit old to
new equivalence, per §4bis.4.

## 10. Milestones and exit criteria

Sequencing is chain-first, then dependency. The two risks, "does ubrn 0.31.0-5
work" and "does a large Rust crypto crate cross-compile and link into an
xcframework", are independent. Wiring them together on the first commit makes every
iOS link failure ambiguous.

### M1a: chain, no crypto dependency

No `matrix-sdk-crypto`. Exits when, on a physical iOS device and an Android
emulator, the probe round-trips a record, a `Vec<u8>`, an async call, a typed
error, and one callback signal, and:

- `core`, `drift`, `no-logger`, `lint`, `agility`, `cold-consume` all green;
- baseline xcframework and aar sizes recorded.

### M1b: dependency added

Adds `matrix-sdk-crypto 0.18.0`. Exits when:

- every M1a criterion still holds with the dependency linked;
- one genuine crypto value has crossed the chain, for example an `OlmMachine`
  identity key;
- the artifact size delta is recorded.

**Size gate:** if the packed npm tarball exceeds roughly 150 MB, the decision in §2
to pack binaries into the tarball re-opens. The pre-agreed fallback is split
per-platform packages resolved through `optionalDependencies`. Naming this number
now is cheaper than discovering it during a release.

### Beyond M1

M2 implements bridge spec §5's surface against real `matrix-sdk-crypto`. M3 adds
multi-participant contract tests and the federation-neutral suite. Bridge spec §14's
V0.2, V0.3, and V1.0 phases follow.

## 11. Out of scope

Per bridge spec §3, and restated because these are the boundaries most likely to
erode: full network sync, timeline, pagination, search, non-crypto application
storage, conversation UI, audio and video including MatrixRTC, push notifications,
product-level group and community logic, contact discovery, permission policy and
capability grants, AI agent and tool gateway policy, and application-level
inter-instance federation.

The bridge encrypts and decrypts regardless of the recipient's domain and has no
notion of a remote instance.

## 12. Open risks

| Risk | Exposure | Handling |
|---|---|---|
| `uniffi-bindgen-react-native` is pre-1.0 (`0.31.0-5`) | The entire codegen chain | Exact pin; M1a exists to find breakage early; generated output committed so a regression is visible as a diff |
| Artifact size may make the npm tarball impractical | Distribution strategy | Measured as an M1b exit criterion with a pre-agreed fallback |
| `uniffi` 0.32.0 exists and would break ubrn 0.31 | Build | Cargo range `"0.31"` excludes it |
| yarn 1.22 is EOL-adjacent | Tooling | Retained for RN compatibility; revisit when it causes a problem |
| UniFFI callback threading across JSI | Signal channel (§7.3) | Exercised in M1a rather than discovered in M3 |
| `matrix-sdk-crypto` MSRV drift | Build | Toolchain pinned above MSRV; bumps are their own commit per repository convention |
