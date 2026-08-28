# react-native-matrix-crypto — M2 design: the encryption core

## 0. Authority and scope of this document

The M1 design, `docs/superpowers/specs/2026-08-27-react-native-matrix-crypto-design.md`,
remains the binding authority for everything it settles: naming, crate layout, the
core/FFI boundary, crypto agility, the no-logger rule, federation neutrality, and the
public facade's shape. This document extends it for M2 only.

Where the two disagree inside M2's scope, this document wins and says why. Everywhere
else the M1 design wins. No decision frozen in M1 §2 is reopened here except binary
distribution, which M1 §10 explicitly made conditional on a measurement that has now
been taken.

## 1. What M2 delivers, and what it does not

M2 turns five typed-but-throwing functions into working cryptography:

| Function | Today | After M2 |
|---|---|---|
| `createCryptoMachine(config)` | throws `not_implemented` | creates and holds a real `OlmMachine` |
| `openCryptoStore(config)` | throws `not_implemented` | opens a persistent, passphrase-encrypted store |
| `receiveSyncChanges(syncDelta)` | throws `not_implemented` | feeds `/sync` output into the machine |
| `encryptEvent(scope, type, payload)` | throws `not_implemented` | returns a real `EventEnvelope` |
| `decryptEvent(rawEvent)` | throws `not_implemented` | returns the decrypted envelope |
| `takeOutgoingRequests()` | **new in M2** | returns what the product must send to its homeserver |
| `markRequestSent(id, response)` | **new in M2** | tells the machine a request was delivered |

The last two are additions to the frozen surface, not changes to it, so no existing
signature moves. They exist because of §3bis, and without them nothing else here
works.

Everything else on the facade keeps throwing `not_implemented` and moves to M3:
`restoreCryptoMachine`, `getDeviceStatuses`, `requestVerification`,
`confirmVerification`, `exportSecrets`, `importSecrets`.

This split is not arbitrary. The five above are the closed set required for two parties
to exchange an encrypted event. The six deferred ones are all about trust
establishment and recovery, which are a separate problem with a separate test shape,
and folding them in would make every M2 failure ambiguous between "the encryption is
wrong" and "the trust plumbing is wrong". That is the same reasoning that split M1a
from M1b, applied again.

`getSupportedAlgorithms` and `getDeviceIdentityKeys` already work and are unchanged in
signature, though §3 changes what the second one reads from.

## 2. Decisions carried in from M1

Restated because M2's implementers will not read the M1 spec end to end:

* The bridge never talks to a homeserver. `receiveSyncChanges` takes a payload the
  product fetched. Transport stays out.
* The bridge has no logger. No exemption for debugging encryption.
* `sender` carries `@user:server` verbatim. No primitive distinguishes a local from a
  federated participant.
* No identifier in the public declarations may say `megolm`, `olm` or `room`. The
  agility gate enforces this by splitting identifiers on case transitions, so
  `MegolmSession` is caught, not just `megolm_session`.
* `matrix-crypto-core` never gains a direct `uniffi` dependency. All logic lives
  there; `matrix-crypto-ffi` mirrors, converts and delegates.
* Every core-to-FFI conversion destructures its source, so a field added later fails
  the build instead of being silently dropped.

## 3. The crypto machine: lifecycle and ownership

`createCryptoMachine` returns `Promise<void>`
(`packages/react-native-matrix-crypto/src/facade.ts:24`). That signature, frozen in
M1a so a product team could compile against the real shape, already decided the
ownership model: **there is one machine per process, held by the library, not a handle
returned to JavaScript.**

M2 honours that rather than reopening it. Returning a handle now would be a breaking
change to a surface whose whole purpose was to stop being one.

Consequences the implementation must respect:

* The machine lives in `matrix-crypto-core` behind a `OnceLock` plus an async-aware
  lock. Not a `std::sync::Mutex`, because it is held across await points.
* `createCryptoMachine` called twice is not an error and does not replace the machine.
  It resolves against the existing one when the config matches, and rejects with
  `already_initialised` when it does not. Silently swapping the machine underneath a
  running app would strand every session it holds.
* Every other function rejects with `not_initialised` when no machine exists. That
  kind joins the open `CryptoErrorKind` union, which consumers already must treat as
  open.

`getDeviceIdentityKeys` currently builds a throwaway `OlmMachine` per call and drops
it (`rust/matrix-crypto-core/src/identity.rs:27`). Once a real machine exists, that
function must read the live machine's keys instead, otherwise it reports keys that
belong to no session. Changing it is part of M2, not a follow-up.

## 3bis. Outbound requests: the half the first draft of this spec forgot

This section exists because a reconnaissance pass on level 2 interoperability found
the gap while Task 5 was still unwritten. It is recorded rather than quietly patched,
because the mistake is instructive: "the bridge does no networking" was silently read
as "the bridge produces nothing to send", and those are not the same statement.

`OlmMachine` is a state machine with an outbound side. `share_room_key` returns
`Vec<Arc<ToDeviceRequest>>`, and `outgoing_requests()`
(`matrix-sdk-crypto-0.18.0/src/machine/mod.rs:535`) yields device key uploads,
one-time key uploads and key queries. **These are not diagnostics. They are the only
way a session key reaches another device, and the only way this device's public keys
reach the homeserver.** A caller that never sends them owns a machine that encrypts
to nobody, holds keys nobody can find, and never learns that any of it happened.

Discarding them, which the first draft did, would have produced software that passes
every in-process test and cannot interoperate with anything. Level 1 would stay green
because the test can hand one machine's output straight to the other. Only level 2
would have caught it, weeks later, and it would have looked like a cryptography bug
rather than a missing API.

**The boundary does not move.** The bridge still performs no request. It hands the
product a description of what to send, and the product, which already owns transport,
sends it and reports back:

```ts
interface OutgoingRequest {
  id: string          // opaque; hand it back verbatim to markRequestSent
  kind: string        // open tag: 'keys_upload' | 'keys_query' | 'to_device' | (string & {})
  body: string        // JSON, sent as-is
}

takeOutgoingRequests(): Promise<OutgoingRequest[]>
markRequestSent(id: string, responseJson: string): Promise<void>
```

`kind` is an open tag for the same reason `algorithm` is: the set grows upstream, and
a consumer must already handle a value it does not recognise. `body` and
`responseJson` cross as strings the bridge does not interpret. Neither carries
plaintext.

This is the shape `matrix-sdk-crypto`'s own FFI bindings use, so it is not an
invention, and it keeps §11's out-of-scope list intact: no network sync, no timeline,
no transport.

## 4. The tokio runtime

`tokio` is currently a dev-dependency only (`rust/matrix-crypto-core/Cargo.toml:20`).
Nothing in the shipped library starts a runtime, and nothing needs one, because the
UniFFI `async fn` exports are driven by the foreign executor rather than by Rust.

That ends in M2. `OlmMachine::share_room_key`, which is group key sharing and
therefore unavoidable for encrypting to more than one device, reaches
`tokio::task::spawn` through `matrix-sdk-common`. Calling it with no runtime in
context panics rather than returning an error.

**Decision:** `matrix-crypto-core` owns exactly one multi-threaded runtime, created
lazily on first use and never torn down, and enters it around the calls that need it.

Three things this must not become:

* Not a runtime per call. Runtime creation spawns threads; doing it per encrypt would
  be both slow and a thread leak under load.
* Not a `current_thread` runtime. Work spawned with `tokio::task::spawn` would then
  only progress while something is actively polling, which is a deadlock waiting for
  a specific call pattern to find it.
* Not a runtime owned by `matrix-crypto-ffi`. The boundary rule in M1 §5.2 puts logic
  in the core, and a runtime is logic: the core's own `cargo test` must exercise the
  same runtime arrangement the shipped library uses, or the tests prove nothing about
  it.

The panic behaviour matters here and is settled: `panic = "unwind"` stays.
`uniffi_core`'s `rust_call_with_out_status`, which every generated FFI call passes
through, wraps the call in `catch_unwind` and turns a Rust panic into a catchable
TypeScript error. It is the bridge's only panic safety net. Since Cargo's `panic`
setting applies to the whole dependency graph, `abort` would defeat it everywhere,
turning a panic triggered by malformed and possibly attacker-influenced ciphertext
into a hard abort of the host application.

## 5. Signal delivery must not block

The signal callback is already declared to return unit:
`fn on_signal(&self, signal: ProbeSignal)` under `#[uniffi::export(with_foreign)]`
(`rust/matrix-crypto-ffi/src/lib.rs:70`). That is the right shape and M2 keeps it.

The risk M2 introduces is different. Today signals are emitted from the same thread
that is already inside a foreign-driven async call. Once a tokio runtime exists,
`matrix-sdk-crypto` can emit from a worker thread, and a callback that crosses into
JavaScript from an arbitrary thread is where UniFFI callback plumbing breaks.

**Requirement:** signal emission is fire-and-forget from the Rust side. No emission
path waits for JavaScript to return, and no emission path holds the machine lock while
it emits. A signal emitted while the lock is held, delivered to a listener that calls
back into the library, is a self-deadlock, and it is the kind that appears only under
a real workload.

M1a's probe already carries one signal end to end on device, so the plumbing is known
to work single-threaded. M2's job is to keep it working when the emitting thread is
not the calling thread, and to prove it with a test that emits from a spawned task.

## 6. Persistent storage

**Decision:** `matrix-sdk-sqlite 0.18.0`, the store `matrix-sdk` itself uses.

Verified to exist at the same version as `matrix-sdk-crypto 0.18.0`, which is the
point: a store crate at a different version would pull a second, independently
versioned `ruma` into the tree, and the dependency comment in
`rust/matrix-crypto-core/Cargo.toml` exists precisely to prevent that.

The crate is feature-gated, and `crypto-store` with `default-features = false` is the
minimal configuration that provides a crypto store.

**Corrected during implementation.** This section first claimed that `matrix-sdk-base`
enters only if you enable more than `crypto-store`. That is false. The published
crate's own manifest reads
`crypto-store = ["dep:matrix-sdk-base", "dep:matrix-sdk-crypto"]`, so `matrix-sdk-base`
arrives with the crypto store itself and cannot be avoided by feature selection. The
feature choice above is still the right one, and `ruma` still unifies to a single copy
in the lockfile, verified. Only the reason given was wrong.

The consequence belongs to §9 rather than here: the dependency tree is larger than
this spec assumed, so the size measurement matters more, not less.

`openCryptoStore(config)` takes the same `CryptoMachineConfig` as
`createCryptoMachine`. The store path and passphrase come from that config; the
library chooses neither. A crypto library that picks its own on-disk location is a
library that writes somewhere the product did not agree to.

The store is encrypted with the passphrase the product supplies. The library does not
derive, cache, persist or log it, and it does not appear in any error.

Sessions surviving an app restart is an M2 exit criterion, not a nice-to-have: a group
session that does not survive restart is indistinguishable from working software until
the first restart in production.

## 7. Encrypt and decrypt

`encryptEvent(scope, type, payload)` returns an `EventEnvelope` whose `algorithm` is
an open tag and whose `scope` is opaque. Neither the signature nor the returned type
names a group-session algorithm, which is what the agility gate checks.

The work behind it, in order: ensure a group session exists for the scope, share it
with the devices the machine knows about, encrypt, and return. `receiveSyncChanges`
is how the machine learns which devices exist, so a product that never calls it will
encrypt to nobody. That ordering constraint belongs in the facade's documentation,
not in a runtime check the library cannot correctly make.

`decryptEvent(rawEvent)` returns the decrypted envelope, or rejects with a typed
error. The existing kinds already cover the real cases: `missing_key`,
`unshared_session`, `unknown_device`, `undecryptable`. Decryption failure is normal
operation in Matrix, not an exceptional condition, and the error must carry enough for
the product to decide whether to retry, request keys, or show a placeholder, without
carrying any ciphertext or plaintext.

`retriable` is set by the bridge and interpreted by the product. M1 §7.3 already
flagged this as the one field that edges toward a product decision, retained because
transience is knowable only at the crypto layer.

## 8. Testing: two levels, in this order

M1 §8.0 already fixed the ordering. M2 executes it.

**Level 1, two parties in one process, no server.** Two machines, each with its own
store, exchanging keys and decrypting each other's events, as `matrix-sdk-crypto`'s
own tests do. Deterministic, fast, and it catches the large majority of defects. This
is an M2 exit criterion.

**Level 2, a real homeserver and a third-party client.** The question level 1 cannot
answer is not "does our code run" but "does a real Matrix client decrypt what we
encrypt, and can we decrypt what it sends". Level 1 tests our implementation against
itself, so a consistent misreading of the protocol passes it cleanly.

M1a demonstrated exactly this failure in miniature: nineteen green tests passed
against an assumed UniFFI error shape while the real one differed, and only running
against real native code exposed it. Level 2 is that same check applied to the
encryption format.

Level 2 is an M2 exit criterion. Level 1 passing while level 2 is skipped would let
the milestone close on software that has never encrypted anything a real client can
read.

The existing interop suite contract in `packages/react-native-matrix-crypto/interop/`
is the vehicle: the same suite runs against a reference binding under Node and against
the real JSI binding on device. M2 extends the suite rather than inventing a second
test shape.

## 9. Distribution: the 150 MB gate has tripped

M1 §10 set a tripwire: if the packed npm tarball exceeds roughly 150 MB, the decision
to pack binaries into the tarball reopens, with per-platform packages resolved through
`optionalDependencies` as the pre-agreed fallback.

**The tripwire has fired, and the pre-agreed fallback does not work as written.**

What the release-profile spike established:

* `lto = true` plus `-C embed-bitcode=no` for the Apple targets cuts the xcframework
  from 152856 KB to 104460 KB, a 31.7% reduction. The `.aar` moves 31488 to 30604 KB.
  Both are real and are kept.
* `strip = "symbols"` alone buys nothing measurable on a `staticlib`, because the
  symbols are the link index rather than removable debug data.
* `opt-level = "z"` makes the iOS artifact 36% *larger*, by suppressing the inlining
  that LTO's cross-crate dead-code elimination depends on.
* `tarballKB` is nonetheless 184608 KB, 120% of the gate, and it has never measured
  only the two build outputs. `package.json`'s `files` entry `android/src/main` also
  ships four pre-link `jniLibs/*.a` archives, roughly 415 MB uncompressed. Leaner
  post-LTO code compresses worse, so archives that baseline's compression ratio hid
  now dominate the total.

Those four archives are **not** removable. `android/CMakeLists.txt` imports the
ABI-matching archive as `IMPORTED_LOCATION` and links it into the module's own `.so`,
and `android/build.gradle` runs that CMake step unconditionally for every consumer
using standard React Native autolinking.
`packages/react-native-matrix-crypto/android/README.md` documents this and warns
against exactly this deletion. An earlier reading of them as redundant was wrong and
is recorded here so it is not re-derived.

**Why `optionalDependencies` does not solve this.** npm's `os` and `cpu` fields
describe the machine running the install, not the mobile target being built. A
developer on macOS building both platforms matches every filter, so the resolver
cannot thin the download for the common case. The fallback helps only a project that
ships to one platform, which is not the case worth optimising for.

**Decision, in priority order.**

1. **Build the Rust as a `cdylib` per Android ABI instead of a `staticlib`, if it
   works.** This attacks the dominant term directly rather than moving it between
   packages. A static archive carries every object file including unreferenced ones;
   a linked, stripped shared library carries what survived. The module's C++ JSI
   adapter would link against the `.so` dynamically, and both land in the APK. It is
   investigated with a measurement before any packaging change is designed on top of
   it, and not before then: it blocks no cryptographic work, so sequencing it ahead of
   the milestone's substance would delay M2 for a question M2 does not depend on.
2. **Drop the root `react-native-matrix-crypto-release.aar`,** 30604 KB, if step 1
   does not close the gap. The project's own `android/README.md` describes it as a
   separate convenience artifact that nothing autolinks against, which makes it the
   one genuinely redundant shipped component. Removing it is a packaging change with a
   consumer-visible consequence and does not happen silently.
3. **Split per-platform packages, installed explicitly rather than resolved
   automatically.** The consumer adds `react-native-matrix-crypto` plus the platform
   packages they build for. This works where `optionalDependencies` does not, at the
   cost of an install step the consumer must know about. It is the fallback, not the
   plan.

Whatever lands, `measure-artifacts.sh` must be corrected first so `tarballKB` states
what it actually contains. A gate whose metric nobody trusts is worse than no gate,
because it produces confident wrong answers in both directions.

## 10. Exit criteria

M2 closes when all of the following hold:

* Two crypto machines in one test process exchange a group key and each decrypts an
  event the other encrypted, with the key travelling through `takeOutgoingRequests`
  rather than being handed over directly. A test that shortcuts the pump proves the
  cryptography and hides the gap §3bis describes.
* A freshly created machine yields a key upload request, so the device is
  discoverable by other clients rather than invisible.
* An encrypted event produced by this library is decrypted by a third-party Matrix
  client against a real homeserver, and an event that client produced is decrypted
  here.
* A session survives process restart through the persistent store.
* A signal emitted from a spawned task reaches a JavaScript listener, on device, with
  no deadlock and no blocking of the emitting thread.
* All five M1 gates stay green, plus the drift gate on regenerated bindings.
* `PROBE_SUMMARY` still passes on device, so M2 is proven not to have broken M1.
* Artifact sizes are re-measured under a corrected metric and recorded.
* No new public identifier names an algorithm, and the agility gate proves it.

## 11. Deferred to M3, deliberately

Device verification (SAS and QR), secret export and import, `getDeviceStatuses`,
`restoreCryptoMachine`, multi-participant scenarios, and cross-implementation testing
against both Synapse and Continuwuity.

Also deferred, carried over from M1's final review and to be scheduled explicitly
rather than absorbed silently into M2: `index.tsx` being invisible to TypeScript,
generated C++ logging present in the shipped binary, missing end-to-end CI gates, two
gates disagreeing on what counts as generated, and the destructuring rule not applied
at `facade.ts:87`.

## 12. Open risks new to M2

| Risk | Exposure | Handling |
|---|---|---|
| tokio runtime interacts badly with UniFFI's foreign executor | Every async call | Runtime lives in core so `cargo test` exercises the shipped arrangement; a spawned-task signal test is an exit criterion |
| Signal emitted while the machine lock is held | Deadlock under real workload, invisible in single-threaded tests | Emission never holds the lock; asserted by a test that emits from a spawned task |
| `cdylib` may not be viable with the JSI adapter's link model | The distribution plan's first option | Investigated with a measurement before anything is designed on top of it |
| Level 2 interop needs real server credentials | Test infrastructure | Credentials stay out of every tracked file; only the level 2 step reads them |
| Store passphrase handling | Key material | Never derived, cached, persisted, logged, or included in an error |
