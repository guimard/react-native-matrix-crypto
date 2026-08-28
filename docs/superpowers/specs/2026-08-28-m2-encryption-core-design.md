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
| `decryptEvent(scope, rawEvent)` | throws `not_implemented` | returns the decrypted envelope |
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

### 3ter. Knowing a device is not the same as being able to reach it

A second correction, found the same way as §3bis: by a review, one layer deeper, and
recorded rather than quietly patched because the mistake repeats a pattern worth
naming.

§3bis established that the outbound requests must leave the process. It did not say
which requests, and the omission matters. A group session key travels to another
device wrapped in an Olm session, and an Olm session cannot exist until this device has
claimed one of the other device's one-time keys. `/keys/query` teaches the machine that
a device exists and what its identity keys are; it does not establish a channel to it.
That is `/keys/claim`, and upstream exposes it as
`OlmMachine::get_missing_sessions(users)`
(`matrix-sdk-crypto-0.18.0/src/machine/mod.rs:794`), which returns an optional
`(OwnedTransactionId, KeysClaimRequest)`.

**A machine that never calls it can never deliver a key to anybody.** `share_room_key`
still succeeds, and still produces to-device requests, but every one of them is an
`m.room_key.withheld` notice carrying code `m.no_olm`: a message whose content is "I
could not send you the key". The failure is silent, permanent, and looks exactly like
success from inside the process.

So the pump's request set includes a keys-claim step, and the ordering is not optional:

1. `/keys/query`, so the machine knows the devices exist.
2. `/keys/claim`, so an Olm session exists to each of them.
3. `/sendToDevice`, carrying the group session key.

The lesson repeats §3bis's exactly. There, "the bridge does no networking" was read as
"the bridge produces nothing to send". Here, "the machine knows about the device" was
read as "the machine can send to the device". Both are one true statement standing in
for a different, false one, and both would have passed every in-process test.

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

The crate is feature-gated. The configuration is `default-features = false` with
`crypto-store` and `bundled`.

`bundled` compiles SQLite from source instead of linking a system one. It is not
optional on mobile: Android's NDK sysroot provides no `libsqlite3` to link against, so
without it every Android target fails at link time with
`ld.lld: error: unable to find library -lsqlite3`. Beyond linking, a cryptographic
store whose on-disk format depends on whichever SQLite the host happens to ship is a
portability and reproducibility problem.

Two details worth keeping, because both are easy to get wrong later:

* The failure is total, not partial. `matrix-crypto-ffi` declares
  `crate-type = ["cdylib", "staticlib", "lib"]`, and rustc finalises none of the
  requested outputs if the invocation fails. So without `bundled` the committed
  configuration produces neither a `.a` nor a `.so` for Android, whichever linking
  mode §9 selects.
* Its size cost is already inside §9's numbers. Both post-store rows were measured
  with `bundled` active, so the 67555 KB tarball includes compiled-in SQLite rather
  than needing an allowance added on top.

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

**`shareScopeKey` tracks the users it is given.** This was found late, by a review
noticing that the two-party test had to reach past the public surface to make the other
party's devices tracked. Upstream's `mark_tracked_users_as_changed`
(`matrix-sdk-crypto-0.18.0/src/store/mod.rs:291`) skips users the machine has never
seen, and a sync payload's `changed_devices` routes only there, so nothing in the
shipped surface could make a user tracked in the first place. A product would have
called `shareScopeKey`, received no error, and encrypted to nobody.

The alternative was an explicit `trackUsers`. It was rejected: it adds surface, and it
lets a product omit a call whose absence fails silently. "Share to these users" already
implies their devices matter, so making it implicit removes a way to hold the API wrong
rather than documenting one.

**The first share to a never-seen user delivers nothing, by construction.** It tracks
the user and arms a keys query; the query only reaches the homeserver through the next
`takeOutgoingRequests`, so no device is known yet and there is nobody to share with.
The product must pump, feed the response back with `markRequestSent`, and call
`shareScopeKey` again. This is §3ter's ordering seen from the caller's side, and it is
an obligation on the product rather than something the library can hide: the library
performs no request, so it cannot wait for one.

Tracking happens **after** the share rather than before, deliberately. Flagging first
arms upstream's `get_user_devices_for_encryption` to wait up to five seconds for an
outstanding keys query, and that wait is unsatisfiable here by construction: the request
reaches the product only through a later `takeOutgoingRequests`, and the machine lock is
held throughout, so no concurrent caller could satisfy it either. Measured on the
two-party test at 7.47 seconds flagging first against 2.47 seconds flagging last, with
identical outcomes. Flagging last arms nothing, because the flag exists for the pump,
which runs afterwards.

`decryptEvent(scope, rawEvent)` returns the decrypted envelope, or rejects with a typed
error.

**Its signature gained the scope during implementation**, and the change is deliberate.
The M1a surface froze it as `decryptEvent(rawEvent)`, which cannot work: decryption
needs the scope for the same reason encryption does, and `encryptEvent` has taken it as
its first parameter all along. The alternative considered was smuggling the scope into
the `unknown` as `{ scope, event }`, which compiles but hides a required argument where
the type system cannot see it, and bypasses the branded `CryptoScopeId` that exists
precisely so a caller cannot pass a bare string. A frozen signature is not broken
lightly, but it is broken when the frozen shape cannot express something required. The
same test rejected a change to `getDeviceIdentityKeys`, where keeping the parameters
cost nothing. The existing kinds already cover the real cases: `missing_key`,
`unshared_session`, `unknown_device`, `undecryptable`. Decryption failure is normal
operation in Matrix, not an exceptional condition, and the error must carry enough for
the product to decide whether to retry, request keys, or show a placeholder, without
carrying any ciphertext or plaintext.

`retriable` is set by the bridge and interpreted by the product. M1 §7.3 already
flagged this as the one field that edges toward a product decision, retained because
transience is knowable only at the crypto layer.

### 7.1 M2 decrypts events. It does not authenticate their senders.

This has to be said in the specification rather than only in a code comment, because it
is a property of what the milestone ships and a product will assume the opposite.

`Envelope.sender` is the sender field the homeserver delivered. Decryption does not
verify it. Upstream is explicit about this: `EncryptionInfo::sender` in
`matrix-sdk-common-0.18.0/src/deserialized_responses.rs:331` is documented as "untrusted
data unless the `verification_state` is `Verified` as well", and `sender_device` carries
the same caveat. There is no stronger sender value sitting in `encryption_info` waiting
to be surfaced; the authentication comes from device verification, which is M3.

`algorithm` is likewise read from the incoming event rather than asserted by us.

So for all of M2, both fields are **unauthenticated transport metadata**, and the
public documentation must say so in those terms. A product that reads the sender of a
successfully decrypted event as the cryptographic sender has assumed something this
milestone does not provide, and that assumption is the shape impersonation takes.

The real fix is `verification_state` reaching the product, which needs a deliberate
decision about what it adds to the public surface rather than a patch. It belongs to
M3 alongside the verification work that makes it meaningful, and it is listed there.

An earlier instruction of mine during implementation asked for the authenticated sender
to be surfaced from `encryption_info`. That was wrong, and it was refused with the
upstream source as evidence, correctly.

### 7.2 Both halves of the trust decision, named rather than defaulted

M2 has no verified devices, and that single absence forces a choice on each side of the
crypto. Both are named here because one of them would otherwise ship as an unexamined
library default.

**Inbound**, `DecryptionSettings` takes `TrustRequirement::Untrusted`. Anything stricter
rejects every event, because nothing is verified.

**Outbound**, `share_room_key` takes `EncryptionSettings::default()`, which carries
`CollectStrategy::AllDevices`. Upstream marks that "not recommended, per the guidance of
[MSC4153]", because it shares with every unblacklisted device rather than only devices
signed by their owner. The recommended identity-based strategy is not available to us:
it gives room keys to nobody whose identity is unpublished, and no identity is published
until cross-signing exists, which is M3's work.

The asymmetry worth noticing is that the inbound choice had to be written, so it was
argued for, while the outbound one arrives free with `default()` and could have shipped
without anyone deciding it. Both construction sites now carry the same comment,
`// M2: verification lands in M3; revisit this with it.`, so one grep finds the whole
decision rather than half of it.

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

**Decision, in priority order. Step 1 was taken, measured, and closed the gate;
steps 2 and 3 are therefore not needed and were not attempted.**

1. **Build the Rust as a `cdylib` per Android ABI instead of a `staticlib`.** ✅ Done.
   A static archive carries every object file including unreferenced ones; a linked,
   stripped shared library carries what survived. ubrn expresses this as
   `android.useSharedLibrary` in `ubrn.config.yaml`, which drives the generated
   `CMakeLists.txt` between `STATIC IMPORTED` and `SHARED IMPORTED`, so the switch is
   a configuration change plus regeneration rather than a hand edit of generated
   output, and `gate:drift` stays green.

   | configuration | aar KB | tarball KB | `android/` unpacked KB |
   |---|---:|---:|---:|
   | staticlib, measured after M2's store landed | 44060 | 263523 | 656809 |
   | cdylib, same source, same features, four ABIs | 23236 | **67555** | 24958 |

   The tarball falls 74.4% and the `jniLibs` component 96.2%, to 44% of the gate.
   Verified with the example app's own `./gradlew :app:assembleDebug`, the real
   autolinking path a consumer takes, rather than a bare `cargo build`; the resulting
   APK carries both `libmatrix_crypto_ffi.so` and `libreact-native-matrix-crypto.so`.

   Worth recording: the staticlib row is 263523 KB, not the 184608 KB measured before
   M2. The store dependency added 79 MB. So `cdylib` did not merely close a gap that
   already existed; it absorbed M2's own growth as well.

2. **Drop the root `react-native-matrix-crypto-release.aar`,** 23236 KB. Not needed.
   Retained.
3. **Split per-platform packages, installed explicitly rather than resolved
   automatically.** Not needed. Retained as the fallback if a later milestone's
   dependencies push the tarball back over the gate.

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

**`verification_state` on the public surface**, per §7.1. It is the only thing that
turns `sender` from transport metadata into an authenticated claim, and it is
meaningless before the verification work that shares this milestone. Deciding its shape
is part of M3's design, not a patch to M2.

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
