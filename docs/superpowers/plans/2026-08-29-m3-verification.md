# M3 Implementation Plan: device verification, sender authenticity, typed sync input

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let two people verify each other's devices by comparing a short string, make a
decrypted event carry what upstream knows about its sender, and stop every consumer
hand-writing a five-field rename against an untyped parameter.

**What this goal deliberately does not say.** It does not say a decrypted event will be
able to read "verified". It cannot, before M4: SAS establishes *local* trust, and upstream's
event path consults only cross-signing. A *device* reads verified after a SAS flow; an
*event* does not. Spec §7 Q6.

**Architecture:** Three layers, unchanged from M1/M2. All logic lands in
`matrix-crypto-core`; `matrix-crypto-ffi` exposes it over UniFFI and owns no logic; the
generated JSI Turbo Module is regenerated, never hand-edited; the TypeScript facade is
hand-written and is the only surface a product sees. SAS verification flows are held by
the core and addressed from JavaScript by opaque id — no handle crosses the bridge.

**Tech Stack:** Rust (`matrix-sdk-crypto`, tokio, UniFFI), `uniffi-bindgen-react-native`,
TypeScript, React Native 0.87, yarn workspaces, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-08-28-m3-design.md`, which is binding for M3 and
whose §7 Q2, Q3, Q5 and Q8 were settled on 2026-08-29. The M1 spec
(`2026-08-27-react-native-matrix-crypto-design.md`) and the M2 spec
(`2026-08-28-m2-encryption-core-design.md`) remain binding everywhere M3's spec does not
override them.

## Task order, and why it is not the obvious one

An earlier draft of this section ordered SAS before `verification_state` so that the
latter's test could "drive a real verification and assert the value changes". **That
rationale was wrong and is recorded here rather than deleted, because the fact that killed
it governs the whole milestone.**

A successful SAS verification does not change a decrypted room event's `verification_state`
at all. Upstream's Megolm path builds sender data from `is_cross_signed_by_owner()` and
`is_cross_signing_trusted()` and never consults `is_locally_trusted()`, which is the only
thing SAS sets. A non-cross-signed device yields `SenderData::DeviceInfo` →
`Unverified(UnsignedDevice)`, before and after, identically. Spec §7 Q6, verified against
`matrix-sdk-crypto` 0.18.0 directly.

So no ordering makes that test writable, and **`verification_state` is not what proves SAS
works.** What proves SAS works is a *device* reading verified afterwards, through
`getDeviceStatuses`. The two features are independent, and the milestone's ordering is
driven by dependency instead:

1. **The typed sync input** (Task 1). Independent of everything; unblocks a consumer today.
2. **The core SAS flow** (Task 2). Everything else in verification stands on it.
3. **The bridged SAS surface** (Task 3). Needs Task 2.
4. **`verification_state` on the envelope** (Task 4). Independent of SAS in fact, placed
   here because it shares the record and error plumbing Task 3 establishes.
5. **Trust changes on the signal channel** (Task 5). Needs Tasks 2 and 3, and must not merge
   ahead of `m3-signal-latency`.
6. **The third-party interoperability proof** (Task 6). Needs everything above.

The fourth M3 item, B2's signal delivery, is carried on branch `m3-signal-latency` and is
not in this plan.

**One constraint that outranks the ordering.** Three of upstream's five verification levels
are unreachable until cross-signing lands in M4. The public type still models all five, by
spec ruling, because widening a closed union later would break consumers. In exchange, the
spec binds the implementation: the unreachable values are documented as unreachable at the
type itself, and **no test may contain a fixture that produces `Verified`** on the event
path. A fixture that faked it would teach precisely the false belief the ruling exists to
prevent.

## Global Constraints

Every task's requirements implicitly include this section. Values are copied verbatim from
the specs that set them.

- **No logger.** The library must not log, on any path. Gate: `yarn gate:logger`.
- **Core/FFI boundary.** `matrix-crypto-core` must have no *direct* dependency on any crate
  in the `uniffi` family (`uniffi`, `uniffi_core`, `uniffi_macros`, `uniffi-*`). A
  transitive one is fine. All logic lives in the core; the FFI crate owns none. Gate:
  `yarn gate:boundary`.
- **Crypto agility.** No public identifier may say `room`, `matrix`, `olm` or `megolm` as
  part of its name. A scope is a `CryptoScopeId`. Gate: `yarn gate:agility`.
- **Generated files are generated.** Never hand-edit anything under `src/generated/`.
  Gates: `yarn gate:drift` and `yarn gate:stubs`.
- **`gate:drift` compares against the git index**, so run it *after* `git add`, and note
  that it regenerates into the working tree it is measuring.
- **UniFFI wire ordinals are assigned by declaration position.** A new error variant must be
  **appended last**; inserting one renumbers every variant after it and makes stale bindings
  decode the wrong error.
- **The facade's frozen signatures may not be broken** except under the M1 spec's G1/G9/G25
  test, which requires demonstrating that the frozen shape *cannot* express something
  required. Additions are not breaks. Narrowing a parameter typed `unknown` on a function
  that has only ever thrown `not_implemented` is not a break either.
- **An added call whose absence fails silently is not acceptable.** This is M2's
  `trackUsers` rejection, and it binds every function added in Task 2. A function a product
  can forget must either be impossible to skip or fail loudly when skipped.
- **The repository is public.** No hostname, user id, access token, homeserver name or other
  infrastructure detail may appear in any tracked file, including test fixtures and
  comments. Real-server credentials live only in the gitignored ledger.
- **Commits:** Conventional Commits, imperative sentence-case subject, one subject per
  commit. **No `Co-Authored-By` trailer naming Claude or Anthropic, and no `Claude-Session:`
  trailer, ever.**
- **`cargo fmt` from the repo root silently passes.** There is no root `Cargo.toml`, so
  `cargo fmt --all --check` prints usage and exits 0. The only correct form is
  `cargo fmt --manifest-path rust/Cargo.toml --all -- --check`.
- **Every check must be able to fail.** Before claiming a test or gate passes, make it face
  something it should reject and confirm it does. Spec §3.2.

---

### Task 1: A typed `SyncDelta`, and one mapping instead of four

**Spec:** §5.1, B3.

**The problem, precisely.** `receiveSyncChanges(syncDelta: unknown)` accepts a five-field
subset of a `/sync` response whose field names differ from the response's own. The two sets
of names have **no member in common**. The mapping between them is hand-written in three
places inside this repository, and every consumer writes a fourth, with no compile-time
help. Its failure mode is the worst in the library: a camelCase payload parses into an
all-default value, resolves successfully, and teaches the machine nothing — after which
every symptom points at the cryptography.

**What must not be undone.** A runtime guard already rejects a non-empty payload that names
none of the five recognised fields, throwing `malformed_payload` before native is called.
That guard is the important half and it stays exactly as it is. It must keep accepting a
payload that names at least one recognised field alongside unrecognised ones — tolerance
for a homeserver adding a `/sync` field is why it checks for *some* recognised field rather
than rejecting any unrecognised one. It must keep accepting `{}`.

**Files:**
- Modify: `packages/react-native-matrix-crypto/src/types.ts` — add `SyncDelta`
- Modify: `packages/react-native-matrix-crypto/src/facade.ts` — type the parameter, export
  the mapping helper, replace the worked example in the doc comment with a pointer to it
- Modify: `packages/react-native-matrix-crypto/src/index.ts` — export both
- Test: `packages/react-native-matrix-crypto/src/facade.test.ts` (or the existing test file
  covering `receiveSyncChanges` — find it rather than assuming the name)

**Interfaces produced (later tasks and consumers rely on these exact names):**

```ts
/**
 * The five fields `receiveSyncChanges` reads. Named as the native call names
 * them, not as a `/sync` response names them: the two vocabularies have no
 * member in common, and renaming here would only move the rename into a
 * place with no compile-time help.
 */
export interface SyncDelta {
  to_device_events?: unknown[]
  changed_devices?: unknown
  one_time_keys_counts?: Record<string, number>
  unused_fallback_keys?: string[]
  next_batch_token?: string
}

/** Maps a `/sync` response to the slice this library consumes. */
export function encryptionSlice(sync: Record<string, unknown>): SyncDelta
```

- [ ] **Step 1: Find the existing tests and read the guard**

Run: `grep -rn "receiveSyncChanges\|malformed_payload" packages/react-native-matrix-crypto/src --include='*.ts'`

Read `facade.ts` around the guard and its doc comment (roughly lines 180–270). Confirm for
yourself which payloads the guard accepts and which it rejects **before** changing
anything. You are about to put a type in front of a guard; if your type and the guard
disagree about what is legal, the type is wrong.

- [ ] **Step 2: Write the failing tests**

Four behaviours, and the third is the one that matters:

```ts
describe('encryptionSlice', () => {
  it('renames all five fields a sync response carries', () => {
    const slice = encryptionSlice({
      to_device: { events: [{ type: 'm.room.encrypted' }] },
      device_lists: { changed: ['@a:example.org'], left: [] },
      device_one_time_keys_count: { signed_curve25519: 42 },
      device_unused_fallback_key_types: ['signed_curve25519'],
      next_batch: 's72595_4483_1934',
      rooms: { join: {} },
      presence: { events: [] },
    })
    expect(slice).toEqual({
      to_device_events: [{ type: 'm.room.encrypted' }],
      changed_devices: { changed: ['@a:example.org'], left: [] },
      one_time_keys_counts: { signed_curve25519: 42 },
      unused_fallback_keys: ['signed_curve25519'],
      next_batch_token: 's72595_4483_1934',
    })
  })

  it('omits absent fields rather than passing undefined', () => {
    expect(encryptionSlice({ next_batch: 'x' })).toEqual({ next_batch_token: 'x' })
    expect(Object.keys(encryptionSlice({ next_batch: 'x' }))).toEqual(['next_batch_token'])
  })

  it('produces something the guard accepts, for an uneventful sync', async () => {
    // The point of this test: the helper and the guard must agree. An empty
    // sync is the shape most syncs have, and a helper that produced a payload
    // its own library rejects would fail here rather than in a product.
    await expect(receiveSyncChanges(encryptionSlice({ rooms: {} }))).resolves.toBeUndefined()
  })

  it('still rejects a camelCase payload', async () => {
    // The guard is what makes the wrong shape loud. Typing the parameter must
    // not weaken it: this is the assertion that proves the runtime half
    // survived the compile-time half being added.
    await expect(
      receiveSyncChanges({ toDeviceEvents: [] } as unknown as SyncDelta),
    ).rejects.toThrow(/malformed_payload/)
  })
})
```

Note the cast in the last test. It is deliberate and must stay: it is how a JavaScript
consumer with no types reaches this function, and the guard exists for exactly them.

- [ ] **Step 3: Run the tests and watch them fail**

Run: `cd packages/react-native-matrix-crypto && yarn test`
Expected: failures naming `encryptionSlice` as undefined. If any test passes at this point,
it is not testing what it claims — fix the test before writing the implementation.

- [ ] **Step 4: Add the type and the helper**

Add `SyncDelta` to `types.ts` with the interface above, plus a doc comment that says why
the fields are snake_case (they are the native call's names; renaming would move the rename
somewhere with no compile-time help) and that omitting a field is correct while passing
`undefined` is not.

Add `encryptionSlice` to `facade.ts`, transcribing the worked example that is already in
the `receiveSyncChanges` doc comment. It is itself a transcription of `encryption_slice` in
`rust/matrix-crypto-core/tests/level_two_interop.rs`, which is the version exercised
against a real homeserver — so the two must stay identical in behaviour, and the doc comment
must say so.

- [ ] **Step 5: Type the parameter and shorten the doc comment**

Change `receiveSyncChanges(syncDelta: unknown)` to `receiveSyncChanges(syncDelta: SyncDelta)`.
The runtime guard stays untouched.

In the doc comment, replace the inline worked example with a pointer to `encryptionSlice`,
and **keep** the rename table, the `malformed_payload` paragraph and the camelCase warning.
The table is still what a reader needs to understand why two vocabularies exist; the warning
is still true for every untyped caller.

- [ ] **Step 6: Export both from the package entry point**

Add `SyncDelta` and `encryptionSlice` to `src/index.ts`. Check `index.tsx` too if it carries
its own export list.

- [ ] **Step 7: Run the tests, then prove the type actually constrains**

Run: `yarn test` and the package's typecheck.

Then prove the compile-time half is real, which no runtime test can do. Temporarily add
`const bad: SyncDelta = { toDeviceEvents: [] }` to a scratch file, run the typecheck, and
confirm it **fails**. Delete the line. Record the exact error text in your report — a type
that does not reject the mistake it was added to prevent is decoration.

- [ ] **Step 8: Update the three existing hand-written mappings**

`packages/example-app/src/levelTwoTransport.ts:248` should now call `encryptionSlice`
instead of carrying its own copy. Leave
`rust/matrix-crypto-core/tests/level_two_interop.rs:548` alone — it is Rust, it is the
reference implementation, and it must stay independent so the two can be compared.

Run the example app's typecheck after this change.

- [ ] **Step 9: Gates and commit**

```bash
cd packages/react-native-matrix-crypto && yarn test && yarn typecheck
cd ../.. && yarn gate:agility && yarn gate:logger && yarn gate:readme && yarn gate:stubs
git add packages/react-native-matrix-crypto/src packages/example-app/src
yarn gate:drift
git commit -m "feat(facade): Type the sync delta and ship its mapping"
```

`gate:drift` runs after `git add` because it compares against the index.

**Definition of done:** a consumer can write `receiveSyncChanges(encryptionSlice(sync))`
with no renames to get wrong; a camelCase object is rejected at compile time for a
TypeScript caller and at runtime for a JavaScript one; and you have seen both rejections
happen rather than inferred them.

---

### Task 2: The SAS flow in the core, with a two-machine proof

**Spec:** §5.1 item V, §7 Q2 and Q5 (both settled 2026-08-29).

All signatures below are copied from `matrix-sdk-crypto` **0.18.0**, which is what
`rust/Cargo.lock` pins. `$R` means that crate's `src/`.

**Files:**
- Create: `rust/matrix-crypto-core/src/verification.rs`
- Modify: `rust/matrix-crypto-core/src/lib.rs` (declare the module)
- Modify: `rust/matrix-crypto-core/src/error.rs` (append error variants — **append only**)
- Test: `rust/matrix-crypto-core/tests/sas_two_party.rs`

**Interfaces produced** (Task 3 bridges exactly these):

```rust
pub struct FlowId(pub String);

pub struct SasMaterial {
    pub emoji: Option<Vec<SasEmoji>>,   // upstream returns Option; see below
    pub decimals: (u16, u16, u16),      // always present once keys are exchanged
}

pub struct SasEmoji { pub symbol: String, pub description: String }

pub enum FlowStage {
    Requested, Ready, Started, KeysExchanged, Confirmed, Done, Cancelled,
}

pub async fn request_flow(user_id: &str, device_id: &str) -> Result<FlowId, MachineError>;
pub async fn accept_flow(flow: &FlowId) -> Result<(), MachineError>;
pub async fn begin_comparison(flow: &FlowId) -> Result<(), MachineError>;
pub async fn flow_stage(flow: &FlowId) -> Result<FlowStage, MachineError>;
pub async fn read_material(flow: &FlowId) -> Result<SasMaterial, MachineError>;
pub async fn confirm_flow(flow: &FlowId) -> Result<(), MachineError>;
pub async fn cancel_flow(flow: &FlowId) -> Result<(), MachineError>;
```

**Read before writing a line of this.** `rust/matrix-crypto-core/src/session.rs`, the
outbound request pump: `PendingKind` at `:930-937`, the pump body at `:1112-1168`, and
`share_scope_key`'s queueing at `:876-892`. It is the worked precedent for everything below
and it took two fix rounds to get right. §7 Q5 says to read it; this is that instruction.

#### The four upstream facts that decide this task's shape

1. **Requests split in two, and only one half is automatic.** *Reaction* requests (the
   `m.key.verification.key` message, MACs, timeout cancellations, the signature upload) are
   queued by upstream into its own cache and already arrive through this repo's
   `takeOutgoingRequests`. **Class (a) needs nothing.** *Action* requests — everything
   returned directly by `request_verification`, `accept*`, `start_sas`, `confirm`, `cancel` —
   are **never queued by upstream**. The caller gets an `OutgoingVerificationRequest` and
   must stash it. Mirror `share_scope_key`'s `queued_to_device` map.

2. **A flow stalls silently without `markRequestSent`.** `InnerSas::mark_request_as_sent`
   (`$R/verification/sas/inner_sas.rs:371-388`) is what moves `Accepted → KeySent` and
   `KeyReceived → KeysExchanged`. Skip it and `emoji()` returns `None` **forever**: no error,
   no timeout, no signal. This is precisely the shape the Global Constraints forbid, so the
   surface must make the omission loud — see the error variant below.

3. **Emoji is optional, decimals are not.** `emoji()` is `Option<[Emoji; 7]>`
   (`$R/verification/sas/mod.rs:628`); `decimals()` is `Option<(u16,u16,u16)>` (`:647`) but is
   populated whenever the state carries keys. A surface offering only emoji has a path with
   nothing to show. Both ship; `decimals` is non-optional in our record.

4. **`accept()` is state-gated.** `Sas::accept()` returns `None` unless the state is
   `SasState::Started` (`$R/verification/sas/mod.rs:436-437`). `None` here is a
   wrong-state error, not an absence.

- [ ] **Step 1: Write the failing two-machine test**

`tests/sas_two_party.rs`, modelled on the existing two-machine test in
`rust/matrix-crypto-core/tests/`. Find it first and follow its harness — do not invent a
second way to stand up two machines.

Three cases, and the second is the one that makes this task worth reviewing:

```rust
#[tokio::test]
async fn two_parties_complete_a_comparison() {
    // alice requests, bob accepts, both reach KeysExchanged, both read
    // material, both confirm, and BOTH sides then report the other's
    // device as verified. Assert on both sides: a one-sided assertion
    // passes when only one side actually transitioned.
}

#[tokio::test]
async fn a_disagreement_refuses() {
    // The strings genuinely differ, one side cancels, and the other
    // observes Cancelled and does NOT report the device verified.
    // A stand-in that always agrees proves nothing (spec section 8).
}

#[tokio::test]
async fn a_flow_that_never_marks_requests_sent_reports_it() {
    // Drive the flow but never call the pump's mark-sent. Assert that
    // read_material returns the not-yet-exchanged error, NOT an Ok with
    // empty material and NOT a hang. This is fact 2 above, made loud.
}
```

- [ ] **Step 2: Run them and watch all three fail**

Run: `cargo test -p matrix-crypto-core --manifest-path rust/Cargo.toml --test sas_two_party`

- [ ] **Step 3: Append the error variants**

In `error.rs`, **appended last** — UniFFI assigns wire ordinals by declaration position, so
inserting renumbers everything after it and stale bindings decode the wrong error. The
existing comment stating this rule is at `matrix-crypto-ffi/src/lib.rs:331-345`; read it.

Three variants, each naming a state a caller can actually reach:
`UnknownFlow` (no flow with that id — the registry's miss), `WrongStage` (the call is
legal but not now, which is what upstream's `None` returns mean), and
`MaterialNotReady` (keys not exchanged yet — fact 2's loud failure).

- [ ] **Step 4: Write the flow registry**

Keyed by flow id, holding the upstream handle. Copy the pump's registry decisions rather
than re-deriving them: it keys by transaction id, evicts superseded kinds, keeps entries on
a failed resolution so an id can be retried, and its `pending` map was **proven** not to
grow without bound. A verification registry needs the same proof — a flow that is cancelled
or done must not be retained forever. Write the test that proves it.

- [ ] **Step 5: Write the flow functions**

Against the signatures in the header block. Every one goes through `with_machine`. Every
action request returned by upstream gets queued into the outbound state, exactly as
`share_scope_key` does, or the flow cannot progress.

`request_verification_with_methods(vec![VerificationMethod::SasV1])` rather than
`request_verification()`: the `qrcode` feature is off, so advertising QR would be a lie the
far side may act on. Upstream's own test does the same
(`$R/machine/tests/interactive_verification.rs:134-135`).

- [ ] **Step 6: Run the tests until all three pass**

- [ ] **Step 7: Prove the disagreement test can fail**

Temporarily make the cancelling side confirm instead. The disagreement test must go red. If
it stays green it is asserting nothing — spec §3.2. Record the observed output, revert.

- [ ] **Step 8: Gates and commit**

```bash
cargo test -p matrix-crypto-core --manifest-path rust/Cargo.toml
cargo fmt --manifest-path rust/Cargo.toml --all -- --check
cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings
yarn gate:boundary && yarn gate:agility && yarn gate:logger
git add rust/
yarn gate:drift
git commit -m "feat(core): Verify a device by short authentication string"
```

`gate:agility` matters here: no public identifier may contain `room`, `matrix`, `olm` or
`megolm`. A SAS vocabulary is very likely clear of all four, and "very likely" is what §3.2
is about — run it rather than assume it.

**Definition of done:** two machines complete a verification and each reports the other's
device verified; a genuine disagreement refuses and you have watched that test fail when
sabotaged; and a flow that never marks its requests sent produces a named error instead of
silence.

---

### Task 3: The bridged SAS surface

**Spec:** §7 Q2 and Q5. **Read the settled rulings before designing the surface.**

**Files:**
- Modify: `rust/matrix-crypto-ffi/src/lib.rs` — records, enum, functions
- Regenerate: `src/generated/` — **never hand-edit**
- Modify: `packages/react-native-matrix-crypto/src/types.ts`, `facade.ts`, `index.ts`
- Test: the facade's existing test file, plus the interop suite

**Regeneration command**, from the repository root:

```bash
yarn --cwd packages/react-native-matrix-crypto codegen
```

`codegen.sh:52-59` warns that its three `ubrn` invocations must not be collapsed into one:
doing so exits 0 and emits stubs, and `gate:drift` still passes. That is a live trap, in the
tree, with a comment on it.

**What the frozen surface gets.** Three signatures stay as they are:
`requestVerification(userId, deviceId): Promise<string>`,
`confirmVerification(verificationId, data: unknown): Promise<void>`,
`getDeviceStatuses(userId): Promise<DeviceStatus[]>`. Per Q2, `confirmVerification`'s
`data` becomes typed — not a break, because that function has only ever thrown
`not_implemented`, so no caller has ever successfully passed anything.

Added calls, per Q2's "additive" ruling, each of which must **fail loudly when skipped**
rather than silently:

```ts
acceptVerification(verificationId: string): Promise<void>
getVerificationMaterial(verificationId: string): Promise<SasMaterial>
cancelVerification(verificationId: string): Promise<void>
getVerificationStage(verificationId: string): Promise<VerificationStage>
```

- [ ] **Step 1: Write the failing facade test**

A full flow driven through the public TypeScript surface against two machines, plus a test
that `getVerificationMaterial` on a flow whose requests were never pumped rejects with the
`material_not_ready` kind rather than resolving with empty material.

- [ ] **Step 2: Run it, watch it fail**

- [ ] **Step 3: Add the FFI records, enum and functions**

Follow the existing pattern exactly — read `matrix-crypto-ffi/src/lib.rs` for how a core
function is exposed, how errors convert, and how records are declared.

The stage enum will be **this repository's first `uniffi::Enum`**. The ordinal-append rule
at `lib.rs:331-345` therefore applies to it from birth, and that comment ships verbatim into
the generated TypeScript — write it knowing it is public documentation.

- [ ] **Step 4: Regenerate and inspect**

Run the codegen command above. Read the diff. Confirm the new functions and the enum are
present and that nothing else moved. `git add` then `yarn gate:drift`, then `yarn gate:stubs`.

- [ ] **Step 5: Write the facade layer**

`SasMaterial` and `VerificationStage` in `types.ts`, the calls in `facade.ts`, exports in
`index.ts`. Every doc comment states what happens if the call is skipped.

**`getDeviceStatuses` must now actually work** — it is the only place in this milestone
where a verification becomes visible as a result. Its `TrustState` returns `'verified'` for
a device that completed SAS.

- [ ] **Step 6: Tests, gates, commit**

Full gate run, `gate:drift` after `git add`, plus the library's typecheck and unit tests.

**Definition of done:** a TypeScript caller drives a verification end to end and
`getDeviceStatuses` reports the far device verified afterwards, where it did not before.

---

### Task 4: `verification_state` on the envelope

**Spec:** §7 Q3, settled 2026-08-29, **including the amendment recording that its
falsification clause fired.** Read the whole ruling; the constraint in its last paragraph
is binding.

**Files:**
- Modify: `rust/matrix-crypto-core/src/session.rs` (the decryption result)
- Modify: `rust/matrix-crypto-ffi/src/lib.rs`, regenerate
- Modify: `packages/react-native-matrix-crypto/src/types.ts`, `facade.ts`
- Test: core decryption tests and the facade tests

**The type, modelling all five upstream levels deliberately:**

```ts
export type SenderVerification =
  | { state: 'verified' }
  | { state: 'unverified'; reason: 'unsigned_device' }
  | { state: 'unverified'; reason: 'unverified_identity' }
  | { state: 'unverified'; reason: 'verification_violation' }
  | { state: 'unverified'; reason: 'mismatched_sender' }
  | { state: 'unverified'; reason: 'no_device'; problem: 'missing' | 'insecure_source' }
```

**Three of these cannot occur before M4** — `verified`, `unverified_identity` and
`verification_violation` all require a published cross-signing master key. The spec ruling
requires that this be documented **at the type**, and that **no test contain a fixture
producing `verified`**. A faked fixture would teach exactly the belief the ruling exists to
prevent. This is the single most important constraint in the task.

The field is added to `EventEnvelope`, is meaningful only on the decrypt path, and joins
`algorithm` and `sender` in needing a doc comment saying so. It is a **snapshot at
decryption time**: upstream tells callers who persist it to mark it dirty when a device
change arrives down the sync. Say that at the field.

- [ ] **Step 1: Write the failing "distinguishes" test**

Two decryptions whose upstream state genuinely differs — an unsigned device and a mismatched
sender — must surface as two different public values. This is what remains provable about
this feature in a SAS-only milestone, and `mismatched_sender` is an impersonation signal, so
a surface that folded it into its neighbours would hide the case a product must react to.

- [ ] **Step 2: Write the "derived not echoed" test**

Sever the wiring between upstream's value and the public field. Exactly the authenticity
assertions must go red and every decryption assertion must stay green. Watch that happen,
record it, restore. Spec §8 requires this specific observation.

- [ ] **Step 3: Implement through the three layers, regenerate, run gates**

- [ ] **Step 4: Commit**

**Definition of done:** two genuinely different upstream states produce two different public
values; severing the wiring turns only the authenticity assertions red; the three
unreachable values are documented as such at the type; and no fixture anywhere fakes
`verified`.

---

### Task 5: Trust changes on the signal channel

**Spec:** §7 Q8, settled 2026-08-29. Read the ruling's second paragraph: it inherits
whatever B2's re-measurement concludes.

**Do not start this task until `m3-signal-latency` has merged.** It changes the same
delivery mechanism, and the spec requires B2's before-and-after to be measured on today's
arrangement rather than on the one verification introduces.

**Files:** the core's observer/signal path, the FFI, `packages/react-native-matrix-crypto/src/signals.ts`.

`CryptoSignal`'s `trust_changed` variant already exists, is typed, and has never had a
producer. This task gives it one: a device whose trust changes through a completed
verification emits `{ kind: 'trust_changed', user, state }`.

`signals.ts`'s `onCryptoSignal` doc comment currently says, at length, that nothing emits
and that whether verification will ride this channel is an open question. **That comment
becomes false with this task and must be rewritten**, not merely appended to.

- [ ] **Step 1: Write the failing test** — a completed verification delivers exactly one
      `trust_changed` to a subscriber, and a listener that throws does not starve the others
      (the existing isolation guarantee must survive a real producer).
- [ ] **Step 2: Watch it fail. Step 3: Implement. Step 4: Watch it pass.**
- [ ] **Step 5: Rewrite the `onCryptoSignal` doc comment** to describe what now emits.
- [ ] **Step 6: Gates and commit.**

---

### Task 6: The third-party interoperability proof

**Spec:** §8, fourth criterion, and §7 Q7.

M2 proved encryption and decryption against `matrix-nio` over a real homeserver in both
directions. This task does the same for verification, at the published TypeScript surface.

**The criterion explicitly permits a negative result**, and this matters: if no available
third-party counterparty implements SAS in a form this can drive, the deliverable is **an
explicit written finding saying so, with the evidence**. Silence is not acceptable; a
finding is. Do not manufacture a passing test out of a counterparty that does not exist.

- [ ] **Step 1: Establish whether the counterparty can do SAS at all.** Read its API. Write
      down what you found before writing any test.
- [ ] **Step 2: If it can** — drive a full flow in both directions, following
      `scripts/run-level-two-interop.sh` and the existing level 2 harness. Credentials come
      from the gitignored ledger and **must not enter any tracked file**, including
      comments and fixtures.
- [ ] **Step 3: If it cannot** — write the finding into the spec's §5.1 record, with the
      version inspected, the API surface examined, and what would have to change.
- [ ] **Step 4: Commit either outcome.**

---

## After the tasks

Once all six are green, re-read spec §8 line by line against the tree and record, for each
criterion, the observation that satisfies it — or that it is unmet. A criterion nobody
checks at the end is a criterion that was never binding. §8's own second criterion had to be
rewritten mid-milestone precisely because it could not be met; that is the standard of
honesty the closing pass applies to the rest.
