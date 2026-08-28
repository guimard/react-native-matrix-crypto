# M2 Encryption Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `createCryptoMachine`, `openCryptoStore`, `receiveSyncChanges`, `encryptEvent` and `decryptEvent` from typed stubs into working cryptography, proven by two machines decrypting each other in process and by a real third-party Matrix client over a real homeserver.

**Architecture:** All logic lands in `matrix-crypto-core` behind a process-wide machine guarded by an async lock, driven by one tokio runtime the core owns. `matrix-crypto-ffi` mirrors and delegates only. The TypeScript facade keeps every signature it froze in M1a.

**Tech Stack:** Rust, `matrix-sdk-crypto 0.18.0`, `matrix-sdk-sqlite 0.18.0`, `matrix-sdk-common 0.18.0`, tokio, UniFFI 0.31 through `uniffi-bindgen-react-native 0.31.0-5`, TypeScript, React Native 0.87.

**Spec:** `docs/superpowers/specs/2026-08-28-m2-encryption-core-design.md`, which extends `docs/superpowers/specs/2026-08-27-react-native-matrix-crypto-design.md`.

## Global Constraints

Every task's requirements implicitly include this section.

* **Exact versions.** `matrix-sdk-crypto = "0.18.0"`, `matrix-sdk-common = "0.18.0"`, `matrix-sdk-sqlite = "0.18.0"`. The three must stay equal so Cargo unifies on one `ruma`. `uniffi = "0.31"` (the range excludes 0.32.0, which breaks ubrn 0.31.0-5).
* **`matrix-sdk-sqlite` features.** Enable `crypto-store` and `bundled`, with `default-features = false`. `bundled` compiles SQLite from source; without it every Android target fails to link against a system `libsqlite3` the NDK sysroot does not provide. Note that `crypto-store` pulls `matrix-sdk-base` on its own, which no feature selection avoids.
* **No logger.** No `println!`, `eprintln!`, `log::`, `tracing` subscriber, `console.*`, or file write anywhere in the bridge, tests included. `gate:logger` enforces it.
* **No algorithm names in public identifiers.** Nothing in the published `.d.ts` or the `#[uniffi::export]` surface may contain `megolm`, `olm` or `room` as an identifier component. `gate:agility` splits identifiers on case transitions, so `MegolmSession` and `roomId` both fail. Internally the core parses a scope string into an `OwnedRoomId`; that is implementation, and it stays out of every public name.
* **Core takes no `uniffi` dependency.** `gate:boundary` enforces it.
* **Destructuring discipline.** Every core-to-FFI conversion destructures its source struct so a field added later fails the build instead of being silently dropped.
* **Federation neutrality.** `sender` carries `@user:server` verbatim. No primitive distinguishes a local from a federated participant.
* **No secrets in tracked files.** Store passphrases, homeserver credentials and access tokens never enter a tracked file, an error message, or a test fixture.
* **`panic = "unwind"` stays.** UniFFI's `catch_unwind` is the bridge's only panic safety net.
* **Commits.** Conventional Commits, sentence-case imperative subject, one subject per commit. A manifest change and its lockfile update go in the same commit. **No `Co-Authored-By` naming Claude or Anthropic, and no `Claude-Session:` trailer, ever.**
* **`TrustRequirement::Untrusted` for all of M2.** Device verification is M3, so no device is verified and any stricter setting would reject every event. This is a deliberate, temporary choice: every construction site carries the comment `// M2: verification lands in M3; revisit this with it.` so M3 can find them all with one grep.

---

## File Structure

**Created:**

* `rust/matrix-crypto-core/src/runtime.rs` — the one tokio runtime the library owns, and the helper that enters it.
* `rust/matrix-crypto-core/src/machine.rs` — process-wide machine and store lifecycle.
* `rust/matrix-crypto-core/src/session.rs` — sync ingestion, encrypt, decrypt.
* `rust/matrix-crypto-core/tests/two_parties.rs` — the level 1 interop test, an integration test because it drives the public core API only.
* `packages/react-native-matrix-crypto/interop/crypto-suite.ts` — level 1 assertions shared between Node and device. **Created by Task 10**, which is also the only task that touches it.

**Modified:**

* `rust/matrix-crypto-core/Cargo.toml` — tokio moves to `[dependencies]`; `matrix-sdk-sqlite` added.
* `rust/matrix-crypto-core/src/lib.rs` — module declarations and re-exports.
* `rust/matrix-crypto-core/src/identity.rs` — reads the live machine instead of building a throwaway one.
* `rust/matrix-crypto-core/src/observer.rs` — non-blocking emission.
* `rust/matrix-crypto-ffi/src/lib.rs` — mirroring and delegation for everything above.
* `packages/react-native-matrix-crypto/src/facade.ts` — real implementations behind the frozen signatures.
* `packages/react-native-matrix-crypto/src/errors.ts` — two new kinds.
* `scripts/measure-artifacts.sh` — report what the tarball actually contains.

---

## How specified each task is, and why it varies

Stated plainly so no implementer mistakes thin text for a complete brief.

**Tasks 1 to 3 are fully specified.** The code is written out and Task 1's was
compiled and run before this plan was committed. Follow it as written; deviations
need a reason.

**Tasks 4 to 8 give the exact upstream signatures, with file and line, plus the
tests and the error-mapping rules.** The bodies are described rather than written,
because each depends on the shapes the previous task settled. An implementer here
is expected to read the cited upstream source, not to guess from the description.

**Tasks 9 to 12 are deliberately thinner.** Their content depends on findings that
do not exist yet: what the two-party test proves missing, what `cdylib` measures,
which homeservers answer, and what a third-party client rejects. Writing
speculative code for them would be writing fiction that later reads as
requirements. Each of these gets an expanded brief at dispatch time, once the
tasks before it have produced the interfaces and the measurements they turn on.

A plan that pretended to equal confidence everywhere would be lying about the
part that matters most.

---

## Task 1: The owned tokio runtime

Nothing in the shipped library starts a runtime today; `tokio` is a dev-dependency only. `matrix-sdk-crypto` reaches `tokio::task::spawn` through `matrix-sdk-common` during group key sharing, and `matrix-sdk-sqlite` uses tokio's filesystem and connection-pool primitives. Both panic outside a runtime context, and UniFFI drives our `async fn` exports from the foreign side, which supplies no such context.

**Files:**
- Create: `rust/matrix-crypto-core/src/runtime.rs`
- Modify: `rust/matrix-crypto-core/src/lib.rs`, `rust/matrix-crypto-core/Cargo.toml`

**Interfaces:**
- Produces: `pub async fn in_runtime<F, T>(future: F) -> T where F: Future<Output = T> + Send + 'static, T: Send + 'static` — every later task wraps its `matrix-sdk-crypto` work in this.

- [ ] **Step 1: Move tokio to a real dependency and add the test executor**

In `rust/matrix-crypto-core/Cargo.toml`, move the tokio line out of `[dev-dependencies]` into `[dependencies]`:

```toml
[dependencies]
tokio = { version = "1", features = ["rt", "rt-multi-thread"] }
```

`macros` is dropped from the shipped feature set: it exists only for `#[tokio::test]`. Add it back under dev-dependencies, along with a non-tokio executor used by Step 2:

```toml
[dev-dependencies]
tokio = { version = "1", features = ["rt", "rt-multi-thread", "macros"] }
futures = { version = "0.3", default-features = false, features = ["executor"] }
```

`futures-executor 0.3.34` is already in `rust/Cargo.lock` transitively, so this adds no new crate to the tree.

- [ ] **Step 2: Write the two failing tests**

Create `rust/matrix-crypto-core/src/runtime.rs` containing only the tests for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Deliberately NOT `#[tokio::test]`. Under `#[tokio::test]` the harness
    /// supplies an ambient runtime, and this test would pass even if
    /// `in_runtime` did nothing at all. The point is that the runtime context
    /// comes from this library.
    #[test]
    fn a_spawn_inside_in_runtime_succeeds_with_no_ambient_runtime() {
        let doubled = futures::executor::block_on(in_runtime(async {
            tokio::task::spawn(async { 21 * 2 }).await.expect("task joined")
        }));

        assert_eq!(doubled, 42);
    }

    /// The control. Without `in_runtime` the same spawn panics, which is the
    /// whole reason `in_runtime` exists. A test suite that only shows the
    /// green path cannot tell a working runtime from a redundant one.
    #[test]
    fn the_same_spawn_panics_without_in_runtime() {
        // Rust's default panic hook prints a backtrace even when the panic is
        // caught. Left in place, this test's output reads as a failure to
        // anyone scanning the log. Silence the hook for the duration and put
        // it back, so a green run looks green.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let outcome = std::panic::catch_unwind(|| {
            futures::executor::block_on(async {
                tokio::task::spawn(async { 42 }).await.expect("task joined")
            })
        });

        std::panic::set_hook(previous);

        assert!(outcome.is_err(), "spawn outside a runtime must panic");
    }
}
```

**Verified:** this task's code was compiled and run in isolation before this
plan was written. Both tests pass, and the control test fails as intended when
`in_runtime` is bypassed. Do not assume the same of Tasks 9 to 12; see the note
below.

- [ ] **Step 3: Run them to verify they fail**

Run: `cargo test --manifest-path rust/Cargo.toml -p matrix-crypto-core runtime`
Expected: FAIL, `cannot find function in_runtime in this scope`.

- [ ] **Step 4: Write the implementation**

Prepend to `rust/matrix-crypto-core/src/runtime.rs`:

```rust
//! The one tokio runtime this library owns.
//!
//! `matrix-sdk-crypto` reaches `tokio::task::spawn` through `matrix-sdk-common`
//! during group key sharing, and `matrix-sdk-sqlite` uses tokio's filesystem and
//! connection-pool primitives. Both panic outside a runtime context. UniFFI drives
//! this crate's `async fn` exports from the foreign side, which provides no such
//! context, so the library must supply its own.

use std::future::Future;
use std::sync::OnceLock;

use tokio::runtime::{Builder, Runtime};

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Multi-threaded on purpose. On a `current_thread` runtime, work handed to
/// `tokio::task::spawn` only progresses while something is actively polling the
/// runtime, which is a deadlock waiting for a specific call pattern to find it.
fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the crypto runtime could not be built")
    })
}

/// Runs `future` inside this library's runtime, so anything it calls sees a
/// runtime context.
///
/// A panic inside `future` propagates here and is caught by UniFFI's
/// `catch_unwind`, reaching the caller as a typed error rather than aborting
/// the host application.
pub async fn in_runtime<F, T>(future: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    match runtime().spawn(future).await {
        Ok(value) => value,
        Err(joined) => std::panic::resume_unwind(
            joined.try_into_panic().unwrap_or_else(|_| Box::new("crypto task cancelled")),
        ),
    }
}
```

Add to `rust/matrix-crypto-core/src/lib.rs`:

```rust
mod runtime;

pub use runtime::in_runtime;
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --manifest-path rust/Cargo.toml -p matrix-crypto-core runtime`
Expected: PASS, 2 tests.

- [ ] **Step 6: Confirm the boundary and logger gates still hold**

Run: `yarn gate:boundary && yarn gate:logger`
Expected: both PASS.

- [ ] **Step 7: Commit**

```bash
git add rust/matrix-crypto-core/src/runtime.rs rust/matrix-crypto-core/src/lib.rs rust/matrix-crypto-core/Cargo.toml rust/Cargo.lock
git commit -m "feat(core): Own a tokio runtime for the crypto work"
```

---

## Task 2: Machine and store lifecycle

`createCryptoMachine` returns `Promise<void>` (`packages/react-native-matrix-crypto/src/facade.ts:24`), which already decided that the library holds one machine per process rather than returning a handle. This task builds that.

**Files:**
- Create: `rust/matrix-crypto-core/src/machine.rs`
- Modify: `rust/matrix-crypto-core/src/lib.rs`, `rust/matrix-crypto-core/src/identity.rs`, `rust/matrix-crypto-core/Cargo.toml`

**Interfaces:**
- Consumes: `in_runtime` from Task 1.
- Produces:
  - `pub struct MachineConfig { pub user_id: String, pub device_id: String, pub store_path: String, pub store_passphrase: Option<String> }`
  - `pub async fn create_machine(config: MachineConfig) -> Result<(), MachineError>`
  - `pub async fn open_store(config: MachineConfig) -> Result<(), MachineError>`
  - `pub async fn with_machine<F, Fut, T>(f: F) -> Result<T, MachineError> where F: FnOnce(&OlmMachine) -> Fut, Fut: Future<Output = T>` — the accessor every later task uses.
  - `pub enum MachineError { NotInitialised, AlreadyInitialised, MalformedIdentifier { detail: String }, Store { detail: String } }`

- [ ] **Step 1: Add the store dependency**

In `rust/matrix-crypto-core/Cargo.toml` under `[dependencies]`:

```toml
# `crypto-store` and nothing else: it is the feature that provides the crypto
# store and declares `matrix-sdk-crypto` as its own dependency. Enabling more
# pulls in `matrix-sdk-base`, the full client state store this library has no
# use for. Version-matched to matrix-sdk-crypto so Cargo unifies on one `ruma`.
matrix-sdk-sqlite = { version = "0.18.0", default-features = false, features = ["crypto-store"] }
```

Run `cargo check --manifest-path rust/Cargo.toml` and confirm `rust/Cargo.lock` gains `matrix-sdk-sqlite` **and no second `ruma`**:

```bash
grep -c 'name = "ruma"' rust/Cargo.lock   # expected: 1
```

- [ ] **Step 2: Write the failing tests**

Create `rust/matrix-crypto-core/src/machine.rs` with the test module only.

Because the machine is process-wide, these tests share state. Run this file's tests single-threaded, and give each test its own temp directory:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn config_in(dir: &std::path::Path) -> MachineConfig {
        MachineConfig {
            user_id: "@alice:example.org".to_string(),
            device_id: "DEVICE1".to_string(),
            store_path: dir.join("store").to_string_lossy().into_owned(),
            store_passphrase: Some("test-passphrase".to_string()),
        }
    }

    #[test]
    fn calls_before_creation_report_not_initialised() {
        reset_for_test();
        let err = futures::executor::block_on(with_machine(|_| async { () })).unwrap_err();
        assert_eq!(err, MachineError::NotInitialised);
    }

    #[test]
    fn creating_twice_with_the_same_config_is_not_an_error() {
        reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        futures::executor::block_on(create_machine(config_in(dir.path()))).unwrap();
        futures::executor::block_on(create_machine(config_in(dir.path()))).unwrap();
    }

    /// Swapping the machine underneath a running app would strand every
    /// session it holds, so a different config is refused rather than honoured.
    #[test]
    fn creating_twice_with_a_different_config_is_refused() {
        reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        futures::executor::block_on(create_machine(config_in(dir.path()))).unwrap();

        let mut other = config_in(dir.path());
        other.device_id = "DEVICE2".to_string();
        let err = futures::executor::block_on(create_machine(other)).unwrap_err();

        assert_eq!(err, MachineError::AlreadyInitialised);
    }

    #[test]
    fn a_malformed_user_id_is_reported_before_any_store_is_touched() {
        reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        let mut config = config_in(dir.path());
        config.user_id = "not-a-user-id".to_string();

        let err = futures::executor::block_on(create_machine(config)).unwrap_err();

        assert_eq!(err, MachineError::MalformedIdentifier { detail: "user id".to_string() });
        assert!(!dir.path().join("store").exists(), "no store on a rejected config");
    }

    /// The criterion that separates working software from software that only
    /// looks like it works until the first restart in production.
    #[test]
    fn identity_keys_survive_a_reopen_of_the_same_store() {
        reset_for_test();
        let dir = tempfile::tempdir().unwrap();

        futures::executor::block_on(create_machine(config_in(dir.path()))).unwrap();
        let first = futures::executor::block_on(crate::device_identity_keys()).unwrap();

        reset_for_test(); // stands in for a process restart
        futures::executor::block_on(open_store(config_in(dir.path()))).unwrap();
        let second = futures::executor::block_on(crate::device_identity_keys()).unwrap();

        assert_eq!(first, second, "a reopened store must yield the same identity");
    }
}
```

Add `tempfile = "3"` to `[dev-dependencies]`.

- [ ] **Step 3: Run them to verify they fail**

Run: `cargo test --manifest-path rust/Cargo.toml -p matrix-crypto-core machine -- --test-threads=1`
Expected: FAIL to compile, `cannot find function create_machine`.

- [ ] **Step 4: Write the implementation**

Prepend to `rust/matrix-crypto-core/src/machine.rs`:

```rust
//! The process-wide crypto machine.
//!
//! `createCryptoMachine` returns `void` on the TypeScript side, a signature
//! frozen in M1a. That already decided the ownership model: one machine per
//! process, held here, never handed out.

use std::future::Future;
use std::sync::OnceLock;

use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId};
use matrix_sdk_crypto::OlmMachine;
use matrix_sdk_sqlite::SqliteCryptoStore;
use tokio::sync::Mutex;

use crate::runtime::in_runtime;

/// Everything needed to create or reopen the machine. The product supplies the
/// store path and passphrase; this library chooses neither. A crypto library
/// that picks its own on-disk location writes somewhere the product did not
/// agree to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineConfig {
    pub user_id: String,
    pub device_id: String,
    pub store_path: String,
    pub store_passphrase: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MachineError {
    #[error("no crypto machine has been created")]
    NotInitialised,
    #[error("a crypto machine already exists with a different configuration")]
    AlreadyInitialised,
    #[error("malformed identifier: {detail}")]
    MalformedIdentifier { detail: String },
    #[error("store error: {detail}")]
    Store { detail: String },
}

struct Held {
    config: MachineConfig,
    machine: Mutex<OlmMachine>,
}

static HELD: OnceLock<Held> = OnceLock::new();

/// A `tokio::sync::Mutex`, not `std::sync::Mutex`: the guard is held across
/// await points, which a std guard cannot be.
async fn build(config: MachineConfig) -> Result<Held, MachineError> {
    let MachineConfig { user_id, device_id, store_path, store_passphrase } = config.clone();

    let user: OwnedUserId = user_id.parse().map_err(|_| MachineError::MalformedIdentifier {
        detail: "user id".to_string(),
    })?;
    if device_id.is_empty() {
        return Err(MachineError::MalformedIdentifier { detail: "device id".to_string() });
    }
    let device: OwnedDeviceId = device_id.as_str().into();

    let store = SqliteCryptoStore::open(&store_path, store_passphrase.as_deref())
        .await
        .map_err(|e| MachineError::Store { detail: store_error_detail(&e) })?;

    let machine = OlmMachine::with_store(&user, &device, store, None)
        .await
        .map_err(|e| MachineError::Store { detail: store_error_detail(&e) })?;

    Ok(Held { config, machine: Mutex::new(machine) })
}

/// Errors must not carry key material, ciphertext or a passphrase. Upstream
/// error `Display` output can embed a path, so only the variant's shape is
/// reported, never its payload.
fn store_error_detail<E>(_error: &E) -> String {
    "the crypto store could not be opened".to_string()
}

async fn init(config: MachineConfig) -> Result<(), MachineError> {
    if let Some(existing) = HELD.get() {
        return if existing.config == config {
            Ok(())
        } else {
            Err(MachineError::AlreadyInitialised)
        };
    }

    let built = in_runtime(build(config)).await?;
    // A concurrent caller may have won the race. Losing it is not an error
    // when the configurations agree, for the same reason a second create is not.
    match HELD.set(built) {
        Ok(()) => Ok(()),
        Err(rejected) => {
            if HELD.get().is_some_and(|held| held.config == rejected.config) {
                Ok(())
            } else {
                Err(MachineError::AlreadyInitialised)
            }
        }
    }
}

/// Creates the machine, or accepts an identical existing one.
pub async fn create_machine(config: MachineConfig) -> Result<(), MachineError> {
    init(config).await
}

/// Reopens a store written by an earlier process. `SqliteCryptoStore::open`
/// creates or opens, and `OlmMachine::with_store` restores the account it
/// finds, so this is the same operation under a name that says what the
/// caller means.
pub async fn open_store(config: MachineConfig) -> Result<(), MachineError> {
    init(config).await
}

/// Runs `f` against the live machine.
///
/// The lock is released before this returns. No caller may emit a signal while
/// holding it: a listener that calls back into the library would self-deadlock.
pub async fn with_machine<F, Fut, T>(f: F) -> Result<T, MachineError>
where
    F: FnOnce(&OlmMachine) -> Fut,
    Fut: Future<Output = T>,
{
    let held = HELD.get().ok_or(MachineError::NotInitialised)?;
    let guard = held.machine.lock().await;
    Ok(f(&guard).await)
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    // `OnceLock` cannot be cleared. Tests that need a fresh machine run in
    // their own process via `--test-threads=1` plus a per-test temp dir; this
    // hook exists so the intent is explicit at each call site rather than
    // implied by ordering.
    unimplemented!("see Step 5")
}
```

- [ ] **Step 5: Resolve the reset problem before going further**

`OnceLock` cannot be reset, so the tests above cannot share one process. Replace the `OnceLock<Held>` with:

```rust
static HELD: std::sync::RwLock<Option<std::sync::Arc<Held>>> = std::sync::RwLock::new(None);
```

and read it with a short synchronous critical section that clones the `Arc` and releases the lock before any await:

```rust
fn held() -> Option<std::sync::Arc<Held>> {
    HELD.read().expect("machine registry poisoned").clone()
}
```

`reset_for_test` then becomes `*HELD.write().unwrap() = None;`. Adjust `init` to take the write lock, re-check under it, and insert.

This is called out as its own step because the `OnceLock` shape reads correctly and is wrong for exactly one reason that only surfaces when the tests run.

- [ ] **Step 6: Rewire `device_identity_keys`**

In `rust/matrix-crypto-core/src/identity.rs`, replace the throwaway-machine body so it reads the live machine.

**Keep both parameters.** `getDeviceIdentityKeys(userId, deviceId)` is a frozen M1a signature, already shipped and already exercised by the on-device probe. Dropping the parameters would be a breaking change to a surface whose purpose is not to break, and would cascade through `matrix-crypto-ffi`, the generated bindings, the facade and the probe. The parameters become an assertion that caller and library agree on who this device is:

```rust
/// The live machine's own public identity keys.
///
/// The identifiers are checked rather than used: the machine already knows
/// who it is, and a caller who disagrees is a caller about to attribute these
/// keys to the wrong identity.
pub async fn device_identity_keys(
    user_id: &str,
    device_id: &str,
) -> Result<IdentityKeys, MachineError> {
    crate::machine::with_machine(|machine| {
        let user_id = user_id.to_owned();
        let device_id = device_id.to_owned();
        async move {
            if machine.user_id().as_str() != user_id || machine.device_id().as_str() != device_id {
                return Err(MachineError::MalformedIdentifier {
                    detail: "identifiers do not match the active machine".to_string(),
                });
            }
            let keys = machine.identity_keys();
            Ok(IdentityKeys {
                curve25519: keys.curve25519.to_base64(),
                ed25519: keys.ed25519.to_base64(),
            })
        }
    })
    .await?
}
```

Delete `IdentityError` and replace it with `MachineError` in `rust/matrix-crypto-ffi/src/lib.rs:109-147`, which currently mirrors it. **That FFI edit belongs to this task**: leaving it for Task 3 would leave the workspace not compiling between the two, and a task must end with `cargo check --manifest-path rust/Cargo.toml` green across the whole workspace, not just `-p matrix-crypto-core`.

The two existing identity tests must now create a machine first, and gain a third asserting that mismatched identifiers are refused.

- [ ] **Step 7: Run the full core suite**

Run: `cargo test --manifest-path rust/Cargo.toml -p matrix-crypto-core -- --test-threads=1`
Expected: PASS, including the reopen test.

- [ ] **Step 8: Commit**

```bash
git add rust/matrix-crypto-core rust/Cargo.toml rust/Cargo.lock
git commit -m "feat(core): Hold one crypto machine backed by a persistent store"
```

---

## Task 3: Expose the lifecycle through FFI and the facade

**Files:**
- Modify: `rust/matrix-crypto-ffi/src/lib.rs`, `packages/react-native-matrix-crypto/src/facade.ts`, `packages/react-native-matrix-crypto/src/errors.ts`
- Regenerate: `packages/react-native-matrix-crypto/src/generated/`, `packages/react-native-matrix-crypto/cpp/generated/`

**Interfaces:**
- Consumes: Task 2's `MachineConfig`, `create_machine`, `open_store`, `MachineError`.
- Produces: `createCryptoMachine(config)`, `openCryptoStore(config)` resolving for real; error kinds `not_initialised` and `already_initialised`.

- [ ] **Step 1: Mirror the config and the error in the FFI crate**

In `rust/matrix-crypto-ffi/src/lib.rs`. The mirror destructures, so a field added to the core struct later fails this build rather than being dropped:

```rust
#[derive(uniffi::Record)]
pub struct CryptoMachineConfig {
    pub user_id: String,
    pub device_id: String,
    pub store_path: String,
    pub store_passphrase: Option<String>,
}

impl From<CryptoMachineConfig> for matrix_crypto_core::MachineConfig {
    fn from(value: CryptoMachineConfig) -> Self {
        let CryptoMachineConfig { user_id, device_id, store_path, store_passphrase } = value;
        Self { user_id, device_id, store_path, store_passphrase }
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MachineError {
    #[error("not initialised")]
    NotInitialised,
    #[error("already initialised")]
    AlreadyInitialised,
    #[error("malformed identifier: {detail}")]
    MalformedIdentifier { detail: String },
    #[error("store error: {detail}")]
    Store { detail: String },
}

impl From<matrix_crypto_core::MachineError> for MachineError {
    fn from(value: matrix_crypto_core::MachineError) -> Self {
        use matrix_crypto_core::MachineError as Core;
        match value {
            Core::NotInitialised => Self::NotInitialised,
            Core::AlreadyInitialised => Self::AlreadyInitialised,
            Core::MalformedIdentifier { detail } => Self::MalformedIdentifier { detail },
            Core::Store { detail } => Self::Store { detail },
        }
    }
}

#[uniffi::export]
pub async fn create_crypto_machine(config: CryptoMachineConfig) -> Result<(), MachineError> {
    matrix_crypto_core::create_machine(config.into()).await.map_err(Into::into)
}

#[uniffi::export]
pub async fn open_crypto_store(config: CryptoMachineConfig) -> Result<(), MachineError> {
    matrix_crypto_core::open_store(config.into()).await.map_err(Into::into)
}
```

The `match` is exhaustive with no wildcard arm, so a variant added to the core error fails this build.

- [ ] **Step 2: Regenerate the bindings**

Run: `yarn --cwd packages/react-native-matrix-crypto codegen`
Then: `yarn gate:drift`
Expected: PASS. Never hand-edit anything under `generated/`.

- [ ] **Step 3: Add the two error kinds**

In `packages/react-native-matrix-crypto/src/errors.ts`, extend the union and the lookup `Map`:

```ts
  | 'not_initialised'
  | 'already_initialised'
```

```ts
  ['NotInitialised', 'not_initialised'],
  ['AlreadyInitialised', 'already_initialised'],
  ['MalformedIdentifier', 'malformed_identifier'],
  ['Store', 'store_corrupt'],
```

Neither new kind is retriable, so `RETRIABLE` is unchanged. Add a test asserting `toCryptoError` maps a `MachineError.NotInitialised` shaped like a real UniFFI error, message `"MachineError.NotInitialised"`, to kind `not_initialised`.

- [ ] **Step 4: Wire the facade**

In `packages/react-native-matrix-crypto/src/facade.ts`, replace the two throwing bodies. Keep both signatures exactly as frozen.

- [ ] **Step 5: Run the TypeScript suite and the gates**

Run: `yarn --cwd packages/react-native-matrix-crypto test && yarn --cwd packages/react-native-matrix-crypto typecheck && yarn gate:agility && yarn gate:drift`
Expected: all PASS. `gate:agility` matters here: `store_path` and `user_id` are fine, and nothing introduced may split into a component equal to `room`, `olm` or `megolm`.

- [ ] **Step 6: Commit**

```bash
git add rust/matrix-crypto-ffi packages/react-native-matrix-crypto
git commit -m "feat: Expose crypto machine creation across the binding chain"
```

---

## Task 4: Ingest sync changes

**Files:**
- Create: `rust/matrix-crypto-core/src/session.rs`
- Modify: `rust/matrix-crypto-core/src/lib.rs`

**Interfaces:**
- Consumes: `with_machine`, `in_runtime`.
- Produces: `pub async fn receive_sync_changes(raw_json: &str) -> Result<SyncOutcome, SessionError>` where `pub struct SyncOutcome { pub to_device_event_count: u32, pub new_session_count: u32 }`.

The bridge takes the JSON the product already fetched. It never performs the request. `EncryptionSyncChanges` borrows, so the deserialised owner must outlive the call.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// An empty sync is the shape a product sends constantly. It must be
    /// accepted and report nothing, not rejected as malformed.
    #[test]
    fn an_empty_sync_is_accepted_and_reports_no_new_sessions() {
        let outcome = futures::executor::block_on(async {
            crate::machine::create_machine(test_config()).await.unwrap();
            receive_sync_changes(r#"{"to_device_events":[],"changed_devices":{"changed":[],"left":[]},"one_time_keys_counts":{}}"#).await
        })
        .unwrap();

        assert_eq!(outcome.to_device_event_count, 0);
        assert_eq!(outcome.new_session_count, 0);
    }

    #[test]
    fn malformed_json_is_reported_as_malformed_not_as_a_store_failure() {
        let err = futures::executor::block_on(receive_sync_changes("{oops")).unwrap_err();
        assert_eq!(err, SessionError::MalformedPayload);
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --manifest-path rust/Cargo.toml -p matrix-crypto-core session -- --test-threads=1`
Expected: FAIL, `cannot find function receive_sync_changes`.

- [ ] **Step 3: Implement**

```rust
use matrix_sdk_common::ruma::api::client::sync::sync_events::DeviceLists;
use matrix_sdk_crypto::types::events::ToDeviceEvents;
use matrix_sdk_crypto::{DecryptionSettings, EncryptionSyncChanges, TrustRequirement};

/// M2: verification lands in M3; revisit this with it.
fn decryption_settings() -> DecryptionSettings {
    DecryptionSettings { sender_device_trust_requirement: TrustRequirement::Untrusted }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("the payload could not be parsed")]
    MalformedPayload,
    #[error("no crypto machine has been created")]
    NotInitialised,
    #[error("the crypto operation failed")]
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    pub to_device_event_count: u32,
    pub new_session_count: u32,
}
```

The body deserialises into owned locals, builds `EncryptionSyncChanges` borrowing them, and calls `machine.receive_sync_changes(changes, &decryption_settings())`. Wrap the whole thing in `in_runtime`. Map every upstream error to `SessionError::Failed`: upstream `Display` output can embed event content, and §7 forbids carrying it.

Confirm the exact field names against `matrix-sdk-crypto-0.18.0/src/machine/mod.rs:3150`: `to_device_events`, `changed_devices`, `one_time_keys_counts`, `unused_fallback_keys`, `next_batch_token`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --manifest-path rust/Cargo.toml -p matrix-crypto-core session -- --test-threads=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/matrix-crypto-core
git commit -m "feat(core): Ingest sync changes into the crypto machine"
```

---

## Task 5: Encrypt

**Files:**
- Modify: `rust/matrix-crypto-core/src/session.rs`, `rust/matrix-crypto-core/src/lib.rs`

**Interfaces:**
- Produces: `pub async fn encrypt_event(scope: &str, event_type: &str, payload_json: &str) -> Result<Envelope, SessionError>` where `pub struct Envelope { pub scope: String, pub algorithm: String, pub event_type: String, pub ciphertext: Vec<u8>, pub sender: String }`.

The scope string parses to an `OwnedRoomId` inside this function. That name appears in no public identifier, which is exactly what the agility design buys.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn encrypting_produces_ciphertext_that_is_not_the_plaintext() {
    let envelope = futures::executor::block_on(async {
        crate::machine::create_machine(test_config()).await.unwrap();
        share_scope_key("!s:example.org", &["@alice:example.org"]).await.unwrap();
        encrypt_event("!s:example.org", "m.room.message", r#"{"body":"hello","msgtype":"m.text"}"#).await
    })
    .unwrap();

    assert!(!envelope.ciphertext.is_empty());
    assert!(
        !String::from_utf8_lossy(&envelope.ciphertext).contains("hello"),
        "the plaintext must not survive in the ciphertext"
    );
    assert_eq!(envelope.sender, "@alice:example.org");
}

/// A scope that is not a valid identifier must be rejected before any
/// cryptographic work happens.
#[test]
fn a_malformed_scope_is_rejected() {
    let err = futures::executor::block_on(encrypt_event("nonsense", "m.room.message", "{}")).unwrap_err();
    assert_eq!(err, SessionError::MalformedPayload);
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test --manifest-path rust/Cargo.toml -p matrix-crypto-core encrypt -- --test-threads=1`
Expected: FAIL.

- [ ] **Step 3: Implement, in two parts**

First `share_scope_key`, which is where the tokio runtime becomes load-bearing:

```rust
/// Group key sharing. This is the call that reaches `tokio::task::spawn`
/// through `matrix-sdk-common`, and the reason Task 1 exists.
pub async fn share_scope_key(scope: &str, users: &[String]) -> Result<(), SessionError> {
```

It parses the scope, parses each user id, and calls
`machine.share_room_key(&scope, users.iter().map(AsRef::as_ref), EncryptionSettings::default())`
(signature at `matrix-sdk-crypto-0.18.0/src/machine/mod.rs:1239`). The returned `Vec<Arc<ToDeviceRequest>>` is what a product would send to its homeserver; M2 returns the count and leaves transport out, per spec §1.

Then `encrypt_event`, which calls
`machine.encrypt_room_event_raw(&scope, event_type, &Raw::from_json_string(payload_json.to_owned())?)`
(signature at `machine/mod.rs:1096`).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --manifest-path rust/Cargo.toml -p matrix-crypto-core encrypt -- --test-threads=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/matrix-crypto-core
git commit -m "feat(core): Encrypt an event to a scope"
```

---

## Task 6: Decrypt

**Files:**
- Modify: `rust/matrix-crypto-core/src/session.rs`

**Interfaces:**
- Produces: `pub async fn decrypt_event(scope: &str, raw_json: &str) -> Result<Envelope, SessionError>`, and the error kinds `MissingKey`, `UnsharedSession`, `UnknownDevice`, `Undecryptable` added to `SessionError`.

Decryption failure is normal operation in Matrix, not an exceptional condition. The distinction between the kinds is what lets a product decide between retrying, requesting keys, and showing a placeholder.

- [ ] **Step 1: Write the failing tests**

One test decrypts what Task 5 encrypted and asserts the payload round-trips exactly. A second feeds an event whose session was never shared and asserts `SessionError::MissingKey`, not a generic failure. A third asserts no error carries any fragment of the ciphertext:

```rust
#[test]
fn no_decryption_error_carries_ciphertext() {
    let err = futures::executor::block_on(decrypt_event("!s:example.org", UNKNOWN_SESSION_EVENT)).unwrap_err();
    let rendered = err.to_string();
    assert!(!rendered.contains("ciphertext"));
    assert!(!rendered.contains(SAMPLE_CIPHERTEXT_FRAGMENT));
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --manifest-path rust/Cargo.toml -p matrix-crypto-core decrypt -- --test-threads=1`
Expected: FAIL.

- [ ] **Step 3: Implement**

Call `machine.decrypt_room_event(&raw, &scope, &decryption_settings())` (`machine/mod.rs:2271`). Map `MegolmError` variants onto the error kinds by matching on the variant, never on its rendered text.

- [ ] **Step 4: Run to verify they pass**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add rust/matrix-crypto-core
git commit -m "feat(core): Decrypt an event and classify the failures"
```

---

## Task 7: Expose sync, encrypt and decrypt through FFI and the facade

Same shape as Task 3: mirror with destructuring, exhaustive `match` with no wildcard, regenerate, wire the facade, keep every frozen signature.

**Files:**
- Modify: `rust/matrix-crypto-ffi/src/lib.rs`, `packages/react-native-matrix-crypto/src/facade.ts`, `packages/react-native-matrix-crypto/src/errors.ts`
- Regenerate: both `generated/` directories

- [ ] **Step 1: Mirror `Envelope`, `SyncOutcome` and `SessionError`**
- [ ] **Step 2: Export `receive_sync_changes`, `encrypt_event`, `decrypt_event`, `share_scope_key`**
- [ ] **Step 3: Regenerate and run `yarn gate:drift`** — Expected: PASS
- [ ] **Step 4: Apply the destructuring rule at `facade.ts:87`**, which the M1 final review flagged as the one site that does not follow it
- [ ] **Step 5: Run `yarn --cwd packages/react-native-matrix-crypto test && yarn gate:agility`** — Expected: PASS. The agility gate is the real check here: `Envelope` must not gain a field or type whose name splits into `room`.
- [ ] **Step 6: Commit**

```bash
git commit -m "feat: Expose encryption and decryption across the binding chain"
```

---

## Task 8: Signals must not block, and must survive a foreign thread

Today signals are emitted from the thread already inside a foreign-driven async call. With a tokio runtime, `matrix-sdk-crypto` can emit from a worker thread. A callback crossing into JavaScript from an arbitrary thread is where UniFFI callback plumbing breaks, and a signal emitted while the machine lock is held self-deadlocks against a listener that calls back in.

**Files:**
- Modify: `rust/matrix-crypto-core/src/observer.rs`, `rust/matrix-crypto-ffi/src/lib.rs`

- [ ] **Step 1: Write the failing test**

```rust
/// The deadlock this test exists to prevent is invisible single-threaded:
/// it needs the emitting thread to differ from the calling thread.
#[test]
fn a_signal_emitted_from_a_spawned_task_reaches_the_observer() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let observer = RecordingObserver { seen: seen.clone() };

    futures::executor::block_on(in_runtime(async move {
        tokio::task::spawn(async move { emit(&observer, ProbeSignal::Started) }).await.unwrap()
    }));

    assert_eq!(seen.lock().unwrap().len(), 1);
}

/// Emission must never happen under the machine lock.
#[test]
fn emitting_while_a_listener_calls_back_into_the_library_does_not_deadlock() {
    // A listener that calls `with_machine` from inside `on_signal`.
    // Must complete rather than hang; the harness timeout is the assertion.
}
```

- [ ] **Step 2: Run to verify they fail** — Expected: FAIL or hang. If the second test hangs rather than failing, that *is* the defect; note the observed behaviour before fixing.
- [ ] **Step 3: Implement** — emission takes no lock, returns unit, and never awaits the foreign side.
- [ ] **Step 4: Run to verify they pass**
- [ ] **Step 5: Commit**

```bash
git commit -m "fix(core): Emit signals without holding the machine lock"
```

---

## Task 9: Level 1 interop, two parties in one process

The milestone's central proof: two machines, two stores, one decrypting what the other encrypted.

**Files:**
- Create: `rust/matrix-crypto-core/tests/two_parties.rs`

This is an integration test rather than a unit test because it must drive the public core API only. It cannot use the process-wide machine for both parties, which is the point worth stating: **the test constructs two `OlmMachine`s directly**, mirroring `matrix-sdk-crypto`'s own test helpers, and exercises the same core functions against each.

- [ ] **Step 1: Write the failing test** — Alice encrypts, keys are exchanged as to-device events, Bob decrypts, and the recovered payload equals the original byte for byte.
- [ ] **Step 2: Run to verify it fails**
- [ ] **Step 3: Implement whatever core plumbing the test proves missing**
- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --manifest-path rust/Cargo.toml -p matrix-crypto-core --test two_parties`

- [ ] **Step 5: Commit**

```bash
git commit -m "test(core): Prove two parties encrypt and decrypt for each other"
```

---

## Task 10: Prove it on the emulator

Level 1 passing under `cargo test` proves the Rust. It does not prove the chain. M1a's lesson: nineteen green tests passed against an assumed UniFFI error shape while the real one differed.

**Files:**
- Modify: `packages/example-app/` probe screen, `packages/react-native-matrix-crypto/interop/crypto-suite.ts`

- [ ] **Step 1: Extend the probe** with a step that creates a machine, encrypts, decrypts and asserts the round trip, printing `PROBE_CHECK round_trip PASS|FAIL`
- [ ] **Step 2: Rebuild both platforms and run on `emulator-5554`**
- [ ] **Step 3: Confirm `PROBE_SUMMARY` counts the new step and all steps pass.** Reports say "emulator", never "device".
- [ ] **Step 4: Commit**

---

## Task 11: Correct the size metric, then measure `cdylib`

`tarballKB` has never measured only the two build outputs. A gate whose metric nobody trusts produces confident wrong answers in both directions, so the metric is fixed before it is used to judge anything.

**Files:**
- Modify: `scripts/measure-artifacts.sh`, `artifact-sizes.json`
- Investigate: `rust/matrix-crypto-ffi/Cargo.toml`, `packages/react-native-matrix-crypto/android/CMakeLists.txt`

- [ ] **Step 1: Make `measure-artifacts.sh` report the tarball's actual composition** — the three largest contributors by unpacked size, from `npm pack --dry-run --json`, whose listing goes to **stderr**, not stdout
- [ ] **Step 2: Re-measure the current configuration under the corrected metric** and record it
- [ ] **Step 3: Build the Android target as a `cdylib` and measure.** A static archive carries every object file including unreferenced ones; a linked, stripped shared library carries what survived. Both the module `.so` and the Rust `.so` land in the APK.
- [ ] **Step 4: Verify a real consumer build still links** — the example app's own `./gradlew` build, not just a successful `cargo build`
- [ ] **Step 5: Record the decision.** If `cdylib` closes the gap, stop. If not, drop the root `.aar` per spec §9 step 2. If still not, per-platform packages.
- [ ] **Step 6: Commit**

---

## Task 12: Level 2 interop, a real homeserver and a third-party client

The question level 1 cannot answer: does a real Matrix client decrypt what we encrypt. Level 1 tests our implementation against itself, so a consistent misreading of the protocol passes it cleanly.

**Credentials:** obtained at this task and not before, from the operator's own deployment repository, whose location is recorded outside this repository. Everything found there is secret. It never enters a tracked file, a test fixture, a log, or a commit. The test reads it from the environment.

**Constraint:** the second homeserver must never be stopped. The proof needs two servers. The hosts themselves are named in the execution ledger, which is not tracked here.

- [ ] **Step 1: Confirm which homeservers are reachable** and record it in the ledger, not in a tracked file
- [ ] **Step 2: Write the level 2 test** — this library encrypts, a third-party client decrypts; that client encrypts, this library decrypts
- [ ] **Step 3: Run it, and treat a first-run failure as the expected outcome.** This is the step that exists to find a divergence between our assumptions and the protocol as implemented elsewhere. A green first run deserves suspicion: confirm the test would fail if the ciphertext were corrupted.
- [ ] **Step 4: Fix what it finds**
- [ ] **Step 5: Commit**

---

## Exit checklist

Every line is a spec §10 exit criterion. M2 is not complete until all are checked.

- [ ] Two machines in one test process exchange a group key and each decrypts the other's event
- [ ] A third-party Matrix client decrypts an event this library produced, over a real homeserver
- [ ] This library decrypts an event that client produced
- [ ] A session survives a store reopen
- [ ] A signal emitted from a spawned task reaches a JavaScript listener on the emulator with no deadlock
- [ ] `gate:workspaces`, `gate:boundary`, `gate:drift`, `gate:logger`, `gate:agility` all green
- [ ] `PROBE_SUMMARY` passes on the emulator, including the new round-trip step
- [ ] Artifact sizes re-measured under the corrected metric and recorded
- [ ] No public identifier names an algorithm, proved by `gate:agility`
- [ ] No commit carries an AI-assistant authorship trailer
