//! The process-wide crypto machine.
//!
//! `createCryptoMachine` returns `void` on the TypeScript side, a signature
//! frozen in M1a. That already decided the ownership model: one machine per
//! process, held here, never handed out.

use std::sync::{Arc, RwLock};

// `matrix-sdk-crypto` does NOT re-export `ruma` at its own crate root (verified by
// reading its vendored source: only `vodozemac` and, behind the `qrcode` feature,
// `matrix_sdk_qrcode` get a `pub use` there). `matrix-sdk-common` does
// (`pub use ruma;`, unconditional), and `matrix-sdk-crypto` 0.18.0 itself depends on
// `matrix-sdk-common = "0.18.0"`, so pinning the same version here guarantees Cargo
// unifies on a single `ruma` in the tree rather than resolving two independently
// versioned copies with incompatible types.
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

/// Process-wide machine registry. An `RwLock`, not a `OnceLock`: tests need
/// to clear this between runs (`reset_for_test`), and a `OnceLock` cannot be
/// reset once set.
static HELD: RwLock<Option<Arc<Held>>> = RwLock::new(None);

/// A `tokio::sync::Mutex`, not `std::sync::Mutex`: the guard is held across
/// await points, which a std guard cannot be.
async fn build(config: MachineConfig) -> Result<Held, MachineError> {
    let MachineConfig {
        user_id,
        device_id,
        store_path,
        store_passphrase,
    } = config.clone();

    let user: OwnedUserId = user_id
        .parse()
        .map_err(|_| MachineError::MalformedIdentifier {
            detail: "user id".to_string(),
        })?;
    if device_id.is_empty() {
        return Err(MachineError::MalformedIdentifier {
            detail: "device id".to_string(),
        });
    }
    let device: OwnedDeviceId = device_id.as_str().into();

    let store = SqliteCryptoStore::open(&store_path, store_passphrase.as_deref())
        .await
        .map_err(|e| MachineError::Store {
            detail: store_error_detail(&e),
        })?;

    let machine = OlmMachine::with_store(&user, &device, store, None)
        .await
        .map_err(|e| MachineError::Store {
            detail: store_error_detail(&e),
        })?;

    Ok(Held {
        config,
        machine: Mutex::new(machine),
    })
}

/// Errors must not carry key material, ciphertext or a passphrase. Upstream
/// error `Display` output can embed a path, so only the variant's shape is
/// reported, never its payload.
fn store_error_detail<E>(_error: &E) -> String {
    "the crypto store could not be opened".to_string()
}

/// Reads the current machine, if any. A short synchronous critical section:
/// the `Arc` is cloned and the lock released before this returns, so no
/// `std::sync::RwLock` guard is ever held across an `.await` -- such a guard
/// is not `Send`, and `in_runtime` requires the futures it drives to be.
fn held() -> Option<Arc<Held>> {
    HELD.read().expect("machine registry poisoned").clone()
}

async fn init(config: MachineConfig) -> Result<(), MachineError> {
    if let Some(existing) = held() {
        return if existing.config == config {
            Ok(())
        } else {
            Err(MachineError::AlreadyInitialised)
        };
    }

    let built = in_runtime(build(config)).await?;

    // A concurrent caller may have won the race while this one was building.
    // Losing it is not an error when the configurations agree, for the same
    // reason a second create is not. Computed synchronously under the write
    // lock, which is released before this returns: a `std::sync::RwLock`
    // guard is not `Send` and must never be held across an `.await`.
    let (result, to_discard) = {
        let mut guard = HELD.write().expect("machine registry poisoned");
        match &*guard {
            Some(existing) if existing.config == built.config => (Ok(()), Some(built)),
            Some(_) => (Err(MachineError::AlreadyInitialised), Some(built)),
            None => {
                *guard = Some(Arc::new(built));
                (Ok(()), None)
            }
        }
    };

    // A discarded `Held` carries a live `SqliteCryptoStore`. Its pooled
    // connections close through a tokio-backed `spawn_blocking`, which needs
    // a runtime context to do it, exactly as opening the store did -- so it
    // cannot simply be allowed to drop here, back on a bare `.await`er with
    // no such context. See `reset_for_test`, which hits the same requirement.
    if let Some(held) = to_discard {
        in_runtime(async move { drop(held) }).await;
    }

    result
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
/// `AsyncFnOnce`, not `FnOnce(&OlmMachine) -> Fut` with `Fut: Future<Output =
/// T>` as a separate generic parameter: a plain closure returning an `async
/// move` block that borrows the `&OlmMachine` it was handed does not
/// type-check against the latter (`Fut` cannot vary with the closure
/// argument's lifetime, so the compiler rejects the borrow as potentially
/// outliving it) even though the borrow is obviously fine here -- the lock
/// guard it comes from outlives the call. `AsyncFnOnce` ties its call future
/// to the argument's lifetime correctly and is the reason a later task's
/// closure can call genuinely async `OlmMachine` methods (share a room key,
/// encrypt, decrypt) and still hold the reference across their own `.await`.
///
/// The lock is released before this returns. No caller may emit a signal while
/// holding it: a listener that calls back into the library would self-deadlock.
pub async fn with_machine<F, T>(f: F) -> Result<T, MachineError>
where
    F: AsyncFnOnce(&OlmMachine) -> T,
{
    let handle = held().ok_or(MachineError::NotInitialised)?;
    let guard = handle.machine.lock().await;
    Ok(f(&guard).await)
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    // `RwLock`, not `OnceLock`: the registry must be clearable between tests
    // that each need their own fresh machine, all run in one process rather
    // than one process per test.
    let previous = HELD.write().expect("machine registry poisoned").take();

    // A live `Held` carries a `SqliteCryptoStore`. Its pooled connections
    // close through a tokio-backed `spawn_blocking`, which needs a runtime
    // context to do it, exactly as opening the store did. Dropped here, on a
    // bare synchronous test thread with no such context, that close panics
    // with "no reactor running" -- and because a second pooled connection
    // panics the identical way while the first is still unwinding, it aborts
    // the whole test process (SIGABRT) rather than merely failing a test.
    if let Some(held) = previous {
        futures::executor::block_on(in_runtime(async move { drop(held) }));
    }
}

/// Serializes this module's and `identity`'s tests against each other.
///
/// `HELD` is process-wide, and cargo's default test harness runs every
/// `#[test]` fn concurrently on its own thread. `--test-threads=1` avoids the
/// resulting races (e.g. one test's `reset_for_test` clearing state a
/// concurrent test is mid-`create_machine` with), but not every invocation of
/// this crate's tests passes it.
///
/// A `tokio::sync::Mutex`, not `std::sync::Mutex`: `identity`'s tests are
/// `#[tokio::test]` `async fn`s that hold this guard across their own
/// `.await` points, and a std guard must never be held across an `.await`
/// (`clippy::await_holding_lock` catches exactly this if it slips back to
/// one). This module's own tests are plain synchronous `#[test]` fns, so they
/// take the guard via `futures::executor::block_on` instead of `.await`.
#[cfg(test)]
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
pub(crate) async fn lock_for_test() -> tokio::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().await
}

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
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let err = futures::executor::block_on(with_machine(async |_| ())).unwrap_err();
        assert_eq!(err, MachineError::NotInitialised);
    }

    #[test]
    fn creating_twice_with_the_same_config_is_not_an_error() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        futures::executor::block_on(create_machine(config_in(dir.path()))).unwrap();
        futures::executor::block_on(create_machine(config_in(dir.path()))).unwrap();
    }

    /// Swapping the machine underneath a running app would strand every
    /// session it holds, so a different config is refused rather than honoured.
    #[test]
    fn creating_twice_with_a_different_config_is_refused() {
        let _guard = futures::executor::block_on(lock_for_test());
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
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        let mut config = config_in(dir.path());
        config.user_id = "not-a-user-id".to_string();

        let err = futures::executor::block_on(create_machine(config)).unwrap_err();

        assert_eq!(
            err,
            MachineError::MalformedIdentifier {
                detail: "user id".to_string()
            }
        );
        assert!(
            !dir.path().join("store").exists(),
            "no store on a rejected config"
        );
    }

    /// The criterion that separates working software from software that only
    /// looks like it works until the first restart in production.
    #[test]
    fn identity_keys_survive_a_reopen_of_the_same_store() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let dir = tempfile::tempdir().unwrap();

        futures::executor::block_on(create_machine(config_in(dir.path()))).unwrap();
        let first = futures::executor::block_on(crate::device_identity_keys(
            "@alice:example.org",
            "DEVICE1",
        ))
        .unwrap();

        reset_for_test(); // stands in for a process restart
        futures::executor::block_on(open_store(config_in(dir.path()))).unwrap();
        let second = futures::executor::block_on(crate::device_identity_keys(
            "@alice:example.org",
            "DEVICE1",
        ))
        .unwrap();

        assert_eq!(
            first, second,
            "a reopened store must yield the same identity"
        );
    }
}
