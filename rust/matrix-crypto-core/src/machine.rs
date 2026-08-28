//! The process-wide crypto machine.
//!
//! `createCryptoMachine` returns `void` on the TypeScript side, a signature
//! frozen in M1a. That already decided the ownership model: one machine per
//! process, held here, never handed out.

use std::future::Future;
use std::pin::Pin;
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
///
/// No `#[derive(Debug)]`: a derive would print `store_passphrase` and
/// `store_path` verbatim, and this struct is `pub`, re-exported at the crate
/// root, and lives for the process lifetime inside `Held` -- any future
/// `{:?}`, any `#[derive(Debug)]` on a struct that embeds it, any
/// `Result<_, MachineConfig>` unwrap, would print the secret. Task 3's own
/// FFI mirror (`CryptoMachineConfig`) already omits the derive for the same
/// reason. `Debug` is hand-written below instead, redacting both fields.
#[derive(Clone, PartialEq, Eq)]
pub struct MachineConfig {
    pub user_id: String,
    pub device_id: String,
    pub store_path: String,
    pub store_passphrase: Option<String>,
}

impl std::fmt::Debug for MachineConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, not field-accessed: a field added later must fail
        // this to compile rather than be silently printed unredacted.
        let MachineConfig {
            user_id,
            device_id,
            store_path: _,
            store_passphrase,
        } = self;
        f.debug_struct("MachineConfig")
            .field("user_id", user_id)
            .field("device_id", device_id)
            .field("store_path", &"[redacted]")
            .field(
                "store_passphrase",
                &store_passphrase.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
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

/// Serialises `create_machine`/`open_store` end to end.
///
/// Held for the whole of `init`, including across `build`'s `.await` -- a
/// `tokio::sync::Mutex`, not `std::sync::Mutex`, exists for exactly this: to
/// be safely held across await points. Without it, two concurrent calls with
/// the *same* config both pass the early `held()` check (both see `None`),
/// both call `SqliteCryptoStore::open` on the same fresh path, and collide on
/// sqlite's own migration lock -- one comes back `Store { detail: "the
/// crypto store could not be opened" }`, even though the brief's own
/// invariant says a second identical create is not an error. Reproduced
/// deterministically (12/12) by a review before this lock existed. With at
/// most one caller ever inside `build()`, that collision cannot happen, and
/// a caller whose config loses against an already-held one is turned away
/// before ever calling `build()` for it -- so it never creates a store on
/// disk for a configuration that is then rejected, the same "no store on a
/// rejected config" rule `a_malformed_user_id_is_reported_before_any_store_is_touched`
/// already asserts for a different kind of rejection. That also means there
/// is no longer a "concurrent caller already inserted while I was building"
/// case to reconcile after the fact: nothing can change `HELD` while this
/// lock is held, so the checked-then-inserted value cannot go stale between
/// the check and the insert.
static INIT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn init(config: MachineConfig) -> Result<(), MachineError> {
    let _serialised = INIT_LOCK.lock().await;

    if let Some(existing) = held() {
        return if existing.config == config {
            Ok(())
        } else {
            Err(MachineError::AlreadyInitialised)
        };
    }

    let built = in_runtime(build(config)).await?;

    // No re-check needed here: `INIT_LOCK` has been held continuously since
    // before the `held()` check above, so nothing else could have written
    // `HELD` in between. `expect`, not a defensive branch that "handles" a
    // conflict that can no longer occur -- a branch that can never run is
    // worse than no branch, because it invites a future reader to wonder
    // when it does.
    let mut guard = HELD.write().expect("machine registry poisoned");
    assert!(guard.is_none(), "HELD changed while INIT_LOCK was held");
    *guard = Some(Arc::new(built));

    Ok(())
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

/// The shape every `with_machine` closure must return: a boxed, pinned
/// future that may borrow the `&OlmMachine` argument for its own lifetime,
/// and is provably `Send`.
///
/// Two designs were tried and rejected before this one, in order:
///
/// 1. `FnOnce(&OlmMachine) -> Fut` with `Fut: Future<Output = T>` as its own
///    generic parameter -- the brief's original shape. A plain closure
///    returning an `async move` block that borrows the `&OlmMachine` it was
///    handed does not type-check against it: `Fut` cannot vary with the
///    closure argument's lifetime, so the borrow is rejected as potentially
///    outliving the call, even though it plainly does not.
/// 2. `AsyncFnOnce(&OlmMachine) -> T` -- ties its call future to the
///    argument's lifetime correctly, which fixes (1). But `with_machine`'s
///    whole call runs inside `in_runtime` (see its doc comment for why),
///    which must prove the *composed* future `Send`, and an `AsyncFnOnce`'s
///    associated future type cannot be named or bounded in stable Rust
///    (`async_fn_traits` is nightly-only -- confirmed by trying it and
///    reading rustc's own suggestion to use it). Generic code has no way to
///    state "and this closure's produced future is also `Send`", so it
///    cannot compile for an unconstrained `F`.
///
/// Boxing sidesteps both: the explicit lifetime in the return type keeps (2)'s
/// fix for (1), and `+ Send` written directly on the trait object is a bound
/// stable Rust can name, unlike the hidden associated type. Construct one
/// with `Box::pin(async move { ... })`; the compiler infers the rest from
/// this bound, no explicit cast needed.
pub type MachineFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Runs `f` against the live machine.
///
/// The whole call runs inside `in_runtime`, not just `build`/`init`. A review
/// caught this the first time round: `tokio::sync::Mutex` needs no reactor,
/// so a version of this function that only locked the mutex and called `f`
/// compiled and passed every `#[tokio::test]`-based test, because
/// `#[tokio::test]` supplies an ambient runtime that hides the gap entirely
/// -- and then panicked the moment a caller's closure reached a
/// store-touching `OlmMachine` method (`outgoing_requests`,
/// `share_room_key`, encrypt, decrypt: anything Tasks 4-6 need) driven from
/// the FFI's actual calling context, which supplies no such thing. See
/// `with_machine_supplies_a_runtime_for_store_touching_calls`, which is
/// deliberately not `#[tokio::test]` for exactly that reason and fails
/// without this wrapping.
///
/// The lock is acquired and `f` is called inside that borrowed runtime
/// context, and released before this returns. No caller may emit a signal
/// while holding it: a listener that calls back into the library would
/// self-deadlock.
pub async fn with_machine<F, T>(f: F) -> Result<T, MachineError>
where
    F: for<'a> FnOnce(&'a OlmMachine) -> MachineFuture<'a, T> + Send + 'static,
    T: Send + 'static,
{
    let handle = held().ok_or(MachineError::NotInitialised)?;
    let result = in_runtime(async move {
        let guard = handle.machine.lock().await;
        f(&guard).await
    })
    .await;
    Ok(result)
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

    /// `MachineConfig` touches no global state, so this needs neither
    /// `lock_for_test` nor `reset_for_test`.
    #[test]
    fn debug_output_redacts_the_store_path_and_passphrase() {
        let config = MachineConfig {
            user_id: "@a:b".to_string(),
            device_id: "D".to_string(),
            store_path: "/Users/alice/Library/store".to_string(),
            store_passphrase: Some("s3cr3t".to_string()),
        };

        let rendered = format!("{config:?}");

        assert!(
            !rendered.contains("/Users/alice/Library/store"),
            "Debug output must not contain the store path: {rendered}"
        );
        assert!(
            !rendered.contains("s3cr3t"),
            "Debug output must not contain the store passphrase: {rendered}"
        );
        // The non-secret fields still appear, so the redaction is not just
        // an empty/panicking Debug impl standing in for a real one.
        assert!(rendered.contains("@a:b"));
        assert!(rendered.contains('D'));

        // `store_passphrase: None` must not read as if a secret were
        // present -- an unconditional "[redacted]" for the whole `Option`
        // would make every config look like it carries a passphrase.
        let no_passphrase = MachineConfig {
            store_passphrase: None,
            ..config
        };
        assert!(format!("{no_passphrase:?}").contains("None"));
    }

    #[test]
    fn calls_before_creation_report_not_initialised() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let err =
            futures::executor::block_on(with_machine(move |_| Box::pin(async {}))).unwrap_err();
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

    /// Deliberately not `#[tokio::test]`, for the same reason `runtime.rs`'s
    /// own tests are not (see that module's comment): an ambient runtime
    /// would make `with_machine` look like it supplies one even if it does
    /// nothing of the kind, which is exactly the gap a review found --
    /// `identity.rs`'s `#[tokio::test]` suite stayed green while the FFI's
    /// actual calling context (no ambient runtime) would have panicked the
    /// first time a caller's closure touched the store.
    #[test]
    fn with_machine_supplies_a_runtime_for_store_touching_calls() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        futures::executor::block_on(create_machine(config_in(dir.path()))).unwrap();

        // `outgoing_requests` is genuinely async and touches the store (it
        // reads the account and queues a keys-upload request) -- unlike
        // `identity_keys()`, which is synchronous and proves nothing here.
        let outcome = futures::executor::block_on(with_machine(move |machine| {
            Box::pin(async move { machine.outgoing_requests().await })
        }));

        outcome
            .expect("with_machine itself must succeed")
            .expect("a store-touching call inside the closure must succeed");
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

    /// Regression test for a review finding: before `INIT_LOCK` serialised
    /// `init`, two concurrent `create_machine` calls with the *same* config
    /// raced two `SqliteCryptoStore::open`s onto the same fresh database and
    /// collided on sqlite's own migration lock, failing deterministically
    /// (12/12 in the review's own probe) even though the brief's own
    /// invariant -- and `creating_twice_with_the_same_config_is_not_an_error`
    /// above -- says a second identical create is not an error. That test
    /// only proves it sequentially; this one proves it under real
    /// concurrency, with real OS threads racing through a barrier rather
    /// than one `.await` after another on a single task.
    #[test]
    fn concurrent_creates_with_the_same_config_all_succeed() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let dir = tempfile::tempdir().unwrap();

        const CALLERS: usize = 4;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(CALLERS));
        let handles: Vec<_> = (0..CALLERS)
            .map(|_| {
                let barrier = std::sync::Arc::clone(&barrier);
                let config = config_in(dir.path());
                std::thread::spawn(move || {
                    barrier.wait();
                    futures::executor::block_on(create_machine(config))
                })
            })
            .collect();

        for (i, handle) in handles.into_iter().enumerate() {
            handle
                .join()
                .unwrap()
                .unwrap_or_else(|e| panic!("caller {i} was refused: {e:?}"));
        }
    }

    /// Regression test for a review finding: before `INIT_LOCK` serialised
    /// `init`, a race-losing config had already run `build()` -- and so had
    /// already created an encrypted `SqliteCryptoStore` on disk at its own
    /// path -- before the write-lock re-check rejected it with
    /// `AlreadyInitialised` (observed in 4/10 runs of the review's probe).
    /// That contradicts the same "no store on a rejected config" rule
    /// `a_malformed_user_id_is_reported_before_any_store_is_touched` asserts
    /// for a different kind of rejection. With `init` serialised, the loser
    /// never calls `build()` at all, so there is nothing to leave behind.
    #[test]
    fn concurrent_creates_with_different_configs_leave_no_store_for_the_loser() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let dir = tempfile::tempdir().unwrap();

        let mut config_a = config_in(dir.path());
        config_a.store_path = dir.path().join("store-a").to_string_lossy().into_owned();
        let mut config_b = config_in(dir.path());
        config_b.device_id = "DEVICE2".to_string();
        config_b.store_path = dir.path().join("store-b").to_string_lossy().into_owned();

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = [config_a, config_b]
            .into_iter()
            .map(|config| {
                let barrier = std::sync::Arc::clone(&barrier);
                let store_path = config.store_path.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let ok = futures::executor::block_on(create_machine(config)).is_ok();
                    (store_path, ok)
                })
            })
            .collect();

        let results: Vec<(String, bool)> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let winners = results.iter().filter(|(_, ok)| *ok).count();
        assert_eq!(
            winners, 1,
            "exactly one of two differently-configured concurrent creates should win: {results:?}"
        );

        for (store_path, ok) in &results {
            if !ok {
                assert!(
                    !std::path::Path::new(store_path).exists(),
                    "a config that lost the race must never have a store on disk at {store_path}"
                );
            }
        }
    }
}
