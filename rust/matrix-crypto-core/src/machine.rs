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
use matrix_sdk_crypto::{CryptoStoreError, OlmMachine};
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
    /// The store at `store_path` was created by a different account (a
    /// different user id, device id, or both) than the one this
    /// `MachineConfig` names. Kept distinct from `Store`: opening a store
    /// that belongs to someone else is a recoverable configuration mistake
    /// -- point this config at the right store, or the right account --
    /// while `Store` covers failures reconfiguring cannot fix, like a full
    /// disk or a permissions problem. Upstream surfaces this distinguishably
    /// as `CryptoStoreError::MismatchedAccount`
    /// (matrix-sdk-crypto-0.18.0/src/store/error.rs), which `build` below
    /// matches on explicitly rather than folding into `Store`'s generic
    /// detail. Fieldless, like `NotInitialised`/`AlreadyInitialised`: the
    /// expected/actual user and device ids upstream's own variant carries
    /// are exactly the identifiers this crate's errors must never contain.
    #[error("the store belongs to a different account")]
    MismatchedAccount,
    /// No verification flow with the identifier this call named is known to
    /// this process. Either the identifier never named a flow, or the flow
    /// it named has finished and the registry has since released it -- see
    /// `verification.rs`'s own eviction rule for exactly when that happens.
    ///
    /// **Appended, not inserted.** The three variants from here down were
    /// added after this enum already had a mirror carrying UniFFI's error
    /// derive, and UniFFI assigns each variant's wire ordinal by
    /// declaration position: inserting one renumbers every variant after it
    /// and makes bindings generated before the insert decode the wrong
    /// error. The rule, and why the mirror's order is deliberately not this
    /// one's, is stated in full at `matrix-crypto-ffi/src/lib.rs`.
    #[error("no such verification flow")]
    UnknownFlow,
    /// The call is one this flow supports, but not at the stage the flow is
    /// currently at -- accepting a flow nobody has requested, starting a
    /// comparison before both sides are ready, confirming or cancelling a
    /// flow that has already finished. This is what upstream reports by
    /// returning `None` from an otherwise infallible call; returned as a
    /// named error rather than passed on as an absence, because "did
    /// nothing, successfully" is the one answer a verification call must
    /// never give.
    #[error("the flow is not at a stage where this call applies")]
    WrongStage,
    /// The flow has not exchanged keys yet, so there is no short
    /// authentication string to show.
    ///
    /// This is the loud form of the one silent failure this flow has.
    /// Upstream advances from "accepted" to "keys exchanged" only when the
    /// caller reports the key message as sent, through the same outbound
    /// pump every other request goes through. A caller that drains the pump
    /// but never resolves what it drained leaves the flow parked forever:
    /// no error, no timeout, and a short authentication string that is
    /// simply never produced. A caller that gets this error back has been
    /// told which of the two it is.
    #[error("the short authentication string is not available yet")]
    MaterialNotReady,
    /// The identifiers this call named are well-formed, but no such device
    /// is in the store.
    ///
    /// Kept distinct from `MalformedIdentifier`, which it was folded into
    /// first: the two call for different things from a caller. A malformed
    /// identifier is a mistake in what was passed and no retry helps; an
    /// unknown device is a device this machine has not been told about yet,
    /// and querying that user's devices through the outbound pump and
    /// trying again is exactly what resolves it. The session taxonomy
    /// already draws this line (`SessionError::UnknownDevice`), and
    /// rendering "malformed identifier: no such device" drew it nowhere.
    ///
    /// Appended, not inserted -- see `UnknownFlow` above.
    #[error("no such device")]
    UnknownDevice,
    /// This process has not yet asked the server for this account's keys, so
    /// it cannot know whether the account already has a signing identity --
    /// and publishing a second one would silently invalidate every
    /// verification every other device of this account has ever made.
    ///
    /// **The refusal is not "the local identity is empty".** That is the
    /// question upstream already asks itself, and answering it again would
    /// refuse nothing upstream does not already accept. This is the
    /// different, stricter question: *have we asked, and did the answer say
    /// there is none.* An empty local identity implies neither.
    ///
    /// Usually recoverable through the ordinary loop: the call that returns
    /// this also queues the key query that lifts it, so a caller drains the
    /// outbound pump, sends what it finds, reports it sent, and calls again.
    /// Nothing else is required of the caller and no credential is involved.
    ///
    /// **"Usually" is load-bearing, and this variant cannot say which case
    /// you are in.** It covers two: nobody has asked, and a query was asked
    /// and answered by a server whose answer settled nothing, which is what
    /// the Matrix specification prescribes for a user a reachable server does
    /// not know. In the second the loop above repeats forever, and it was
    /// measured doing so. `IdentityStatus::account_keys_answer_unsettled` is
    /// what tells them apart, and its own doc comment says what to do about
    /// the second.
    ///
    /// A variant of its own would say it better. It is not added because the
    /// wire ordinals after this enum's last variant are reserved by work in
    /// flight, and UniFFI numbers variants by declaration position, so one
    /// appended here would be misdecoded by every binding generated before
    /// it. When those land, splitting this is the change to make.
    ///
    /// Appended, not inserted -- see `UnknownFlow` above.
    #[error("the account's keys have not been fetched yet")]
    AccountKeysNotFetched,
    /// The server has been asked for this account's keys and the answer named
    /// a signing identity whose private keys this device does not hold.
    ///
    /// Kept distinct from `AccountKeysNotFetched`, and the distinction is
    /// the point of both: one says "we do not know", the other says "we know,
    /// and the answer is yes". Only the second can be resolved by joining the
    /// identity that already exists rather than by asking again. Minting over
    /// it is exactly the destruction this pair of variants exists to prevent
    /// -- it would replace the account's identity on the server and reset the
    /// trust of every device and every user who had verified the old one.
    ///
    /// Appended, not inserted -- see `UnknownFlow` above.
    #[error("this account already has a signing identity this device does not hold")]
    IdentityAlreadyExists,
    /// This machine holds no public signing identity for the account, so
    /// there is nothing for this device to verify itself against, and
    /// nothing for it to publish.
    ///
    /// **Two calls report it and they are asking for the same decision.**
    /// `crate::request_self_flow` reports it because there is no identity to
    /// join. `crate::bootstrap_identity` reports it because there is none to
    /// publish; it used to create one at this point, and creating one at
    /// this point is what an honest homeserver plus ordinary two-device
    /// timing turned into a creation over an identity another device had
    /// published a moment earlier. The remedy for both is
    /// `crate::create_identity`, and its own documentation says why it is a
    /// decision a product makes rather than a refusal a handler retries.
    ///
    /// The mirror image of `IdentityAlreadyExists`, and the pair says the
    /// whole rule between them: a device that does not hold the private keys
    /// **joins** the identity the account has, and a device facing an account
    /// with no identity at all has nothing to join. Only one of the two calls
    /// is ever the right one, and each names the other's precondition.
    ///
    /// Distinguished from `AccountKeysNotFetched` by the same question
    /// `signing.rs`'s gate asks and for the same reason: this one means the
    /// server was asked and named no identity, so the remedy is to create one
    /// with `crate::create_identity`. `AccountKeysNotFetched` means nobody
    /// has asked, and asking is the remedy. Collapsing them would send a
    /// caller to create an identity on the strength of a question never put.
    ///
    /// Appended, not inserted -- see `UnknownFlow` above.
    #[error("this account has no signing identity to verify against")]
    IdentityNotKnown,
    /// This device does not hold the account's complete private signing
    /// keys, so there is nothing for it to write into server-side storage.
    ///
    /// Distinguished from `IdentityNotKnown`, which is about the *account*
    /// having no identity at all, and from `IdentityAlreadyExists`, which is
    /// a bootstrap refusing. This one says the account's identity is not the
    /// question: whatever the account has, this device cannot write a copy
    /// of what it does not hold. The remedy is whichever of
    /// `crate::bootstrap_identity` or `crate::request_self_flow` applies,
    /// and `IdentityStatus` is what says which.
    ///
    /// Appended, not inserted -- see `UnknownFlow` above.
    #[error("this device does not hold the account's private signing keys")]
    PrivateKeysNotHeld,
    /// The account data handed to `crate::recover_identity` holds no
    /// complete server-side recovery to restore from.
    ///
    /// **Two situations arrive here and this library cannot tell them
    /// apart, which is stated rather than hidden.** Either the account has
    /// no recovery -- nobody ever ran `crate::create_recovery`, or the
    /// writes it produced were never all completed -- or the caller did not
    /// hand over all of the account data that does exist. This call sees
    /// only what it was given, so those two are the same observation from
    /// here. `crate::recover_identity`'s own doc comment names every account
    /// data event a complete recovery needs, which is what turns the second
    /// case into something a caller can check.
    ///
    /// Appended, not inserted -- see `UnknownFlow` above.
    #[error("no complete server-side recovery was supplied")]
    RecoveryNotSetUp,
    /// The passphrase or recovery key does not open this account's
    /// server-side recovery.
    ///
    /// **Kept apart from `RecoveryDataMalformed`, and that separation is the
    /// point of both.** This one is a typo: the stored recovery is intact,
    /// the secret was wrong, and asking the user again is the whole remedy.
    /// The other means no secret will ever open it. A product that folded
    /// them would either tell a user with a typo that their recovery is
    /// destroyed, or leave a user whose recovery really is destroyed
    /// retyping forever.
    ///
    /// Upstream draws the same line rather than this crate inventing it:
    /// `SecretStorageKey::from_account_data` verifies the reconstructed key
    /// against a MAC stored alongside the key description and reports
    /// `DecodeError::Mac` when it does not match
    /// (`matrix-sdk-crypto-0.18.0/src/secret_storage.rs`). Every other
    /// `DecodeError` variant describes input this library could not parse at
    /// all, which is the other error.
    ///
    /// Appended, not inserted -- see `UnknownFlow` above.
    #[error("the passphrase or recovery key does not open this recovery")]
    RecoveryKeyIncorrect,
    /// A server-side recovery was supplied and could not be read.
    ///
    /// The mirror image of `RecoveryKeyIncorrect`: no secret opens this, so
    /// a product must stop asking for one. What lands here is account data
    /// that is not JSON, a key description this library cannot parse or
    /// whose algorithm it does not implement, an encrypted secret whose own
    /// MAC does not verify under a key that did verify, and a stored seed
    /// that is not a signing key.
    ///
    /// **One further case is deliberately folded in here and named rather
    /// than left to be discovered: a recovery written for an identity the
    /// account has since replaced.** Upstream reports that distinguishably
    /// (`SecretImportError::MismatchedPublicKeys`), and it is not damaged
    /// data. It is folded because a product does the same thing about both,
    /// which is to stop asking for a passphrase and set recovery up again;
    /// the distinction that changes what a product *says* is a wrong
    /// passphrase, and that one is a variant of its own. If a product is
    /// ever found needing to word those two differently, splitting this is
    /// the change to make.
    ///
    /// Appended, not inserted -- see `UnknownFlow` above.
    #[error("the stored recovery could not be read")]
    RecoveryDataMalformed,
    /// The account data handed to `crate::create_recovery` already names a
    /// server-side recovery, and writing a second one would take the first
    /// one away.
    ///
    /// The same shape as `IdentityAlreadyExists`, one layer over, and for
    /// the same reason: two situations reach this call looking identical
    /// and need opposite things done. One is a user replacing their own
    /// passphrase, where the old recovery key is *meant* to stop working.
    /// The other is a product writing a recovery for a user who already set
    /// one up in another Matrix client, where the recovery key that stops
    /// working is one somebody wrote down and was told to keep forever.
    /// Nothing inside this library can tell those apart, so it refuses and
    /// makes the destructive one something a product has to perform
    /// deliberately.
    ///
    /// The remedy is at `crate::create_recovery`, and it is not "call it
    /// again": the product clears the existing pointer and key description
    /// from account data first, which is the act that takes the old
    /// recovery away, and then calls this.
    ///
    /// Appended, not inserted -- see `UnknownFlow` above.
    #[error("this account already has a server-side recovery")]
    RecoveryAlreadyExists,
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
        .map_err(|e| match e {
            // Matched by variant, not text, same as every other upstream
            // error this crate classifies -- see `session.rs`'s
            // `classify_megolm_error` for the fuller form of this rule.
            CryptoStoreError::MismatchedAccount { .. } => MachineError::MismatchedAccount,
            other => MachineError::Store {
                detail: store_error_detail(&other),
            },
        })?;

    // Seeded from the store this machine has just opened, not left at its
    // default. A process reopening a store that already holds the account's
    // private signing keys has not just acquired them, and the arrival
    // signal `verification::announce_state_changes` produces would otherwise
    // fire on every launch of a device that finished setting itself up
    // months ago. See `signing::note_private_keys_held`.
    crate::signing::seed_private_keys_held(machine.cross_signing_status().await.is_complete());

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
/// context, and released before this returns.
///
/// Prefer not to emit a signal from inside `f`. This used to say a listener
/// calling back into the library would self-deadlock; that is no longer true,
/// because `observer::emit` hands delivery to its own thread and returns
/// immediately, so nothing waits on the foreign side while this lock is held.
/// The remaining reason is ordering rather than liveness: a listener that
/// reads library state during `f` observes it mid-update, before whatever `f`
/// is doing has been committed. Finish the locked work, release, then emit.
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
    // Cleared **first**, and the order is the whole point of doing it here
    // at all. A verification registry entry holds an upstream handle, which
    // holds an `Arc` on the crypto store this function is about to drop.
    // Clearing while `HELD` still holds its own reference releases the
    // registry's without running the store's destructor. Clearing
    // afterwards makes the registry's reference the *last* one, released on
    // this bare synchronous test thread -- which is precisely the abort the
    // block below exists to avoid, relocated rather than removed. It was
    // written that way once and read twice without anyone noticing;
    // `verification.rs`'s
    // `the_registry_is_emptied_before_the_store_it_holds_alive_is_dropped`
    // is what now keeps these two statements in this order.
    //
    // `session`'s request registry needs no such treatment *for this
    // reason*: it holds request bodies and ids, not store handles, which is
    // why only this one is reset from here for the ordering above. One field
    // of it is not a request body, and it is cleared further down.
    crate::verification::reset_flows_for_test();

    // Same reason, one layer up: a recorder installed by one test would
    // otherwise keep receiving another test's signals, and a test that
    // asserts on "exactly one signal" would fail for a reason belonging to
    // its neighbour.
    crate::observer::reset_crypto_observer_for_test();

    // Same reason again, one layer across: the latch is process-wide, and a
    // test whose machine held the private signing keys would otherwise leave
    // the next test's fresh machine looking as though it already had them,
    // so the arrival that test exists to observe would never be announced.
    // `build` seeds it for every machine created after this point; this
    // covers the window in between.
    crate::signing::seed_private_keys_held(false);

    // The one field of `session`'s registry that is not a request body:
    // whether this process has been answered a key query about its own
    // account. That is a fact about *which account* is held, and this
    // function is the only place in the codebase where the held account
    // changes, so leaving it set would hand the next machine a gate standing
    // open on the previous machine's answer. Harmless while every proof of
    // that gate lives in its own file under `tests/`; the point of clearing
    // it is that a proof written inside `src/` is then possible, instead of
    // passing or failing for a reason belonging to its neighbour.
    crate::session::forget_account_keys_answered_for_test();

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

    /// A second account must not inherit the first one's answer.
    ///
    /// This function is the only place in the codebase where one process
    /// holds account A and then account B, and `account_keys_answered` is a
    /// fact about *which account* has been asked about. Left standing across
    /// the swap, the second machine's `bootstrap_identity` would be served
    /// on the strength of a key query about the first, which is the whole
    /// defect this boolean exists to prevent, reached through the test
    /// harness instead of through the wire.
    ///
    /// **This test is the reason the clearing exists rather than the other
    /// way round.** Deleting
    /// `crate::session::forget_account_keys_answered_for_test()` from
    /// `reset_for_test` leaves every other test in this crate green,
    /// measured; the gate's real proofs all live in their own files under
    /// `tests/`, one process each, so none of them can see this. It is a
    /// unit test inside `src/` because that is exactly the kind the omission
    /// would have silently broken.
    #[test]
    fn a_test_reset_forgets_that_the_previous_account_was_asked_about() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let first = tempfile::tempdir().unwrap();
        futures::executor::block_on(create_machine(config_in(first.path()))).unwrap();

        let query = futures::executor::block_on(crate::take_outgoing_requests())
            .expect("draining the pump must not fail")
            .into_iter()
            .find(|request| request.kind == "keys_query" && request.body.contains("@alice:"))
            .expect("a fresh machine owes a key query naming its own account");
        futures::executor::block_on(crate::mark_request_sent(
            &query.id,
            r#"{"device_keys":{"@alice:example.org":{}}}"#,
        ))
        .expect("answering the account key query must not fail");
        assert!(
            crate::session::account_keys_answered(),
            "the premise: this account has been asked about and answered, or the reset below \
             has nothing to undo"
        );

        reset_for_test();

        assert!(
            !crate::session::account_keys_answered(),
            "the reset swaps the held account, so what the previous one was told must not \
             carry over. A second machine here would mint on an answer about somebody else"
        );
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

    /// A parked finding from Task 2's review: opening a store written by a
    /// different account is a recoverable configuration mistake -- point
    /// this config at the right store, or the right account -- not a
    /// storage failure like a full disk, which reconfiguring cannot fix.
    /// Before this test, both collapsed into the same opaque `Store {
    /// detail: "the crypto store could not be opened" }`, indistinguishable
    /// from each other. Upstream distinguishes the two itself
    /// (`CryptoStoreError::MismatchedAccount`,
    /// matrix-sdk-crypto-0.18.0/src/store/error.rs, raised by
    /// `OlmMachine::with_store` exactly when the caller's user/device id
    /// does not match the account already on disk); this test proves
    /// `build` keeps that distinction instead of erasing it.
    #[test]
    fn reopening_a_store_with_a_different_account_is_reported_distinctly() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let dir = tempfile::tempdir().unwrap();

        futures::executor::block_on(create_machine(config_in(dir.path()))).unwrap();
        reset_for_test(); // stands in for a process restart with the wrong config

        let mut mismatched = config_in(dir.path());
        mismatched.user_id = "@mallory:example.org".to_string();
        let err = futures::executor::block_on(open_store(mismatched)).unwrap_err();

        assert_eq!(err, MachineError::MismatchedAccount);
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
