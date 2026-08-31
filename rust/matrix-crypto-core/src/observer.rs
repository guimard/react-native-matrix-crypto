use std::sync::{Arc, RwLock};

use crate::error::ProbeError;
use crate::identity::TrustState;
use crate::probe::{probe, ProbeReport};

/// A state change that belongs to no call in flight. Spec sections 7 and 11.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeSignal {
    pub kind: String,
    pub detail: String,
}

/// Implemented by the FFI layer's adapter, and through it by JavaScript.
pub trait ProbeObserver: Send + Sync {
    fn on_signal(&self, signal: ProbeSignal);
}

/// Emits `signal` to `observer`, fire-and-forget. Spec section 5.
///
/// Two hazards motivate this, neither visible in a single-threaded call:
///
/// - Once a tokio runtime exists (`runtime::in_runtime`), the code that
///   discovers a signal can be running on a worker thread rather than
///   whatever thread a foreign caller is blocked on. A callback crossing
///   into JavaScript from an arbitrary thread is exactly where UniFFI
///   callback plumbing breaks, so that path has to be exercised, not
///   assumed -- see
///   `a_signal_emitted_from_a_spawned_task_reaches_the_observer` below.
/// - `machine::with_machine` holds `Held::machine`'s `tokio::sync::Mutex`
///   for the whole of its closure, and that mutex is not reentrant.
///   Calling `on_signal` synchronously from inside such a closure, into a
///   listener that calls back into this library, is a guaranteed
///   self-deadlock: the listener's own call would wait on a guard that
///   cannot be released until the listener returns. See
///   `emitting_while_a_listener_calls_back_into_the_library_does_not_deadlock`
///   below.
///
/// Both are solved the same way: `on_signal` always runs on a thread of the
/// library's own, detached from the caller's call stack. That closure
/// captures only the observer and the signal, both by value, so it carries
/// no lock the caller might be holding: no `.await`, no blocking wait for
/// the foreign side to return, and no dependency on an ambient tokio
/// context; see
/// `a_signal_emitted_with_no_ambient_runtime_reaches_the_observer` below,
/// which is the only test here that would notice if that last one stopped
/// being true.
///
/// **One cost the caller does pay, and it is not the handoff.**
/// `runtime::spawn_blocking_detached` reaches this library's runtime through
/// `OnceLock::get_or_init`, so if nothing has built that runtime yet, the
/// call that gets there first builds it -- two worker threads, their reactor
/// and their timer -- synchronously, on whatever thread it was called on.
///
/// That is not hypothetical here, and it is worth being exact about which
/// path it is. The only shipped emitter is `probe_with_observer` below, and
/// nothing on the way to it enters `in_runtime`: not `matrix-crypto-ffi`'s
/// export, which adapts the observer and forwards, and not
/// `probe_with_observer` itself, which calls `emit` before the
/// `probe(...).await` that follows it.
/// That is unlike the machine paths, where the core function reaches for
/// `in_runtime` internally -- `machine::create_machine` and
/// `machine::with_machine` both do. So on a cold process whose first native
/// call is `runProbe`, the first `emit` is what constructs the runtime, on
/// whatever thread UniFFI is polling that future on. A cold launch's
/// `PROBE_SIGNAL_MS` therefore has runtime construction inside it.
///
/// It is a one-off cost per process rather than a per-signal one, which is
/// why it is recorded here rather than treated as a defect -- but it is a
/// cost `std::thread::spawn` did not have, so "costs the caller nothing
/// beyond the handoff", which this comment used to say, was wrong.
///
/// **What none of that establishes is B2's measured gap, and an earlier draft
/// of this comment was fairly read as saying it did.** Two things about that
/// gap are now measured rather than argued, and both narrow it without
/// closing it:
///
/// - **The excess is confined to the first signal of a process.** Timing a
///   second signal in the same process makes the two emission paths
///   indistinguishable -- a median gap of 0 ms against 22 ms on the first
///   signal under the same CPU saturation.
/// - **It is not fixed work.** The two arms share a floor: launches on both
///   deliver in 0-1 ms, which bounds any constant added cost far below the
///   observed median gap. What the gap does instead is grow with contention,
///   which is the signature of exposure to scheduling rather than of a
///   constant amount of work.
///
/// So runtime construction is on this path, is genuinely one-off, and is *a*
/// candidate for a first-use cost. Which first-use step dominates -- building
/// the runtime, creating the first blocking-pool thread, or simply having
/// more handoffs to be descheduled between -- is not separated by anything
/// measured here, and this comment no longer claims otherwise. The numbers
/// and the experiment are in
/// `docs/measurements/2026-08-29-signal-delivery-latency.md`.
///
/// **The thread comes from the runtime's blocking pool, not from a fresh
/// `std::thread::spawn` per signal.** This used to spawn one operating
/// system thread per signal, which was cheap while one probe signal fired
/// once per process and stops being cheap the moment real crypto events
/// travel this path (spec section 5.1, B2).
/// `runtime::spawn_blocking_detached` keeps the three properties emission
/// depends on -- no ambient runtime needed, no worker thread occupied,
/// nothing the caller waits on -- and replaces one operating system thread
/// per signal with a reusable pool; see
/// `a_burst_is_delivered_without_a_thread_per_signal` below, which counts the
/// threads rather than leaving that last claim to a reader.
///
/// It does not keep *every* property a thread per signal had, and the three
/// it gives up are the ones worth knowing about:
///
/// - The pool is capped -- tokio's 512 -- where a thread per signal was
///   bounded only by the process's thread table. Past the cap, delivery
///   queues instead of proceeding.
/// - **That cap is shared, and the sharing runs both ways.** The direction
///   `runtime.rs` names is outbound: a listener population that parks pool
///   threads delays the crypto store. The inbound direction is the one this
///   file is about: `matrix-sdk-sqlite`'s blocking work reaches the same
///   pool, so store work can now delay *signal delivery*. A thread per
///   signal made that impossible. `runtime.rs` carries the bound that makes
///   it an acceptable trade rather than an open one.
/// - The first emission in a process may build the runtime, as above.
///
/// Note also what this is *not*: handing this to `tokio::task::spawn` would
/// put a foreign callback that blocks for as long as JavaScript likes onto
/// one of two worker threads shared with encryption, and two such listeners
/// would stall the runtime.
///
/// Callers must never call this while holding a lock this crate owns.
/// Correctness does not depend on that discipline -- `emit` itself takes no
/// lock, so it cannot deadlock regardless -- but a caller that produces a
/// signal from work done under a lock should still finish that work and
/// let the lock be released before calling this, simply so a listener
/// never observes the signal before the operation that produced it has
/// visibly completed.
pub(crate) fn emit(observer: &Arc<dyn ProbeObserver>, signal: ProbeSignal) {
    let observer = Arc::clone(observer);
    crate::runtime::spawn_blocking_detached(move || observer.on_signal(signal));
}

/// Identifies the emission path in the **built artifact**, not in the source
/// tree someone happens to be reading.
///
/// B2's measurement compared two APKs that differed in one function body,
/// and nothing in either APK -- nor in anything either one printed -- said
/// which body it carried. Android imports the Rust library as a prebuilt
/// (`android/CMakeLists.txt`) from a gitignored `jniLibs/`, with no Gradle
/// dependency edge back to this crate, so `:app:assembleRelease` will
/// happily repackage a stale `.so`. `probe`'s `core_version` was the only
/// build identifier crossing the bridge and it is the crate version,
/// identical on both arms. "Both arms ran the same `.so`" therefore could
/// not be excluded from the measurement's own output; it had to be taken on
/// trust from the build procedure. That is exactly the shape spec section
/// 3.2 rejects everywhere else here: a check that reports success without
/// having examined its target.
///
/// So the artifact identifies itself. This is a compile-time FNV-1a hash of
/// the source text of the two files that decide how a signal is delivered --
/// this one and `runtime.rs` -- read with `include_str!`, which reads what
/// the compiler read. `probe` appends it to `core_version`, so every probe
/// run says which emission path produced it, including runs nobody planned
/// as an experiment.
///
/// What it does not claim: it covers source text only, and says nothing
/// about the compiler, the target, the optimisation level or the rest of the
/// crate. Any edit to either file changes it, a comment included. Both are
/// the right way round for the job -- it can report a difference where the
/// behaviour is identical, and it cannot report sameness where the emission
/// source differs, which is the direction the measurement needed.
pub(crate) const EMIT_BUILD: u32 = fnv1a(
    fnv1a(FNV_OFFSET_BASIS, include_str!("observer.rs").as_bytes()),
    include_str!("runtime.rs").as_bytes(),
);

const FNV_OFFSET_BASIS: u32 = 0x811c_9dc5;

/// FNV-1a, 32 bit, seeded so several files can be chained into one value.
///
/// `const fn` on purpose: the hash must be fixed when the artifact is built,
/// not recomputed at run time from whatever source happens to be on the
/// machine running it -- a run-time hash of a file the binary does not carry
/// would identify the checkout, which is the thing already known.
const fn fnv1a(seed: u32, bytes: &[u8]) -> u32 {
    let mut hash = seed;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        i += 1;
    }
    hash
}

/// Runs the probe, emitting one signal on the way through.
pub async fn probe_with_observer(
    input: String,
    payload: Vec<u8>,
    observer: Arc<dyn ProbeObserver>,
) -> Result<ProbeReport, ProbeError> {
    if input.is_empty() {
        return Err(ProbeError::Rejected {
            reason: "input must not be empty".to_string(),
        });
    }

    emit(
        &observer,
        ProbeSignal {
            kind: "probe_started".to_string(),
            detail: input.clone(),
        },
    );

    probe(input, payload).await
}

// ------------------------------------------------------- the crypto channel

/// A crypto state change that belongs to no call in flight and that every
/// subscriber should learn about. Spec sections 7.3 and 11.
///
/// Distinct from [`ProbeSignal`] in what it is *for*, not merely in shape. A
/// probe signal is one call's own diagnostic and reaches only the caller
/// that asked for it; these are broadcast, and they describe state this
/// library changed on its own account while the caller was doing something
/// else -- or nothing at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoSignal {
    /// A comparison this process took part in completed, and a device
    /// belonging to `user` now reports `state`.
    ///
    /// **A comparison and not a scan.** A verification finished by scanning
    /// a code moves the same device to the same value and emits nothing
    /// here: `verification::take_pending_completions` reads
    /// `SasState::Done`'s own `verified_devices` for this variant, and a
    /// code flow never reaches one. Such a flow announces
    /// [`CryptoSignal::VerificationCompleted`] instead, which names the
    /// flow and carries no trust, and that variant is where the asymmetry
    /// between the two is argued. A product that needs to know either way
    /// reads [`crate::device_statuses`], which is what both of them tell it
    /// to do anyway.
    ///
    /// Carries the user rather than the device, matching the shape the
    /// TypeScript union has declared since M1. Which of that user's devices
    /// moved is [`crate::device_statuses`]' answer, and reading it there is
    /// what keeps one description of trust in this library rather than two.
    TrustChanged { user: String, state: TrustState },
    /// The other side asked this device to verify itself, the flow exists,
    /// and `flow_id` is the name every call in [`crate::verification`]
    /// takes for it.
    ///
    /// **This variant carries something a receiving side cannot get any
    /// other way.** Nothing else in this library hands a receiver the name
    /// of a flow it did not start; without it a product has to read the
    /// transaction id out of the raw to-device event, which is a protocol
    /// detail this library otherwise keeps to itself.
    VerificationRequested {
        user: String,
        device_id: String,
        flow_id: String,
    },
    /// A flow this process took part in finished by scanning a code, and
    /// `flow_id` is the name it was known by.
    ///
    /// # Why this is not a `TrustChanged`
    ///
    /// Because in two of the three modes the protocol defines there is no
    /// trust change to report at the moment a scan completes, and in the
    /// third the change is one a product could not tell from something
    /// else. All three were measured rather than reasoned about, by
    /// mirroring the comparison path onto a code and watching what each of
    /// `tests/qr_cross_user.rs`, `tests/qr_self_established_shows.rs` and
    /// `tests/qr_self_new_login_shows.rs` did with it:
    ///
    /// * **Verifying another user**, and **verifying our own account with
    ///   the new login showing**: upstream's `QrVerificationState::Done`
    ///   names *no device at all*. What those flows verify is an identity,
    ///   and the naive mirror announced nothing in either.
    /// * **Verifying our own account with the established device showing**
    ///   is the one mode where a device is named, and there a `TrustChanged`
    ///   would be truthful. Emitting it in one mode of three would mean a
    ///   product that got it in testing and never saw it in the field, for
    ///   a reason decided by which phone a person picked up.
    /// * Announcing the *identity* instead does not save it. For another
    ///   user, [`crate::device_statuses`] still reads unverified at that
    ///   moment: verifying them signs their master key, and nothing in this
    ///   library's store carries that signature until a later key query
    ///   brings it back. A `TrustChanged` saying `Verified` there would be
    ///   contradicted by the call a product is told to read when it arrives.
    ///   `tests/qr_cross_user.rs` measures exactly that.
    /// * For our own account, the identity does read verified immediately,
    ///   and its `TrustChanged` would be the same signal, under the same
    ///   user, that M4 already emits when the private signing seeds arrive
    ///   by gossip a sync or two later. That collision is not theoretical:
    ///   with no producer here at all, an assertion of the form "a
    ///   `TrustChanged` for this account arrived after the flow" passes.
    ///
    /// So the honest fact at that moment is not about trust. It is that
    /// **this flow finished**, which is true in all three modes and true on
    /// both screens. A product reads [`crate::device_statuses`] or
    /// [`crate::identity_status`] when it gets this, which is the same
    /// contract `TrustChanged` carries and the reason neither variant
    /// carries the answer itself.
    ///
    /// # What it does not say
    ///
    /// **Only a flow that finished by scanning announces here**, and a
    /// comparison that finishes still announces a `TrustChanged` and
    /// nothing else. **That is a named limit of this milestone rather than
    /// a shape anybody defends.** The two variants carry disjoint halves of
    /// one fact: a `TrustChanged` names a user and no flow, so a caller
    /// holding two verifications with that user cannot tell which finished,
    /// and this one names a flow and no trust. A product therefore writes
    /// two paths, and the side that *received* an invitation cannot know in
    /// advance which it will get, because the peer decides by scanning or
    /// by comparing a string.
    ///
    /// The fix is additive: every completed flow announcing this, with
    /// `TrustChanged` left exactly as it is, so nothing already true stops
    /// being true. It is deferred because it reaches back into the
    /// short-string flows M3 and M4 settled and tested, and re-settling
    /// those belongs to a change that can carry them.
    ///
    /// **One thing whoever writes it will walk into.** Making a completed
    /// comparison announce both variants is the first time an announcement
    /// pass legitimately produces two signals for one flow, and there is no
    /// order between them: `emit_crypto` detaches each into its own task.
    /// Every signal assertion in the test suite today compares a vector with
    /// `assert_eq!`, which every one of them can do because every one of
    /// those vectors has a single element. The day a pass produces two, that
    /// comparison is order-dependent and will go red intermittently. Both
    /// orders have already been observed in one session. Sort, or compare as
    /// a set, before adding the second producer rather than after the first
    /// flake.
    ///
    /// **A flow that was refused or timed out announces nothing**, here or
    /// anywhere else. That gap is older than codes and is the same for both
    /// shapes; a product watching a flow it wants to give up on still has
    /// to read [`crate::flow_stage`].
    VerificationCompleted { flow_id: String },
}

/// Implemented by the FFI layer's adapter, and through it by JavaScript.
///
/// One per process rather than one per call, which is the whole difference
/// from [`ProbeObserver`]: there is no call in flight to hand these to.
pub trait CryptoObserver: Send + Sync {
    fn on_signal(&self, signal: CryptoSignal);
}

/// The one observer this process delivers crypto signals to.
///
/// A `std::sync::RwLock` rather than a `OnceLock`: a JavaScript bundle
/// reloads, and a stale observer holding a dead runtime has to be
/// replaceable. Every critical section below is a clone or a store with no
/// `.await` and no foreign call inside it, so this can never be the lock a
/// listener deadlocks on -- `emit_crypto` clones the handle out and calls
/// through it afterwards, exactly as `emit` does.
static CRYPTO_OBSERVER: RwLock<Option<Arc<dyn CryptoObserver>>> = RwLock::new(None);

/// Registers the process's crypto observer, replacing any previous one.
///
/// **Not a call a product makes, and deliberately so.** The Global
/// Constraint that an added call must not fail silently when skipped cannot
/// be met by a registration call: forgetting it produces exactly the
/// silence this channel already had, with nothing to report it. So the
/// TypeScript side calls this from `onCryptoSignal` itself, on the first
/// subscription, and a product that subscribes cannot forget to install
/// what its subscription needs.
pub fn set_crypto_observer(observer: Arc<dyn CryptoObserver>) {
    *CRYPTO_OBSERVER
        .write()
        .expect("the crypto observer registry is never held across a panic") = Some(observer);
}

/// Forgets the registered observer, so this process is once again one that
/// nobody is listening to.
///
/// **The counterpart to `set_crypto_observer`, and it is not optional.**
/// Without it, the last unsubscribe on the TypeScript side leaves an
/// observer installed with nothing behind it, and the producers keep doing
/// their full pass: an inbound invitation is registered, marked announced,
/// and delivered into an empty listener set. `register_if_absent` then
/// refuses it for the rest of the flow's life, so a later subscriber is
/// never told about an invitation that is still live -- and there is no
/// call that lists inbound flows, so there is no way back before it
/// expires. Clearing restores the property the whole channel rests on:
/// with nobody listening, nothing is consumed.
///
/// The shape this protects is `useEffect(() => onCryptoSignal(h), [])` --
/// subscribe on mount, unsubscribe on unmount -- which is the ordinary
/// React Native idiom and therefore the default integration, not an edge
/// case.
///
/// # The property is restored *between* syncs, and two windows are left
///
/// This call is the whole answer for an unsubscribe that lands between one
/// `receive_sync_changes` and the next. It is not the whole answer for one
/// that lands *inside* one, and that case is real: the JavaScript thread is
/// free while `await receiveSyncChanges(..)` is in flight, so a
/// navigation-driven unmount runs its cleanup there.
///
/// **The wide half is closed elsewhere.** `verification::announce_state_changes`
/// reads this registry once, at entry, and everything after that point
/// consumes -- registering an inbound flow *is* the producer's
/// deduplication. So an unsubscribe arriving after that read used to leave
/// the invitation registered and undelivered, which is this function's own
/// failure through a narrower window. It is closed by
/// `verification::announce`, which puts the registration back whenever
/// [`emit_crypto`] reports that nobody took the signal.
///
/// **The narrow half is inherent and is not closed.** `emit_crypto` reads
/// the observer, hands the signal to a thread of the library's own, and
/// returns; an unsubscribe landing between that read and the listener
/// actually running is indistinguishable here from a delivery. Closing it
/// would mean holding this registry's lock across a foreign call made from
/// inside the sync path, which is the deadlock `emit_crypto`'s own doc
/// comment exists to refuse. Measured rather than guessed at, on the
/// arrangement `tests/sas_two_party.rs` drives: the announcing pass is the
/// last few tens of microseconds of a `receive_sync_changes` that takes
/// roughly five milliseconds, and the handoff is the tail of that. What
/// makes the residue smaller than it looks is that the listener set the
/// stale handle points at is the *same* set a remount fills, so a
/// subscriber returning before the detached thread runs still receives the
/// signal; the loss needs the set to be empty at that instant and to stay
/// empty until the flow expires.
pub fn clear_crypto_observer() {
    *CRYPTO_OBSERVER
        .write()
        .expect("the crypto observer registry is never held across a panic") = None;
}

/// The registered observer, if there is one.
///
/// Read by the producers *before* they do any work, which is what makes
/// this channel silent by default and free by default at once: with nobody
/// subscribed, `verification::announce_state_changes` returns before it
/// touches the crypto store at all.
pub(crate) fn crypto_observer() -> Option<Arc<dyn CryptoObserver>> {
    CRYPTO_OBSERVER
        .read()
        .expect("the crypto observer registry is never held across a panic")
        .clone()
}

/// Delivers one crypto signal, fire-and-forget, on the same detached path
/// [`emit`] uses.
///
/// Every hazard `emit`'s doc comment lists applies here unchanged, and one
/// of them applies harder: these signals are produced from inside
/// `receive_sync_changes`' own call stack, so a synchronous delivery would
/// run a foreign listener on the thread a product pumps its sync on, and a
/// listener that called back into this library from there would self-
/// deadlock exactly as `emit`'s own test demonstrates.
///
/// # What this path does and does not inherit from B2's cost line
///
/// `emit` names three candidates for the excess it measured on a process's
/// first signal, and says none of them is separated by anything measured
/// there: building the runtime, creating the first blocking-pool thread,
/// or simply having more handoffs to be descheduled between.
///
/// **This path eliminates the first of the three, and only the first.**
/// Not by measurement but by reading, which is enough for this one:
/// `announce_state_changes` is reached only from `receive_sync_changes`,
/// which has already been through `machine::with_machine`, which enters
/// `runtime::in_runtime`, which is what builds the runtime. So
/// `OnceLock::get_or_init` has fired long before anything here reaches
/// `spawn_blocking_detached`, and runtime construction cannot be inside a
/// crypto signal's latency. That is checkable statically and does not
/// depend on a measurement.
///
/// **The other two are untouched**, and this comment claims nothing about
/// them. The first crypto signal of a process still creates the first
/// blocking-pool thread, and still crosses however many handoffs the
/// arrangement costs.
///
/// **The crypto channel's own first-signal latency has never been
/// measured.** B2's harness times `PROBE_SIGNAL_MS` on the probe path,
/// through a release build on a device, and nothing equivalent exists for
/// this one. A reader should treat the paragraph above as what it is -- an
/// argument that removes one candidate -- rather than as a statement that
/// this path is free of the effect B2 found.
///
/// # Why this reports back
///
/// Returns whether an observer was there to take the signal. **Not for
/// diagnostics.** A producer that consumed something in order to produce a
/// signal -- registering an inbound flow, which is the announcement path's
/// own deduplication -- has to be able to put it back when the signal
/// reaches nobody, or the thing it announced is consumed and undelivered at
/// once. `verification::announce` is the caller that does that, and the one
/// this return value exists for.
///
/// A `true` is not a delivery receipt. It says an observer was registered
/// at the instant this read the registry, nothing about whether the
/// listener behind it still exists when the detached thread runs it. That
/// residue is [`clear_crypto_observer`]'s to describe.
pub(crate) fn emit_crypto(signal: CryptoSignal) -> bool {
    // No observer, no thread, no work. With nobody subscribed a dropped
    // signal is the correct outcome rather than a lost one -- but only if
    // producing it consumed nothing, which is what the caller uses this
    // answer to make true.
    let Some(observer) = crypto_observer() else {
        return false;
    };
    crate::runtime::spawn_blocking_detached(move || observer.on_signal(signal));
    true
}

/// Forgets the registered observer, so one test's recorder does not receive
/// another test's signals.
#[cfg(test)]
pub(crate) fn reset_crypto_observer_for_test() {
    *CRYPTO_OBSERVER
        .write()
        .expect("the crypto observer registry is never held across a panic") = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{
        create_machine, lock_for_test, reset_for_test, with_machine, MachineConfig,
    };
    use std::sync::mpsc;
    use std::time::Duration;

    /// Forwards every signal it receives down a channel.
    ///
    /// A `Mutex<Vec<_>>` recorder, M1a's own shape, would race emission's
    /// detached delivery thread: nothing says the vector holds the signal
    /// by the instant a test happens to check it, now that emission is
    /// fire-and-forget. A channel lets a test wait, bounded, instead of
    /// guessing how long "before returning" now takes -- it never does,
    /// which is the whole point of this task.
    struct ChannelObserver {
        tx: mpsc::Sender<ProbeSignal>,
    }

    impl ProbeObserver for ChannelObserver {
        fn on_signal(&self, signal: ProbeSignal) {
            let _ = self.tx.send(signal);
        }
    }

    fn channel_observer() -> (Arc<dyn ProbeObserver>, mpsc::Receiver<ProbeSignal>) {
        let (tx, rx) = mpsc::channel();
        (Arc::new(ChannelObserver { tx }), rx)
    }

    /// Generous relative to how fast delivery actually completes, and the
    /// evidence for that is in this file rather than in someone's notes:
    /// `a_burst_is_delivered_without_a_thread_per_signal` below emits `BURST`
    /// signals and requires every one of them delivered inside this same
    /// bound, on whatever machine is running the suite. Whatever that run
    /// costs there, one signal costs less. Tight enough, meanwhile, that a
    /// genuinely broken delivery path fails a test in a few seconds rather
    /// than hanging it.
    ///
    /// A number quoted from a measurement nobody can re-run is the defect
    /// `SIGNAL_WAIT_MS` was re-derived to remove, turned inward; the earlier
    /// draft of this comment quoted "roughly eight microseconds per signal"
    /// from exactly such a measurement.
    const DELIVERY_BOUND: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn emits_one_signal_that_reaches_the_observer() {
        let (observer, rx) = channel_observer();
        let report = probe_with_observer("hi".to_string(), vec![1, 2], observer)
            .await
            .unwrap();

        assert_eq!(report.echoed, "hi");
        let signal = rx
            .recv_timeout(DELIVERY_BOUND)
            .expect("the probe_started signal must reach the observer");
        assert_eq!(signal.kind, "probe_started");
        assert_eq!(signal.detail, "hi");
    }

    #[tokio::test]
    async fn emits_no_signal_when_input_is_rejected() {
        let (observer, rx) = channel_observer();
        // A clone, not the original: `probe_with_observer` takes its
        // argument by value, and the rejected path returns without ever
        // cloning it further, so passing `observer` itself would drop the
        // last strong reference to `ChannelObserver` on return -- and with
        // it, `tx` -- turning the channel disconnected rather than merely
        // empty. Keeping this clone alive for the rest of the test is what
        // makes `Empty` the correct, non-flaky outcome below.
        let err = probe_with_observer(String::new(), vec![], Arc::clone(&observer))
            .await
            .unwrap_err();

        assert_eq!(
            err,
            ProbeError::Rejected {
                reason: "input must not be empty".to_string()
            }
        );
        // Rejection returns before `emit` is ever called, so nothing races
        // this check: no thread is spawned on this path, unlike the
        // positive case above.
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    /// The deadlock this test exists to prevent is invisible
    /// single-threaded: it needs the emitting thread to differ from the
    /// calling thread. Deliberately not `#[tokio::test]`: an ambient
    /// runtime would let an `emit` that only works given one slip through
    /// unnoticed here, the same gap `runtime.rs`'s and `machine.rs`'s own
    /// non-`#[tokio::test]` tests guard against, and for the same reason.
    #[test]
    fn a_signal_emitted_from_a_spawned_task_reaches_the_observer() {
        let (observer, rx) = channel_observer();

        futures::executor::block_on(crate::runtime::in_runtime(async move {
            tokio::task::spawn(async move {
                emit(
                    &observer,
                    ProbeSignal {
                        kind: "probe_started".to_string(),
                        detail: "from-a-worker-thread".to_string(),
                    },
                );
            })
            .await
            .unwrap()
        }));

        let signal = rx
            .recv_timeout(DELIVERY_BOUND)
            .expect("a signal emitted from a spawned task must still reach the observer");
        assert_eq!(signal.kind, "probe_started");
    }

    /// `emit` must not need an ambient tokio runtime.
    ///
    /// This is the one test in this file that reaches `emit` with no runtime
    /// in scope at all. `emits_one_signal_that_reaches_the_observer` is a
    /// `#[tokio::test]`; the two that emit from a spawned task and from
    /// under the machine lock both do so from inside `in_runtime`. All three
    /// would keep passing if `emit` silently acquired that requirement. It
    /// could: `emit` hands its work to a blocking pool now, and
    /// `tokio::task::spawn_blocking` -- the free function, as opposed to the
    /// method on the runtime this crate owns -- reads the ambient runtime and
    /// panics when there is none.
    ///
    /// A foreign caller reaches this library on a thread that has never seen
    /// tokio, and nothing obliges a future signal-producing path to enter
    /// `in_runtime` before it emits. That makes "no ambient runtime needed" a
    /// property rather than an implementation detail, and this file's own
    /// history is the argument for pinning it: `runtime.rs` records the same
    /// class of gap, where sixteen tests passed against a shipped path that
    /// would have panicked, because `#[tokio::test]` had been supplying the
    /// context the product does not have.
    ///
    /// Deliberately NOT `#[tokio::test]`, and it says so twice: here, as its
    /// two neighbours do, and again as the first statement in the body. The
    /// attribute alone used to carry this test's entire target. Edited to
    /// `#[tokio::test]` -- by someone making the file look consistent, or by
    /// a tool -- it would keep passing while examining nothing, which is the
    /// failure it exists to catch. The assertion is what turns that edit
    /// into a red test instead of a silent one.
    #[test]
    fn a_signal_emitted_with_no_ambient_runtime_reaches_the_observer() {
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "this test proves nothing with an ambient runtime in scope: it must reach \
             `emit` from a thread that has never seen tokio, so it must not be a \
             `#[tokio::test]` and must not be called from inside `in_runtime`"
        );

        let (observer, rx) = channel_observer();

        emit(
            &observer,
            ProbeSignal {
                kind: "probe_started".to_string(),
                detail: "from-no-runtime".to_string(),
            },
        );

        let signal = rx
            .recv_timeout(DELIVERY_BOUND)
            .expect("a signal emitted with no ambient runtime must reach the observer");
        assert_eq!(signal.kind, "probe_started");
    }

    /// One operating system thread per signal is what B2's cost line names,
    /// and this is the assertion that closes it, rather than a note saying
    /// it was measured once somewhere.
    ///
    /// `std::thread::ThreadId` is never reused within a process, so a thread
    /// per signal would show exactly `BURST` distinct delivering threads.
    /// Tokio caps its blocking pool at 512 threads by default and this crate
    /// does not raise it, so the pool cannot show more than 512 however the
    /// burst is scheduled. `BURST` is set above that cap so the two
    /// implementations cannot both satisfy the assertion: the shipped one
    /// passes by construction, and reverting `emit` to `std::thread::spawn`
    /// fails here with a count rather than with a timeout.
    ///
    /// The burst is concurrent rather than sequential, deliberately. The
    /// microbenchmark this replaces emitted one signal at a time and waited
    /// for nothing, so what it measured was how fast a loop can call `emit`
    /// -- not the regime the cost line describes ("once verification and key
    /// events flow through the channel"). Every signal here is in flight
    /// before any of them is waited on.
    ///
    /// The timing assertion is deliberately coarse: the whole burst must be
    /// delivered inside `DELIVERY_BOUND`, the same bound a single signal gets
    /// elsewhere in this file. That is what makes `DELIVERY_BOUND` a measured
    /// number rather than a quoted one -- if `BURST` signals fit inside it,
    /// one does, on whatever machine is running the suite. It is not a
    /// performance threshold: one on shared CI hardware is a flake generator,
    /// and this bound is meant to stay far looser than anything it could
    /// plausibly measure.
    ///
    /// No margin is quoted, and that is deliberate. Quoting one would mean
    /// quoting a measurement this file cannot show you -- the defect
    /// `DELIVERY_BOUND`'s own comment was rewritten to remove. Nothing here
    /// writes to stdout either, and that is a constraint rather than a
    /// preference: `scripts/assert-no-logger.sh` scans this crate's `src` for
    /// the print macros and does not exempt `#[cfg(test)]`. The actual
    /// durations travel in the assertion messages, where a reader who wants
    /// them can get them by making the test fail.
    #[test]
    fn a_burst_is_delivered_without_a_thread_per_signal() {
        use std::collections::HashSet;
        use std::sync::Mutex;
        use std::time::Instant;

        /// Comfortably above tokio's blocking pool cap, so the two
        /// implementations give different answers.
        const BURST: usize = 2000;
        /// Tokio's default `max_blocking_threads`, which this crate leaves
        /// alone -- see `runtime::spawn_blocking_detached`.
        const POOL_CAP: usize = 512;

        struct Counting {
            tx: mpsc::Sender<()>,
            threads: Arc<Mutex<HashSet<std::thread::ThreadId>>>,
        }

        impl ProbeObserver for Counting {
            fn on_signal(&self, _signal: ProbeSignal) {
                self.threads
                    .lock()
                    .expect("the recorder's mutex is never held across a panic")
                    .insert(std::thread::current().id());
                let _ = self.tx.send(());
            }
        }

        let (tx, rx) = mpsc::channel();
        let threads = Arc::new(Mutex::new(HashSet::new()));
        let observer: Arc<dyn ProbeObserver> = Arc::new(Counting {
            tx,
            threads: Arc::clone(&threads),
        });

        let started = Instant::now();
        for _ in 0..BURST {
            emit(
                &observer,
                ProbeSignal {
                    kind: "probe_started".to_string(),
                    detail: String::new(),
                },
            );
        }
        let handed_off = started.elapsed();

        for i in 0..BURST {
            rx.recv_timeout(DELIVERY_BOUND)
                .unwrap_or_else(|e| panic!("signal {i} of {BURST} was never delivered: {e}"));
        }
        let delivered = started.elapsed();

        let distinct = threads
            .lock()
            .expect("the recorder's mutex is never held across a panic")
            .len();

        assert!(
            distinct <= POOL_CAP,
            "{BURST} signals were delivered by {distinct} distinct threads, more than the \
             blocking pool's {POOL_CAP}-thread cap allows: emission is spawning threads of \
             its own again rather than reusing the pool (handed off in {handed_off:?}, \
             all delivered in {delivered:?})"
        );
        assert!(
            delivered < DELIVERY_BOUND,
            "{BURST} signals took {delivered:?} to deliver, which does not fit inside the \
             {DELIVERY_BOUND:?} a single signal is given elsewhere in this file \
             (handed off in {handed_off:?}, across {distinct} threads)"
        );
    }

    /// Emission must never happen under the machine lock.
    ///
    /// Reproduces the hazard directly: a listener whose `on_signal` calls
    /// back into the library via `with_machine`, while a signal is emitted
    /// from *inside* another `with_machine` closure -- the guard is held
    /// for that closure's whole body. If emission ever ran `on_signal`
    /// synchronously on that same stack, the listener's own call would
    /// wait on a guard its own caller cannot release until the listener
    /// returns: an unrecoverable self-deadlock, not a slow path.
    ///
    /// A `tokio::sync::Mutex` deadlock cannot be interrupted or timed out
    /// from inside the stuck call -- there is no API for that -- so the
    /// whole risky sequence runs on its own thread, and this test's only
    /// assertion is a bounded wait on a channel that sequence signals when,
    /// and only when, it finishes. A regression here fails this test after
    /// `DEADLOCK_BOUND`; it does not stall the process and it does not
    /// stall the suite: nothing else in this binary waits on that thread,
    /// and an unjoined thread does not keep the test process alive past
    /// the harness's own exit once every `#[test]` fn has returned.
    ///
    /// `DEADLOCK_BOUND` is generous, deliberately: this crate's tests that
    /// touch the shared machine registry -- every one of `machine.rs`'s,
    /// `identity.rs`'s and `session.rs`'s -- all serialise on the same
    /// `TEST_LOCK`, several dozen of them, and several do genuine sqlite
    /// and crypto work while holding it. At default (parallel) test
    /// harness scheduling, this test can end up queued behind most of
    /// them before it ever starts its own work -- measured up to several
    /// seconds of *legitimate* queueing, well short of this bound, but
    /// nowhere near instant either. A tight bound here would make the
    /// test flaky under ordinary contention, not sensitive to the one
    /// thing it exists to catch: a wait that would never end.
    #[test]
    fn emitting_while_a_listener_calls_back_into_the_library_does_not_deadlock() {
        const DEADLOCK_BOUND: Duration = Duration::from_secs(60);

        struct CallsBackIn {
            reentered_tx: mpsc::Sender<()>,
        }

        impl ProbeObserver for CallsBackIn {
            fn on_signal(&self, _signal: ProbeSignal) {
                // The listener calls back into the library from inside its
                // own callback: exactly the shape spec section 5 names.
                futures::executor::block_on(with_machine(|_m| Box::pin(async {})))
                    .expect("the listener's own call into the library must succeed");
                let _ = self.reentered_tx.send(());
            }
        }

        let (done_tx, done_rx) = mpsc::channel::<()>();

        std::thread::spawn(move || {
            let _serial = futures::executor::block_on(lock_for_test());
            reset_for_test();
            let dir = tempfile::tempdir().expect("tempdir");
            futures::executor::block_on(create_machine(MachineConfig {
                user_id: "@alice:example.org".to_string(),
                device_id: "DEVICE1".to_string(),
                store_path: dir.path().join("store").to_string_lossy().into_owned(),
                store_passphrase: Some("test-passphrase".to_string()),
            }))
            .expect("create_machine");

            let (reentered_tx, reentered_rx) = mpsc::channel::<()>();
            let observer: Arc<dyn ProbeObserver> = Arc::new(CallsBackIn { reentered_tx });

            // Emit from *inside* a `with_machine` closure: the guard is
            // held for the whole closure body, exactly the lock-held
            // hazard this test exists to catch.
            futures::executor::block_on(with_machine(move |_m| {
                Box::pin(async move {
                    emit(
                        &observer,
                        ProbeSignal {
                            kind: "probe_started".to_string(),
                            detail: String::new(),
                        },
                    );
                })
            }))
            .expect("with_machine");

            // Unbounded on purpose: the outer `recv_timeout` below is what
            // turns a hang into a failure, once for this whole sequence,
            // rather than duplicating a second timeout for this one wait.
            reentered_rx
                .recv()
                .expect("the listener callback must fire");

            reset_for_test();
            let _ = done_tx.send(());
        });

        done_rx.recv_timeout(DEADLOCK_BOUND).expect(
            "emitting under the machine lock must not deadlock a listener \
             that calls back into the library",
        );
    }
}
