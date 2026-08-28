use std::sync::Arc;

use crate::error::ProbeError;
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
/// Both are solved the same way: `on_signal` always runs on a freshly
/// spawned OS thread, detached from the caller's call stack. That thread
/// captures only the observer and the signal, both by value, so it carries
/// no lock the caller might be holding, and calling this costs the caller
/// nothing beyond the spawn itself -- no `.await`, no blocking wait for the
/// foreign side to return, and no dependency on an ambient tokio context
/// (unlike `tokio::task::spawn`, which panics without one, this needs no
/// runtime at all). The `JoinHandle` is discarded rather than joined; that
/// does not cancel the spawned thread, it only stops the caller from
/// waiting on it, which is the point of "fire-and-forget".
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
    std::thread::spawn(move || observer.on_signal(signal));
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

    /// Generous relative to how fast a thread spawn actually completes;
    /// tight enough that a genuinely broken delivery path still fails a
    /// test in a few seconds rather than hanging it.
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
