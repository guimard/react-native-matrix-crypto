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

/// Runs `work` on this library's blocking pool, and does not wait for it.
///
/// Three properties, each of which something in this crate depends on:
///
/// - **It needs no ambient runtime.** `tokio::task::spawn_blocking` is a free
///   function that reads the thread's ambient runtime and panics when there is
///   none. This reaches the runtime this crate owns directly, so it works from
///   any thread, including a foreign one that has never seen tokio. That is
///   the property `observer::emit` inherited from `std::thread::spawn` and
///   must keep: a signal can be produced on a path a foreign caller drove
///   without entering `in_runtime` first.
/// - **It cannot stall the runtime's async work.** The blocking pool is a
///   different set of threads from the two workers `in_runtime` schedules on,
///   so work handed here may block for as long as it likes -- and a foreign
///   callback may block for as long as the foreign side likes -- without
///   stopping encryption or any other call in flight. Handing the same work to
///   `spawn` would occupy a worker for its whole duration, and there are two.
/// - **It is bounded, unlike a thread per call.** Tokio caps the pool (512
///   threads by default) and reuses idle threads rather than creating one per
///   task. Past the cap, work queues. That cap is shared rather than ours
///   alone: `matrix-sdk-sqlite` reaches the same pool through `deadpool-sync`
///   and `deadpool-runtime`, whose `spawn_blocking` is tokio's, so a caller
///   that parked hundreds of pool threads would delay the crypto store too.
///   That is a real trade against a thread per call, which has no shared cap
///   to exhaust, and it is taken deliberately -- the alternative bound is the
///   process's own thread table, which fails harder and later.
pub(crate) fn spawn_blocking_detached<F>(work: F)
where
    F: FnOnce() + Send + 'static,
{
    // Dropped rather than awaited: that is what "detached" means here.
    // Dropping the handle does not cancel the closure -- a blocking task
    // handed to the pool runs to completion regardless -- it only stops
    // anyone from waiting on it.
    drop(runtime().spawn_blocking(work));
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
            joined
                .try_into_panic()
                .unwrap_or_else(|_| Box::new("crypto task cancelled")),
        ),
    }
}

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
            tokio::task::spawn(async { 21 * 2 })
                .await
                .expect("task joined")
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
