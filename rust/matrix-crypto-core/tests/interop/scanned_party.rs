//! The mautrix-go counterparty, driven as a subprocess.
//!
//! `interop/harness.rs` drives `matrix-nio` the same way and carries
//! everything that is not specific to a counterparty: the homeserver, the
//! login, the pump, the teardown. This file adds only the second
//! counterparty, because `matrix-nio` cannot serve a proof about scanning a
//! code and mautrix-go can. `interop/mautrix_party/main.go`'s header carries
//! the evidence for both halves of that sentence.
//!
//! # Nothing here asserts anything about cryptography
//!
//! Every assertion in this file is about the subprocess: that a command
//! could be written, that a reply parsed, that the process is alive. The
//! claims the milestone rests on are in `tests/level_two_scanned.rs`, on
//! purpose, for the reason `interop/harness.rs` gives at more length.

// The test binary that includes this uses most of it. Allowed here for
// `interop/harness.rs`'s reason.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

/// Where the compiled counterparty is. Built by
/// `scripts/run-level-two-interop.sh`, which needs a Go toolchain for
/// exactly this and says so when it does not find one.
pub const PARTY_BINARY_ENV: &str = "MATRIX_INTEROP_MAUTRIX_PARTY";

/// The account this proof gives to the library. Its own, rather than the one
/// the other level 2 proofs share, and the reason is not tidiness: this proof
/// needs an account whose cross-signing identity **this library minted**, and
/// `level_two_identity` leaves the shared account holding one that a fresh
/// store cannot hold the private half of. Two proofs racing for who bootstraps
/// first is exactly the order dependency no reader of either could see.
pub const SCANNED_USER_ENV: &str = "MATRIX_INTEROP_SCANNED_USER";

/// The account the cross-user counterparty logs in to. A third party in a
/// cross-user verification has to be a different user, and it has to hold a
/// cross-signing identity of its own: mode `0x00` signs the other person's
/// master key with the user-signing private key, which only the account that
/// minted the identity has.
pub const SCANNER_USER_ENV: &str = "MATRIX_INTEROP_SCANNER_USER";

/// The account this library *shows* a code to. A third one, and it is not
/// tidiness: a flow this counterparty accepts never finishes, and an
/// unfinished flow makes upstream cancel every later verification with the
/// same person (`verification/cache.rs:86-104`). Keeping the two phases that
/// leave one on their own account is what stops the phases that must complete
/// from inheriting it. `tests/level_two_scanned.rs`'s header has the whole of
/// why a flow this library shows does not finish against this counterparty.
pub const SHOWN_USER_ENV: &str = "MATRIX_INTEROP_SHOWN_USER";

pub struct MautrixParty {
    pub child: Child,
    pub stdin: ChildStdin,
    pub stdout: BufReader<ChildStdout>,
    pub stderr: Arc<Mutex<String>>,
    /// What this party calls itself in a panic message. Three of them run
    /// in one test and "the counterparty failed" would not say which.
    pub name: String,
    /// Every callback event this party has reported, in arrival order,
    /// kept rather than consumed. See [`MautrixParty::drain`].
    pub seen: Vec<Value>,
}

impl MautrixParty {
    pub fn start(binary: &std::path::Path, name: &str) -> Self {
        let mut child = Command::new(binary)
            // The password reaches the subprocess by inheriting this
            // process's environment, never on the command line: `ps` shows
            // argv to every user on the machine and environments only to
            // the owner. The same rule `NioParty::start` follows.
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| {
                panic!(
                    "could not start the mautrix counterparty at {}; build it with \
                     `go build -tags goolm` and point {PARTY_BINARY_ENV} at the result \
                     ({error})",
                    binary.display()
                )
            });

        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = BufReader::new(child.stdout.take().expect("stdout was piped"));
        let mut child_stderr = child.stderr.take().expect("stderr was piped");

        // Drained on its own thread rather than left to fill a 64 KiB pipe
        // buffer and deadlock the child mid-reply. Kept in memory and only
        // ever surfaced inside a panic message, so a passing run prints
        // nothing.
        let stderr = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&stderr);
        std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let _ = child_stderr.read_to_end(&mut buffer);
            if let Ok(mut sink) = sink.lock() {
                sink.push_str(&String::from_utf8_lossy(&buffer));
            }
        });

        MautrixParty {
            child,
            stdin,
            stdout,
            stderr,
            name: name.to_string(),
            seen: Vec::new(),
        }
    }

    pub fn stderr_so_far(&self) -> String {
        self.stderr
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// One command, one reply, and a panic naming the step if the reply says
    /// the counterparty could not do it.
    pub fn call(&mut self, command: Value) -> Value {
        let reply = self.try_call(command);
        assert_eq!(
            reply["ok"],
            json!(true),
            "the mautrix counterparty {:?} failed {:?}: {}",
            self.name,
            reply["op"],
            reply["error"]
        );
        reply
    }

    /// The same, without the assertion, for the one command whose failure is
    /// a result rather than a fault. A refusal is what this proof asks the
    /// counterparty for on purpose, and a transport that panicked on it
    /// could not tell it apart from a broken step.
    pub fn try_call(&mut self, command: Value) -> Value {
        let op = command["op"].as_str().unwrap_or("<none>").to_string();
        writeln!(self.stdin, "{command}").expect("the mautrix counterparty must accept a command");
        self.stdin.flush().expect("the command must be flushed");

        let mut line = String::new();
        let read = self
            .stdout
            .read_line(&mut line)
            .expect("the mautrix counterparty's reply must be readable");
        assert!(
            read > 0,
            "the mautrix counterparty {:?} closed its output without replying to {op:?}. \
             Its stderr was:\n{}",
            self.name,
            self.stderr_so_far()
        );

        let mut reply: Value = serde_json::from_str(&line).unwrap_or_else(|_| {
            panic!(
                "the mautrix counterparty {:?} replied to {op:?} with something that is not \
                 JSON: {line}\nIts stderr was:\n{}",
                self.name,
                self.stderr_so_far()
            )
        });
        reply["op"] = json!(op);
        reply
    }

    /// Runs `/sync` on the counterparty until it has seen an event of that
    /// kind, or panics naming what did not happen and everything it did see.
    ///
    /// Bounded by a number of turns rather than by wall-clock time: every
    /// turn is one `/sync` with its own server-side timeout, so a slow
    /// homeserver costs turns rather than producing a deadline that fires
    /// while a request is still in flight.
    pub fn sync_until_seen(&mut self, kind: &str) {
        for _ in 0..40 {
            self.call(json!({"op": "sync", "timeout_ms": 1000}));
            self.drain();
            if self.saw(kind) {
                return;
            }
        }
        panic!(
            "the mautrix counterparty {:?} never reported {kind:?} within forty syncs. It \
             reported {:?}. Its stderr was:\n{}",
            self.name,
            self.seen,
            self.stderr_so_far()
        );
    }

    /// Moves whatever the helper's callbacks have seen since the last drain
    /// into this party's own record of them.
    ///
    /// Kept rather than returned and discarded, and that is not tidiness: a
    /// predicate that drained the queue looking for one event threw away
    /// every other event that arrived in the same turn, including a
    /// cancellation that explains why the thing it was waiting for never
    /// came. That cost an hour.
    pub fn drain(&mut self) {
        let batch = self.call(json!({"op": "events"}))["events"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        self.seen.extend(batch);
    }

    /// Whether an event of that kind has been seen at any point.
    pub fn saw(&self, kind: &str) -> bool {
        self.seen.iter().any(|event| event["event"] == json!(kind))
    }

    /// Every event of that kind seen so far.
    pub fn all(&self, kind: &str) -> Vec<&Value> {
        self.seen
            .iter()
            .filter(|event| event["event"] == json!(kind))
            .collect()
    }

    /// Forgets what has been seen, so a later phase's assertions are about
    /// that phase. Called between phases and never inside one.
    pub fn forget(&mut self) {
        self.seen.clear();
    }
}

impl Drop for MautrixParty {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
