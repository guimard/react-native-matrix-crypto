//! Level 2 for device verification: a third-party client's verification
//! reaching this library over a real homeserver.
//!
//! # The question, and why `sas_two_party.rs` cannot answer it
//!
//! `tests/sas_two_party.rs` drives a bare `matrix_sdk_crypto::OlmMachine`
//! as the counterparty. Both sides are then upstream's own verification
//! state machine, so a consistent misreading of the protocol -- ours or
//! upstream's -- passes it and looks like success. This file asks the
//! question that catches that: **does a verification from a client written
//! by people who have never seen this code work against it**, over a
//! homeserver neither side controls. It is the standard M2 set for
//! encryption (`level_two_interop.rs`), applied to verification.
//!
//! The counterparty is the same `matrix-nio` subprocess, driven through the
//! `sas_*` operations in `tests/interop/nio_party.py`.
//!
//! # nio opens the flow, and that is a fact about nio
//!
//! `matrix-nio` 0.26.0 implements the short-string verification in exactly
//! one shape: the bare `m.key.verification.start` MSC3122 deprecated, to
//! device, with `accept`, `key`, `mac` and `cancel` after it. Its event
//! vocabulary contains no `m.key.verification.request`, no `ready` and no
//! `done`, and it has no in-room verification at all. So this library's own
//! invitation reaches it as an unrecognised to-device event and is
//! discarded, and **nio has to be the side that opens the flow.** Answering
//! that shape is what this milestone's last change made possible; before
//! it, such a flow existed inside this library's machine and no call on its
//! public surface could see or answer it.
//!
//! # HOW FAR THIS GETS, AND WHERE IT STOPS
//!
//! It stops short of a completed verification, and the reason is in the
//! counterparty rather than here. **`matrix-nio` 0.26.0 encodes the SAS
//! commitment as lowercase hexadecimal** (`crypto/sas.py`:
//! `sha256(...).hexdigest()`, in both `_check_commitment` and
//! `from_key_verification_start`). The specification requires unpadded
//! base64, which is what `matrix-sdk-crypto` 0.18.0 sends and checks
//! (`verification/sas/helpers.rs`'s `calculate_commitment`). Two nio clients
//! agree with each other and nio agrees with nobody else, in either
//! direction: whichever side starts, the other's commitment is rejected.
//!
//! This is a regression in the counterparty rather than a long-standing
//! quirk: nio 0.25.2 computed the same value with libolm's `olm.sha256`,
//! which returns unpadded base64. The port to `vodozemac` in 0.26.0
//! replaced it with Python's `hexdigest()`. nio's own tests pair two nio
//! objects, so nothing there could notice.
//!
//! So this test **attributes** the halt rather than merely reporting it.
//! When nio refuses, its own process recomputes the digest over its own
//! start message and this library's public key and returns it written both
//! ways; the assertion is that the unpadded-base64 rendering is exactly
//! what this library sent and the hexadecimal one is not. That settles,
//! from inside the counterparty, that the two sides hashed the same bytes
//! and disagreed only about how to write the result down.
//!
//! # A green run can never mean "still blocked", and here is exactly how
//!
//! `tests/interop/requirements.txt` pins matrix-nio at 0.26.0, so nothing
//! about the counterparty moves underneath this test until somebody moves
//! that line. When somebody does, and the release they move to has fixed
//! the encoding, **the failure is a timeout and not an assertion**: nio's
//! commitment check succeeds, it never cancels, and the loop below waits
//! for a cancellation that does not come until its own deadline expires.
//!
//! That is worth being precise about, because a timeout is the failure
//! shape most likely to be read as a flaky harness and retried. So the
//! deadline message says what it means -- that the counterparty never
//! cancelled, that this test was written against a defective one, and what
//! to do about it -- rather than leaving that to the assertions further
//! down which describe the defect, because every one of those is
//! downstream of the loop and none of them is reached on that path.
//!
//! What to do about it, in full: drop this file's "how far this gets"
//! framing, drive the flow to `verified` on both sides, and add the run
//! that matters most -- two people reading different strings, ending in a
//! refusal the counterparty decides on rather than is told to make. Both
//! of those are proven at level 1 today and are the two things this proof
//! is missing.
//!
//! # What is therefore proven here, and what is proven elsewhere
//!
//! Proven here, over a real homeserver, against an implementation whose
//! *protocol* code shares nothing with this one -- the event vocabulary,
//! the flow shape, and the commitment computation that turned out to be the
//! defect are Python written by people who have never seen this code.
//!
//! **The floor is the same one the encryption proof has, and it is named
//! here rather than left to a sibling file.** matrix-nio 0.26 moved its
//! ratchet to `vodozemac`, the crate `matrix-sdk-crypto` uses, and
//! `rust/Cargo.lock` and `tests/interop/requirements.txt` pin 0.10.0 on
//! both sides. nio's SAS key agreement and MAC derivation go through
//! `vodozemac::sas`, and so do this library's, so a defect inside that
//! crate -- or a misreading shared below the protocol line -- passes both
//! sides of this test. What two independent implementations genuinely check
//! here is everything above it. This file said "shares no verification code
//! with this one", which is the stronger sentence and is not the true one;
//! `README.md` already applies this floor to the encryption proof in the
//! same terms.
//!
//! * a third-party client's bare `m.key.verification.start` reaches this
//!   library and is **announced on the crypto signal channel**, with an
//!   identifier every call in this library answers to;
//! * `accept_flow` on that request-less flow produces an
//!   `m.key.verification.accept` the third party parses, negotiates
//!   against, and acts on -- it answers with its own key;
//! * this library carries its own half of the key exchange to completion
//!   on the third party's key and **derives a short authentication
//!   string**. Its half: nio refuses at its commitment check *before*
//!   `establish_sas`, so it never derives one, and this run therefore says
//!   nothing about whether the two implementations would compute the same
//!   string;
//! * and when the third party then cancels, this library reports the flow
//!   `Cancelled` and verifies nothing.
//!
//! **That is the milestone's exit criterion for this task met, not a
//! fallback taken.** The criterion asks that a third-party client
//! *participate* in a SAS flow over a real homeserver. nio participates: it
//! opens the flow, negotiates against this library's accept, sends its key,
//! and cancels. It does implement SAS in a form this can drive; it simply
//! cannot be driven to completion, which is a smaller claim than "no
//! available counterparty implements SAS" and a different one.
//!
//! Not provable here, and proven at level 1 instead: that the two sides
//! compute the same string, that both end up reporting each other verified,
//! and that a genuine disagreement between the strings ends in a refusal.
//! All three need a counterparty that can reach a short authentication
//! string, and nio 0.26.0 cannot. `sas_two_party.rs` carries all three, for
//! both flow shapes, against a machine this library does not control.
//!
//! # Why this proof is at the core and not at the published surface
//!
//! M2 ran its third-party proof twice -- once against the Rust core and
//! once through the published TypeScript package -- because the bridge was
//! new and the second leg was the only thing that could show the payloads
//! survived it. This task adds a second leg for neither, and the reason is
//! that **it adds nothing to the boundary to carry**: no FFI type, no enum
//! variant, no call, no generated file. `lib.rs` is untouched, so the
//! branch introduces no public identifier at all.
//!
//! What crosses for a request-less flow is what already crossed for a
//! request-shaped one -- the same `verification_requested` signal, the same
//! opaque identifier, the same six calls -- and that crossing is already
//! pinned: `matrix-crypto-ffi`'s `value_mapping.rs` and `error_mapping.rs`
//! fix every value and every error the boundary carries, and the facade's
//! own suite covers the TypeScript half. A surface leg here would exercise
//! the same bridge with the same payloads and could only fail for reasons
//! those already catch.
//!
//! What it could *not* do is anything this file does: the wire format
//! against a third party is a property of the messages the core builds, and
//! is unchanged by the bridge that carries the calls. So the leg is
//! declined on the argument above rather than omitted silently, which is
//! the thing that would have been wrong.
//!
//! # The room, which nothing is encrypted in
//!
//! An encrypted room is created and never used to send anything. It is
//! there because `matrix-nio` only queries the device keys of users it
//! shares an *encrypted room* with (`base_client.py`'s `_handle_olm_events`
//! filters `device_lists.changed` by exactly that), and a
//! `m.key.verification.start` naming a device the receiver has never
//! queried is dropped on arrival by both implementations. So the room is
//! how the two devices come to know of each other, and nothing more.
//!
//! # Running it
//!
//! `./scripts/run-level-two-interop.sh`, which starts a throwaway
//! homeserver, installs the pinned counterparty and runs this test and its
//! sibling. See `level_two_interop.rs`'s header for the environment
//! variables the manual path takes.
//!
//! `#[ignore]`, so an ordinary `cargo test` needs no network, no container
//! and no credential.

use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use matrix_crypto_core::{
    accept_flow, begin_comparison, create_machine, device_statuses, flow_stage, read_material,
    receive_sync_changes, set_crypto_observer, CryptoObserver, CryptoSignal, FlowId, FlowStage,
    MachineConfig, MachineError, OutgoingRequest, TrustState,
};
use serde_json::{json, Value};

#[path = "interop/harness.rs"]
mod harness;
use harness::{
    encode_segment, encryption_slice, login, pump_and_send, required_env, run, Homeserver,
    NioParty, Teardown, HOMESERVER_ENV, PASSWORD_ENV, PYTHON_ENV, USER_ENV,
};

/// Not a credential: the store lives in a temporary directory this test
/// also deletes, and nothing outside this process opens it.
const STORE_PASSPHRASE: &str = "level-two-verification";

/// How nio words the refusal its commitment check produces
/// (`crypto/sas.py`'s `_commitment_mismatch_error`), and the specification's
/// own code for it. Matched on the code and never on the human-readable
/// reason beside it, which is the counterparty's prose.
const MISMATCHED_COMMITMENT: &str = "m.mismatched_commitment";

/// How long any one "advance both sides" loop below gets.
///
/// Generous rather than tight: each is bounded by a condition that must
/// become true and ends in an assertion naming what did not happen, so a
/// slow homeserver costs time and a broken one still fails readably rather
/// than hanging.
const PATIENCE: Duration = Duration::from_secs(90);

// ---------------------------------------------------------------------------
// The signal channel, recorded
// ---------------------------------------------------------------------------

/// Records what the crypto signal channel delivered, in order.
///
/// A channel rather than a vector, for the reason `sas_two_party.rs` gives:
/// delivery is detached, so a test that looked at a vector at the wrong
/// instant would report an absence that was really a not-yet.
struct Recorder {
    tx: mpsc::Sender<CryptoSignal>,
}

impl CryptoObserver for Recorder {
    fn on_signal(&self, signal: CryptoSignal) {
        let _ = self.tx.send(signal);
    }
}

/// One `/sync`, fed to the library, with what it carried and what the
/// library handed out in response.
struct Synced {
    to_device: Vec<Value>,
    outgoing: Vec<OutgoingRequest>,
}

/// The homeserver, the credential to talk to it with, where the sync cursor
/// has reached, and what the channel has said.
struct Session<'a> {
    homeserver: &'a Homeserver,
    token: String,
    since: String,
    signals: mpsc::Receiver<CryptoSignal>,
}

impl Session<'_> {
    /// One `/sync`, through the library, with the pump drained afterwards.
    ///
    /// Every sync a product performs goes through `receiveSyncChanges`,
    /// including the ones carrying nothing, and every request the library
    /// hands out is posted and reported. That is the whole of what this
    /// test does on the library's behalf between assertions.
    fn sync(&mut self) -> Synced {
        let sync = self.homeserver.ok(
            "GET",
            &format!(
                "/_matrix/client/v3/sync?timeout=2000&since={}",
                encode_segment(&self.since)
            ),
            Some(&self.token),
            None,
        );
        self.since = sync["next_batch"]
            .as_str()
            .expect("a /sync response carries a next_batch")
            .to_string();

        run(receive_sync_changes(&encryption_slice(&sync).to_string()))
            .expect("a real /sync payload must be accepted");

        Synced {
            to_device: sync["to_device"]["events"]
                .as_array()
                .cloned()
                .unwrap_or_default(),
            outgoing: pump_and_send(self.homeserver, &self.token),
        }
    }

    /// Syncs until `reached` says so, or fails naming what did not happen.
    fn sync_until(&mut self, what: &str, mut reached: impl FnMut(&mut Self, &Synced) -> bool) {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let synced = self.sync();
            if reached(self, &synced) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{what} did not happen within {PATIENCE:?} of syncing and pumping"
            );
        }
    }

    /// The next signal the channel delivered, if one has.
    ///
    /// Waits briefly rather than not at all: delivery is detached, so a
    /// `try_recv` immediately after the sync that caused a signal would
    /// report an absence that was really a not-yet. Every caller is inside
    /// a loop, so a signal missed on one turn is picked up on the next and
    /// only the loop's own deadline is load-bearing.
    fn next_signal(&self) -> Option<CryptoSignal> {
        self.signals.recv_timeout(Duration::from_millis(250)).ok()
    }
}

/// Whether the library's own device list for that user names the device
/// yet. Read through the call a product would make, never through the
/// machine directly.
fn device_statuses_contains(user_id: &str, device_id: &str) -> bool {
    run(device_statuses(user_id))
        .expect("the library's machine must be live")
        .into_iter()
        .any(|status| status.device_id == device_id)
}

/// What this library reports about one of the counterparty's devices,
/// through the call a product would make.
fn library_trust(user_id: &str, device_id: &str) -> TrustState {
    run(device_statuses(user_id))
        .expect("the library's machine must be live")
        .into_iter()
        .find(|status| status.device_id == device_id)
        .unwrap_or_else(|| {
            panic!(
                "the library must know the counterparty's device {device_id} before it \
                 can say anything about it"
            )
        })
        .trust
}

/// The per-recipient content of one of the library's own outgoing to-device
/// requests, if the batch carried one of that type addressed to that device.
///
/// Read out of what the pump handed over, which is the only copy this test
/// has of what the library said: the homeserver does not give it back.
fn outgoing_content(
    batch: &[OutgoingRequest],
    event_type: &str,
    user_id: &str,
    device_id: &str,
) -> Option<Value> {
    batch
        .iter()
        .filter(|request| request.kind == "to_device")
        .filter_map(|request| serde_json::from_str::<Value>(&request.body).ok())
        .filter(|body| body["event_type"] == json!(event_type))
        .find_map(|body| body["messages"][user_id][device_id].as_object().cloned())
        .map(Value::Object)
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[test]
#[ignore = "needs a real homeserver, a credential in the environment, and matrix-nio; \
            run ./scripts/run-level-two-interop.sh"]
fn a_third_party_clients_verification_reaches_the_short_authentication_string() {
    let homeserver = Homeserver::new(required_env(HOMESERVER_ENV));
    let user = required_env(USER_ENV);
    let password = required_env(PASSWORD_ENV);
    let python = std::env::var(PYTHON_ENV).unwrap_or_else(|_| "python3".to_string());
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("interop")
        .join("nio_party.py");
    assert!(
        script.is_file(),
        "the nio counterparty script is missing from {}",
        script.display()
    );

    let dir = tempfile::tempdir().expect("temp dir");
    let library_store = dir.path().join("library-store");
    let nio_store = dir.path().join("nio-store");
    std::fs::create_dir_all(&nio_store).expect("the nio store directory must be creatable");

    // ---- 1. The library's device --------------------------------------
    let library = login(
        &homeserver,
        &user,
        &password,
        "level-two-verification-library",
    );
    // Declared before anything else exists on the homeserver, and before
    // `nio` below, so an unwind kills the subprocess first and this then
    // removes what the run created. Every resource is registered with it
    // the moment its identifier is in hand.
    let mut teardown = Teardown::new(&homeserver, &library, &password);

    // ---- 2. The room the two devices meet in ---------------------------
    // Nothing is ever encrypted in it. See this file's header.
    let room = homeserver.ok(
        "POST",
        "/_matrix/client/v3/createRoom",
        Some(&library.token),
        Some(
            &json!({
                "preset": "private_chat",
                "name": "react-native-matrix-crypto level 2 verification",
                "initial_state": [{
                    "type": "m.room.encryption",
                    "state_key": "",
                    "content": { "algorithm": "m.megolm.v1.aes-sha2" }
                }],
            })
            .to_string(),
        ),
    );
    let scope = room["room_id"]
        .as_str()
        .expect("createRoom returns a room id")
        .to_string();
    teardown.owns_room(&scope);

    // ---- 3. The counterparty's device ----------------------------------
    let mut nio = NioParty::start(&python, &script, &nio_store);
    let nio_login = nio.call(json!({ "op": "login" }));
    let nio_user_id = nio_login["user_id"]
        .as_str()
        .expect("the counterparty reports its user id")
        .to_string();
    let nio_device_id = nio_login["device_id"]
        .as_str()
        .expect("the counterparty reports its device id")
        .to_string();
    teardown.owns_device(&nio_device_id);

    assert_eq!(
        nio_user_id, library.user_id,
        "both devices must belong to the same account, which is what makes this a \
         one-credential test"
    );
    assert_ne!(
        nio_device_id, library.device_id,
        "the counterparty must be a second device, not the same one"
    );

    // ---- 4. The library's machine, its observer, and its keys -----------
    run(create_machine(MachineConfig {
        user_id: library.user_id.clone(),
        device_id: library.device_id.clone(),
        store_path: library_store.to_string_lossy().into_owned(),
        store_passphrase: Some(STORE_PASSPHRASE.to_string()),
    }))
    .expect("the library's machine must be creatable");

    // Installed before the first sync, which is what this library's own
    // documentation tells a product to do and what the announcement below
    // depends on: this flow shape has no second chance.
    let (tx, rx) = mpsc::channel();
    set_crypto_observer(Arc::new(Recorder { tx }));

    for _ in 0..6 {
        if pump_and_send(&homeserver, &library.token).is_empty() {
            break;
        }
    }

    // ---- 5. Each device learns the other exists -------------------------
    let initial = homeserver.ok(
        "GET",
        "/_matrix/client/v3/sync?timeout=0",
        Some(&library.token),
        None,
    );
    run(receive_sync_changes(
        &encryption_slice(&initial).to_string(),
    ))
    .expect("a real /sync payload must be accepted");
    pump_and_send(&homeserver, &library.token);

    let mut session = Session {
        homeserver: &homeserver,
        token: library.token.clone(),
        since: initial["next_batch"]
            .as_str()
            .expect("a /sync response carries a next_batch")
            .to_string(),
        signals: rx,
    };

    // Asserted rather than assumed, and it is the precondition the whole
    // exchange rests on: a start naming a device the receiver has never
    // queried is dropped on arrival, by both implementations, with nothing
    // sent back. If this fails, everything below would fail for a reason
    // that has nothing to do with verification.
    session.sync_until("the library learned the counterparty's device", |_, _| {
        device_statuses_contains(&library.user_id, &nio_device_id)
    });
    assert_eq!(
        library_trust(&library.user_id, &nio_device_id),
        TrustState::Unverified,
        "a device this machine merely knows the keys of is not verified; without this \
         the trust assertion at the end could pass against a surface that answered the \
         same thing throughout"
    );

    // ---- 6. The counterparty opens a comparison -------------------------
    let started = nio.call(json!({
        "op": "sas_start",
        "user_id": library.user_id,
        "device_id": library.device_id,
    }));
    let transaction = started["transaction_id"]
        .as_str()
        .expect("the counterparty reports the transaction id it opened")
        .to_string();
    assert_eq!(
        started["event_type"],
        json!("m.key.verification.start"),
        "the counterparty must open the flow with a bare start, which is the only shape \
         it speaks: {started}"
    );

    // ---- THE FIRST PROOF: it is announced, with a usable identifier -----
    // A flow that arrives this way is in no map this library can enumerate;
    // it is recognised from the sync that carried it and confirmed against
    // the machine before anything is announced. Until that landed, such a
    // flow reached this library, existed inside its machine, and could be
    // reached through no call on the public surface at all.
    let mut announced: Option<CryptoSignal> = None;
    session.sync_until(
        "the counterparty's start reached the library",
        |session, _| {
            announced = session.next_signal();
            announced.is_some()
        },
    );
    let announced = announced.expect("the loop above returns only once a signal arrived");
    let CryptoSignal::VerificationRequested {
        user,
        device_id,
        flow_id,
    } = announced.clone()
    else {
        panic!(
            "a comparison the counterparty started must be announced as an invitation, \
             not as {announced:?}"
        );
    };
    assert_eq!(
        user, library.user_id,
        "the announcement must name who is asking; both devices are on one account here"
    );
    assert_eq!(
        device_id, nio_device_id,
        "the announcement must name the counterparty's device"
    );
    assert_eq!(
        flow_id, transaction,
        "the identifier the channel hands over must be the transaction id the \
         counterparty put on the wire, or a product cannot answer what it was told about"
    );
    let flow = FlowId(flow_id);

    // ---- 7. The library agrees ------------------------------------------
    // There is no `ready` stage on this shape: the flow is a comparison from
    // the moment it exists, so there is nothing to start, and this library
    // says so rather than building a second comparison under the same name.
    assert_eq!(
        run(flow_stage(&flow)).expect("an announced flow is findable by the identifier given"),
        FlowStage::Started
    );
    assert_eq!(
        run(begin_comparison(&flow))
            .expect_err("a flow that arrived as a comparison cannot have one started"),
        MachineError::WrongStage
    );

    run(accept_flow(&flow)).expect("a comparison the counterparty started can be agreed to");
    let answered = pump_and_send(&homeserver, &library.token);
    let accept = outgoing_content(
        &answered,
        "m.key.verification.accept",
        &library.user_id,
        &nio_device_id,
    )
    .unwrap_or_else(|| {
        panic!(
            "agreeing must have queued an m.key.verification.accept addressed to the \
             counterparty's device; the pump handed out {:?}",
            answered
                .iter()
                .map(|request| &request.kind)
                .collect::<Vec<_>>()
        )
    });
    let our_commitment = accept["commitment"]
        .as_str()
        .expect("an accept carries the commitment the specification requires")
        .to_string();

    // ---- 8. Both sides are advanced, in turn ----------------------------
    // Each is waiting on a message the other will not send until it has
    // synced, so a call that let either drive on its own deadlocks -- and
    // did, on the first run of this test: the counterparty sat for ninety
    // seconds with its key sent while this side's key went unposted,
    // because this side was blocked inside that call.
    //
    // This side reaches a short authentication string. The counterparty
    // does not, and stops with a refusal; see this file's header for whose
    // defect that is, and the block after this one for how it is attributed
    // rather than assumed.
    let mut our_key: Option<String> = None;
    let mut material = None;
    let mut nio_report: Option<Value> = None;
    let deadline = Instant::now() + PATIENCE;
    loop {
        let synced = session.sync();
        if our_key.is_none() {
            our_key = outgoing_content(
                &synced.outgoing,
                "m.key.verification.key",
                &library.user_id,
                &nio_device_id,
            )
            .and_then(|content| content["key"].as_str().map(str::to_owned));
        }
        if material.is_none()
            && run(flow_stage(&flow)).expect("the flow exists") == FlowStage::KeysExchanged
        {
            material =
                Some(run(read_material(&flow)).expect("the string is available at this stage"));
        }
        if nio_report.is_none() {
            let report = nio.call(json!({
                "op": "sas_await",
                "transaction_id": transaction,
                "want": "canceled",
                "timeout_s": 2,
            }));
            if report["reached"] == json!(true) {
                nio_report = Some(report);
            }
        }
        if material.is_some() && our_key.is_some() && nio_report.is_some() {
            break;
        }
        // The one message in this file that has to be read by somebody
        // who did not write it, and the only place the "nio may have been
        // fixed" guidance can reach them. This is the failure a corrected
        // counterparty produces -- a wait for a cancellation that never
        // comes -- and it looks exactly like a flaky harness unless it
        // says otherwise. The assertions below cannot carry the guidance:
        // on this path none of them is reached.
        assert!(
            Instant::now() < deadline,
            "the exchange did not reach its end within {PATIENCE:?}.\n\
             This side: {:?}, its key seen: {}.\n\
             The counterparty: {}\n\
             \n\
             READ THIS BEFORE RETRYING. This is not a flaky harness, and \
             the likeliest cause is good news. This test expects matrix-nio \
             to REFUSE, at its own commitment check: 0.26.0 writes the SAS \
             commitment as hexadecimal where the specification requires \
             unpadded base64, so it rejects every spec-compliant peer. If \
             the pin in tests/interop/requirements.txt has moved to a \
             release that fixed that, nio no longer cancels, nothing ever \
             satisfies the wait above, and this is what that looks like.\n\
             \n\
             What to do: check the pinned version. If it moved, this file's \
             whole framing is out of date -- drive the flow to verified on \
             both sides, and add the run this proof has never been able to \
             make, where the two strings genuinely differ and the \
             counterparty refuses on its own. Both are proven at level 1 in \
             sas_two_party.rs today and neither has ever been proven \
             against a third party. If the pin did not move, the \
             counterparty stalled somewhere else and its state is above.",
            run(flow_stage(&flow)),
            our_key.is_some(),
            nio_report
                .as_ref()
                .map_or_else(|| "still going".to_string(), Value::to_string)
        );
    }
    let our_key = our_key.expect("the loop breaks only once this side's key was seen");
    let nio_report = nio_report.expect("the loop breaks only once the counterparty stopped");

    // ---- THE SECOND PROOF: this library got a string out of it ----------
    // The key exchange completed against an implementation whose protocol
    // code shares nothing with this one, and this library derived the string
    // a person would be shown. **Not against one that shares no code at
    // all**, and this is the assertion where that distinction bites
    // hardest: the key agreement is the half `vodozemac` performs on both
    // sides, at the same pinned 0.10.0. See this file's header. That the counterparty answered the agreement
    // with a key at all is the other half of it: it parsed the accept this
    // library built for a request-less flow, negotiated against it, and
    // acted on it.
    let material = material.expect("the loop breaks only once this side had a string");
    assert!(
        material
            .emoji
            .as_ref()
            .is_some_and(|emoji| emoji.len() == 7),
        "the counterparty's start offered the symbol form and this library negotiated it \
         out of the counterparty's own list, so there must be seven symbols to show"
    );
    assert_eq!(
        nio_report["we_started_it"],
        json!(true),
        "this whole file rests on the counterparty having opened the flow, which is the \
         only direction the two implementations have in common: {nio_report}"
    );

    // And the counterparty did *not* get one, which is the asymmetry the
    // block below explains. Asked rather than inferred from its having
    // cancelled: `established_sas` is what nio sets when the key exchange
    // succeeds, and it is unset here.
    let counterparty_string = nio.call(json!({
        "op": "sas_await",
        "transaction_id": transaction,
        "want": "string",
        "timeout_s": 2,
    }));
    assert_eq!(
        counterparty_string["reached"],
        json!(false),
        "the counterparty must NOT have reached a short authentication string. If it \
         did, the exchange got further than this file says it can, and the header is \
         wrong: {counterparty_string}"
    );

    // ---- THE THIRD PROOF: whose defect the halt is ----------------------
    assert_eq!(
        nio_report["cancel_code"],
        json!(MISMATCHED_COMMITMENT),
        "the counterparty is expected to stop at its own commitment check, and only \
         there. Anything else means the halt has a different cause than this file's \
         header describes, and the header is then wrong: {nio_report}"
    );

    let probe = nio.call(json!({
        "op": "sas_commitment_probe",
        "transaction_id": transaction,
        "peer_key": our_key,
    }));
    assert_eq!(
        probe["received"],
        json!(our_commitment),
        "the counterparty must have received exactly the commitment this library sent, \
         or this attribution is about the wrong value: {probe}"
    );
    assert_eq!(
        probe["unpadded_base64"],
        json!(our_commitment),
        "**the two sides hashed the same bytes.** The counterparty recomputed the digest \
         over its own start message and this library's public key, and its \
         unpadded-base64 rendering is exactly what this library sent -- so the canonical \
         JSON, the key and the hash all agree, and only the encoding of the result does \
         not. If this ever fails, the disagreement is a real one about what to hash and \
         this file's header is wrong: {probe}"
    );
    // There was a third assertion here, `assert_ne!(probe["hex"],
    // our_commitment)`, written as the tripwire that would fire when nio
    // was fixed. It could not: 64 hexadecimal characters can never equal a
    // 43-character unpadded-base64 string, and the assertion above already
    // pins that string exactly. It was a tautology, its message was worded
    // for an `assert_eq!`, and nothing nio does affects either value --
    // the probe returns both renderings unconditionally. The tripwire that
    // does work is the loop deadline above; see this file's header.

    // ---- 9. And this library reports the refusal, verifying nothing -----
    let mut seen_on_the_wire = false;
    session.sync_until("the refusal reached the library", |_, synced| {
        for event in &synced.to_device {
            if event["type"] == json!("m.key.verification.cancel")
                && event["content"]["transaction_id"] == json!(transaction)
            {
                assert_eq!(
                    event["content"]["code"],
                    json!(MISMATCHED_COMMITMENT),
                    "the counterparty's cancellation must carry the code it reported \
                     internally: {event}"
                );
                seen_on_the_wire = true;
            }
        }
        seen_on_the_wire && run(flow_stage(&flow)).ok() == Some(FlowStage::Cancelled)
    });
    assert!(
        seen_on_the_wire,
        "the loop above returns only once the cancellation was seen"
    );
    assert_eq!(
        run(flow_stage(&flow)).expect("a cancelled flow is still readable"),
        FlowStage::Cancelled
    );
    assert_eq!(
        run(read_material(&flow)).expect_err("a cancelled flow has nothing left to show"),
        MachineError::WrongStage
    );
    assert_eq!(
        library_trust(&library.user_id, &nio_device_id),
        TrustState::Unverified,
        "a comparison that ended in a cancellation must verify nothing"
    );
    assert_eq!(
        nio_report["verified"],
        json!(false),
        "nor on the counterparty's side, asserted there too because a one-sided \
         assertion passes when only one side transitioned: {nio_report}"
    );
    assert_eq!(
        nio_report["other_device_verified"],
        json!(false),
        "and the counterparty's own device store must still say so: {nio_report}"
    );

    // ---- Tidy up ---------------------------------------------------------
    nio.call(json!({ "op": "quit" }));
    teardown.counterparty_logged_itself_out();
}
