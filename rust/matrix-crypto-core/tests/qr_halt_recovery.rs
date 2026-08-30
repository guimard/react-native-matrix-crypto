//! Abandoning a code flow that halted, and verifying that person afterwards.
//!
//! # The situation this file is about
//!
//! A peer scans the code this device is showing and then says it is finished
//! without waiting for the person here to confirm that the scan was theirs.
//! That is not hypothetical: `tests/level_two_scanned.rs` measures a real
//! third-party client doing it off the wire, and `tests/qr_cross_user.rs`
//! builds the same shape by hand. Upstream advances the two halves of such a
//! flow unalike from that one message. `VerificationRequest::receive_done`
//! moves a `Transitioned` request to `Done` unconditionally
//! (`verification/requests.rs:934-940`); `QrVerification::receive_done` moves
//! only a code that is `Confirmed` or `Reciprocated` and leaves a `Scanned`
//! one exactly where it is (`verification/qrcode.rs:392-440`).
//!
//! So the flow stops with the request finished, the code still `Scanned`, and
//! a person still looking at a question nobody will answer.
//!
//! # What that costs, measured rather than reasoned about
//!
//! Upstream allows one live verification per person.
//! `VerificationCache::insert` cancels **both** when a second is opened while
//! an older uncancelled one with the same user is in the cache
//! (`verification/cache.rs:86-104`), and its sweep keeps everything that is
//! neither done nor cancelled. A code left at `Scanned` is neither, so it
//! survives every sweep.
//!
//! **The cost is the next two verifications with that person, and both are
//! silent.** Phase 2 measures them. The first attempt is agreed to by the
//! peer and then reads `Cancelled` the moment it becomes a code, nobody having
//! refused it and no error having been returned to anybody. The second never
//! leaves the process: the first left a live *request* behind its dead code,
//! because `insert_qr` cancels the request through the handle it holds and
//! `VerificationRequest::generate_qr_code` then writes `Transitioned` over
//! that `Cancelled` (`verification/requests.rs:403-418`), so upstream's sweep
//! keeps it and the next `insert_request` cancels it and its successor
//! together.
//!
//! **Two, and not "every later verification for the life of the process",
//! which is what the escalation this file answers claimed.** Each of those
//! inserts cancels the old flow as well as the new one, so the attempts that
//! die are also what clears the way. The corrected sentence is not a
//! reassurance: two verifications die with no error attached to anything, and
//! a person reading their screen has no way to tell that from a peer who
//! walked away.
//!
//! # What is proven here, and in what order
//!
//! One machine per process, so all five phases are one test with two
//! accounts.
//!
//! 1. **A flow halts.** The library shows a code, the peer scans it, the peer
//!    says it is done before this side has confirmed. The stage stops at
//!    `CodeScanned`.
//! 2. **The silent casualties, which are the control for phase 5.** The next
//!    flow with that person reads `Cancelled` the moment it becomes a code,
//!    and the one after that is cancelled before it reaches the wire.
//! 3. **A second halt**, built the same way, because phase 2 spent the first.
//! 4. **It is abandoned.** `cancel_flow` reaches the code, reports success and
//!    leaves the flow `Cancelled`. Before this milestone it reached the
//!    comparison and the request and not the code, and the request behind a
//!    halted flow is already `Done`, so the call refused.
//! 5. **And the same person is verified afterwards.** A fresh flow, driven end
//!    to end through the published surface, reaches `Done` and announces a
//!    completion.
//!
//! Phases 2 and 5 are the same situation and the same calls, differing in
//! whether the halted flow behind them was abandoned, and they end opposite
//! ways. That pairing is the point of the file: an assertion that a fresh flow
//! completes proves nothing on its own, because it would also pass on a
//! machine where the halt had never mattered.
//!
//! # Why it is its own file
//!
//! Because a halted flow poisons the account it was left on, so a proof that
//! the poison can be cleared cannot share a process with a proof that leaves
//! poison behind. `qr_cross_user.rs` ends by stranding a flow deliberately, to
//! measure the registry sweep; every phase here would then be running against
//! an account that already carried one.
//!
//! # The one liberty this harness takes, named
//!
//! **The peer's own cancellations are not relayed.** Upstream's
//! one-verification-per-person rule is symmetric: a bare `OlmMachine` left
//! holding a live flow refuses to agree to the next one just as this library
//! does. Left alone, the peer would therefore fail phase 2 before this library
//! could, and the measurement would be about the wrong machine. So the peer
//! retires each spent flow on its own side and the message it produces is
//! dropped rather than delivered, which leaves every cancellation this file
//! measures attributable to this library alone.
//!
//! That is not a convenience. It is what the counterparty measured in
//! `tests/level_two_scanned.rs` actually does: mautrix-go sends
//! `m.key.verification.done` the instant it accepts a scan, considers its own
//! side complete, and sends nothing further. A peer that has moved on and will
//! never speak about that flow again is the real shape, and it is the shape
//! this library has to survive.
//!
//! # Which side is the library
//!
//! **Alice is the library**, driven only through this crate's public surface
//! against the one process-wide machine. Bob is a bare `OlmMachine` standing
//! in for a third-party client. This file relays between the two exactly what
//! a homeserver would relay, and the one thing it deliberately does not relay
//! is named above.

use matrix_crypto_core::{
    bootstrap_identity, cancel_flow, confirm_scan, create_machine, flow_stage, identity_status,
    in_runtime, mark_request_sent, offer_scanning, read_code, request_flow, share_scope_key,
    take_outgoing_requests, CryptoSignal, FlowId, FlowStage, MachineConfig, MachineError,
};
use matrix_sdk_common::ruma::OwnedUserId;
use matrix_sdk_crypto::matrix_sdk_qrcode::QrVerificationData;
use matrix_sdk_crypto::{OlmMachine, VerificationRequest};

#[path = "scanned/harness.rs"]
mod harness;
use harness::{
    cross_signed_machine, deliver_to_bare, deliver_to_library, deliver_verification_request,
    drain_signals, drain_to_quiet, every_method, mode_of, one_of, pump_bare_to_library,
    pump_to_bare, queried_users, subscribe, MODE_CROSS_USER,
};

/// The library.
const ALICE: &str = "@alice:example.org";
const ALICE_DEVICE: &str = "ALICEDEVICE";
/// The other user. A bare upstream machine that has set cross-signing up.
const BOB: &str = "@bob:example.org";
const BOB_DEVICE: &str = "BOBDEVICE";
/// Somewhere for the one call on the shipped surface that tracks a user to
/// point at. Nothing is ever encrypted to it.
const SCOPE: &str = "!halt-recovery:example.org";

/// A `/keys/query` answer naming an account that has published no signing
/// identity, which is what lifts `bootstrap_identity`'s ordering gate.
const NO_IDENTITY: &str = r#"{"device_keys":{"@alice:example.org":{}}}"#;

/// The message a peer sends when it considers a flow over.
///
/// Hand-built rather than pumped out of the bare machine, for the reason
/// `qr_cross_user.rs` gives at its own copy: the point is a peer doing
/// something upstream's own client would not, which is saying it is finished
/// while this side is still waiting for a person to answer. Nothing about the
/// shape is invented. It is the to-device event the specification defines and
/// the one `VerificationMachine::receive_any_event` dispatches on
/// (`verification/machine.rs:501-527`).
fn a_done_from(sender: &str, flow_id: &str) -> serde_json::Value {
    serde_json::json!({
        "sender": sender,
        "type": "m.key.verification.done",
        "content": { "transaction_id": flow_id },
    })
}

#[test]
fn a_halted_code_flow_can_be_abandoned_and_the_same_person_verified_afterwards() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(in_runtime(async move {
        subscribe();
        let alice_user: OwnedUserId = ALICE.parse().expect("a literal user id parses");

        // A product asks to take part in verification by a scannable code.
        // Off until it does, so without this line every flow below negotiates
        // the short string alone and nothing here can happen.
        offer_scanning(true);

        // ---- The other user ----------------------------------------------
        let bob = cross_signed_machine(BOB, BOB_DEVICE).await;

        // ---- The library --------------------------------------------------
        create_machine(MachineConfig {
            user_id: ALICE.to_string(),
            device_id: ALICE_DEVICE.to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        let batch = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let upload = one_of(
            &batch,
            "keys_upload",
            "a fresh machine must have keys to publish",
        );
        let upload_body: serde_json::Value =
            serde_json::from_str(&upload.body).expect("the pump's own body is well-formed JSON");
        let alice_device_keys = upload_body
            .get("device_keys")
            .cloned()
            .expect("a fresh machine's upload carries its device keys");
        mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
            .await
            .expect("a keys-upload response must be accepted");

        // Matched on the user it asks about, not on its kind, for
        // `qr_cross_user.rs`'s reason: one wire tag covers this account's own
        // query and everybody else's.
        let account_query = batch
            .iter()
            .find(|request| {
                request.kind == "keys_query"
                    && queried_users(&request.body).iter().any(|u| u == ALICE)
            })
            .expect("a fresh machine must owe a key query for its own account");
        mark_request_sent(&account_query.id, NO_IDENTITY)
            .await
            .expect("answering the account key query must not fail");

        // ---- Alice mints and publishes her identity ------------------------
        //
        // Mode 0x00 puts this account's own master key into the code, so a
        // device holding none of its private signing keys could not build one
        // and every phase below would be unreachable.
        bootstrap_identity()
            .await
            .expect("an account with no identity may mint one");
        assert!(
            identity_status()
                .await
                .expect("reading the identity status must not fail")
                .private_keys_held,
            "a cross-user code carries this account's master key"
        );

        let published = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let signing_keys = one_of(
            &published,
            "signing_keys_upload",
            "a bootstrap must publish the identity it minted",
        );
        let alice_identity: serde_json::Value = serde_json::from_str(&signing_keys.body)
            .expect("the pump's own body is well-formed JSON");
        let alice_master = alice_identity
            .get("master_key")
            .cloned()
            .expect("a published identity carries a master key");
        let alice_self_signing = alice_identity
            .get("self_signing_key")
            .cloned()
            .expect("a published identity carries a self-signing key");
        for request in &published {
            mark_request_sent(&request.id, "{}")
                .await
                .expect("a bootstrap publication response must be accepted");
        }

        // ---- Each learns what the other published --------------------------
        bob.peer
            .mark_request_as_sent(
                &matrix_sdk_common::ruma::TransactionId::new(),
                &harness::keys_query_response(
                    &serde_json::json!({
                        "device_keys": { ALICE: { ALICE_DEVICE: alice_device_keys } },
                        "master_keys": { ALICE: alice_master },
                        "self_signing_keys": { ALICE: alice_self_signing },
                    })
                    .to_string(),
                ),
            )
            .await
            .expect("the bare machine must accept a keys-query response");

        share_scope_key(SCOPE, &[BOB.to_string()])
            .await
            .expect("tracking a user must not fail");
        let batch = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let bob_query = batch
            .iter()
            .find(|request| {
                request.kind == "keys_query"
                    && queried_users(&request.body).iter().any(|u| u == BOB)
            })
            .expect("a machine that has just started tracking a user must ask about them");
        mark_request_sent(
            &bob_query.id,
            &serde_json::json!({
                "device_keys": { BOB: { BOB_DEVICE: bob.signed_device_keys } },
                "master_keys": { BOB: bob.master_key },
                "self_signing_keys": { BOB: bob.self_signing_key },
            })
            .to_string(),
        )
        .await
        .expect("answering a key query must not fail");

        // ===================================================================
        // PHASE 1: A FLOW HALTS
        // ===================================================================
        let (halted, _peer_side) = show_a_code_and_have_it_scanned(&bob.peer, &alice_user).await;
        assert_eq!(
            flow_stage(&halted).await.expect("the flow exists"),
            FlowStage::CodeScanned,
            "the peer has scanned and this side has not answered, which is the one \
             moment a code flow asks a person anything"
        );

        // The peer says it is finished before anybody here has confirmed.
        deliver_to_library(vec![a_done_from(BOB, &halted.0)]).await;
        assert_eq!(
            flow_stage(&halted).await.expect("the flow exists"),
            FlowStage::CodeScanned,
            "nothing the peer said moved this device's own code, so the stage a product \
             reads must not move either: this is the halt"
        );
        drain_to_quiet();
        retire_on_the_peers_side(&bob.peer, &alice_user);

        // ===================================================================
        // PHASE 2: THE SILENT CASUALTIES, WHICH ARE THE CONTROL FOR PHASE 5
        // ===================================================================
        // What a person meets today if they simply try again. Two empty syncs
        // first, and they are not padding: see `a_new_request_needs_one_sync`
        // at the foot of this file, which is the same rule stated once and
        // relied on four times.
        deliver_to_bare(&bob.peer, Vec::new()).await;
        deliver_to_library(Vec::new()).await;

        let doomed = request_flow(BOB, BOB_DEVICE)
            .await
            .expect("a known device can be asked to verify again");
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;
        let doomed_side = bob
            .peer
            .get_verification_request(&alice_user, &doomed.0)
            .expect("the other user must have received the invitation");
        let ready = doomed_side
            .accept_with_methods(every_method())
            .expect("a fresh invitation can be accepted");
        deliver_verification_request(&ready, BOB, ALICE, ALICE_DEVICE).await;
        assert_eq!(
            flow_stage(&doomed).await.expect("the flow exists"),
            FlowStage::Ready,
            "the invitation itself is agreed to, which is what makes the next assertion \
             the surprising one and what makes it worth measuring"
        );

        let offered = read_code(&doomed)
            .await
            .expect("two cross-signed accounts can show each other a code");
        assert_eq!(mode_of(&offered.payload), MODE_CROSS_USER);
        assert_eq!(
            flow_stage(&doomed).await.expect("the flow exists"),
            FlowStage::Cancelled,
            "THE FIRST COST OF THE HALT, MEASURED. A code was built for a flow the peer \
             had just agreed to, and it was dead before anybody could point a camera at \
             it. Upstream cancelled it against the halted flow still sitting in its \
             cache, and returned nothing to anybody to say so. Phase 5 is this same \
             situation with the halted flow abandoned first, and it ends the other way"
        );
        drain_to_quiet();
        retire_on_the_peers_side(&bob.peer, &alice_user);

        // AND THE ATTEMPT AFTER THAT ONE DIES TOO, WHICH IS WHY THE FIX IS
        // WORTH HAVING RATHER THAN A THING A PRODUCT COULD RETRY AROUND.
        //
        // The flow above left a **live request** behind its dead code, and
        // that is upstream clobbering its own cancellation rather than
        // anything this library did: `insert_qr` cancels the request through
        // the handle it was given, and `VerificationRequest::generate_qr_code`
        // then writes `InnerRequest::Transitioned` over the `Cancelled` it
        // just produced (`verification/requests.rs:403-418`). So the sweep
        // that removes finished requests keeps this one, and the next
        // `insert_request` cancels it and its successor together
        // (`verification/machine.rs:165-197`).
        //
        // No peer is involved in this measurement at all. Nothing was pumped,
        // nothing was relayed, and the flow is dead on arrival, which makes it
        // this library's own machine and nobody else's.
        deliver_to_bare(&bob.peer, Vec::new()).await;
        deliver_to_library(Vec::new()).await;
        let doomed_again = request_flow(BOB, BOB_DEVICE)
            .await
            .expect("asking is still allowed; it is the asking that comes back dead");
        assert_eq!(
            flow_stage(&doomed_again).await.expect("the flow exists"),
            FlowStage::Cancelled,
            "THE SECOND COST. This one never even reached the peer: it was cancelled \
             inside this process, against the wreckage the attempt above left, before a \
             single byte went out. Two attempts, then, are what one halted flow costs a \
             person who only retries"
        );
        drain_to_quiet();

        // ===================================================================
        // PHASE 3: A SECOND HALT, BECAUSE PHASE 2 SPENT THE FIRST
        // ===================================================================
        // Upstream's own "cancel both" cleared phase 1's flow as a side effect
        // of killing phase 2's, which is the correction this file carries: a
        // halted flow does not block every later verification for the life of
        // the process, it takes the next two down with it. So phase 4 needs a
        // halt of its own.
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;
        retire_on_the_peers_side(&bob.peer, &alice_user);
        deliver_to_bare(&bob.peer, Vec::new()).await;
        deliver_to_library(Vec::new()).await;
        let (stranded, _peer_side) = show_a_code_and_have_it_scanned(&bob.peer, &alice_user).await;
        deliver_to_library(vec![a_done_from(BOB, &stranded.0)]).await;
        assert_eq!(
            flow_stage(&stranded).await.expect("the flow exists"),
            FlowStage::CodeScanned,
            "the same halt as phase 1, on a machine that has since watched a flow die"
        );
        drain_to_quiet();

        // ===================================================================
        // PHASE 4: IT IS ABANDONED
        // ===================================================================
        // Before the code arm existed, `cancel_flow` read the comparison and
        // the request, and the request behind a halted flow is already `Done`,
        // so this call answered `Err(WrongStage)` and a product had nothing to
        // offer the person in front of it.
        cancel_flow(&stranded)
            .await
            .expect("a halted code flow must be abandonable through this surface");
        assert_eq!(
            flow_stage(&stranded).await.expect("the flow exists"),
            FlowStage::Cancelled,
            "and the abandonment must be visible on the flow the caller named, not only \
             in the return value: a product shows a person something on the strength of \
             this"
        );
        assert_eq!(
            cancel_flow(&stranded).await,
            Err(MachineError::WrongStage),
            "and a second abandonment is still refused, so the new arm did not turn this \
             into a call that reports success for work it did not do"
        );

        // A product sends what it queued.
        let crossed = pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;
        assert!(
            crossed.contains(&"m.key.verification.cancel".to_string()),
            "abandoning must reach the other side through the pump, or the peer would be \
             left showing a screen of its own: {crossed:?}"
        );

        // ===================================================================
        // PHASE 5: AND THE SAME PERSON IS VERIFIED AFTERWARDS
        // ===================================================================
        // Phase 2 with one difference: the halted flow behind this one was
        // abandoned rather than left. Same two accounts, same mode, same calls.
        deliver_to_bare(&bob.peer, Vec::new()).await;
        deliver_to_library(Vec::new()).await;
        drain_to_quiet();

        let (recovered, recovered_side) =
            show_a_code_and_have_it_scanned(&bob.peer, &alice_user).await;
        assert_eq!(
            flow_stage(&recovered).await.expect("the flow exists"),
            FlowStage::CodeScanned,
            "THE RECOVERY. A code shown after a halted flow was abandoned reaches the \
             stage phase 2's could not: it is alive, the peer read it, and a person is \
             being asked the one question this mode asks"
        );

        confirm_scan(&recovered)
            .await
            .expect("a code somebody has scanned can be confirmed");
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;
        drain_to_quiet();
        pump_bare_to_library(&bob.peer, BOB, ALICE, ALICE_DEVICE).await;

        assert!(
            recovered_side.is_done(),
            "the other side must have finished the flow, which is a different fact from \
             this side's own stage and the one a peer's user would be shown: {:?}",
            recovered_side.state()
        );
        assert_eq!(
            flow_stage(&recovered).await.expect("the flow exists"),
            FlowStage::Done,
            "and this side must say so too. This is the sentence the whole file exists \
             for: after abandoning a halted flow, a fresh verification with the same \
             person completes"
        );
        let signals = drain_signals("the recovered flow finished");
        assert_eq!(
            signals,
            vec![CryptoSignal::VerificationCompleted {
                flow_id: recovered.0.clone(),
            }],
            "and a product watching the signal channel is told, which is how it learns \
             the recovery worked without polling"
        );
    }));
}

// ---------------------------------------------------------------------------
// The steps several phases share
// ---------------------------------------------------------------------------

/// One cross-user flow driven from this library's invitation to the moment
/// the peer has scanned the code and said so.
///
/// Three phases need exactly this and differ only in what they do next, which
/// is the shape of the whole file: a control and a change rather than two
/// differently written sequences.
///
/// Returns the identifier a product would hold and the peer's own handle for
/// the flow, which is what lets a phase ask the other machine directly rather
/// than asking this library about a record it may have swept.
async fn show_a_code_and_have_it_scanned(
    peer: &OlmMachine,
    alice_user: &OwnedUserId,
) -> (FlowId, VerificationRequest) {
    let flow = request_flow(BOB, BOB_DEVICE)
        .await
        .expect("a known device can be asked to verify");
    pump_to_bare(peer, ALICE, BOB, BOB_DEVICE).await;

    let request = peer
        .get_verification_request(alice_user, &flow.0)
        .expect("the other user must have received the invitation");
    let ready = request
        .accept_with_methods(every_method())
        .unwrap_or_else(|| {
            panic!(
                "a fresh invitation can be accepted, and the peer's own state was {:?}",
                request.state()
            )
        });
    deliver_verification_request(&ready, BOB, ALICE, ALICE_DEVICE).await;

    let code = read_code(&flow)
        .await
        .expect("two cross-signed accounts can show each other a code");
    assert_eq!(
        mode_of(&code.payload),
        MODE_CROSS_USER,
        "a code shown to another user carries both master keys and must say so"
    );

    let scanned = QrVerificationData::from_bytes(&code.payload)
        .expect("what this library produced must decode as what the format defines");
    let peer_code = request
        .scan_qr_code(scanned)
        .await
        .expect("a cross-signed peer can scan a cross-signed peer's code")
        .expect("a ready flow that announced scanning produces a code object");
    let reciprocation = peer_code
        .reciprocate()
        .expect("a scanner must tell the other side it scanned");
    deliver_verification_request(&reciprocation, BOB, ALICE, ALICE_DEVICE).await;

    (flow, request)
}

/// Ends every flow the peer still holds with this library, and drops the
/// messages that say so.
///
/// The one liberty this harness takes, and this is the function that takes it.
/// See the file header for why it is here and why it is faithful: the
/// counterparty that produced this finding sends `m.key.verification.done` the
/// instant it accepts a scan, treats its own side as complete, and never
/// speaks about the flow again. Without this the peer's own copy of upstream's
/// one-verification-per-person rule would refuse the next invitation before
/// this library could refuse anything, and every cancellation this file
/// measures would be attributable to the wrong machine.
///
/// `VerificationRequest::cancel` reaches the peer's code as well as its
/// request: its own last act is to look the flow up in the verification cache
/// and cancel whatever is there (`verification/requests.rs:596-603`).
fn retire_on_the_peers_side(peer: &OlmMachine, library_user: &OwnedUserId) {
    for request in peer.get_verification_requests(library_user) {
        let _discarded = request.cancel();
    }
}

/// Why every phase above opens with two empty syncs, stated once.
///
/// Upstream cancels a new request outright while another request with the same
/// person is still in its map and not cancelled, and a **finished** request is
/// not a cancelled one (`VerificationMachine::insert_request`,
/// `verification/machine.rs:165-197`). The only thing that removes a finished
/// request from that map is `VerificationMachine::garbage_collect`
/// (`verification/machine.rs:240-254`, `retain(|_, v| !(v.is_done() ||
/// v.is_cancelled()))`), and its only caller is `preprocess_sync_changes`
/// (`machine/mod.rs:1767-1778`), at the top of every `receive_sync_changes`.
///
/// So one sync between two verifications with the same person is upstream's
/// requirement rather than an artefact of any harness, and it is provable with
/// no homeserver in the room: every sync this file uses for it carries no
/// events at all, and both machines here are ordinary `OlmMachine`s.
/// `packages/react-native-matrix-crypto/src/facade.ts` states it where a
/// product author reads it, on `requestVerification` and its two siblings.
///
/// Removing either sync turns the phase that follows into a `Cancelled` flow,
/// which is how the sentence was established rather than assumed.
#[allow(dead_code)]
fn a_new_request_needs_one_sync() {}
