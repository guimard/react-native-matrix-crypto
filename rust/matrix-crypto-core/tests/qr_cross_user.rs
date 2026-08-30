//! Verifying **another user** by showing them a code. Mode `0x00`.
//!
//! # What this file is
//!
//! Two real machines belonging to two different accounts, no homeserver, and
//! the flow driven through this crate's shipped surface on one side:
//!
//! 1. Alice, the library, mints her account's signing identity and publishes
//!    it.
//! 2. Bob, a bare upstream machine standing in for a third-party client,
//!    mints his and signs his own device.
//! 3. Each learns what the other published, which is all a homeserver ever
//!    does here.
//! 4. Alice asks Bob to verify, Bob agrees, and Alice asks for a code.
//! 5. **The code declares mode `0x00`**, read off the bytes rather than
//!    asked of the library, because both master signing keys travel in it.
//! 6. Bob scans it and says so. Alice confirms that he did. The flow
//!    finishes and Alice has signed Bob's identity.
//! 7. **Then the same thing with the screens the other way round**: Bob
//!    shows and the library scans. A person points whichever phone they are
//!    holding at the other, so a library that could only show would fail
//!    whenever they pointed the wrong one -- and a scan is the half that
//!    depends on this library announcing that it can scan at all, which no
//!    default of upstream's ever does.
//!
//! # Which side is the library
//!
//! **Alice is the library**, driven only through this crate's public
//! surface against the one process-wide machine. Bob is a bare
//! `OlmMachine`. This file relays between the two exactly what a homeserver
//! would relay and nothing else.
//!
//! # Why the mode is read off the payload
//!
//! Asking upstream which mode upstream had just produced would be a test
//! agreeing with itself. [`harness::mode_of`] reads the byte a foreign
//! scanner reads, after checking the header and version in front of it. Mode
//! `0x00` is the one that carries two master keys, and it is the only one
//! reachable between two different accounts; producing `0x01` or `0x02` here
//! would mean the library had built a code claiming these two devices belong
//! to one person.

use matrix_crypto_core::{
    bootstrap_identity, confirm_scan, create_machine, device_statuses, flow_stage, identity_status,
    in_runtime, mark_request_sent, read_code, receive_sync_changes, request_flow, share_scope_key,
    submit_scanned_code, take_outgoing_requests, CryptoSignal, FlowStage, MachineConfig,
    MachineError, TrustState,
};
use matrix_sdk_common::ruma::OwnedUserId;
use matrix_sdk_crypto::matrix_sdk_qrcode::QrVerificationData;
use matrix_sdk_crypto::QrVerificationState;

#[path = "scanned/harness.rs"]
mod harness;
use harness::{
    cross_signed_machine, deliver_verification_request, drain_signals, drain_to_quiet,
    every_method, mode_of, one_of, pump_bare_to_library, pump_to_bare, queried_users, subscribe,
    uploaded_signatures, with_our_signature, MODE_CROSS_USER,
};

/// The library.
const ALICE: &str = "@alice:example.org";
const ALICE_DEVICE: &str = "ALICEDEVICE";
/// The other user. A bare upstream machine that has set cross-signing up,
/// which is every Element user.
const BOB: &str = "@bob:example.org";
const BOB_DEVICE: &str = "BOBDEVICE";
/// Somewhere for the one call on the shipped surface that tracks a user to
/// point at. Nothing is ever encrypted to it.
const SCOPE: &str = "!cross-user:example.org";

/// A `/keys/query` answer naming an account that has published no signing
/// identity, which is what lifts `bootstrap_identity`'s ordering gate.
const NO_IDENTITY: &str = r#"{"device_keys":{"@alice:example.org":{}}}"#;

#[test]
fn another_user_verifies_by_scanning_a_code_this_library_showed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(in_runtime(async move {
        // Before anything syncs. See `qr_self_established_shows.rs` at the
        // same place.
        subscribe();
        let alice_user: OwnedUserId = ALICE.parse().expect("a literal user id parses");

        // ---- The other user ---------------------------------------------
        let bob = cross_signed_machine(BOB, BOB_DEVICE).await;

        // ---- The library -------------------------------------------------
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

        // Matched on the user it asks about, not on its kind: `keys_query`
        // is one wire tag for this account's own query and everybody
        // else's, so a kind-only match could lift the gate below with an
        // answer about somebody else.
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

        // ---- Alice mints and publishes her identity ----------------------
        //
        // Mode 0x00 puts *this account's own master key* into the code, so
        // this step is the precondition the whole file rests on and M4 is
        // what made it reachable at all.
        bootstrap_identity()
            .await
            .expect("an account with no identity may mint one");
        assert!(
            identity_status()
                .await
                .expect("reading the identity status must not fail")
                .private_keys_held,
            "a cross-user code carries this account's master key, so a device that \
             held none of its private signing keys could not build one and every \
             assertion below would be unreachable"
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

        // ---- Each learns what the other published ------------------------
        //
        // Bob's half. He needs Alice's device to answer her at all, and
        // Alice's *master key* to check the first key in the code she is
        // about to show him: upstream's scan checks the first key against
        // the other user's identity and the second against his own
        // (`verification/qrcode.rs:604-607`).
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

        // Alice's half. `share_scope_key` first, because upstream's
        // `mark_tracked_users_as_changed` skips every user it has never
        // seen and tracking is the only thing on this surface that
        // introduces one; `tests/two_parties.rs` documents that at length.
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

        // ---- The flow ----------------------------------------------------
        let flow = request_flow(BOB, BOB_DEVICE)
            .await
            .expect("a device the machine has been told about can be asked to verify");
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;

        let bob_request = bob
            .peer
            .get_verification_request(&alice_user, &flow.0)
            .expect("the other user must have received the invitation");
        let ready = bob_request
            .accept_with_methods(every_method())
            .expect("a fresh invitation can be accepted");
        deliver_verification_request(&ready, BOB, ALICE, ALICE_DEVICE).await;

        // ---- The code ----------------------------------------------------
        let code = read_code(&flow)
            .await
            .expect("two cross-signed accounts can show each other a code");
        assert_eq!(
            mode_of(&code.payload),
            MODE_CROSS_USER,
            "a code shown to another user carries both master keys and must say so. \
             A self-verification mode here would mean the library had built a code \
             claiming these two devices belong to one person"
        );
        assert_eq!(
            code.modules.len(),
            code.width as usize * code.width as usize,
            "the symbol must be a square of its own declared side: a product draws \
             it row by row and a mismatch is a code nothing can read"
        );
        assert!(
            code.width >= 21,
            "21 squares is the smallest symbol the format defines; anything below \
             it is not one: {}",
            code.width
        );
        // The payload is authentication material and must never be
        // printable. Asserted here as well as in the unit test, because
        // this is the only place a real one exists.
        let rendered = format!("{code:?}");
        assert!(
            !rendered.contains("payload: ["),
            "the shared secret in a code must not reach a debug line: {rendered}"
        );

        // ---- The stages a scanned flow passes through ---------------------
        //
        // One sequence, compared once, for the reason
        // `qr_self_established_shows.rs` gives at the same place.
        let mut stages = vec![flow_stage(&flow).await.expect("the flow exists")];

        // ---- Bob scans it -------------------------------------------------
        let scanned = QrVerificationData::from_bytes(&code.payload)
            .expect("what this library produced must decode as what the format defines");
        let bob_code = bob_request
            .scan_qr_code(scanned)
            .await
            .expect("a cross-signed peer can scan a cross-signed peer's code")
            .expect("a ready flow that announced scanning produces a code object");
        assert!(
            matches!(bob_code.state(), QrVerificationState::Reciprocated),
            "the side that scanned owes the other one a message: {:?}",
            bob_code.state()
        );
        let reciprocation = bob_code
            .reciprocate()
            .expect("a scanner must tell the other side it scanned");
        deliver_verification_request(&reciprocation, BOB, ALICE, ALICE_DEVICE).await;
        stages.push(flow_stage(&flow).await.expect("the flow exists"));

        // ---- Alice says it really was him ---------------------------------
        confirm_scan(&flow)
            .await
            .expect("a code somebody has scanned can be confirmed");
        stages.push(flow_stage(&flow).await.expect("the flow exists"));
        assert_eq!(
            stages,
            vec![
                FlowStage::Started,
                FlowStage::CodeScanned,
                FlowStage::Confirmed
            ],
            "the screen a person is looking at while verifying another user passes \
             through the same three situations it does while verifying a device of \
             their own, and the middle one is the only moment either asks a question"
        );
        let crossed = pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;
        assert!(
            crossed.contains(&"m.key.verification.done".to_string()),
            "confirming a scan must reach the other side through the pump: {crossed:?}"
        );
        drain_to_quiet();
        let crossed = pump_bare_to_library(&bob.peer, BOB, ALICE, ALICE_DEVICE).await;
        assert!(
            crossed.contains(&"m.key.verification.done".to_string()),
            "the other side's acknowledgement must reach the library: {crossed:?}"
        );

        // ---- What a product is told, and why it is not a trust change ------
        //
        // Verifying another user signs their master key. Nothing about a
        // *device* changes here at all -- upstream's own completed code
        // names no device in this mode -- and the identity it does name will
        // not read verified until our signature comes back on a later key
        // query, which is the step this file performs a few lines below and
        // calls the homeserver's other half. So a `TrustChanged` saying
        // `Verified` at this moment would be contradicted by the very call a
        // product is told to read when one arrives. The assertion under this
        // one measures that rather than asserting it from a distance.
        let signals = drain_signals("a code this library showed another user was scanned");
        assert_eq!(
            signals,
            vec![CryptoSignal::VerificationCompleted {
                flow_id: flow.0.clone(),
            }],
            "the flow finished, and that is the only thing that is true of all three \
             modes at this moment"
        );
        let statuses = device_statuses(BOB)
            .await
            .expect("reading device statuses must not fail");
        assert!(
            !statuses.iter().any(
                |status| status.device_id == BOB_DEVICE && status.trust == TrustState::Verified
            ),
            "the other user's device must NOT read verified yet: this is what makes a \
             trust change the wrong signal here, and if it ever becomes true on its \
             own then the reasoning above has to be revisited rather than quietly \
             outlived: {statuses:?}"
        );

        // ---- It finished --------------------------------------------------
        assert!(
            bob_code.is_done(),
            "the other side must have finished the flow: {:?}",
            bob_code.state()
        );
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Done,
            "a flow that finished by scanning must report that it finished. This is \
             also what the registry's eviction rule reads, so a flow stuck short of \
             it would stay in the registry for the life of the process"
        );

        // ---- And what it was for --------------------------------------------
        //
        // Verifying another user signs their master key with our
        // user-signing key. That signature is the whole product of a
        // cross-user verification: it is what tells this account's other
        // devices, and everyone else, that we vouched for them.
        let owed = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let signature = one_of(
            &owed,
            "signature_upload",
            "verifying another user must sign their identity",
        );
        assert!(
            signature.body.contains(BOB),
            "the signature must be over the other user's keys: {}",
            signature.body
        );
        let our_signature = uploaded_signatures(&signature.body, BOB);
        for request in &owed {
            mark_request_sent(&request.id, r#"{"failures":{}}"#)
                .await
                .expect("a signature upload response must be accepted");
        }

        // The homeserver's other half, and it is not bookkeeping. Upstream
        // decides another user's device is trusted by checking *our*
        // user-signing key's signature on *their* master key, read out of
        // our own store. Making the signature does not put it there; the
        // next key query does, which is what a real client does on the next
        // device-list change. Without this the assertion below is about a
        // store that has never seen the signature this flow produced.
        // `tests/verified_sender.rs` calls this step seven and needs it for
        // exactly the same reason.
        receive_sync_changes(
            &serde_json::json!({ "changed_devices": { "changed": [BOB] } }).to_string(),
        )
        .await
        .expect("the library must accept a device-list change");
        let requery = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let requery = requery
            .iter()
            .find(|request| {
                request.kind == "keys_query"
                    && queried_users(&request.body).iter().any(|u| u == BOB)
            })
            .expect("a sync naming the other user as changed must get a key query issued");
        mark_request_sent(
            &requery.id,
            &serde_json::json!({
                "device_keys": { BOB: { BOB_DEVICE: bob.signed_device_keys } },
                "master_keys": { BOB: with_our_signature(bob.master_key, &our_signature) },
                "self_signing_keys": { BOB: bob.self_signing_key },
            })
            .to_string(),
        )
        .await
        .expect("answering a key query must not fail");

        let statuses = device_statuses(BOB)
            .await
            .expect("reading device statuses must not fail");
        assert!(
            statuses.iter().any(
                |status| status.device_id == BOB_DEVICE && status.trust == TrustState::Verified
            ),
            "the device on the other end of a completed flow must read verified: \
             {statuses:?}"
        );

        // ---- The registry does not keep it ---------------------------------
        //
        // The one property a third handle in the flow record could have
        // broken, measured rather than argued. The registry releases a
        // finished flow on the next registration, and it decides what is
        // finished from the stage above -- which no code handle is consulted
        // for. A scanned flow that never reported finishing would sit in the
        // map for the life of the process, one entry per verification.
        let next = request_flow(BOB, BOB_DEVICE)
            .await
            .expect("a known device can be asked to verify again");
        assert_eq!(
            flow_stage(&flow)
                .await
                .expect_err("the finished flow must have been released"),
            MachineError::UnknownFlow,
            "registering another flow must sweep the one that finished by scanning, \
             exactly as it sweeps one that finished by comparing a string"
        );

        // ---- And now the other way round --------------------------------------
        //
        // The same two accounts, the same mode, and the screens swapped: Bob
        // shows and the library reads. This is the half a product gets
        // whenever its user points *their* phone at somebody else's, and it
        // is the half that depends on this library saying it can scan --
        // upstream's default announced list never carries that method, in
        // any version, so a build that took the default would find that Bob
        // could not produce a code for it at all.
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;
        let bob_request = bob
            .peer
            .get_verification_request(&alice_user, &next.0)
            .expect("the other user must have received the second invitation");
        let ready = bob_request
            .accept_with_methods(every_method())
            .expect("a fresh invitation can be accepted");
        deliver_verification_request(&ready, BOB, ALICE, ALICE_DEVICE).await;

        let bob_code = bob_request
            .generate_qr_code()
            .await
            .expect("the other user's store must be readable")
            .expect(
                "a peer whose counterparty announced it can scan must be able to show \
                 a code; `Ok(None)` here means this library did not say so",
            );
        let shown = bob_code
            .to_bytes()
            .expect("a code upstream just built encodes");
        assert_eq!(
            mode_of(&shown),
            MODE_CROSS_USER,
            "a code shown by another user carries both master keys"
        );

        // The stages the *scanning* side passes through, which are not the
        // ones the showing side passes through and are the half a product
        // gets whenever its user points their own phone at somebody else's.
        // Nothing is ever asked of this person after the scan: there is no
        // `CodeScanned` here, because nobody scanned *this* screen.
        let mut scanning = vec![flow_stage(&next).await.expect("the flow exists")];
        submit_scanned_code(&next, &shown)
            .await
            .expect("a payload read off another user's screen must be accepted");
        scanning.push(flow_stage(&next).await.expect("the flow exists"));
        assert_eq!(
            scanning,
            vec![FlowStage::Ready, FlowStage::Confirmed],
            "a side that has scanned has done everything asked of it and is waiting \
             on the other, which is what `Confirmed` says. Reporting `Started` there \
             would tell a product the flow had not moved at all"
        );
        let crossed = pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;
        assert!(
            crossed.contains(&"m.key.verification.start".to_string()),
            "scanning must tell the other side it was scanned, and that message is \
             the one thing a caller cannot send for itself: {crossed:?}"
        );

        let confirmation = bob_code
            .confirm_scanning()
            .expect("the side that was scanned confirms it");
        drain_to_quiet();
        deliver_verification_request(&confirmation, BOB, ALICE, ALICE_DEVICE).await;
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;

        // The fourth position, and the one a product reaches whenever its
        // user points their own phone at somebody else's screen: this side
        // scanned rather than showed, and it is told the flow finished on
        // the same terms.
        let signals = drain_signals("a code this library scanned was confirmed by its owner");
        assert_eq!(
            signals,
            vec![CryptoSignal::VerificationCompleted {
                flow_id: next.0.clone(),
            }],
            "which screen was held up decides nothing about who needs telling: both \
             sides of a scanned flow have a person waiting on an answer"
        );

        assert!(
            bob_code.is_done(),
            "the flow driven from the other screen must finish too: {:?}",
            bob_code.state()
        );
        assert_eq!(
            flow_stage(&next).await.expect("the flow exists"),
            FlowStage::Done,
            "a flow this library finished by scanning must report that it finished"
        );
    }));
}
