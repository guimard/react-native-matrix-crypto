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
//! 8. **And then with the other person starting it.** Everything above is
//!    driven by this side asking first. At least half of real use is the
//!    other way, and it goes through a different call -- [`accept_flow`],
//!    which is the third and last of the three places this library says what
//!    it can do. Nothing drove it until this step, so reverting that one
//!    line to what it said before codes existed left the whole suite green.
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
    accept_flow, confirm_scan, create_identity, create_machine, device_statuses, flow_stage,
    identity_status, in_runtime, mark_request_sent, offer_scanning, read_code,
    receive_sync_changes, request_flow, share_scope_key, submit_scanned_code,
    take_outgoing_requests, CryptoSignal, FlowStage, MachineConfig, MachineError, TrustState,
};
use matrix_sdk_common::ruma::OwnedUserId;
use matrix_sdk_crypto::matrix_sdk_qrcode::QrVerificationData;
use matrix_sdk_crypto::QrVerificationState;

#[path = "scanned/harness.rs"]
mod harness;
use harness::{
    cross_signed_machine, deliver_to_bare, deliver_to_library, deliver_verification_request,
    drain_signals, drain_to_quiet, every_method, mode_of, one_of, pump_bare_to_library,
    pump_to_bare, queried_users, subscribe, uploaded_signatures, with_our_signature,
    MODE_CROSS_USER,
};

/// The message a peer sends when it considers a flow over.
///
/// Hand-built rather than pumped out of the bare machine, because the point
/// of the phase that uses it is a peer doing something upstream's own client
/// would not: saying it is finished while this side is still waiting for a
/// person to answer. Nothing about the shape is invented -- it is the
/// to-device event the specification defines, and it is what
/// `VerificationMachine::receive_any_event` dispatches on
/// (`verification/machine.rs:501-527`).
fn a_done_from(sender: &str, flow_id: &str) -> serde_json::Value {
    serde_json::json!({
        "sender": sender,
        "type": "m.key.verification.done",
        "content": { "transaction_id": flow_id },
    })
}

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
/// identity, which is what lifts `create_identity`'s ordering gate.
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

        // The product asks to take part in verification by a scannable code.
        // Off until it does, and off is byte for byte the wire this library
        // put out before codes existed, so without this line every flow
        // below negotiates the short string alone and nothing here can
        // happen. `tests/qr_announcement.rs` is where that default is the
        // subject rather than the setting.
        offer_scanning(true);

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
        create_identity()
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
        // ---- the polarity of the grid, which nothing else here reads ------
        //
        // `true` means dark. A mapping the other way round produces the
        // photographic negative of a valid code, which most scanners refuse
        // and some read as a different code -- and it changes no length, no
        // width and no payload byte, so every other assertion in this
        // repository passes against it. The only other thing that would
        // catch it is a person holding a phone at the end of the milestone,
        // which is the most expensive check there is and the last one.
        //
        // The top row of a symbol carries a finder pattern at each end:
        // seven dark squares, then one light separator between the finder
        // and the data. Read off the drawn grid at both corners, so this
        // cannot pass on one that happened to be dark.
        assert_eq!(
            code.width,
            harness::SYMBOL_WIDTH,
            "upstream fixes the version of every one of these symbols, so a \
             different side means it stopped doing that and the finder patterns \
             below are being read at the wrong offsets"
        );
        let side = harness::SYMBOL_WIDTH as usize;
        let top = harness::row_of(&code, 0);
        assert!(
            top[..7].iter().all(|square| *square) && !top[7],
            "the top-left finder must be seven dark squares and then a light \
             separator. An inverted grid is the photographic negative of a valid \
             code and is what a product would hand to a camera: {:?}",
            &top[..8]
        );
        assert!(
            top[side - 7..].iter().all(|square| *square) && !top[side - 8],
            "and the top-right finder the same: {:?}",
            &top[side - 8..]
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
        // not read verified until our signature comes back on the key query
        // this completion queues, which is the step this file performs a few
        // lines below and calls the homeserver's other half. So a
        // `TrustChanged` saying `Verified` at this moment would be
        // contradicted by the very call a product is told to read when one
        // arrives. The assertion under this one measures that rather than
        // asserting it from a distance.
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

        // ---- And the question that makes the signature worth anything -------
        //
        // THE HOMESERVER'S OTHER HALF, QUEUED BY THE COMPLETION RATHER THAN
        // ASKED OF THE PRODUCT.
        //
        // Upstream decides another user's device is trusted by checking *our*
        // user-signing key's signature on *their* master key, read out of our
        // own store. Making the signature does not put it there; a
        // `/keys/query` does. Nothing used to queue one: upstream volunteers
        // it only for a user it has newly started tracking
        // (`store/mod.rs:255-273`), and the other route,
        // `device_lists.changed`, is a homeserver's to send and it sends it
        // only for people an encrypted room is shared with. So this library
        // answered `Unverified` about the person it had just verified, for
        // the life of the process, and no call on the published surface could
        // fix it. `verification::queue_peer_key_queries` is what queues it
        // now, and this is the assertion that says so.
        //
        // Read out of the **same drain** as the signature upload, with no
        // sync, no device-list change and no second call in between: the only
        // thing that can have produced it is the completion itself.
        let requery = owed
            .iter()
            .find(|request| {
                request.kind == "keys_query"
                    && queried_users(&request.body).iter().any(|u| u == BOB)
            })
            .expect(
                "a completed cross-user code verification must queue a key query about \
                 the person it verified, or this library reports them unverified for \
                 the life of the process and nothing a product can call fixes it",
            );
        assert_ne!(
            requery.id, signature.id,
            "and it must be a request of its own rather than the signature upload read \
             twice"
        );

        // AND IT MUST COME OUT BEHIND THE SIGNATURE UPLOAD, NOT IN FRONT OF IT.
        //
        // The pump hands out one order and a product sends in it. This query
        // asks the server to hand back what the upload beside it is about to
        // tell the server, so a query that went first would be answered with a
        // master key that does not carry the signature yet, and the person
        // would read unverified after a verification that succeeded. That is
        // not hypothetical: it is what a queue-time sequence stamp produced,
        // and `tests/level_two_scanned.rs` is where it was seen, because a
        // level 1 test answers the query by hand and cannot notice. This is the
        // assertion that keeps it from coming back.
        let position = |id: &str| {
            owed.iter()
                .position(|request| request.id == id)
                .expect("both requests came out of this batch")
        };
        assert!(
            position(&signature.id) < position(&requery.id),
            "the signature upload must be handed out before the key query that reads it \
             back: {owed:?}"
        );

        // Answered in the order a product would send them, which is the order
        // the pump handed them out.
        mark_request_sent(&signature.id, r#"{"failures":{}}"#)
            .await
            .expect("a signature upload response must be accepted");
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
            "the device on the other end of a completed flow must read verified, and \
             the only thing this side did to get there was the ordinary pump loop: \
             {statuses:?}"
        );

        // Everything else the completion left in the pump, answered so the
        // phases below start from an empty one.
        for request in &owed {
            if request.id == signature.id || request.id == requery.id {
                continue;
            }
            mark_request_sent(&request.id, r#"{"failures":{}}"#)
                .await
                .expect("the remaining requests of a completed flow must be resolvable");
        }

        // ---- The registry does not keep it ---------------------------------
        //
        // The one property a third handle in the flow record could have
        // broken, measured rather than argued. The registry releases a flow
        // that is over on the next registration, and for a flow that became
        // a code it reads that off **the code handle**, which is consulted
        // before the request. A scanned flow that never reported finishing
        // would sit in the map for the life of the process, one entry per
        // verification.
        //
        // This is the ordinary shape, where the code really did finish. The
        // last phase of this file drives the other one, where it never does.
        //
        // One empty sync first, and it is not padding. Upstream cancels a new
        // request outright while another request with the same person is
        // still in its map and not cancelled, and a *finished* request is not
        // a cancelled one (`VerificationMachine::insert_request`,
        // `verification/machine.rs:165-197`); the only thing that empties
        // that map is `garbage_collect`, at the top of every
        // `receive_sync_changes`. This sync used to be a device-list change,
        // which was doing that job as a side effect while it fetched the
        // signature back. The completion now queues that key query itself, so
        // what is left here is the sync alone, which is what a product owes
        // between two verifications with one person and what
        // `requestVerification` says in `facade.ts`. Removing it turns the
        // call below into a `Cancelled` flow, which is how it was found.
        receive_sync_changes("{}")
            .await
            .expect("the library must accept an empty sync");
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

        // ---- And now with the other person starting it -------------------------
        //
        // The third call site. `request_flow` and `request_self_flow` say
        // what this library can do when it asks; `accept_flow` says it when
        // it answers, and a flow the other person opened is the only way to
        // reach it. Until this ran, reverting that one line to the
        // short-string-only list every release before this one used left all
        // four code binaries, `sas_two_party` and every library test green.
        //
        // It is also the direction a product's user is in whenever somebody
        // else starts the verification, which is at least half of real use,
        // and upstream carries `we_started` into the code it builds -- so
        // this is a different object from the ones above, not the same one
        // reached differently.
        // One empty sync on the other side first, and it is not decoration.
        // Upstream cancels a *new* request outright whenever another request
        // with the same user is still in its map and not already cancelled
        // (`verification/machine.rs:165-192`) -- and the two flows above are
        // finished, not cancelled. A request born cancelled is not in
        // `InnerRequest::Created`, so `request_to_device` silently falls back
        // to upstream's own default method list
        // (`verification/requests.rs:230-237`) and the invitation goes out
        // announcing three methods rather than the four it was built with.
        // That is what this test hit first: the flow below reached `Ready`
        // and then refused to produce a code, naming a negotiation nobody
        // had asked for.
        //
        // Upstream empties that map at the top of every `receive_sync_changes`,
        // which is what a real client does constantly and what this line is.
        deliver_to_bare(&bob.peer, Vec::new()).await;

        let bob_device_handle = bob
            .peer
            .get_device(&alice_user, ALICE_DEVICE.into(), None)
            .await
            .expect("the other user's store must be readable")
            .expect("the other user knows this library's device");
        let (inbound, invitation) =
            bob_device_handle.request_verification_with_methods(every_method());
        deliver_verification_request(&invitation, BOB, ALICE, ALICE_DEVICE).await;

        // The identifier a product would be handed on the crypto signal
        // channel, taken here from the request the other side built, which
        // is the same string a homeserver relays. Nothing local registered
        // it, so this also drives the half of `handles` that finds a flow
        // the other side started.
        let inbound_flow = matrix_crypto_core::FlowId(inbound.flow_id().as_str().to_string());
        assert_eq!(
            flow_stage(&inbound_flow)
                .await
                .expect("a flow the other side opened must be answerable"),
            FlowStage::Requested,
            "the invitation must have arrived and built a flow, or the agreement \
             below would be agreeing to nothing"
        );

        accept_flow(&inbound_flow)
            .await
            .expect("an invitation from a known device can be agreed to");
        let crossed = pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;
        assert!(
            crossed.contains(&"m.key.verification.ready".to_string()),
            "agreeing must reach the other side through the pump: {crossed:?}"
        );

        // The proof that the agreement carried the scanning half: upstream
        // refuses to build a code unless *this* side's announced list
        // contains the showing method and the other side's contains the
        // scanning one. Both halves of that came from `accept_flow` here.
        let code = read_code(&inbound_flow)
            .await
            .expect("a flow the other person opened can still show a code");
        assert_eq!(
            mode_of(&code.payload),
            MODE_CROSS_USER,
            "the mode does not depend on who asked first"
        );
        let top = harness::row_of(&code, 0);
        assert!(
            top[..7].iter().all(|square| *square) && !top[7],
            "and neither does the polarity of what a product draws: {:?}",
            &top[..8]
        );

        let scanned = QrVerificationData::from_bytes(&code.payload)
            .expect("what this library produced must decode as what the format defines");
        let bob_code = inbound
            .scan_qr_code(scanned)
            .await
            .expect("a cross-signed peer can scan a cross-signed peer's code")
            .expect("a ready flow that announced scanning produces a code object");
        let reciprocation = bob_code
            .reciprocate()
            .expect("a scanner must tell the other side it scanned");
        deliver_verification_request(&reciprocation, BOB, ALICE, ALICE_DEVICE).await;

        confirm_scan(&inbound_flow)
            .await
            .expect("a code somebody has scanned can be confirmed");
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;
        pump_bare_to_library(&bob.peer, BOB, ALICE, ALICE_DEVICE).await;

        assert!(
            bob_code.is_done(),
            "a flow the other person opened must finish like any other: {:?}",
            bob_code.state()
        );
        assert_eq!(
            flow_stage(&inbound_flow).await.expect("the flow exists"),
            FlowStage::Done,
            "and this side must say so too"
        );

        // ---- And a peer that walks away after scanning -------------------------
        //
        // The shape the registry's own boundedness argument now turns on,
        // and it is reachable rather than theoretical. Upstream advances the
        // request and the code from the same `m.key.verification.done`, but
        // it does not advance them alike: `VerificationRequest::receive_done`
        // moves `Transitioned` to `Done` unconditionally
        // (`verification/requests.rs:934-940`), while `QrVerification::receive_done`
        // moves only a code that is `Confirmed` or `Reciprocated` and leaves
        // a `Scanned` or `Created` one exactly where it is
        // (`verification/qrcode.rs:392-440`).
        //
        // So a peer that scans this device's code and then says it is done,
        // without waiting for the person here to answer, leaves the request
        // finished and the code not. **Reading the code first is what makes
        // that matter**: before this milestone the sweep read the request and
        // saw `Done`. It now reads the code, which says `Scanned`, and
        // without the retirement rule this phase measures the record would
        // stay in the registry for the life of the process, one entry per
        // such flow.
        //
        // Both empty syncs first, for the reason the phase above gives at
        // length: upstream cancels a new request outright while another for
        // the same user is still in its map, and a sync is what empties it.
        deliver_to_bare(&bob.peer, Vec::new()).await;
        deliver_to_library(Vec::new()).await;
        let stranded = request_flow(BOB, BOB_DEVICE)
            .await
            .expect("a known device can be asked to verify again");
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;
        let bob_request = bob
            .peer
            .get_verification_request(&alice_user, &stranded.0)
            .expect("the other user must have received the invitation");
        let ready = bob_request
            .accept_with_methods(every_method())
            .expect("a fresh invitation can be accepted");
        deliver_verification_request(&ready, BOB, ALICE, ALICE_DEVICE).await;

        let code = read_code(&stranded)
            .await
            .expect("two cross-signed accounts can show each other a code");
        let scanned = QrVerificationData::from_bytes(&code.payload)
            .expect("what this library produced must decode as what the format defines");
        let bob_code = bob_request
            .scan_qr_code(scanned)
            .await
            .expect("a cross-signed peer can scan a cross-signed peer's code")
            .expect("a ready flow that announced scanning produces a code object");
        let reciprocation = bob_code
            .reciprocate()
            .expect("a scanner must tell the other side it scanned");
        deliver_verification_request(&reciprocation, BOB, ALICE, ALICE_DEVICE).await;
        assert_eq!(
            flow_stage(&stranded).await.expect("the flow exists"),
            FlowStage::CodeScanned,
            "the peer has scanned and this side has not answered, which is the one \
             moment a code flow asks a person anything"
        );

        // The peer gives up rather than waiting to be confirmed.
        deliver_to_library(vec![a_done_from(BOB, &stranded.0)]).await;
        assert_eq!(
            flow_stage(&stranded).await.expect("the flow exists"),
            FlowStage::CodeScanned,
            "nothing the peer said moved this device's own code, so the stage a \
             product reads must not move either: the person here is still being \
             asked a question nobody will act on"
        );

        // ---- And the registry lets it go anyway --------------------------------
        //
        // The assertion the boundedness argument in `release_finished` names.
        // A record whose *stage* will never reach a finished one is still
        // retired once the request behind it has, which is what stops this
        // shape accumulating. Measured through the one thing an integration
        // test can see: a swept record is rebuilt from upstream without its
        // code handle and reads as no flow at all, while a retained one
        // answers from the registry with the stage above.
        deliver_to_bare(&bob.peer, Vec::new()).await;
        deliver_to_library(Vec::new()).await;
        request_flow(BOB, BOB_DEVICE)
            .await
            .expect("a known device can be asked to verify again");
        assert_eq!(
            flow_stage(&stranded)
                .await
                .expect_err("the stranded flow must have been released"),
            MachineError::UnknownFlow,
            "a flow whose request is over must be swept even though its code never \
             finished, or every peer that walked away after scanning would leave an \
             entry behind for the life of the process"
        );
    }));
}
