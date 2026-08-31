//! A product that can put a code on a screen and cannot read one: what it
//! makes possible, and what it is told when nothing is possible.
//!
//! # The failure this file is written against
//!
//! On 2026-08-31 a product turned scannable codes on, a real Element Web
//! client on the same account began a self-verification, and **Element chose
//! to show its own code and wait for the product to scan it**. The product
//! has no scanner. Nothing was asked of this library, so no error reached
//! anybody, and when the person eventually asked for a code the answer was
//! `wrong_stage`: a complaint about a stage, in answer to a question about
//! methods, on a flow whose stage was fine.
//!
//! Element did nothing wrong. The claim was ours: the switch announced
//! showing and scanning together, so a product with a screen and no scanner
//! had to claim a camera in order to get a code at all.
//!
//! # What is watched here, and what makes each of them fail
//!
//! 1. **A show-only flow finishes against a peer that can only scan.**
//!    Announcing less must not cost the half that works: this side draws,
//!    the counterparty reads, and the flow reaches `Done` on both sides with
//!    nothing for anybody to compare. The counterparty in phase 2 answers
//!    with the scanning half alone, so it is not a full client being
//!    cornered into scanning; it is the client a show-only product is meant
//!    to work with.
//! 2. **Two devices that can only show are told so.** They have no code mode
//!    between them, which is what two code-showing products on one account
//!    are. Before this branch the answer was `CodeNotOffered` while the
//!    request was ready, which told a correct product to go and re-check its
//!    own switch, and `WrongStage` once the flow had moved on, which told it
//!    to wait or start again. Both of those are wrong and the second is the
//!    one a person met.
//!
//! **A peer that can scan has no choice but to scan** is the third claim
//! this branch rests on and it is not here: it needs a counterparty that
//! announced *everything*, so that being unable to show is visibly this
//! side's doing rather than its own. `tests/qr_announcement.rs` makes it,
//! against a peer that answered with every method it has, in the section
//! where the show-only wire is read off the pump.
//!
//! # Which side is the library
//!
//! **The library is the established device**, the one that minted the
//! account's identity, and the counterparty is a second login that holds
//! none of it. That is `qr_self_established_shows.rs`'s arrangement, chosen
//! because it is the arrangement in which this library shows a code, which
//! is the only arrangement a show-only product has.
//!
//! # One `#[test]`, two phases
//!
//! This library holds one crypto machine per process and Cargo runs the
//! tests in one binary concurrently, so the phases are sequential inside a
//! single test rather than two of them. The refusal comes first and the
//! completion second, so that the completion is not measured against a
//! machine that has just verified the device it is about to verify again.

use matrix_crypto_core::{
    cancel_flow, confirm_scan, create_identity, create_machine, flow_stage, identity_status,
    in_runtime, mark_request_sent, offer_codes, read_code, request_flow, take_outgoing_requests,
    CodeCapabilities, CryptoSignal, FlowStage, MachineConfig, MachineError,
};
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId, TransactionId};
use matrix_sdk_crypto::matrix_sdk_qrcode::QrVerificationData;
use matrix_sdk_crypto::{OlmMachine, QrVerificationState};

#[path = "scanned/harness.rs"]
mod harness;
use harness::{
    deliver_to_library, deliver_verification_request, device_keys_of, drain_signals,
    drain_to_quiet, keys_query_response, mode_of, one_of, pump_bare_to_library, pump_to_bare,
    queried_users, scanning_only, settle_key_upload, showing_only, subscribe, MODE_SELF_TRUSTED,
};

const ACCOUNT: &str = "@alice:example.org";
/// The library: the device that set the account up, and the one that draws.
const MAIN_DEVICE: &str = "FIRSTLOGIN";
/// The bare upstream machine: a login that has just happened.
const NEW_DEVICE: &str = "NEWLOGIN";

#[test]
fn a_product_that_only_shows_completes_with_a_scanner_and_is_told_when_there_is_none() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(in_runtime(async move {
        subscribe();
        let account: OwnedUserId = ACCOUNT.parse().expect("a literal user id parses");
        let new_device_id: OwnedDeviceId = NEW_DEVICE.into();

        // **The whole subject of this file.** A screen, and no camera, which
        // is the truthful answer for the product on the owner's desk and was
        // unsayable until this branch.
        offer_codes(CodeCapabilities {
            can_show: true,
            can_scan: false,
        });

        // ---- The login that has just happened ------------------------------
        let new_login = OlmMachine::new(&account, &new_device_id).await;
        settle_key_upload(&new_login).await;
        let new_login_keys =
            serde_json::to_value(device_keys_of(&new_login, &account, &new_device_id).await)
                .expect("upstream device keys serialise");

        // ---- The library ----------------------------------------------------
        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: MAIN_DEVICE.to_string(),
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
        let main_device_keys = upload_body
            .get("device_keys")
            .cloned()
            .expect("a fresh machine's upload carries its device keys");
        mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
            .await
            .expect("a keys-upload response must be accepted");

        let account_query = batch
            .iter()
            .find(|request| {
                request.kind == "keys_query"
                    && queried_users(&request.body).iter().any(|u| u == ACCOUNT)
            })
            .expect("a fresh machine must owe a key query for its own account");
        mark_request_sent(
            &account_query.id,
            &serde_json::json!({
                "device_keys": { ACCOUNT: { NEW_DEVICE: new_login_keys.clone() } },
            })
            .to_string(),
        )
        .await
        .expect("answering the account key query must not fail");

        // ---- This device mints the account's identity ------------------------
        create_identity()
            .await
            .expect("an account with no identity may mint one");
        assert!(
            identity_status()
                .await
                .expect("reading the identity status must not fail")
                .private_keys_held,
            "everything a code needs except the announcement has to be in place, or \
             a refusal below could be about an identity rather than about what the \
             two sides said they can do"
        );

        let published = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let signing_keys = one_of(
            &published,
            "signing_keys_upload",
            "a bootstrap must publish the identity it minted",
        );
        let identity: serde_json::Value = serde_json::from_str(&signing_keys.body)
            .expect("the pump's own body is well-formed JSON");
        let master_key = identity
            .get("master_key")
            .cloned()
            .expect("a published identity carries a master key");
        let self_signing_key = identity
            .get("self_signing_key")
            .cloned()
            .expect("a published identity carries a self-signing key");
        let user_signing_key = identity
            .get("user_signing_key")
            .cloned()
            .expect("a published identity carries a user-signing key");
        // **The confirming answer, because reporting the upload is not one.**
        // Minting records that this store holds an identity no homeserver
        // has accepted, and every door into a self-verification refuses
        // while that record stands: from inside a process, an identity this
        // device holds and has never seen accepted cannot be told apart from
        // one the account has since replaced. The two bodies this library
        // cannot tell from a successful upload are exactly what a dropped
        // connection hands a product, so reporting the upload clears
        // nothing. What clears it is the query the mint queues behind the
        // publication, answered the way a homeserver that accepted it would
        // answer: all three key maps for this account, and the account's
        // other device alongside them, because an answer naming no device of
        // the account would retire the login this flow is with.
        let confirming = published
            .iter()
            .find(|request| {
                request.kind == "keys_query"
                    && queried_users(&request.body).iter().any(|u| u == ACCOUNT)
            })
            .expect("the mint must queue the query that confirms its publication")
            .clone();
        for request in &published {
            if request.id == confirming.id {
                continue;
            }
            mark_request_sent(&request.id, "{}")
                .await
                .expect("a bootstrap publication response must be accepted");
        }
        mark_request_sent(
            &confirming.id,
            &serde_json::json!({
                "device_keys": { ACCOUNT: { NEW_DEVICE: new_login_keys } },
                "failures": {},
                "master_keys": { ACCOUNT: master_key.clone() },
                "self_signing_keys": { ACCOUNT: self_signing_key.clone() },
                "user_signing_keys": { ACCOUNT: user_signing_key.clone() },
            })
            .to_string(),
        )
        .await
        .expect("the confirming answer must be accepted");
        assert!(
            !identity_status()
                .await
                .expect("reading the identity status must not fail")
                .identity_publication_pending,
            "the publication has to be confirmed before any flow with a device of \
             this account can be opened, and a test that left it owed would be \
             measuring that refusal rather than the mode it is about"
        );

        // ---- The new login learns what the account published -----------------
        new_login
            .mark_request_as_sent(
                &TransactionId::new(),
                &keys_query_response(
                    &serde_json::json!({
                        "device_keys": { ACCOUNT: { MAIN_DEVICE: main_device_keys } },
                        "master_keys": { ACCOUNT: master_key },
                        "self_signing_keys": { ACCOUNT: self_signing_key },
                        "user_signing_keys": { ACCOUNT: user_signing_key },
                    })
                    .to_string(),
                ),
            )
            .await
            .expect("the bare machine must accept a keys-query response");

        // =====================================================================
        // Phase 1: two devices that can only show
        // =====================================================================
        //
        // The counterparty answers with a show-only list of its own, so
        // between them there is a screen at each end and no camera anywhere.
        // Nothing is missing but the mode: both identities exist, each side
        // knows the other's device, and the flow is agreed.

        let stalemate = request_flow(ACCOUNT, NEW_DEVICE)
            .await
            .expect("a device of this account can be asked to verify itself");
        pump_to_bare(&new_login, ACCOUNT, ACCOUNT, NEW_DEVICE).await;

        let peer_request = new_login
            .get_verification_request(&account, &stalemate.0)
            .expect("the new login must have received the invitation");
        let ready = peer_request
            .accept_with_methods(showing_only())
            .expect("a fresh invitation can be accepted");
        deliver_verification_request(&ready, ACCOUNT, ACCOUNT, MAIN_DEVICE).await;
        assert_eq!(
            flow_stage(&stalemate).await.expect("the flow exists"),
            FlowStage::Ready,
            "the other device agreed, so this is a flow where a code would be \
             produced if there were any mode to produce one in"
        );

        // Neither side can build one, and the two halves are separate
        // findings: upstream refuses a code unless the builder announced
        // showing and the reader announced scanning, so with no camera at
        // either end the refusal is symmetric.
        assert!(
            peer_request
                .generate_qr_code()
                .await
                .expect("the other device's store must be readable")
                .is_none(),
            "a device told this side has no camera must not be able to build a code"
        );
        assert_eq!(
            read_code(&stalemate)
                .await
                .expect_err("two devices that can only show have no code mode"),
            MachineError::PeerCannotScan,
            "**this is the sentence the product was never told.** The far side did \
             not announce a camera, nothing on this device can change that, and the \
             answer is to compare the short string instead. `CodeNotOffered` would \
             send a product that correctly announced showing to go and re-check its \
             own switch, which is the one place the answer is not"
        );

        // ---- AND THE SAME ANSWER ONCE THE FLOW HAS MOVED ON ------------------
        //
        // **The stage complaint, and where it came from.** Upstream carries
        // the two method lists on `VerificationRequestState::Ready` and on no
        // other state, so a flow that has become a comparison could be asked
        // why there is no code and had no way to answer. It answered
        // `WrongStage`: wait, or start again, which are the two things that
        // cannot help. The registry keeps the negotiation while upstream is
        // still willing to state it, and this is what reads it back.
        //
        // The short string is the one method both sides still announce, so
        // the counterparty starting one is the ordinary way a flow like this
        // moves on rather than a contrivance.
        let (_peer_sas, start) = peer_request
            .start_sas()
            .await
            .expect("the other device's store must be readable")
            .expect("a ready request can start a comparison");
        deliver_verification_request(&start, ACCOUNT, ACCOUNT, MAIN_DEVICE).await;
        assert_eq!(
            flow_stage(&stalemate).await.expect("the flow exists"),
            FlowStage::Started,
            "the counterparty opened a comparison, so the request has transitioned \
             and upstream has stopped saying what was negotiated"
        );
        assert_eq!(
            read_code(&stalemate)
                .await
                .expect_err("a flow that never had a code mode still has none"),
            MachineError::PeerCannotScan,
            "a flow that has moved on must give the same answer as the flow it was a \
             moment ago. This is the assertion the hardware failure is about: the \
             answer here was `WrongStage`, which is a complaint about a stage in \
             reply to a question about methods, and it left a product with nothing \
             to say to a person except a word from a state machine"
        );

        // Refused and swept before the next flow: upstream cancels a new
        // request outright while another with the same user is still live
        // and uncancelled (`verification/machine.rs:165-192`).
        cancel_flow(&stalemate)
            .await
            .expect("a live flow can be refused");
        pump_to_bare(&new_login, ACCOUNT, ACCOUNT, NEW_DEVICE).await;
        deliver_to_library(Vec::new()).await;
        drain_to_quiet();

        // =====================================================================
        // Phase 2: the same product, against a counterparty that can scan
        // =====================================================================

        let flow = request_flow(ACCOUNT, NEW_DEVICE)
            .await
            .expect("a device of this account can be asked to verify itself");
        pump_to_bare(&new_login, ACCOUNT, ACCOUNT, NEW_DEVICE).await;

        let peer_request = new_login
            .get_verification_request(&account, &flow.0)
            .expect("the new login must have received the invitation");
        // **The scanning half alone, deliberately.** This is the shape a
        // show-only product is meant to meet: a camera on the other end and
        // no screen offered from it. `tests/qr_announcement.rs` drives the
        // other shape, a counterparty that announced everything and is left
        // unable to show anyway.
        let ready = peer_request
            .accept_with_methods(scanning_only())
            .expect("a fresh invitation can be accepted");
        deliver_verification_request(&ready, ACCOUNT, ACCOUNT, MAIN_DEVICE).await;
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Ready,
            "the other device agreed, so the flow is where a code is produced"
        );

        // ---- This side draws ---------------------------------------------------
        let code = read_code(&flow)
            .await
            .expect("a product that announced showing must be able to show");
        assert_eq!(
            mode_of(&code.payload),
            MODE_SELF_TRUSTED,
            "the device holding the account's private signing keys says so in the \
             code it shows, and announcing one half rather than two must not change \
             which mode a code carries"
        );

        // ---- The new login scans it -------------------------------------------
        let scanned = QrVerificationData::from_bytes(&code.payload)
            .expect("what this library produced must decode as what the format defines");
        let peer_code = peer_request
            .scan_qr_code(scanned)
            .await
            .expect("a new login that knows the account's identity can scan its code")
            .expect("a ready flow that announced scanning produces a code object");
        assert!(
            matches!(peer_code.state(), QrVerificationState::Reciprocated),
            "the side that scanned owes the other one a message: {:?}",
            peer_code.state()
        );
        let reciprocation = peer_code
            .reciprocate()
            .expect("a scanner must tell the other side it scanned");
        deliver_verification_request(&reciprocation, ACCOUNT, ACCOUNT, MAIN_DEVICE).await;
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::CodeScanned,
            "a reciprocation must reach a show-only flow exactly as it reaches one \
             that announced both halves. **This is what `m.reciprocate.v1` is in the \
             show-only list for**, although nothing here can watch that: upstream \
             consults nobody's announced methods before accepting this message, so \
             this assertion would pass with the entry removed. `SHOWING_ONLY` in \
             `src/verification.rs` carries the two implementations that do consult \
             it and says plainly that no test in this repository can"
        );

        // ---- The person says it really was their new phone ---------------------
        confirm_scan(&flow)
            .await
            .expect("a code somebody has scanned can be confirmed");
        let crossed = pump_to_bare(&new_login, ACCOUNT, ACCOUNT, NEW_DEVICE).await;
        assert!(
            crossed.contains(&"m.key.verification.done".to_string()),
            "confirming a scan must reach the other device through the pump: {crossed:?}"
        );
        drain_to_quiet();
        let crossed = pump_bare_to_library(&new_login, ACCOUNT, ACCOUNT, MAIN_DEVICE).await;
        assert!(
            crossed.contains(&"m.key.verification.done".to_string()),
            "the other device's acknowledgement must reach the library: {crossed:?}"
        );

        assert_eq!(
            drain_signals("a show-only flow finished"),
            vec![CryptoSignal::VerificationCompleted {
                flow_id: flow.0.clone(),
            }],
            "a product that verified by code has nothing to poll, and a product that \
             announced one half rather than two must be told it finished on the same \
             terms as one that announced both"
        );
        assert!(
            peer_code.is_done(),
            "the other device must have finished the flow: {:?}",
            peer_code.state()
        );
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Done,
            "**a show-only flow completes.** Announcing less cost nothing but the \
             direction this product could never have run"
        );
    }));
}
