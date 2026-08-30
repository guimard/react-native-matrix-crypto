//! Verifying **our own account with the new login holding up its screen**.
//! Mode `0x02`.
//!
//! # Why this file and its sibling both exist
//!
//! A person verifying their new phone against their old one holds up one of
//! the two and points the other at it. Which of the two they pick decides
//! which mode the protocol uses, and there is nothing a product can do to
//! influence that choice: it is made by a hand. A library that implemented
//! one of the two would work exactly half the time, and the half it failed
//! on would be chosen by its user.
//!
//! This file is the half where **the new login shows**. Its sibling,
//! `qr_self_established_shows.rs`, is the other. They are separate binaries
//! because each needs the library's one process-wide machine to be a
//! different device: here it is the login that has just happened and holds
//! none of the account's private signing keys, and there it is the device
//! that minted them.
//!
//! # What mode `0x02` says
//!
//! *I am showing you this code and I do not hold this account's private
//! signing keys.* So the code carries the showing device's own key first and
//! the account's master key second, and the scanner checks the first against
//! the device it is verifying rather than against an identity. That is why
//! it is a different mode rather than a different reading of the same one.
//!
//! # Which side is the library
//!
//! **The library is the new device**, the one that has nothing. The bare
//! `OlmMachine` is the one that already has everything. This file relays
//! between the two exactly what a homeserver would relay and nothing else.

use matrix_crypto_core::{
    confirm_scan, create_machine, device_statuses, flow_stage, identity_status, in_runtime,
    mark_request_sent, read_code, request_self_flow, take_outgoing_requests, CryptoSignal,
    FlowStage, MachineConfig, TrustState,
};
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId, TransactionId};
use matrix_sdk_crypto::matrix_sdk_qrcode::QrVerificationData;
use matrix_sdk_crypto::QrVerificationState;

#[path = "scanned/harness.rs"]
mod harness;
use harness::{
    cross_signed_machine, deliver_verification_request, drain_signals, drain_to_quiet,
    every_method, keys_claim_response, keys_query_response, mode_of, one_of, pump_bare_to_library,
    pump_to_bare, queried_users, subscribe, MODE_SELF_UNTRUSTED,
};

const ACCOUNT: &str = "@alice:example.org";
/// The library: a login that has just happened and holds nothing.
const NEW_DEVICE: &str = "NEWLOGIN";
/// The bare upstream machine: the device that set the account up.
const OLD_DEVICE: &str = "FIRSTLOGIN";

#[test]
fn a_new_login_shows_a_code_and_the_account_verifies_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(in_runtime(async move {
        // Before anything syncs. See `qr_self_established_shows.rs` at the
        // same place.
        subscribe();
        let account: OwnedUserId = ACCOUNT.parse().expect("a literal user id parses");
        let new_device: OwnedDeviceId = NEW_DEVICE.into();

        // ---- The device that got there first -----------------------------
        let first = cross_signed_machine(ACCOUNT, OLD_DEVICE).await;

        // ---- The new login ------------------------------------------------
        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: NEW_DEVICE.to_string(),
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
        let new_device_keys = upload_body
            .get("device_keys")
            .cloned()
            .expect("a fresh machine's upload carries its device keys");
        let new_one_time_keys = upload_body
            .get("one_time_keys")
            .cloned()
            .expect("a fresh machine's upload carries one-time keys");
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
                "device_keys": { ACCOUNT: { OLD_DEVICE: first.signed_device_keys } },
                "master_keys": { ACCOUNT: first.master_key },
                "self_signing_keys": { ACCOUNT: first.self_signing_key },
                "user_signing_keys": { ACCOUNT: first.user_signing_key },
            })
            .to_string(),
        )
        .await
        .expect("answering the account key query must not fail");

        // ---- The state a second login is actually in ----------------------
        let before = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            before.identity_known,
            "the answer named an identity, so upstream must have stored one: {before:?}"
        );
        assert!(
            !before.private_keys_held,
            "the mode this file is about is the one a device shows when it holds \
             none of the account's private signing keys. Against a device that held \
             them the library would produce the *other* self mode and this test \
             would be measuring its sibling: {before:?}"
        );

        // ---- The first device learns the new one --------------------------
        first
            .peer
            .mark_request_as_sent(
                &TransactionId::new(),
                &keys_query_response(
                    &serde_json::json!({
                        "device_keys": { ACCOUNT: { NEW_DEVICE: new_device_keys } },
                        "master_keys": { ACCOUNT: first.master_key },
                        "self_signing_keys": { ACCOUNT: first.self_signing_key },
                        "user_signing_keys": { ACCOUNT: first.user_signing_key },
                    })
                    .to_string(),
                ),
            )
            .await
            .expect("the bare machine must accept a keys-query response");

        // The first device opens a session with the new one before it is
        // asked for anything, because upstream will not answer a secret
        // request it has no session for. A real first device is in this
        // state already, having shared keys with its owner's other devices
        // for months. `tests/self_verification.rs` says the same at more
        // length.
        let (claim_id, _claim) = first
            .peer
            .get_missing_sessions(std::iter::once(account.as_ref()))
            .await
            .expect("the bare machine's session manager must be readable")
            .expect("the first device knows a device of this account it has no session with");
        first
            .peer
            .mark_request_as_sent(
                &claim_id,
                &keys_claim_response(
                    &serde_json::json!({
                        "one_time_keys": { ACCOUNT: { NEW_DEVICE: new_one_time_keys } }
                    })
                    .to_string(),
                ),
            )
            .await
            .expect("the bare machine must accept a keys-claim response");

        // ---- The flow ------------------------------------------------------
        //
        // `request_self_flow`, not `request_flow`: a new login does not know
        // which of its owner's devices is to hand, and this call names none.
        let flow = request_self_flow()
            .await
            .expect("an account with an identity can be asked to verify a new device");
        pump_to_bare(&first.peer, ACCOUNT, ACCOUNT, OLD_DEVICE).await;

        let peer_request = first
            .peer
            .get_verification_request(&account, &flow.0)
            .expect("the first device must have received the invitation");
        let ready = peer_request
            .accept_with_methods(every_method())
            .expect("a fresh invitation can be accepted");
        deliver_verification_request(&ready, ACCOUNT, ACCOUNT, NEW_DEVICE).await;
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Ready,
            "the other device agreed, so the flow is where a code would be produced"
        );

        // ---- The code -------------------------------------------------------
        let code = read_code(&flow)
            .await
            .expect("a new login can show a code for its own account");
        assert_eq!(
            mode_of(&code.payload),
            MODE_SELF_UNTRUSTED,
            "a device showing a code for its own account while holding none of the \
             account's private signing keys must say so in the code. The other self \
             mode would claim the showing device already trusts the master key, \
             which this one has no way to know"
        );
        assert_eq!(
            code.modules.len(),
            code.width as usize * code.width as usize,
            "the symbol must be a square of its own declared side"
        );

        // ---- The stages a scanned flow passes through -------------------------
        //
        // One sequence, compared once, for the reason
        // `qr_self_established_shows.rs` gives at the same place: three
        // assertions taken one at a time all pass against a stage that
        // answers every question the same way, which is the defect being
        // measured.
        let mut stages = vec![flow_stage(&flow).await.expect("the flow exists")];

        // ---- The established device scans it ---------------------------------
        let scanned = QrVerificationData::from_bytes(&code.payload)
            .expect("what this library produced must decode as what the format defines");
        let peer_code = peer_request
            .scan_qr_code(scanned)
            .await
            .expect("the device that holds the identity can scan a new login's code")
            .expect("a ready flow that announced scanning produces a code object");
        assert!(
            matches!(peer_code.state(), QrVerificationState::Reciprocated),
            "the side that scanned owes the other one a message: {:?}",
            peer_code.state()
        );
        let reciprocation = peer_code
            .reciprocate()
            .expect("a scanner must tell the other side it scanned");
        deliver_verification_request(&reciprocation, ACCOUNT, ACCOUNT, NEW_DEVICE).await;
        stages.push(flow_stage(&flow).await.expect("the flow exists"));

        // ---- The person says it really was their other phone ------------------
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
            "the mode a person gets is decided by which phone they picked up, so the \
             stage has to be as truthful for the new login holding up its screen as \
             it is for the established device holding up its own"
        );
        let crossed = pump_to_bare(&first.peer, ACCOUNT, ACCOUNT, OLD_DEVICE).await;
        assert!(
            crossed.contains(&"m.key.verification.done".to_string()),
            "confirming a scan must reach the other device through the pump: {crossed:?}"
        );
        // A cut rather than a check, and in this one file it is a no-op:
        // measured, by removing it and watching the test still pass. This
        // device holds none of the account's private keys, so M4's identity
        // latch never fires here, and it opened the flow itself, so no
        // invitation is announced back to it. Kept anyway, and the reason is
        // that the two sibling files both go red without theirs: what makes
        // the assertion below mean "what this one sync produced" is the cut,
        // not the fixture that happens to have nothing to clear.
        drain_to_quiet();
        let crossed = pump_bare_to_library(&first.peer, ACCOUNT, ACCOUNT, NEW_DEVICE).await;
        assert!(
            crossed.contains(&"m.key.verification.done".to_string()),
            "the other device's acknowledgement must reach the library: {crossed:?}"
        );

        // ---- What a product is told, and the signal it is not ------------------
        //
        // **This is the mode that signals by accident**, and the accident is
        // measured rather than guarded against in the abstract. A new login
        // that verifies itself asks its other devices for the account's
        // private signing seeds, they arrive a sync or two later, and their
        // arrival announces `TrustChanged` for this very account. So an
        // assertion of the form "a `TrustChanged` for this account arrived
        // after the flow" passes here with **no completion producer at all**,
        // which is exactly the shape M4 found vacuous once already.
        //
        // The whole vector, at the sync that finished the flow and before
        // the seeds have been asked for, is what tells the two apart.
        let signals = drain_signals("a code this new login showed was scanned and confirmed");
        assert_eq!(
            signals,
            vec![CryptoSignal::VerificationCompleted {
                flow_id: flow.0.clone(),
            }],
            "the completion of a scanned flow must be its own signal, arriving at the \
             sync that finished it. Anything a product had to tell apart from the \
             seeds' arrival would be a signal it could not act on"
        );

        assert!(
            peer_code.is_done(),
            "the other device must have finished the flow: {:?}",
            peer_code.state()
        );
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Done,
            "a flow that finished by scanning must report that it finished"
        );

        // ---- What the flow was for --------------------------------------------
        //
        // Verifying our own device signs the *device*, with the account's
        // self-signing key, and only the side that holds the private keys
        // can do it. That side is the first device here, so this is what it
        // owes.
        let uploads: Vec<serde_json::Value> = first
            .peer
            .outgoing_requests()
            .await
            .expect("the bare machine's requests must be readable")
            .iter()
            .filter_map(|request| match request.request() {
                matrix_sdk_crypto::types::requests::AnyOutgoingRequest::SignatureUpload(upload) => {
                    Some(
                        serde_json::to_value(&upload.signed_keys)
                            .expect("an upstream signature upload serialises"),
                    )
                }
                _ => None,
            })
            .collect();
        assert!(
            uploads.iter().any(|upload| upload
                .get(ACCOUNT)
                .and_then(|keys| keys.get(NEW_DEVICE))
                .is_some()),
            "the established device must have signed the new one with the account's \
             self-signing key; it owes {uploads:?}"
        );

        let statuses = device_statuses(ACCOUNT)
            .await
            .expect("reading device statuses must not fail");
        assert!(
            statuses.iter().any(
                |status| status.device_id == OLD_DEVICE && status.trust == TrustState::Verified
            ),
            "the device that scanned this one's code must read verified: {statuses:?}"
        );

        // ---- And the seeds ------------------------------------------------------
        //
        // Marking our own identity verified is what sets upstream's
        // `should_request_secrets`, and a flow driven by a code sets it the
        // same way one driven by a short string does. The whole point of a
        // new login verifying itself is that it comes away able to sign, so
        // a flow that finished without this would have proven the device and
        // left it unable to do anything with the proof.
        assert!(
            !identity_status()
                .await
                .expect("reading the identity status must not fail")
                .private_keys_held,
            "the seeds must not already be here, or the assertion below would pass \
             for a reason that has nothing to do with this flow"
        );
        let crossed = pump_to_bare(&first.peer, ACCOUNT, ACCOUNT, OLD_DEVICE).await;
        assert!(
            crossed.contains(&"m.secret.request".to_string()),
            "verifying our own identity by scanning must ask our other devices for \
             the seeds this device lacks: {crossed:?}"
        );
        let crossed = pump_bare_to_library(&first.peer, ACCOUNT, ACCOUNT, NEW_DEVICE).await;
        assert!(
            crossed.contains(&"m.room.encrypted".to_string()),
            "the first device must answer the secret request, encrypted to the new \
             device: {crossed:?}"
        );
        let after = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            after.private_keys_held,
            "the seeds arrived by gossip inside an ordinary sync, so this device now \
             holds the account's private signing keys: {after:?}"
        );

        // And *that* is what announces a trust change, on a later sync than
        // the one above and under this account's own name. Asserted here so
        // the pair is on the record: two facts, two moments, two signals a
        // product can act on separately. A single one would have left a
        // product unable to tell "my verification finished" from "my new
        // device can sign now", which are different sentences on a screen.
        let arrival = drain_signals("the private signing keys arrived");
        assert_eq!(
            arrival,
            vec![CryptoSignal::TrustChanged {
                user: ACCOUNT.to_string(),
                state: TrustState::Verified,
            }],
            "the seeds' arrival keeps the signal M4 gave it, unchanged and separate \
             from the completion above"
        );

        // The account's own device id is used once here so the fixture's
        // unused binding does not go unread by the compiler.
        let _ = &new_device;
    }));
}
