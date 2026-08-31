//! The receiving side of a self-verification must read the gate too.
//!
//! # The shape, and why one door was not enough
//!
//! The eighth round gated `request_self_flow`, and gave this reason: a
//! self-verification signs another of our devices with **this** device's
//! self-signing key and asks the account's other devices for its
//! cross-signing seeds, both under whatever identity this store holds.
//!
//! **That is a property of the flow, not of the call that opens it.** Either
//! side may start one, and the receiving side reaches the identical
//! completion through `accept_flow`, `begin_comparison` and `confirm_flow`.
//! Measured on the store `tests/self_verification_stale_identity.rs` builds:
//! five calls refused, `accept_flow` was served, the comparison ran to
//! `Done`, and the library queued a `signature_upload` signing another
//! device of the account with a stale identity's self-signing key, with the
//! gate never consulted.
//!
//! # Why the gate here is scoped rather than unconditional
//!
//! Measured: a bare `account_keys_answered()` check at the top of
//! `accept_flow` turns nine tests red, all of them in
//! `tests/sas_two_party.rs`, which verifies **another user**. Verifying
//! somebody else needs nothing of our own identity, and that whole file runs
//! with the gate shut on purpose. So the gate applies when the flow's
//! counterparty is our own account and to nothing else, which is the
//! distinction `request_self_flow` and `request_flow` already draw between
//! themselves and which nobody had written down at this door.
//!
//! `sas_two_party.rs` is therefore the other half of this file's evidence:
//! it is eleven tests that drive `accept_flow`, `begin_comparison` and
//! `confirm_flow` to a completed verification with `account_keys_fetched`
//! false, and they must stay green.
//!
//! # What this file does not claim
//!
//! It gates a door. **There is no single choke point behind these doors**,
//! and that was checked rather than assumed: the signature upload has two
//! producers, one queued by this crate through `verification::queue` and one
//! upstream queues for itself in `mark_sas_as_done` and hands over through
//! `OlmMachine::outgoing_requests`. The only place both meet is the pump,
//! `session::take_outgoing_requests`. Putting the invariant there would
//! cover every present and future door at once; it is not done here, and the
//! ninth report says so plainly rather than leaving it implied.

use matrix_crypto_core::{
    accept_flow, bootstrap_identity, cancel_flow, create_identity, create_machine, create_recovery,
    flow_stage, identity_status, in_runtime, mark_request_sent, receive_sync_changes,
    recover_identity, request_self_flow, take_outgoing_requests, FlowId, MachineConfig,
    MachineError, OutgoingRequest,
};
use matrix_sdk_common::ruma::exports::http;
use matrix_sdk_common::ruma::{
    api::client::keys::{
        get_keys::v3::Response as KeysQueryResponse,
        upload_keys::v3::Response as KeysUploadResponse,
    },
    api::IncomingResponse,
    OwnedDeviceId, OwnedUserId,
};
use matrix_sdk_crypto::{
    types::requests::{AnyOutgoingRequest, OutgoingVerificationRequest},
    OlmMachine,
};
use matrix_sdk_sqlite::SqliteCryptoStore;
use serde_json::{json, Value};

const ACCOUNT: &str = "@alice:example.org";
const DEVICE: &str = "DEVICEONE";
const PEER: &str = "PEERDEVIC";
const STORE_PASSPHRASE: &str = "test-passphrase";

fn http_ok(body: &str) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(200)
        .body(body.as_bytes().to_vec())
        .expect("response")
}
fn keys_upload_response(body: &str) -> KeysUploadResponse {
    KeysUploadResponse::try_from_http_response(http_ok(body)).expect("upload response")
}
fn keys_query_response(body: &str) -> KeysQueryResponse {
    KeysQueryResponse::try_from_http_response(http_ok(body)).expect("query response")
}

fn names_the_account(body: &str) -> bool {
    let parsed: Value = serde_json::from_str(body).expect("json");
    parsed
        .get("device_keys")
        .and_then(|u| u.get(ACCOUNT))
        .is_some()
}

/// Turns an upstream to-device request into the sync slice
/// `receive_sync_changes` accepts, addressed to this library's device.
fn relay_to_library(body: &str, sender_device: &str) -> Value {
    let parsed: Value = serde_json::from_str(body).expect("to-device json");
    let content = parsed["messages"][ACCOUNT][DEVICE].clone();
    assert!(
        !content.is_null(),
        "the peer must address this library's device; got {parsed}"
    );
    json!({
        "type": parsed["event_type"],
        "sender": ACCOUNT,
        "content": content,
        "_sender_device": sender_device,
    })
}

async fn deliver(events: Vec<Value>) {
    let payload = json!({ "to_device_events": events }).to_string();
    receive_sync_changes(&payload)
        .await
        .expect("the library must accept a sync");
}

fn kinds(batch: &[OutgoingRequest]) -> Vec<&str> {
    batch.iter().map(|r| r.kind.as_str()).collect()
}

#[test]
fn an_inbound_self_verification_reads_the_gate() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();
    let account: OwnedUserId = ACCOUNT.parse().expect("user id");
    let this_device: OwnedDeviceId = DEVICE.into();
    let peer_device: OwnedDeviceId = PEER.into();

    // ---- an earlier process leaves a store holding a STALE identity ----
    let this_device_keys = {
        let store_path = store_path.clone();
        let account = account.clone();
        let this_device = this_device.clone();
        futures::executor::block_on(in_runtime(async move {
            let store = SqliteCryptoStore::open(&store_path, Some(STORE_PASSPHRASE))
                .await
                .expect("store");
            let machine = OlmMachine::with_store(&account, &this_device, store, None)
                .await
                .expect("bare machine");
            let upload_id = machine
                .outgoing_requests()
                .await
                .expect("requests")
                .iter()
                .find(|r| matches!(r.request(), AnyOutgoingRequest::KeysUpload(_)))
                .expect("a fresh machine uploads its keys")
                .request_id()
                .to_owned();
            machine
                .mark_request_as_sent(
                    &upload_id,
                    &keys_upload_response(r#"{"one_time_key_counts":{}}"#),
                )
                .await
                .expect("upload accepted");
            machine
                .bootstrap_cross_signing(false)
                .await
                .expect("the earlier process mints an identity");
            let keys = machine
                .get_device(&account, &this_device, None)
                .await
                .expect("store")
                .expect("own device")
                .as_device_keys()
                .to_owned();
            let value = serde_json::to_value(keys).expect("device keys");
            drop(machine);
            value
        }))
    };

    // ---- the peer: another device of the same account -------------------
    let peer_state = futures::executor::block_on(in_runtime({
        let account = account.clone();
        let peer_device = peer_device.clone();
        async move {
            let peer = OlmMachine::new(&account, &peer_device).await;
            let upload_id = peer
                .outgoing_requests()
                .await
                .expect("requests")
                .iter()
                .find(|r| matches!(r.request(), AnyOutgoingRequest::KeysUpload(_)))
                .expect("a fresh machine uploads its keys")
                .request_id()
                .to_owned();
            peer.mark_request_as_sent(
                &upload_id,
                &keys_upload_response(r#"{"one_time_key_counts":{}}"#),
            )
            .await
            .expect("upload accepted");
            // The peer learns about this library's device, the ordinary way.
            peer.mark_request_as_sent(
                &matrix_sdk_common::ruma::TransactionId::new(),
                &keys_query_response(
                    &json!({
                        "device_keys": { ACCOUNT: { DEVICE: this_device_keys } },
                        "failures": {},
                        "master_keys": {},
                        "self_signing_keys": {},
                        "user_signing_keys": {},
                    })
                    .to_string(),
                ),
            )
            .await
            .expect("the peer must accept a key query answer");
            let keys = peer
                .get_device(&account, &peer_device, None)
                .await
                .expect("store")
                .expect("own device")
                .as_device_keys()
                .to_owned();
            (peer, serde_json::to_value(keys).expect("device keys"))
        }
    }));
    let (peer, peer_device_keys) = peer_state;

    futures::executor::block_on(in_runtime(async move {
        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: DEVICE.to_string(),
            store_path,
            store_passphrase: Some(STORE_PASSPHRASE.to_string()),
        })
        .await
        .expect("the library reopens the store");

        let premise = identity_status().await.expect("status");
        assert!(premise.identity_known && premise.private_keys_held);
        assert!(!premise.account_keys_fetched);

        // The library has to know the peer's device before an invitation
        // from it can be built. An answer carrying device keys and NO
        // cross-signing keys is exactly what the eighth round classifies as
        // contradicting a store holding an identity, so the gate stays shut.
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::AccountKeysNotFetched)
        );
        let batch = take_outgoing_requests().await.expect("drain");
        let q = batch
            .iter()
            .find(|r| r.kind == "keys_query" && names_the_account(&r.body))
            .expect("the refusal queues the query")
            .clone();
        let answer = json!({
            "device_keys": { ACCOUNT: { PEER: peer_device_keys } },
            "failures": {},
            "master_keys": {},
            "self_signing_keys": {},
            "user_signing_keys": {},
        })
        .to_string();
        mark_request_sent(&q.id, &answer)
            .await
            .expect("the answer must be accepted");

        let after = identity_status().await.expect("status");
        assert!(
            !after.account_keys_fetched,
            "the gate must still be shut, or this probe measures nothing: {after:?}"
        );

        // ---- the five calls that already refuse on this store -----------
        //
        // Asserted rather than assumed, because the whole point of this file
        // is that a sixth path into the same store was served while these
        // five were refusing. If any of them started being served, the
        // premise would be gone and the assertion below would be measuring
        // something else.
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::AccountKeysNotFetched)
        );
        assert_eq!(
            create_identity().await,
            Err(MachineError::AccountKeysNotFetched)
        );
        assert_eq!(
            create_recovery("verification-test-passphrase", &[])
                .await
                .err(),
            Some(MachineError::AccountKeysNotFetched)
        );
        assert_eq!(
            recover_identity("verification-test-passphrase", &[]).await,
            Err(MachineError::AccountKeysNotFetched)
        );
        assert_eq!(
            request_self_flow().await.err(),
            Some(MachineError::AccountKeysNotFetched)
        );
        let _ = take_outgoing_requests().await.expect("drain");

        // ---- the invitation arrives from the account's other device -----
        let (request_handle, outgoing) = peer
            .get_device(&account, &this_device, None)
            .await
            .expect("the peer's store")
            .expect("the peer knows nothing about this device")
            .request_verification();
        let flow_id = request_handle.flow_id().as_str().to_string();
        let body = match &outgoing {
            OutgoingVerificationRequest::ToDevice(to_device) => {
                serde_json::to_string(to_device).expect("serialise")
            }
            OutgoingVerificationRequest::InRoom(_) => panic!("to-device only"),
        };
        deliver(vec![relay_to_library(&body, PEER)]).await;

        // ---- The question this file exists for -------------------------
        let flow = FlowId(flow_id.clone());
        assert_eq!(
            accept_flow(&flow).await.err(),
            Some(MachineError::AccountKeysNotFetched),
            "accepting a self-verification on a store whose identity the server has never \
             been asked about runs a comparison that ends in this device signing another \
             device of the account with that identity's self-signing key, and in asking the \
             account's other devices for its cross-signing seeds"
        );

        // Nothing may have gone out to the account's other devices, which is
        // a separate claim from the refusal: a call that queued the answer
        // and then reported a refusal would have spoken already.
        let batch = take_outgoing_requests().await.expect("drain");
        assert!(
            !batch.iter().any(|r| r.kind == "to_device"),
            "the refusal must send nothing; got {:?}",
            kinds(&batch)
        );
        assert!(
            !batch.iter().any(|r| r.kind == "signature_upload"),
            "and must sign nothing; got {:?}",
            kinds(&batch)
        );

        // And it is recoverable in the same way every other refusal on this
        // surface is: it queues the query that lifts it.
        assert!(
            batch
                .iter()
                .any(|r| r.kind == "keys_query" && names_the_account(&r.body)),
            "the refusal must queue the key query that lifts it, or a store holding an \
             identity could never self-verify at all; got {:?}",
            kinds(&batch)
        );

        // The flow is untouched rather than destroyed: a product whose gate
        // opens a moment later accepts the same invitation.
        assert!(
            matches!(
                flow_stage(&flow).await,
                Ok(matrix_crypto_core::FlowStage::Requested)
            ),
            "the invitation must still be answerable once the gate opens: {:?}",
            flow_stage(&flow).await
        );

        let end = identity_status().await.expect("status");
        assert!(
            !end.account_keys_fetched,
            "and nothing here may have opened the gate as a side effect: {end:?}"
        );
        let _ = cancel_flow(&flow).await;
    }));
}
