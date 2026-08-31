//! The receiving side of a self-verification reads the *second* arm of the
//! gate too, and nothing measured that until this file.
//!
//! # The half that was covered, and the half that was not
//!
//! `refuse_own_flow_until_the_identity_is_settled` refuses a flow with our
//! own account on two conditions. The first is "this process has never been
//! answered about this account", and it is measured at every door:
//! `tests/self_verification_stale_identity.rs` for `request_self_flow` and
//! for `request_flow` handed our own identifiers, and
//! `tests/self_verification_inbound_stale_identity.rs` for `accept_flow`.
//!
//! The second is "this store holds an identity no homeserver has ever
//! asserted back", the arm the tenth round added, and it was measured at
//! four calls: `create_recovery`, `recover_identity`, `request_self_flow`
//! and `request_flow`, all of them in
//! `tests/identity_publication_interrupted.rs`. `accept_flow` was not one of
//! them. Measured before this file existed: deleting that arm's three lines
//! from the helper reddened that one file and left every other test in this
//! crate green, including both files that drive `accept_flow`.
//!
//! It is not a corner. Three M5 tests reached it the first time the two
//! branches met, one of them through this very door, and each of them was
//! about something else entirely.
//!
//! # Why the refusal is right here
//!
//! An identity this device minted and has never seen accepted cannot be told
//! apart, from inside a process, from one the account has since replaced.
//! Completing this flow signs the account's other device with that
//! identity's self-signing key and asks that device for the account's
//! cross-signing seeds. The other side opened the flow, so no call of ours
//! that already reads the gate stands between the invitation and the
//! signature: `begin_comparison` and `confirm_flow` deliberately read
//! nothing, because refusing there would refuse a person who had already
//! compared the string.
//!
//! # And it is a gate rather than a brick
//!
//! The last act answers the query the mint queued the way a homeserver that
//! accepted the publication would answer it, and the same invitation is then
//! accepted. That is the whole cost of this arm, stated as a measurement
//! rather than as a promise: one round trip, on a flow the peer is still
//! holding open.

use matrix_crypto_core::{
    accept_flow, cancel_flow, create_identity, create_machine, flow_stage, identity_status,
    in_runtime, mark_request_sent, take_outgoing_requests, FlowId, FlowStage, MachineConfig,
    MachineError,
};
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId, TransactionId};
use matrix_sdk_crypto::OlmMachine;

#[path = "scanned/harness.rs"]
mod harness;
use harness::{
    deliver_verification_request, device_keys_of, keys_query_response, one_of, queried_users,
    settle_key_upload,
};

const ACCOUNT: &str = "@alice:example.org";
/// The library: the device that mints, and the one the invitation reaches.
const MAIN_DEVICE: &str = "FIRSTLOGIN";
/// A bare upstream machine standing in for another device of the same
/// account, which is the only kind of counterparty this gate applies to.
const OTHER_DEVICE: &str = "NEWLOGIN";
const STORE_PASSPHRASE: &str = "test-passphrase";

#[test]
fn an_inbound_self_verification_refuses_while_the_publication_is_unconfirmed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(in_runtime(async move {
        let account: OwnedUserId = ACCOUNT.parse().expect("a literal user id parses");
        let main_device_id: OwnedDeviceId = MAIN_DEVICE.into();
        let other_device_id: OwnedDeviceId = OTHER_DEVICE.into();

        // ---- The account's other device --------------------------------
        //
        // A bare machine, so its keys are real and upstream will store them.
        // A hand-written device would be dropped for a bad self-signature
        // and the invitation below would never become a flow, which is a
        // failure this file could easily mistake for its own subject.
        let other = OlmMachine::new(&account, &other_device_id).await;
        settle_key_upload(&other).await;
        let other_keys =
            serde_json::to_value(device_keys_of(&other, &account, &other_device_id).await)
                .expect("upstream device keys serialise");

        // ---- The library -----------------------------------------------
        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: MAIN_DEVICE.to_string(),
            store_path,
            store_passphrase: Some(STORE_PASSPHRASE.to_string()),
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

        // One answer doing two jobs, both of them a homeserver's: it names
        // no signing identity, which is what lifts the gate's first arm and
        // leaves only the arm this file is about, and it names the account's
        // other device, without which the invitation below is dropped before
        // it reaches the flow registry.
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
                "device_keys": { ACCOUNT: { OTHER_DEVICE: other_keys.clone() } },
            })
            .to_string(),
        )
        .await
        .expect("answering the account key query must not fail");

        // And the other device has to know this one before it can address an
        // invitation to it.
        other
            .mark_request_as_sent(
                &TransactionId::new(),
                &keys_query_response(
                    &serde_json::json!({
                        "device_keys": { ACCOUNT: { MAIN_DEVICE: main_device_keys } },
                    })
                    .to_string(),
                ),
            )
            .await
            .expect("the bare machine must accept a keys-query response");

        // ---- The mint, with the publication left owed -------------------
        //
        // The publication is handed out and the upload is reported, which is
        // the caller's own word and deliberately not a confirmation: the two
        // bodies this library cannot tell from a success are what a dropped
        // connection produces. The query the mint queues behind it is left
        // unanswered, which is precisely the state a product is in between
        // sending the publication and hearing the server assert it back.
        create_identity()
            .await
            .expect("an account with no identity may mint one");
        let published = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let publication = one_of(
            &published,
            "signing_keys_upload",
            "a mint must publish the identity it minted",
        );
        let identity: serde_json::Value = serde_json::from_str(&publication.body)
            .expect("the pump's own body is well-formed JSON");
        let confirming = published
            .iter()
            .find(|request| {
                request.kind == "keys_query"
                    && queried_users(&request.body).iter().any(|u| u == ACCOUNT)
            })
            .expect("the mint must queue the query that confirms its publication")
            .clone();
        mark_request_sent(&publication.id, "{}")
            .await
            .expect("the caller's own report of the upload must still be accepted");

        let owed = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            owed.account_keys_fetched,
            "the gate's first arm must be open, or the refusal below is the one the \
             two stale-identity files already measure: {owed:?}"
        );
        assert!(
            owed.identity_known && owed.private_keys_held,
            "and this device must hold the identity it is about to be refused for \
             signing under: {owed:?}"
        );
        assert!(
            owed.identity_publication_pending,
            "and the publication must still be owed, or there is nothing here for \
             the second arm to read: {owed:?}"
        );

        // ---- The invitation, from the account's other device ------------
        let library_device = other
            .get_device(&account, &main_device_id, None)
            .await
            .expect("the other device's store must be readable")
            .expect("the other device has just been told about this one");
        let (peer_side, invitation) = library_device.request_verification();
        deliver_verification_request(&invitation, ACCOUNT, ACCOUNT, MAIN_DEVICE).await;
        let flow = FlowId(peer_side.flow_id().as_str().to_string());
        assert_eq!(
            flow_stage(&flow)
                .await
                .expect("the invitation builds a flow"),
            FlowStage::Requested,
            "the invitation must have reached the registry, or the refusal below \
             would be about a flow that never existed"
        );

        // ---- THE ASSERTION THIS FILE EXISTS FOR ------------------------
        assert_eq!(
            accept_flow(&flow).await.err(),
            Some(MachineError::IdentityNotKnown),
            "agreeing to a self-verification while this store holds an identity no \
             homeserver has asserted back runs a comparison that ends in this device \
             signing the account's other device with that identity's self-signing \
             key. From inside this process that identity cannot be told apart from \
             one the account has since replaced"
        );

        // A separate claim from the refusal, and the one the ninth round
        // found false at this door: a call that spoke first and refused
        // afterwards would have signed already.
        let after = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        assert!(
            !after.iter().any(|request| request.kind == "to_device"),
            "the refusal must send nothing to the account's other devices; got {:?}",
            after
                .iter()
                .map(|request| request.kind.as_str())
                .collect::<Vec<_>>()
        );
        assert!(
            !after
                .iter()
                .any(|request| request.kind == "signature_upload"),
            "and must sign nothing; got {:?}",
            after
                .iter()
                .map(|request| request.kind.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            flow_stage(&flow).await.expect("the flow still exists"),
            FlowStage::Requested,
            "and the invitation must be left answerable rather than destroyed, or the \
             remedy below would need the peer to start again"
        );

        // ---- The remedy, which is one round trip -----------------------
        //
        // The query the mint queued, answered the way a homeserver holding
        // this identity answers: all three key maps for this account, and
        // the account's other device alongside them, since an answer naming
        // no device of the account retires the ones it omits and this flow
        // is with one of them.
        mark_request_sent(
            &confirming.id,
            &serde_json::json!({
                "device_keys": { ACCOUNT: { OTHER_DEVICE: other_keys } },
                "failures": {},
                "master_keys": { ACCOUNT: identity["master_key"] },
                "self_signing_keys": { ACCOUNT: identity["self_signing_key"] },
                "user_signing_keys": { ACCOUNT: identity["user_signing_key"] },
            })
            .to_string(),
        )
        .await
        .expect("the confirming answer must be accepted");
        let confirmed = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            !confirmed.identity_publication_pending,
            "the server has asserted this identity, so the record must go: {confirmed:?}"
        );
        accept_flow(&flow)
            .await
            .expect("the same invitation is answerable once the publication is confirmed");

        // Cancelled rather than left live: the peer is holding a flow open
        // and this test is the only thing that can close it.
        cancel_flow(&flow)
            .await
            .expect("a live flow can be refused");
    }));
}
