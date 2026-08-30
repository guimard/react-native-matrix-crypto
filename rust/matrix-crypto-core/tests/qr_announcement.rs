//! What this library says it can do, read off the wire rather than off the
//! constant that decides it.
//!
//! # The criterion this file exists for
//!
//! Verification by a scannable code needs both sides to announce their half
//! before either can produce one, so making codes work at all means saying
//! two more things on every flow this library opens or answers. Said
//! unconditionally, that lands on consumers who will never scan anything: a
//! peer's client is told this side can scan, shows its user a code, asks
//! them to point a camera at it, and nothing on this end can read it -- with
//! no error reaching the product, because nothing was asked of this library.
//!
//! So it is not unconditional. `offer_scanning` is off until a product calls
//! it, and **the first thing this file asserts is that a build which never
//! calls it puts out the wire it put out before codes existed.** That
//! criterion was in the design, was struck from it as unachievable, and was
//! restored by the owner on 2026-08-30 once it turned out to be one runtime
//! `Vec` away. It never had a test. This is the test.
//!
//! # Three call sites, and the wire is the only place they meet
//!
//! `request_flow`, `request_self_flow` and `accept_flow` each tell the other
//! side what this library can do. A switch that reached two of the three
//! would leave one direction quietly behaving the old way, which is the
//! same half-working this milestone spent its effort avoiding elsewhere.
//! Two of them are here; `request_self_flow` is asserted the same way in
//! `qr_self_new_login_shows.rs`, which is the file that has an account with
//! another device to fan out to.
//!
//! # Off is not merely quiet
//!
//! Upstream refuses to build a code unless *both* sides announced their half
//! (`verification/requests.rs:1222-1228`), so with this off a peer's own
//! `generate_qr_code` returns nothing and its client falls through to the
//! short string. That is observed here rather than argued, and it is
//! observed against a pair of accounts where **everything else a code needs
//! is already in place** -- both identities minted, both published, each
//! known to the other -- so the nothing it returns can only be the
//! announcement.

use matrix_crypto_core::{
    accept_flow, bootstrap_identity, cancel_flow, create_machine, flow_stage, identity_status,
    in_runtime, mark_request_sent, offer_scanning, read_code, request_flow, share_scope_key,
    take_outgoing_requests, FlowId, FlowStage, MachineConfig, MachineError,
};
use matrix_sdk_common::ruma::events::key::verification::VerificationMethod;
use matrix_sdk_common::ruma::OwnedUserId;

#[path = "scanned/harness.rs"]
mod harness;
use harness::{
    cross_signed_machine, deliver_to_bare, deliver_verification_request, every_method,
    methods_announced, one_of, pump_to_bare, queried_users,
};

const ALICE: &str = "@alice:example.org";
const ALICE_DEVICE: &str = "ALICEDEVICE";
const BOB: &str = "@bob:example.org";
const BOB_DEVICE: &str = "BOBDEVICE";
const SCOPE: &str = "!announcement:example.org";

const NO_IDENTITY: &str = r#"{"device_keys":{"@alice:example.org":{}}}"#;

/// What every release of this library before scannable codes announced, and
/// what a build that never asks for them must still announce.
///
/// Written out rather than referred to. A test that compared the library's
/// list against the library's own constant would pass whatever that constant
/// became.
const BEFORE_CODES: &[&str] = &["m.sas.v1"];

/// And what asking for them adds.
const WITH_CODES: &[&str] = &[
    "m.sas.v1",
    "m.qr_code.show.v1",
    "m.qr_code.scan.v1",
    "m.reciprocate.v1",
];

#[test]
fn a_build_that_never_asks_for_codes_announces_what_it_always_did() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(in_runtime(async move {
        let alice_user: OwnedUserId = ALICE.parse().expect("a literal user id parses");

        // ---- Everything a code needs, except the announcement ------------
        //
        // Both accounts cross-signed and each knowing the other's identity,
        // so that when a code fails to appear below there is exactly one
        // thing left that could have stopped it.
        let bob = cross_signed_machine(BOB, BOB_DEVICE).await;

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

        bootstrap_identity()
            .await
            .expect("an account with no identity may mint one");
        assert!(
            identity_status()
                .await
                .expect("reading the identity status must not fail")
                .private_keys_held,
            "this file's whole point is that the announcement is the only thing \
             missing, so everything else a code needs has to be in place"
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
        for request in &published {
            mark_request_sent(&request.id, "{}")
                .await
                .expect("a bootstrap publication response must be accepted");
        }

        bob.peer
            .mark_request_as_sent(
                &matrix_sdk_common::ruma::TransactionId::new(),
                &harness::keys_query_response(
                    &serde_json::json!({
                        "device_keys": { ALICE: { ALICE_DEVICE: alice_device_keys } },
                        "master_keys": { ALICE: identity.get("master_key") },
                        "self_signing_keys": { ALICE: identity.get("self_signing_key") },
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

        // ================================================================
        // The default: nothing has asked for codes
        // ================================================================

        // ---- What an invitation this side sends says --------------------
        let flow = request_flow(BOB, BOB_DEVICE)
            .await
            .expect("a device the machine has been told about can be asked to verify");
        let batch = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let invitation = one_of(
            &batch,
            "to_device",
            "the invitation must be queued for the pump",
        );
        assert_eq!(
            methods_announced(&invitation.body, BOB, BOB_DEVICE),
            BEFORE_CODES,
            "a product that never asked for scannable codes must send the invitation \
             every release before this one sent, byte for byte. The whole list, not \
             a membership test: a list that had grown one entry would still contain \
             the short string, and growing by one entry is the change this exists to \
             catch"
        );
        mark_request_sent(&invitation.id, "{}")
            .await
            .expect("a to-device response must be accepted");
        let event = harness::relay_to(&invitation.body, ALICE, BOB, BOB_DEVICE)
            .expect("the invitation addresses the other user's device");
        deliver_to_bare(&bob.peer, vec![event]).await;

        let bob_request = bob
            .peer
            .get_verification_request(&alice_user, &flow.0)
            .expect("the other user must have received the invitation");
        let ready = bob_request
            .accept_with_methods(every_method())
            .expect("a fresh invitation can be accepted");
        deliver_verification_request(&ready, BOB, ALICE, ALICE_DEVICE).await;
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Ready,
            "the other side agreed, so this is a flow where a code would be produced \
             if either side could"
        );

        // ---- Off makes a code unavailable, not merely unadvertised ------
        //
        // The other side offered everything and holds everything: his own
        // identity, ours, and our device. The only thing missing is our half
        // of the announcement, so this `Ok(None)` has exactly one cause.
        assert!(
            bob_request
                .generate_qr_code()
                .await
                .expect("the other user's store must be readable")
                .is_none(),
            "a peer must not be able to build a code for a client that did not ask \
             to scan. If this ever returns a code, that peer's client shows its user \
             a square and asks them to have it scanned, nothing here can read it, \
             and no error reaches anybody -- the failure lands on a person who did \
             nothing wrong and is invisible to both products"
        );
        assert_eq!(
            read_code(&flow)
                .await
                .expect_err("a build that did not ask for codes cannot show one"),
            MachineError::CodeNotOffered,
            "and this side must say so by name rather than reporting a stage or an \
             identity. This is the arm a developer meets on their first test run, \
             which is the whole reason the default is off"
        );

        cancel_flow(&flow)
            .await
            .expect("a live flow can be refused");
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;

        // ---- What an agreement this side sends says ---------------------
        //
        // The third call site, and the one no test drove until now.
        // `request_flow` above says what this library can do when it asks;
        // this says it when it answers, and only a flow the other person
        // opened reaches it.
        deliver_to_bare(&bob.peer, Vec::new()).await;
        let alice_device_handle = bob
            .peer
            .get_device(&alice_user, ALICE_DEVICE.into(), None)
            .await
            .expect("the other user's store must be readable")
            .expect("the other user knows this library's device");
        let (inbound, their_invitation) =
            alice_device_handle.request_verification_with_methods(every_method());
        deliver_verification_request(&their_invitation, BOB, ALICE, ALICE_DEVICE).await;

        let inbound_flow = FlowId(inbound.flow_id().as_str().to_string());
        accept_flow(&inbound_flow)
            .await
            .expect("an invitation from a known device can be agreed to");
        let batch = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let agreement = one_of(
            &batch,
            "to_device",
            "the agreement must be queued for the pump",
        );
        assert_eq!(
            methods_announced(&agreement.body, BOB, BOB_DEVICE),
            BEFORE_CODES,
            "answering an invitation must announce the same list as sending one. A \
             switch that reached the two calls that ask and not the one that answers \
             would leave every flow the other person started behaving the old way, \
             which is a product working for half its users and no way to tell which"
        );
        for request in &batch {
            mark_request_sent(&request.id, "{}")
                .await
                .expect("a to-device response must be accepted");
        }
        cancel_flow(&inbound_flow)
            .await
            .expect("a live flow can be refused");
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;

        // ================================================================
        // And once a product has asked
        // ================================================================

        offer_scanning(true);

        let flow = request_flow(BOB, BOB_DEVICE)
            .await
            .expect("a device the machine has been told about can be asked to verify");
        let batch = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let invitation = one_of(
            &batch,
            "to_device",
            "the invitation must be queued for the pump",
        );
        assert_eq!(
            methods_announced(&invitation.body, BOB, BOB_DEVICE),
            WITH_CODES,
            "asking for codes must reach the wire and not stop at a constant"
        );
        mark_request_sent(&invitation.id, "{}")
            .await
            .expect("a to-device response must be accepted");
        let event = harness::relay_to(&invitation.body, ALICE, BOB, BOB_DEVICE)
            .expect("the invitation addresses the other user's device");
        deliver_to_bare(&bob.peer, vec![event]).await;

        let bob_request = bob
            .peer
            .get_verification_request(&alice_user, &flow.0)
            .expect("the other user must have received the invitation");
        let ready = bob_request
            .accept_with_methods(every_method())
            .expect("a fresh invitation can be accepted");
        deliver_verification_request(&ready, BOB, ALICE, ALICE_DEVICE).await;

        // The mirror of the assertion above, on the same two machines with
        // the same keys and the same everything else. Only the switch moved.
        assert!(
            bob_request
                .generate_qr_code()
                .await
                .expect("the other user's store must be readable")
                .is_some(),
            "and once this side has asked, the same peer with the same keys must be \
             able to build the code it could not build a moment ago"
        );
        cancel_flow(&flow)
            .await
            .expect("a live flow can be refused");
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;

        // ---- And the call that answers, again ---------------------------
        deliver_to_bare(&bob.peer, Vec::new()).await;
        let (inbound, their_invitation) =
            alice_device_handle.request_verification_with_methods(every_method());
        deliver_verification_request(&their_invitation, BOB, ALICE, ALICE_DEVICE).await;
        let inbound_flow = FlowId(inbound.flow_id().as_str().to_string());
        accept_flow(&inbound_flow)
            .await
            .expect("an invitation from a known device can be agreed to");
        let batch = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let agreement = one_of(
            &batch,
            "to_device",
            "the agreement must be queued for the pump",
        );
        assert_eq!(
            methods_announced(&agreement.body, BOB, BOB_DEVICE),
            WITH_CODES,
            "the third call site must move with the other two"
        );

        // ---- And undoing it ---------------------------------------------
        //
        // A switch a product cannot turn back off is a latch, and a product
        // that stopped offering codes -- because it dropped its scanner, or
        // because a user turned the feature off -- would keep telling every
        // peer otherwise.
        //
        // The two lines before it are bookkeeping upstream forces: it
        // cancels a new request outright while another with the same user is
        // still in its map and not cancelled
        // (`verification/machine.rs:165-192`), and a request born cancelled
        // announces upstream's own default rather than the list it was built
        // with (`verification/requests.rs:230-237`). Refusing the live flow
        // and syncing is what a real client does between two verifications,
        // and without it this assertion reads a list nobody chose.
        for request in &batch {
            mark_request_sent(&request.id, "{}")
                .await
                .expect("a to-device response must be accepted");
        }
        cancel_flow(&inbound_flow)
            .await
            .expect("a live flow can be refused");
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;
        harness::deliver_to_library(Vec::new()).await;

        offer_scanning(false);
        let last = request_flow(BOB, BOB_DEVICE)
            .await
            .expect("a known device can be asked to verify again");
        let batch = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let invitation = one_of(
            &batch,
            "to_device",
            "the invitation must be queued for the pump",
        );
        assert_eq!(
            methods_announced(&invitation.body, BOB, BOB_DEVICE),
            BEFORE_CODES,
            "the switch must be a switch and not a latch: a product that stops \
             offering codes must stop announcing them, or every peer keeps being \
             told to hold up a screen at a client that no longer reads one"
        );
        cancel_flow(&last)
            .await
            .expect("a live flow can be refused");

        // The literals this file compares against are the names that go on
        // the wire, so they are checked against the names upstream writes
        // rather than against this repository's own spelling of them.
        assert_eq!(
            serde_json::to_value(VerificationMethod::QrCodeScanV1)
                .expect("an upstream method name serialises"),
            serde_json::json!("m.qr_code.scan.v1"),
        );
    }));
}
