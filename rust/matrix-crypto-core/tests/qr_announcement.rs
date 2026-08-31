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
//! So it is not unconditional. `offer_codes` claims nothing until a product
//! calls it, and **the first thing this file asserts is that a build which
//! never calls it puts out the wire it put out before codes existed.** That
//! criterion was in the design, was struck from it as unachievable, and was
//! restored by the owner on 2026-08-30 once it turned out to be one runtime
//! `Vec` away. It never had a test. This is the test.
//!
//! # Saying one half of it, which is the thing it could not say
//!
//! `offer_codes` used to be a single boolean, so "codes" meant showing and
//! scanning together and a product with a screen and no scanner had to claim
//! a camera to get a code at all. On 2026-08-31 a product holding that shape
//! met a real Element Web client, which took the claim at its word, showed
//! its own code and waited. **The middle section below is that sentence
//! being said properly**, off the pump's own request body: showing, the
//! reciprocation a peer needs in order to answer, and no camera.
//!
//! # Three call sites, and the wire is the only place they meet
//!
//! `request_flow`, `request_self_flow` and `accept_flow` each tell the other
//! side what this library can do. A switch that reached two of the three
//! would leave one direction quietly behaving the old way, which is the
//! same half-working this milestone spent its effort avoiding elsewhere.
//! Two of them are here; `request_self_flow` is asserted the same way in
//! `qr_self_new_login_shows.rs`, which is the file that has an account with
//! another device to fan out to. All three are asserted for the show-only
//! answer as well as for the other two, because a switch that reached one
//! call site with two halves and another with one would announce a camera on
//! flows the other side opened and none on the flows this side did.
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
    accept_flow, cancel_flow, create_identity, create_machine, flow_stage, identity_status,
    in_runtime, mark_request_sent, offer_codes, read_code, request_flow, share_scope_key,
    take_outgoing_requests, CodeCapabilities, FlowId, FlowStage, MachineConfig, MachineError,
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

/// And what asking for both halves adds.
const WITH_CODES: &[&str] = &[
    "m.sas.v1",
    "m.qr_code.show.v1",
    "m.qr_code.scan.v1",
    "m.reciprocate.v1",
];

/// What a product that can draw a code and cannot read one says.
///
/// **`m.qr_code.scan.v1` is absent and that absence is the assertion.** With
/// it present a peer may answer by showing its own code and waiting for a
/// camera this product does not have, which is what a real Element Web
/// client did on hardware on 2026-08-31. Without it, that peer's own
/// `generate_qr_code` returns nothing and it has no choice but to scan.
///
/// `m.reciprocate.v1` is present although this side never sends that
/// message: it is the far side's permission to send one, and upstream's own
/// show-only default carries it (`verification/requests.rs:60-65`) while
/// mautrix-go refuses to scan without it. See `SHOWING_ONLY` in
/// `src/verification.rs` for the whole of that finding, including the part
/// no test here can watch.
///
/// Written out rather than referred to, like the two lists above and for the
/// same reason: a test that compared the library's list against the
/// library's own constant would pass whatever that constant became.
const SHOW_ONLY: &[&str] = &["m.sas.v1", "m.qr_code.show.v1", "m.reciprocate.v1"];

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

        create_identity()
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
        // The confirming query the mint queues behind the publication,
        // answered the way a homeserver that accepted it answers: all three
        // key maps for this account, and this device alongside them. Only
        // that clears the publication record, because reporting the upload
        // is the caller's own word and the two bodies this library cannot
        // tell from a success are what a dropped connection produces.
        let confirming = published
            .iter()
            .find(|request| {
                request.kind == "keys_query"
                    && queried_users(&request.body).iter().any(|u| u == ALICE)
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
                "device_keys": { ALICE: { ALICE_DEVICE: alice_device_keys.clone() } },
                "failures": {},
                "master_keys": { ALICE: identity["master_key"] },
                "self_signing_keys": { ALICE: identity["self_signing_key"] },
                "user_signing_keys": { ALICE: identity["user_signing_key"] },
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
            "and the identity must be published, which this file has said in words \
             since it was written and nothing has ever checked. Reporting the upload \
             is the caller's own word for it; what a homeserver says is the query the \
             mint queues behind the publication, and until that is answered every \
             door into a self-verification refuses this store"
        );

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
        // A product that can show a code and cannot scan one
        // ================================================================
        //
        // The answer that could not be given at all until this branch, and
        // the one the example app on the owner's desk needs: it draws a code
        // and has no scanner. Both call sites, because the flow a person
        // starts from Element arrives at the second one.

        offer_codes(CodeCapabilities {
            can_show: true,
            can_scan: false,
        });

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
            SHOW_ONLY,
            "a product that can draw a code and cannot read one must say exactly \
             that. The whole list, not a membership test: what makes this list right \
             is the entry that is missing from it, and no membership test can see an \
             absence"
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

        // ---- THE PEER HAS NO CHOICE BUT TO SCAN -------------------------
        //
        // The counterparty answered with every method it has, so it can show
        // a code as far as it is concerned. It cannot show one *here*,
        // because upstream tests the far side's list for
        // `m.qr_code.scan.v1` before it builds anything
        // (`verification/requests.rs:1222-1228`) and this side did not send
        // it. That is the whole mechanism: a claim withheld is a choice
        // removed, and the choice removed is the one that killed a flow on
        // hardware.
        assert!(
            bob_request
                .generate_qr_code()
                .await
                .expect("the other user's store must be readable")
                .is_none(),
            "a peer told this side has no camera must not be able to build a code \
             for it to read. If this ever returns a code, that peer's client shows \
             its user a square and asks them to have it scanned, and this product \
             has no scanner"
        );
        // And this side can still show one, which is the half that has to
        // keep working: a show-only product that could announce showing and
        // then not show would be worse off than before.
        read_code(&flow)
            .await
            .expect("a product that announced showing must be able to show");

        cancel_flow(&flow)
            .await
            .expect("a live flow can be refused");
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;
        harness::deliver_to_library(Vec::new()).await;

        // ---- And the call that answers ----------------------------------
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
            SHOW_ONLY,
            "and answering an invitation must withhold the camera too. This is the \
             call site a flow started from the other person's client reaches, which \
             is the one the hardware failure came through"
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
        harness::deliver_to_library(Vec::new()).await;

        // ================================================================
        // And once a product has asked for both halves
        // ================================================================

        offer_codes(CodeCapabilities {
            can_show: true,
            can_scan: true,
        });

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

        offer_codes(CodeCapabilities {
            can_show: false,
            can_scan: false,
        });
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
