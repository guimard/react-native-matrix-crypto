//! Every way asking for a scannable code, or handing one in, can fail.
//!
//! # The one this file was written for
//!
//! Upstream answers **seven** different conditions with the same `Ok(None)`
//! when it is asked to build a code, and the worst of them is the one this
//! milestone exists downstream of: *this device has no signing identity*.
//! Passed on as an absence, a person sees a screen with no code on it and no
//! reason given, and there is nothing for a product to say, because nothing
//! was said to it.
//!
//! That is not a hypothetical shape. It is the shape of the failure this
//! repository has found more than a dozen times, and the first assertion
//! below is the one that pins it: a device that has never bootstrapped asks
//! for a code and is told, by name, that it does not hold the private
//! signing keys -- which is exactly what M4's own `identity_status` says
//! about it, asserted here beside the refusal so the two cannot come to
//! disagree.
//!
//! # Which side is the library
//!
//! **Alice is the library**, driven only through this crate's public
//! surface against the one process-wide machine. Bob and Carol are bare
//! upstream machines standing in for third-party clients: Bob has minted a
//! signing identity and Carol has not, and that difference is what
//! separates two of the refusals below.
//!
//! # Why one test function
//!
//! One crypto machine per process, and these refusals need it in two
//! different states -- before Alice has an identity and after. Splitting
//! them into two `#[test]`s in this file would run them concurrently
//! against the same machine and the second state would arrive under the
//! first one's feet. The phases below are ordered, and each assertion says
//! what it is for.

use matrix_crypto_core::{
    bootstrap_identity, cancel_flow, create_machine, flow_stage, identity_status, in_runtime,
    mark_request_sent, read_code, share_scope_key, submit_scanned_code, take_outgoing_requests,
    FlowId, FlowStage, MachineConfig, MachineError,
};
use matrix_sdk_common::ruma::events::key::verification::VerificationMethod;
use matrix_sdk_common::ruma::OwnedUserId;
use matrix_sdk_crypto::OlmMachine;

#[path = "scanned/harness.rs"]
mod harness;
use harness::{
    cross_signed_machine, deliver_verification_request, every_method, one_of, pump_to_bare,
    queried_users, settle_key_upload,
};

/// The library.
const ALICE: &str = "@alice:example.org";
const ALICE_DEVICE: &str = "ALICEDEVICE";
/// A peer who has set cross-signing up, which is every Element user.
const BOB: &str = "@bob:example.org";
const BOB_DEVICE: &str = "BOBDEVICE";
/// A peer who has not. The control for `PeerIdentityNotKnown`: without her,
/// "the other user has no identity" and "nobody has an identity" would be
/// the same assertion.
const CAROL: &str = "@carol:example.org";
const CAROL_DEVICE: &str = "CAROLDEVICE";
/// Somewhere for the one call on the shipped surface that tracks a user to
/// point at. Nothing is ever encrypted to it.
const SCOPE: &str = "!refusals:example.org";

/// The two ed25519 keys and the secret from upstream's own documented
/// example, byte for byte (`matrix-sdk-qrcode-0.18.0/src/types.rs`, the
/// `from_bytes` doctest, which asserts they decode).
///
/// They belong to nobody. That is what they are for: every scan below is
/// meant to be refused, and a payload built from real keys of a real flow
/// would be refused for a different reason than the one being tested.
const A_KEY: &[u8] =
    b"kS /\x92i\x1e6\xcd'g\xf9#\x11\xd8\x8a\xa2\xf61\x05\x1b6\xef\xfc\xa4%\x80\x1a\x0c\xd2\xe8\x04";
const ANOTHER_KEY: &[u8] =
    b"\xbdR|\xf8n\x07\xa4\x1f\xb4\xcc3\x0eBT\xe7[~\xfd\x87\xd06B\xdfoVv%\x9b\x86\xae\xbcM";
const A_SECRET: &[u8] = b"SHARED_SECRET";

/// A payload that decodes cleanly and names `flow_id`.
///
/// Assembled here from the format the specification fixes rather than taken
/// from a flow, because the flows in this file cannot produce one: a peer
/// cannot build a code naming an identity this account does not have, which
/// is the very condition under test. Upstream's decoder reads a fixed
/// header, a version, a mode, a big-endian flow id length, the flow id, two
/// keys and the rest as the shared secret
/// (`matrix-sdk-qrcode-0.18.0/src/types.rs:206-217`), and that is what this
/// writes.
fn payload_naming(flow_id: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(b"MATRIX");
    payload.push(2);
    payload.push(harness::MODE_SELF_UNTRUSTED);
    payload.extend_from_slice(
        &u16::try_from(flow_id.len())
            .expect("a flow id in this test is a handful of bytes")
            .to_be_bytes(),
    );
    payload.extend_from_slice(flow_id.as_bytes());
    payload.extend_from_slice(A_KEY);
    payload.extend_from_slice(ANOTHER_KEY);
    payload.extend_from_slice(A_SECRET);
    payload
}

fn config(store_path: String) -> MachineConfig {
    MachineConfig {
        user_id: ALICE.to_string(),
        device_id: ALICE_DEVICE.to_string(),
        store_path,
        store_passphrase: Some("test-passphrase".to_string()),
    }
}

/// Teaches the library about some users' devices, and about their signing
/// identities where they published one.
///
/// `share_scope_key` first, and it is not decoration: upstream's
/// `mark_tracked_users_as_changed` skips every user it has never seen, so a
/// sync naming a stranger as changed routes nowhere and no key query is
/// ever issued for them. Tracking is the only thing on this library's
/// shipped surface that introduces a user, which `tests/two_parties.rs`
/// documents at length. Nothing is encrypted here; the call cannot deliver
/// anything, because no device of theirs is known yet, and that is the
/// point of making it.
async fn teach_alice_about(user_ids: &[&str], keys: serde_json::Value) {
    let tracked: Vec<String> = user_ids.iter().map(|user| user.to_string()).collect();
    share_scope_key(SCOPE, &tracked)
        .await
        .expect("tracking a user must not fail");
    let batch = take_outgoing_requests()
        .await
        .expect("the pump must be drainable");
    let query = batch
        .iter()
        .find(|request| {
            request.kind == "keys_query"
                && user_ids.iter().all(|wanted| {
                    queried_users(&request.body)
                        .iter()
                        .any(|asked| asked == wanted)
                })
        })
        .unwrap_or_else(|| {
            panic!(
                "a machine that has just started tracking users must ask about them; \
                 the batch carried {:?}",
                batch
                    .iter()
                    .map(|request| request.kind.as_str())
                    .collect::<Vec<_>>()
            )
        });
    mark_request_sent(&query.id, &keys.to_string())
        .await
        .expect("answering a key query must not fail");
}

/// Opens a flow against `peer` and drives it to the point where either side
/// could show a code, with the peer answering with `methods`.
async fn ready_flow(
    peer: &OlmMachine,
    peer_user: &str,
    peer_device: &str,
    methods: Vec<VerificationMethod>,
) -> FlowId {
    let flow = matrix_crypto_core::request_flow(peer_user, peer_device)
        .await
        .expect("a device the machine has been told about can be asked to verify");
    pump_to_bare(peer, ALICE, peer_user, peer_device).await;

    // Keyed by the *other* user of the flow, which from the peer's side is
    // the library. Keying it by the peer's own id finds nothing and reports
    // it as an invitation that never arrived.
    let library: OwnedUserId = ALICE.parse().expect("a literal user id parses");
    let request = peer
        .get_verification_request(&library, &flow.0)
        .expect("the peer must have received the invitation");
    let ready = request
        .accept_with_methods(methods)
        .expect("a fresh invitation can be accepted");
    deliver_verification_request(&ready, peer_user, ALICE, ALICE_DEVICE).await;

    assert_eq!(
        flow_stage(&flow).await.expect("the flow exists"),
        FlowStage::Ready,
        "the peer agreed, so the flow is where a code would be produced"
    );
    flow
}

#[test]
fn every_refusal_a_scannable_code_can_give_is_named() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(in_runtime(async move {
        // ---- The counterparties ----------------------------------------
        let bob = cross_signed_machine(BOB, BOB_DEVICE).await;
        let carol_user: OwnedUserId = CAROL.parse().expect("a literal user id parses");
        let carol_device: matrix_sdk_common::ruma::OwnedDeviceId = CAROL_DEVICE.into();
        let carol = OlmMachine::new(&carol_user, &carol_device).await;
        settle_key_upload(&carol).await;
        let carol_device_keys =
            serde_json::to_value(harness::device_keys_of(&carol, &carol_user, &carol_device).await)
                .expect("upstream device keys serialise");

        // ---- The library, which has never bootstrapped ------------------
        create_machine(config(store_path))
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

        // Alice's own account query, answered with an account that has no
        // identity. Kept for later: it is what lifts `bootstrap_identity`'s
        // first gate, in the second phase below.
        let own_query = batch
            .iter()
            .find(|request| {
                request.kind == "keys_query"
                    && queried_users(&request.body).iter().any(|u| u == ALICE)
            })
            .expect("a fresh machine must owe a key query for its own account");
        mark_request_sent(
            &own_query.id,
            &serde_json::json!({ "device_keys": { ALICE: {} } }).to_string(),
        )
        .await
        .expect("answering the account key query must not fail");

        // Both counterparties in one answer, because both are tracked by one
        // call. Bob published a signing identity and Carol published none,
        // which is the only difference between them and is what separates
        // two of the refusals below.
        teach_alice_about(
            &[BOB, CAROL],
            serde_json::json!({
                "device_keys": {
                    BOB: { BOB_DEVICE: bob.signed_device_keys },
                    CAROL: { CAROL_DEVICE: carol_device_keys },
                },
                "master_keys": { BOB: bob.master_key },
                "self_signing_keys": { BOB: bob.self_signing_key },
            }),
        )
        .await;

        // Bob has to know Alice's device before he can answer her.
        bob.peer
            .mark_request_as_sent(
                &matrix_sdk_common::ruma::TransactionId::new(),
                &harness::keys_query_response(
                    &serde_json::json!({
                        "device_keys": { ALICE: { ALICE_DEVICE: alice_device_keys.clone() } },
                    })
                    .to_string(),
                ),
            )
            .await
            .expect("the bare machine must accept a keys-query response");

        // ================================================================
        // Phase one: a device with no signing identity
        // ================================================================

        let before = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            !before.private_keys_held && !before.identity_known,
            "every assertion in this phase is about a device that has never \
             bootstrapped, and would pass for the wrong reason against one that \
             had: {before:?}"
        );

        let flow = ready_flow(&bob.peer, BOB, BOB_DEVICE, every_method()).await;

        // ---- THE ONE THIS FILE EXISTS FOR ------------------------------
        //
        // Upstream returns `Ok(None)` here and writes a warning nobody will
        // ever read. A product passing that on shows a person an empty
        // square and has nothing to say about it. What it gets instead is
        // the reason, in M4's own words, and the reason is actionable: this
        // device has to hold the account's private signing keys before it
        // can put the account's master key into a code.
        assert_eq!(
            read_code(&flow)
                .await
                .expect_err("a device with no private signing keys cannot build a cross-user code"),
            MachineError::PrivateKeysNotHeld,
            "showing a code without an identity must be a named refusal. Upstream \
             answers this with `Ok(None)` and a warning, which reaches a person as \
             a screen with no code on it and no reason given"
        );
        assert!(
            !identity_status()
                .await
                .expect("reading the identity status must not fail")
                .private_keys_held,
            "the refusal must name the same condition the status call reports; a \
             refusal that disagreed with `identity_status` would send a product to \
             fix something that is not broken"
        );

        // ---- Scanning refuses too, and says whose identity is missing ---
        //
        // A payload for *this* flow, so the flow id upstream checks first
        // matches and the refusal that comes back is the identity one.
        // Upstream names the user whose identity is missing, and here that
        // is us.
        assert_eq!(
            submit_scanned_code(&flow, &payload_naming(&flow.0))
                .await
                .expect_err("a device with no identity cannot scan"),
            MachineError::IdentityNotKnown,
            "scanning without an identity is refused by upstream and must arrive \
             named. `IdentityNotKnown` rather than `PeerIdentityNotKnown` because \
             upstream says which side it is and this is ours"
        );

        // ---- A payload for a different flow -----------------------------
        //
        // Upstream checks the flow id before it looks at any identity, so
        // this is refused for a reason that has nothing to do with the
        // phase this test is in.
        assert_eq!(
            submit_scanned_code(&flow, &payload_naming("a-flow-that-is-not-this-one"))
                .await
                .expect_err("a code for another flow cannot be scanned into this one"),
            MachineError::ScannedCodeRefused,
            "a code for another flow must not arrive as the identity refusal above"
        );

        // ---- A payload that is not one of these codes at all ------------
        //
        // Refused before anything reaches the flow: turning bytes into a
        // code is a separate, earlier step with an error type upstream's
        // scan error does not wrap.
        //
        // **Indistinguishable from the two lines above today, and that is a
        // scheduled fold rather than an accident.** "You pointed the camera
        // at the wrong thing", "that code is for a different verification"
        // and "those keys are not the ones expected" are three different
        // things to say to a person; the design's section 4 requires all
        // three to reach a product separately, and the task that crosses
        // the payload to TypeScript is where they separate. Asserted
        // together here so the day they separate, this is what has to be
        // updated.
        assert_eq!(
            submit_scanned_code(&flow, b"this is not a code")
                .await
                .expect_err("bytes that do not decode cannot be scanned"),
            MachineError::ScannedCodeRefused,
            "a payload that does not decode must not arrive as the identity \
             refusal above: a person who pointed a camera at the wrong thing and \
             a person whose account is not set up need to be told different things"
        );

        // Relayed, not merely drained: a refusal the peer never hears
        // leaves his side of the flow live, and the invitation below is
        // then a second one against a device that already has one open.
        cancel_flow(&flow)
            .await
            .expect("a live flow can be refused");
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;

        // ---- A peer that cannot scan ------------------------------------
        //
        // Answered with the one method this library announced before this
        // milestone, which is also all `matrix-nio` and every short-string-
        // only client announces. Nothing about identities has changed
        // between this flow and the one above, so the different answer can
        // only come from the negotiation.
        let sas_only =
            ready_flow(&bob.peer, BOB, BOB_DEVICE, vec![VerificationMethod::SasV1]).await;
        assert_eq!(
            read_code(&sas_only)
                .await
                .expect_err("a peer that did not offer to scan cannot be shown a code"),
            MachineError::CodeNotOffered,
            "a flow whose peer cannot scan must not be reported as a stage: waiting \
             will never help, and the answer is to compare a short string instead"
        );
        cancel_flow(&sas_only)
            .await
            .expect("a live flow can be refused");
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;

        // ---- A flow nobody has agreed to yet ----------------------------
        let unanswered = matrix_crypto_core::request_flow(BOB, BOB_DEVICE)
            .await
            .expect("a known device can be asked to verify");
        assert_eq!(
            flow_stage(&unanswered).await.expect("the flow exists"),
            FlowStage::Requested,
            "this assertion is about a flow the peer has not answered, and would \
             pass for the wrong reason against one that had"
        );
        assert_eq!(
            read_code(&unanswered)
                .await
                .expect_err("a flow nobody has agreed to has no code"),
            MachineError::WrongStage
        );
        cancel_flow(&unanswered)
            .await
            .expect("a live flow can be refused");
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;

        // ---- A flow that never existed ----------------------------------
        assert_eq!(
            read_code(&FlowId("not-a-flow".to_string()))
                .await
                .expect_err("no flow ever had that identifier"),
            MachineError::UnknownFlow
        );

        // ================================================================
        // Phase two: a device that has bootstrapped, and a peer that has not
        // ================================================================

        bootstrap_identity()
            .await
            .expect("an account with no identity may mint one");
        take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        assert!(
            identity_status()
                .await
                .expect("reading the identity status must not fail")
                .private_keys_held,
            "the refusal below is about the *other* user's identity, so this one \
             must be in place or it would pass for the reason phase one tested"
        );

        // Carol has to know Alice's device before she can answer.
        carol
            .mark_request_as_sent(
                &matrix_sdk_common::ruma::TransactionId::new(),
                &harness::keys_query_response(
                    &serde_json::json!({
                        "device_keys": { ALICE: { ALICE_DEVICE: alice_device_keys } },
                    })
                    .to_string(),
                ),
            )
            .await
            .expect("the bare machine must accept a keys-query response");

        let with_carol = ready_flow(&carol, CAROL, CAROL_DEVICE, every_method()).await;
        assert_eq!(
            read_code(&with_carol)
                .await
                .expect_err("a code cannot name an identity the other user does not have"),
            MachineError::PeerIdentityNotKnown,
            "the other user having no identity is not this device having none: the \
             first is fixed by the other person and the second by this one, and a \
             product that showed the same sentence for both would send half its \
             users to fix something that is not broken"
        );
    }));
}
