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
    accept_flow, cancel_flow, create_identity, create_machine, flow_stage, identity_status,
    in_runtime, mark_request_sent, offer_codes, read_code, share_scope_key, submit_scanned_code,
    take_outgoing_requests, CodeCapabilities, CryptoSignal, FlowId, FlowStage, MachineConfig,
    MachineError,
};
use matrix_sdk_common::ruma::events::key::verification::VerificationMethod;
use matrix_sdk_common::ruma::OwnedUserId;
use matrix_sdk_crypto::OlmMachine;

#[path = "scanned/harness.rs"]
mod harness;
use harness::{
    cross_signed_machine, deliver_verification_request, drain_signals, drain_to_quiet,
    every_method, no_signal, one_of, pump_to_bare, queried_users, settle_key_upload, subscribe,
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
/// Another device of the library's own account.
///
/// The control for the *other* half of that pair. `IdentityNotKnown` and
/// `PeerIdentityNotKnown` are decided by one branch on whether the flow's
/// other end is us, and against a peer alone that branch can be deleted
/// outright with nothing noticing. A flow with this device is the only way
/// to reach its first arm.
const ALICE_OTHER_DEVICE: &str = "ALICESECOND";
/// A peer whose device the library has never been told about. The control
/// for the refusal that says so: without him, "this side holds no record of
/// that device" and "the keys in that code are not that device's" would be
/// the same assertion, and they call for opposite things.
const DAVE: &str = "@dave:example.org";
const DAVE_DEVICE: &str = "DAVEDEVICE";
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

/// A flow identifier too long to fit in the symbol upstream builds.
///
/// Not an arbitrary large number. `matrix-sdk-qrcode` fixes every symbol at
/// version 7 with error correction `L`
/// (`matrix-sdk-qrcode-0.18.0/src/utils.rs:69-72`), which holds 154 bytes,
/// and the payload around the identifier is about ninety of them. Anything
/// past roughly sixty therefore cannot be drawn. Two hundred is comfortably
/// over without being absurd -- a transaction identifier is a free-form
/// string and the other side chooses it.
fn an_unencodable_flow_id() -> String {
    "z".repeat(200)
}

/// The to-device event a device of this account sends to open a flow.
///
/// Hand-built, which is the point: every identifier in a flow this library
/// did not start comes from the other side, and upstream mints its own when
/// asked, so a transaction id this long cannot be produced by asking. A
/// homeserver relays whatever a client sent.
fn an_invitation_naming(flow_id: &str, from_device: &str) -> serde_json::Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("this machine's clock is after 1970")
        .as_millis();
    serde_json::json!({
        "sender": ALICE,
        "type": "m.key.verification.request",
        "content": {
            "from_device": from_device,
            "transaction_id": flow_id,
            // Every method, so nothing below is refused for the negotiation
            // rather than for the reason it is about.
            "methods": [
                "m.sas.v1",
                "m.qr_code.show.v1",
                "m.qr_code.scan.v1",
                "m.reciprocate.v1",
            ],
            // Upstream drops an invitation older than ten minutes, so this
            // has to be now rather than a fixed literal.
            "timestamp": now,
        },
    })
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
        // The product asks to take part in verification by a scannable code.
        // Off until it does, and off is byte for byte the wire this library
        // put out before codes existed, so without this line every flow
        // below negotiates the short string alone and nothing here can
        // happen. `tests/qr_announcement.rs` is where that default is the
        // subject rather than the setting.
        offer_codes(CodeCapabilities {
            can_show: true,
            can_scan: true,
        });

        // ---- The counterparties ----------------------------------------
        let bob = cross_signed_machine(BOB, BOB_DEVICE).await;
        // Another device of the library's own account. A bare machine, so
        // its keys are real and upstream will store them; a hand-written
        // device would be dropped for a bad self-signature and the self flow
        // below would fail to start for a reason that is not its subject.
        let account: OwnedUserId = ALICE.parse().expect("a literal user id parses");
        let alice_other: matrix_sdk_common::ruma::OwnedDeviceId = ALICE_OTHER_DEVICE.into();
        let sibling = OlmMachine::new(&account, &alice_other).await;
        settle_key_upload(&sibling).await;
        let sibling_keys =
            serde_json::to_value(harness::device_keys_of(&sibling, &account, &alice_other).await)
                .expect("upstream device keys serialise");

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
        // identity. Kept for later: it is what lifts `create_identity`'s
        // first gate, in the second phase below.
        let own_query = batch
            .iter()
            .find(|request| {
                request.kind == "keys_query"
                    && queried_users(&request.body).iter().any(|u| u == ALICE)
            })
            .expect("a fresh machine must owe a key query for its own account");
        // Naming the account's other device and no signing identity: the
        // second half is what lifts `create_identity`'s ordering gate in
        // phase two, and the first is what makes a flow with our own other
        // device possible at all.
        mark_request_sent(
            &own_query.id,
            &serde_json::json!({
                "device_keys": { ALICE: { ALICE_OTHER_DEVICE: sibling_keys.clone() } },
            })
            .to_string(),
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

        // And the account's other device has to know this one before it can
        // answer.
        sibling
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

        // ---- The three vocabularies, told apart --------------------------
        //
        // "You pointed the camera at the wrong thing", "that code is for a
        // different verification" and "those bytes did not arrive intact"
        // are three different things to say to a person, and the design's
        // section 4 requires all three to reach a product separately. They
        // arrived as one error until the payload crossed to TypeScript;
        // these four assertions are what hold them apart now, and each of
        // them failed against the code that folded them.
        //
        // Every one of these is refused before any identity is consulted,
        // so the phase this test is in changes none of them.

        // A well-formed code, for a verification that is not this one.
        // Upstream reads the flow id before it looks at any identity.
        assert_eq!(
            submit_scanned_code(&flow, &payload_naming("a-flow-that-is-not-this-one"))
                .await
                .expect_err("a code for another flow cannot be scanned into this one"),
            MachineError::ScannedCodeForAnotherFlow,
            "a code for another flow must not arrive as the identity refusal above, \
             nor as the two decoding refusals below: nothing is damaged and nothing \
             is suspicious, and the answer is to scan the other screen"
        );

        // Not one of these codes at all. Refused before anything reaches
        // the flow: turning bytes into a code is a separate, earlier step
        // with an error type upstream's scan error does not wrap.
        assert_eq!(
            submit_scanned_code(&flow, b"this is not a code")
                .await
                .expect_err("bytes that are not a code cannot be scanned"),
            MachineError::ScannedCodeUnrecognised,
            "a payload with no header of ours must not arrive as the identity \
             refusal above: a person who pointed a camera at a link and a person \
             whose account is not set up need to be told different things"
        );

        // A code whose version this library does not speak. Grouped with
        // the line above rather than with the two below, deliberately:
        // nothing here is damaged, this is simply not a code we can use.
        let mut from_the_future = payload_naming(&flow.0);
        from_the_future[6] = 0x03;
        assert_eq!(
            submit_scanned_code(&flow, &from_the_future)
                .await
                .expect_err("a code from a version this library does not speak cannot be scanned"),
            MachineError::ScannedCodeUnrecognised,
            "a version this library does not implement is not a damaged payload, \
             and telling a person to scan again would send them round a loop that \
             cannot end"
        );

        // **The scanner hazard, driven rather than described.** A product
        // whose scanner hands back a decoded `String` has already lost this
        // payload: it is binary, and a string round trip replaces every byte
        // that is not valid text. This is that exact round trip, and what
        // comes back must say the bytes did not survive -- not that the
        // person aimed badly, and not that the code was for something else.
        let through_a_string = String::from_utf8_lossy(&payload_naming(&flow.0))
            .as_bytes()
            .to_vec();
        assert_ne!(
            through_a_string,
            payload_naming(&flow.0),
            "the round trip must actually damage the payload, or the assertion \
             below would be testing nothing"
        );
        assert_eq!(
            submit_scanned_code(&flow, &through_a_string)
                .await
                .expect_err("a payload that went through a string cannot be scanned"),
            MachineError::ScannedCodeMalformed,
            "a mangled payload must say so. Observed: the two ed25519 keys no \
             longer decompress to points on the curve, which upstream reports as \
             a decoding failure and this library must report as damage rather \
             than as a wrong code"
        );

        // ---- The four arms that argued for themselves and were held by
        // ---- nothing
        //
        // Upstream reports seven decoding failures and this library sorts
        // them into two of the sentences above. Three of the seven were
        // asserted: the header, the version and the keys. The other four
        // could be moved across the boundary between "you aimed at the wrong
        // thing" and "the bytes did not survive" **all at once**, and the
        // whole workspace stayed green. The doc comments on the production
        // match argue at length about two of them in particular, and an
        // argument in a comment with nothing underneath it is the shape this
        // repository keeps finding.

        // A mode byte this library does not implement. Grouped with the
        // header and the version, and this is the arm whose comment says
        // why: a client speaking a revision of the format we do not have is
        // not a damaged payload, and telling a person to scan again sends
        // them round a loop that cannot end.
        let mut unknown_mode = payload_naming(&flow.0);
        unknown_mode[7] = 0x09;
        assert_eq!(
            submit_scanned_code(&flow, &unknown_mode)
                .await
                .expect_err("a mode this library does not implement cannot be scanned"),
            MachineError::ScannedCodeUnrecognised,
            "an unknown mode is not one of these codes, in the sense that matters: \
             nothing a person does with the camera makes it readable"
        );

        // Bytes that stop early. The likeliest of all of these in the field,
        // because it is what a half-read scan produces, and the arm whose
        // comment says a payload too short to carry a header at all is
        // damage rather than somebody else's square.
        let cut_short = payload_naming(&flow.0)[..40].to_vec();
        assert_eq!(
            submit_scanned_code(&flow, &cut_short)
                .await
                .expect_err("a payload that stops mid-key cannot be scanned"),
            MachineError::ScannedCodeMalformed,
            "a truncated payload must be reported as damage: the answer is to scan \
             the same code again, which is exactly the answer an unrecognised code \
             must not be given"
        );

        // Two bytes short of a code, which never even reaches the header
        // check. Asserted beside the one above because they take different
        // routes to the same refusal, and because the comment on this arm
        // claims this case specifically.
        assert_eq!(
            submit_scanned_code(&flow, b"MA")
                .await
                .expect_err("bytes that stop before a header cannot be scanned"),
            MachineError::ScannedCodeMalformed,
            "bytes that run out before the header is even read are damage rather \
             than a code somebody else wrote"
        );

        // A flow identifier that is not text. Reachable from a payload whose
        // header, version and mode are all ours, which is what makes it
        // damage rather than a foreign code.
        let mut unreadable_identifier = payload_naming(&flow.0);
        unreadable_identifier[10] = 0xff;
        assert_eq!(
            submit_scanned_code(&flow, &unreadable_identifier)
                .await
                .expect_err("a payload whose identifier is not text cannot be scanned"),
            MachineError::ScannedCodeMalformed,
            "an identifier that is not text arrives inside an otherwise perfectly \
             formed code, so it is damage to those bytes and not a different \
             format"
        );

        // A shared secret too short to be one. The last of the seven, and
        // the one a partial read of the tail produces.
        let full = payload_naming(&flow.0);
        let clipped_secret = full[..full.len() - 10].to_vec();
        assert_eq!(
            submit_scanned_code(&flow, &clipped_secret)
                .await
                .expect_err("a payload whose secret is too short cannot be scanned"),
            MachineError::ScannedCodeMalformed,
            "a secret shorter than the format allows is the tail of a code that did \
             not all arrive"
        );

        // ---- The condition that is none of the four, and cannot be reached
        //
        // Upstream has a fifth answer for a scanned code:
        // `ScanError::MissingDeviceKeys`, raised when this side holds no
        // record of the other device. It needs the opposite of what
        // `ScannedCodeRefused` tells a product to do -- a key query and the
        // very same code again, rather than refusing and starting over -- so
        // it is mapped to `UnknownDevice`, which is this library's existing
        // name for exactly that remedy.
        //
        // **Nothing here can produce it, and this is why**, because a
        // production arm nobody can reach is worth saying so about rather
        // than leaving as an implied claim. A code is only scanned into a
        // flow, and a flow only exists in one of two ways. Outbound,
        // `request_flow` refuses an unknown device before any flow is
        // created. Inbound, the invitation itself never becomes a flow: an
        // event from a device this library has no record of is dropped
        // before it reaches the registry, which is what the two deliveries
        // below measure.
        //
        // Dave is the control for that. He is never taught to this library,
        // and he knows this library's device because a peer cannot address
        // an invitation without one.
        let dave_user: OwnedUserId = DAVE.parse().expect("a literal user id parses");
        let dave_device: matrix_sdk_common::ruma::OwnedDeviceId = DAVE_DEVICE.into();
        let dave = OlmMachine::new(&dave_user, &dave_device).await;
        settle_key_upload(&dave).await;
        let dave_device_keys =
            serde_json::to_value(harness::device_keys_of(&dave, &dave_user, &dave_device).await)
                .expect("upstream device keys serialise");
        dave.mark_request_as_sent(
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

        let library_user: OwnedUserId = ALICE.parse().expect("a literal user id parses");
        let library_device = dave
            .get_device(&library_user, ALICE_DEVICE.into(), None)
            .await
            .expect("the peer's store must be readable")
            .expect("the peer has just been told about this library's device");
        let (unknown_sender, invitation) =
            library_device.request_verification_with_methods(every_method());
        deliver_verification_request(&invitation, DAVE, ALICE, ALICE_DEVICE).await;
        let from_a_stranger = FlowId(unknown_sender.flow_id().as_str().to_string());
        assert_eq!(
            flow_stage(&from_a_stranger)
                .await
                .expect_err("an invitation from an unknown device must not become a flow"),
            MachineError::UnknownFlow,
            "an invitation from a device this library has no record of never \
             reaches the registry, which is what makes upstream's \
             `MissingDeviceKeys` unreachable from this surface: there is no flow \
             to scan a code into"
        );

        // The control, and the reason the assertion above is about the
        // device record rather than about the delivery path. The same peer,
        // the same call, the same relay: the only thing that changes is that
        // this library has now been told what device Dave is.
        teach_alice_about(
            &[DAVE],
            serde_json::json!({
                "device_keys": { DAVE: { DAVE_DEVICE: dave_device_keys } },
            }),
        )
        .await;
        let (known_sender, invitation) =
            library_device.request_verification_with_methods(every_method());
        deliver_verification_request(&invitation, DAVE, ALICE, ALICE_DEVICE).await;
        let from_a_known_device = FlowId(known_sender.flow_id().as_str().to_string());
        assert_eq!(
            flow_stage(&from_a_known_device)
                .await
                .expect("an invitation from a known device must become a flow"),
            FlowStage::Requested,
            "the delivery path itself works, so the refusal above is about the \
             device record and nothing else"
        );
        cancel_flow(&from_a_known_device)
            .await
            .expect("a live flow can be refused");

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
            MachineError::PeerCannotScan,
            "a flow whose peer cannot scan must not be reported as a stage: waiting \
             will never help, and the answer is to compare a short string instead. \
             Nor as `CodeNotOffered`, which this answered until the code switch \
             stopped being one boolean: that name says the fault is this build's \
             own announcement, and this side announced everything it has"
        );
        cancel_flow(&sas_only)
            .await
            .expect("a live flow can be refused");
        pump_to_bare(&bob.peer, ALICE, BOB, BOB_DEVICE).await;

        // ---- The same refusal about our own account ---------------------
        //
        // `read_code` decides between two named refusals on one branch:
        // whether the identity the code would carry is this account's or the
        // other end's. Every assertion so far has been about somebody else,
        // and against those alone the branch can be deleted outright -- both
        // arms would answer `PeerIdentityNotKnown` and nothing would notice.
        // A flow with a device of our own account is the only way to reach
        // the first arm.
        //
        // The counterparty here is a second device of this same account, so
        // the identity upstream looks for is ours, and this account has
        // none.
        let with_our_own = ready_flow(&sibling, ALICE, ALICE_OTHER_DEVICE, every_method()).await;
        assert_eq!(
            read_code(&with_our_own)
                .await
                .expect_err("a code for our own account needs our own identity"),
            MachineError::IdentityNotKnown,
            "our account having no identity is not the other user having none: the \
             first is fixed here by `create_identity` and the second cannot be \
             fixed here at all, and a product told the wrong one either sets up an \
             identity it already has or waits for one that will never arrive"
        );
        cancel_flow(&with_our_own)
            .await
            .expect("a live flow can be refused");
        pump_to_bare(&sibling, ALICE, ALICE, ALICE_OTHER_DEVICE).await;

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

        create_identity()
            .await
            .expect("an account with no identity may mint one");

        // **The publication is finished here, not drained and dropped.**
        // Minting records that this store holds an identity no homeserver
        // has accepted, and every door into a self-verification refuses
        // while that record stands: from inside a process, an identity this
        // device holds and has never seen accepted cannot be told apart from
        // one the account has since replaced. `accept_flow` below is one of
        // those doors, because the invitation it answers comes from a device
        // of this same account.
        //
        // Reporting the upload does not clear the record and is not meant
        // to: the two bodies this library cannot tell from a successful
        // upload are exactly what a dropped connection hands a product. What
        // clears it is the query the mint queues behind the publication,
        // answered the way a homeserver that accepted it would answer, which
        // is the sequence a product runs and the one this phase now runs.
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
                .expect("a publication response must be accepted");
        }
        // All three key maps, which is what a homeserver holding this
        // identity sends and what upstream needs to store one, and the
        // account's other device alongside them: an answer naming no device
        // of the account would retire the sibling this phase's own flow is
        // with, and the refusal below would then be about a device this
        // library had forgotten.
        mark_request_sent(
            &confirming.id,
            &serde_json::json!({
                "device_keys": { ALICE: { ALICE_OTHER_DEVICE: sibling_keys } },
                "failures": {},
                "master_keys": { ALICE: identity["master_key"] },
                "self_signing_keys": { ALICE: identity["self_signing_key"] },
                "user_signing_keys": { ALICE: identity["user_signing_key"] },
            })
            .to_string(),
        )
        .await
        .expect("the confirming answer must be accepted");

        let minted = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            minted.private_keys_held,
            "the refusal below is about the *other* user's identity, so this one \
             must be in place or it would pass for the reason phase one tested"
        );
        assert!(
            !minted.identity_publication_pending,
            "and the publication must be confirmed, or the `accept_flow` below is \
             refused for holding an identity no homeserver has accepted and this \
             phase measures that refusal instead of the one it is about: {minted:?}"
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

        // ---- An identifier that cannot be drawn -------------------------
        //
        // The last refusal `read_code` can give, and the only one this side
        // never chooses: upstream fixes the symbol at a version that holds
        // 154 bytes, and about ninety of those are spent before the flow
        // identifier. Ours are ordinary transaction ids and always fit. The
        // other side's are whatever the other side sent, which is why this
        // is reachable at all and why it is reported as a malformed
        // identifier rather than as a stage or a store failure.
        //
        // Driven through `accept_flow`, because a flow this library started
        // cannot have an identifier this library did not mint.
        let unencodable = an_unencodable_flow_id();
        harness::deliver_to_library(vec![an_invitation_naming(&unencodable, ALICE_OTHER_DEVICE)])
            .await;
        let oversized = FlowId(unencodable);
        assert_eq!(
            flow_stage(&oversized)
                .await
                .expect("an invitation from a device of this account builds a flow"),
            FlowStage::Requested,
            "the hand-built invitation must have been accepted by upstream, or the \
             refusal below would be about a flow that never existed"
        );
        accept_flow(&oversized)
            .await
            .expect("an invitation from a known device can be agreed to");
        take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        assert_eq!(
            read_code(&oversized)
                .await
                .expect_err("a flow identifier this long cannot be drawn"),
            MachineError::MalformedIdentifier {
                detail: "flow id".to_string()
            },
            "a code that cannot be encoded must name what could not be encoded. \
             Everything else about this flow is in order -- both identities are \
             present, both sides offered to scan -- so any other refusal would \
             send a product looking at the wrong thing"
        );
        cancel_flow(&oversized)
            .await
            .expect("a live flow can be refused");
        take_outgoing_requests()
            .await
            .expect("the pump must be drainable");

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

        // ---- The fourth scanning refusal, which needs both identities ----
        //
        // A well-formed code, naming *this* flow, carrying keys that belong
        // to nobody. Everything upstream checks before the keys now passes:
        // the flow id matches, Bob's device is known, this account has an
        // identity and so has Bob. What is left is the comparison the whole
        // method exists for, and it fails.
        //
        // This is what `ScannedCodeRefused` means now that the three
        // refusals above have names of their own, and it is the one of the
        // four that can mean something is wrong rather than that a camera
        // was aimed badly. Unreachable in phase one, where the identity
        // refusal comes first, which is why it is asserted here.
        let with_bob = ready_flow(&bob.peer, BOB, BOB_DEVICE, every_method()).await;
        assert_eq!(
            submit_scanned_code(&with_bob, &payload_naming(&with_bob.0))
                .await
                .expect_err("a code carrying keys nobody holds cannot be scanned"),
            MachineError::ScannedCodeRefused,
            "a code for this flow whose keys are not this flow's must not arrive as \
             any of the three refusals above: those say a person aimed a camera \
             badly, and this one is what an interposed party would look like"
        );

        // ---- And what a refusal announces, which is nothing ----------------
        //
        // **A flow that was refused or that timed out tells a subscriber
        // nothing at all**, for a comparison as much as for a code. That is
        // older than codes and is deliberate rather than overlooked, but
        // until this phase existed it was a sentence in three doc comments
        // and a property no test observed. A sentence cannot notice when it
        // stops being true: a later change that started announcing on
        // cancel, or that stopped announcing at all, would have left every
        // test in this repository green.
        //
        // Subscribed here rather than at the top of this file on purpose.
        // Everything above runs with no observer installed, which is the
        // shape those refusals were written against and the shape in which
        // `announce_state_changes` returns before it touches anything.
        subscribe();
        // One pass with nothing in it first, and it is not decoration. This
        // account minted a signing identity above, and M4's arrival latch
        // fires on the first announcement pass that has somebody to announce
        // to -- so without this the very next assertion sees a `TrustChanged`
        // for this account in the same vector as the invitation it is about.
        // Watched: removing these two lines fails with exactly that pair.
        //
        // **Where in the vector is deliberately not stated.** `emit_crypto`
        // detaches every signal into its own task, so two signals from one
        // pass have no ordering relationship at all; both orders have been
        // observed. An earlier version of this comment named one of them.
        harness::deliver_to_library(Vec::new()).await;
        drain_to_quiet();

        // The positive half, first, and it is what stops the negative half
        // being vacuous. A `no_signal` alone passes just as well against a
        // channel that was never installed as against one that correctly had
        // nothing to say, and this file had never installed one.
        let inbound = FlowId("refusal-silence-transaction-id".to_string());
        harness::deliver_to_library(vec![an_invitation_naming(&inbound.0, ALICE_OTHER_DEVICE)])
            .await;
        assert_eq!(
            drain_signals("an invitation from another device of this account"),
            vec![CryptoSignal::VerificationRequested {
                user: ALICE.to_string(),
                device_id: ALICE_OTHER_DEVICE.to_string(),
                flow_id: inbound.0.clone(),
            }],
            "the channel has to be able to deliver here, or the silence asserted \
             below would be the silence of a channel nobody installed"
        );

        // And now the refusals. One flow this side never answered and one it
        // had agreed to, so the assertion covers a flow refused before it
        // began as well as one refused after.
        cancel_flow(&inbound)
            .await
            .expect("an invitation can be refused");
        cancel_flow(&with_bob)
            .await
            .expect("a live flow can be refused");
        take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        harness::deliver_to_library(Vec::new()).await;
        no_signal(
            "a refused flow is not a state change this channel reports, so a product \
             that waits on it waits for ever and has to read the stage instead",
        );
    }));
}
