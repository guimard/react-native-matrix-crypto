//! Two parties verify each other by comparing a short authentication string.
//!
//! # Which side is the library, and which is not
//!
//! The same asymmetry `tests/two_parties.rs` documents at length, and for
//! the same reason: this library holds one crypto machine per process, so
//! two parties cannot both be created through `create_machine`.
//!
//! * **Alice is the library.** Every operation attributed to her goes
//!   through this crate's public surface -- `request_flow`, `accept_flow`,
//!   `begin_comparison`, `flow_stage`, `read_material`, `confirm_flow`,
//!   `cancel_flow`, and the outbound pump they all depend on.
//! * **Bob is a bare `matrix_sdk_crypto::OlmMachine`**, driven directly,
//!   the way upstream's own `interactive_verification` tests drive their
//!   second party. He stands in for a client this library does not control.
//!
//! What the successful case proves is therefore not "two copies of the
//! library agree with each other", which is the weaker claim a symmetric
//! setup makes. It is that the library and a machine it does not control
//! reach the same short authentication string, and that **each ends up
//! reporting the other's device as verified** -- asserted on both sides,
//! because a one-sided assertion passes when only one side transitioned.
//!
//! # Four tests, one process, one machine
//!
//! Both registries this file exercises -- the machine registry in
//! `machine.rs` and the outbound pump's in `session.rs` -- are process-wide,
//! and an integration test cannot reach the `#[cfg(test)]` reset helpers
//! that let this crate's unit tests start clean. Cargo gives each file under
//! `tests/` its own process, so this file owns one machine for its whole
//! lifetime; the four tests in it share that machine and serialise on
//! `SERIAL` so they cannot race each other for it.
//!
//! Each test brings its own counterparty under its own **user** id, not
//! merely its own device id. A second device under a user this machine has
//! already queried would never be asked about: upstream re-derives who to
//! query from which tracked users are flagged as changed, and a user it has
//! already answered for is not flagged again.
//!
//! Driven by `futures::executor::block_on(in_runtime(..))` rather than
//! `#[tokio::test]`, following `tests/two_parties.rs`: what runtime there is
//! comes from this crate, and the bare machine needs a tokio context this
//! crate happens to be the only supplier of.

use std::collections::BTreeMap;
use std::sync::Mutex as StdMutex;

use matrix_crypto_core::{
    accept_flow, begin_comparison, cancel_flow, confirm_flow, create_machine, flow_stage,
    in_runtime, mark_request_sent, read_material, receive_sync_changes, request_flow,
    share_scope_key, take_outgoing_requests, with_machine, FlowId, FlowStage, MachineConfig,
    MachineError,
};
use matrix_sdk_common::ruma::api::client::keys::get_keys::v3::Response as KeysQueryResponse;
use matrix_sdk_common::ruma::api::client::keys::upload_keys::v3::Response as KeysUploadResponse;
use matrix_sdk_common::ruma::api::client::sync::sync_events::DeviceLists;
use matrix_sdk_common::ruma::api::client::to_device::send_event_to_device::v3::Response as ToDeviceResponse;
use matrix_sdk_common::ruma::api::IncomingResponse;
use matrix_sdk_common::ruma::events::key::verification::VerificationMethod;
use matrix_sdk_common::ruma::events::AnyToDeviceEvent;
// `exports::http`, not a direct `http` dependency: the exact version ruma's
// own `IncomingResponse::try_from_http_response` requires, reached through
// ruma's re-export -- the same reasoning `session.rs` documents for itself.
use matrix_sdk_common::ruma::exports::http;
use matrix_sdk_common::ruma::serde::Raw;
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId, TransactionId};
use matrix_sdk_crypto::types::requests::{AnyOutgoingRequest, OutgoingVerificationRequest};
use matrix_sdk_crypto::{
    DecryptionSettings, EncryptionSyncChanges, OlmMachine, Sas, TrustRequirement,
};

const ALICE_USER: &str = "@alice:example.org";
const ALICE_DEVICE: &str = "ALICEDEVICE";
/// A scope only ever used to make the library ask who a user's devices are.
/// Nothing is encrypted to it and nothing is read out of it: it is here
/// because tracking a user is what gets a device query issued, and this
/// library deliberately exposes no other way to ask for one.
const SCOPE: &str = "!verification:example.org";

/// Serialises the four tests over the one machine and the one pump this
/// process has. `into_inner` on a poisoned lock deliberately: a test that
/// panicked has already failed, and the remaining ones should report their
/// own outcome rather than a poisoning inherited from it.
static SERIAL: StdMutex<()> = StdMutex::new(());

/// The library machine's published device keys, captured the first time a
/// test needs them, so each counterparty can be taught who this device is.
static LIBRARY_DEVICE_KEYS: StdMutex<Option<String>> = StdMutex::new(None);

// ---------------------------------------------------------------- helpers

/// A fixed-shape 200 response, the form ruma's own
/// `IncomingResponse::try_from_http_response` expects.
fn http_ok(body: &str) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(200)
        .body(body.as_bytes().to_vec())
        .expect("a fixed-shape http::Response with no custom headers cannot fail to build")
}

fn keys_upload_response(body: &str) -> KeysUploadResponse {
    KeysUploadResponse::try_from_http_response(http_ok(body))
        .expect("this test builds its own well-formed keys-upload response")
}

fn keys_query_response(body: &str) -> KeysQueryResponse {
    KeysQueryResponse::try_from_http_response(http_ok(body))
        .expect("this test builds its own well-formed keys-query response")
}

/// `{"device_keys": {user: {device: keys}}}`, the `/keys/query` response
/// shape.
fn query_body(user_id: &str, device_id: &str, device_keys: &serde_json::Value) -> String {
    serde_json::json!({ "device_keys": { user_id: { device_id: device_keys } } }).to_string()
}

/// The top-level `event_type` a to-device request's JSON body declares.
///
/// Every assertion in this file about what crossed the wire goes through
/// this rather than stopping at `kind == "to_device"`: the six messages a
/// verification exchanges are all to-device requests, so the kind alone
/// cannot tell a key from a cancellation. `tests/two_parties.rs` records a
/// review finding where exactly that distinction was the whole test.
fn declared_event_type(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("event_type")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| "<no event_type in body>".to_string())
}

/// Turns one to-device request body into the to-device event the addressed
/// device would have received from its homeserver.
///
/// The only place this test relays anything, and it does no more than a
/// homeserver does: it reads the per-recipient content out of the request
/// and wraps it with the sender and type the request itself declares. It
/// reaches into neither machine. `None` when the request is not addressed
/// to that device at all.
fn relay_to(body: &str, sender: &str, user_id: &str, device_id: &str) -> Option<serde_json::Value> {
    let request: serde_json::Value = serde_json::from_str(body).ok()?;
    let event_type = request.get("event_type")?.as_str()?;
    let content = request.get("messages")?.get(user_id)?.get(device_id)?;
    Some(serde_json::json!({
        "sender": sender,
        "type": event_type,
        "content": content,
    }))
}

/// The wire body of one request upstream handed back to its caller rather
/// than queueing.
fn verification_body(request: &OutgoingVerificationRequest) -> String {
    match request {
        OutgoingVerificationRequest::ToDevice(to_device) => {
            serde_json::to_string(to_device).expect("an upstream to-device request serialises")
        }
        // Unreachable: an in-room flow only exists if an in-room
        // verification event was fed to the machine, and this library has
        // no entry point that does that. Asserted rather than mapped, so
        // this stops being true loudly.
        OutgoingVerificationRequest::InRoom(_) => {
            panic!("this library runs to-device verification flows only")
        }
    }
}

/// M3 verifies devices but publishes no cross-signing identity, so both
/// machines decrypt with upstream's most permissive trust requirement --
/// the same deliberate placeholder `session.rs`'s own
/// `decryption_settings()` documents, mirrored here so the counterparty is
/// held to the same standard the library holds itself to.
fn decryption_settings() -> DecryptionSettings {
    DecryptionSettings {
        sender_device_trust_requirement: TrustRequirement::Untrusted,
    }
}

/// Hands events to the bare machine as a sync would.
async fn deliver_to_bare(bob: &OlmMachine, events: Vec<serde_json::Value>) {
    let to_device_events: Vec<Raw<AnyToDeviceEvent>> = events
        .into_iter()
        .map(|event| {
            Raw::from_json_string(event.to_string())
                .expect("this test builds its own well-formed event")
        })
        .collect();
    let changed_devices = DeviceLists::default();
    let counts = BTreeMap::new();

    bob.receive_sync_changes(
        EncryptionSyncChanges {
            to_device_events,
            changed_devices: &changed_devices,
            one_time_keys_counts: &counts,
            unused_fallback_keys: None,
            next_batch_token: None,
        },
        &decryption_settings(),
    )
    .await
    .expect("the bare machine must accept a sync it is the addressee of");
}

/// Hands events to the library as a sync would, through its own public
/// entry point and its own wire shape.
async fn deliver_to_library(events: Vec<serde_json::Value>) {
    let payload = serde_json::json!({ "to_device_events": events }).to_string();
    receive_sync_changes(&payload)
        .await
        .expect("the library must accept a sync it is the addressee of");
}

/// Drains the library's outbound pump, relays every to-device request in it
/// to the counterparty, **marks each one sent**, and reports what crossed.
///
/// The mark is the step this whole module turns on. Upstream advances the
/// comparison only when the key message is reported sent, so a version of
/// this helper that relayed without marking would leave the flow parked
/// forever -- which is what `a_flow_that_never_marks_requests_sent_reports_it`
/// does on purpose, by hand, rather than through here.
async fn pump_to_bare(bob: &OlmMachine, bob_user: &str, bob_device: &str) -> Vec<String> {
    let batch = take_outgoing_requests()
        .await
        .expect("the pump must be drainable");

    let mut crossed = Vec::new();
    let mut events = Vec::new();
    for request in batch.iter().filter(|request| request.kind == "to_device") {
        if let Some(event) = relay_to(&request.body, ALICE_USER, bob_user, bob_device) {
            crossed.push(declared_event_type(&request.body));
            events.push(event);
        }
        mark_request_sent(&request.id, "{}")
            .await
            .expect("a to-device response must be accepted");
    }

    if !events.is_empty() {
        deliver_to_bare(bob, events).await;
    }
    crossed
}

/// The mirror image: drains the bare machine's own outbound requests,
/// relays its to-device ones to the library, and marks them sent on its
/// side.
async fn pump_bare_to_library(bob: &OlmMachine, bob_user: &str) -> Vec<String> {
    let batch = bob
        .outgoing_requests()
        .await
        .expect("the bare machine's requests must be readable");

    let mut crossed = Vec::new();
    let mut events = Vec::new();
    for request in &batch {
        if let AnyOutgoingRequest::ToDeviceRequest(to_device) = request.request() {
            let body =
                serde_json::to_string(to_device).expect("an upstream to-device request serialises");
            if let Some(event) = relay_to(&body, bob_user, ALICE_USER, ALICE_DEVICE) {
                crossed.push(declared_event_type(&body));
                events.push(event);
            }
            bob.mark_request_as_sent(request.request_id(), &ToDeviceResponse::new())
                .await
                .expect("the bare machine must accept its own to-device response");
        }
    }

    if !events.is_empty() {
        deliver_to_library(events).await;
    }
    crossed
}

/// Relays one request the bare machine handed back to its caller.
async fn deliver_verification_request(request: &OutgoingVerificationRequest, sender: &str) {
    let body = verification_body(request);
    let event = relay_to(&body, sender, ALICE_USER, ALICE_DEVICE)
        .expect("the counterparty addresses the library's own device");
    deliver_to_library(vec![event]).await;
}

/// Does the library report that device as verified?
///
/// Read through `with_machine`, this crate's own public accessor for the
/// machine it holds: M3 has no public "is this device verified" call yet
/// (that is a later task's), and asserting the outcome of a verification
/// through anything less than the machine's own answer would be asserting
/// on this test's bookkeeping instead of on the library's state.
async fn library_reports_verified(user_id: &str, device_id: &str) -> bool {
    let user: OwnedUserId = user_id.parse().expect("a literal user id parses");
    let device: OwnedDeviceId = device_id.into();
    with_machine(move |machine| {
        Box::pin(async move {
            machine
                .get_device(&user, &device, None)
                .await
                .expect("the store must be readable")
                .expect("the device this test verified must be known")
                .is_verified()
        })
    })
    .await
    .expect("the library's machine must be live")
}

/// Does the bare machine report the library's device as verified?
async fn bare_reports_verified(bob: &OlmMachine) -> bool {
    let alice: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
    let device: OwnedDeviceId = ALICE_DEVICE.into();
    bob.get_device(&alice, &device, None)
        .await
        .expect("the bare machine's store must be readable")
        .expect("the bare machine knows the library's device")
        .is_verified()
}

/// Creates the one library machine this process has, once, and returns its
/// published device keys.
async fn library_device_keys() -> serde_json::Value {
    if let Some(keys) = LIBRARY_DEVICE_KEYS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
    {
        return serde_json::from_str(keys).expect("this test stored well-formed JSON");
    }

    // `keep()`, unlike `tests/two_parties.rs`: the store outlives the test
    // that created it here, because the following tests in this file share
    // the machine it belongs to. `session.rs`'s own `test_config` does the
    // same, for the same reason.
    let dir = tempfile::tempdir().expect("temp dir").keep();
    create_machine(MachineConfig {
        user_id: ALICE_USER.to_string(),
        device_id: ALICE_DEVICE.to_string(),
        store_path: dir.join("store").to_string_lossy().into_owned(),
        store_passphrase: Some("test-passphrase".to_string()),
    })
    .await
    .expect("the library's machine must be creatable");

    let batch = take_outgoing_requests()
        .await
        .expect("the pump must be drainable");
    let upload = batch
        .iter()
        .find(|request| request.kind == "keys_upload")
        .expect("a fresh machine must have keys to publish");
    let body: serde_json::Value =
        serde_json::from_str(&upload.body).expect("the pump's own body is well-formed JSON");
    let device_keys = body
        .get("device_keys")
        .cloned()
        .expect("a fresh machine's upload carries its device keys");
    mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
        .await
        .expect("a keys-upload response must be accepted");

    *LIBRARY_DEVICE_KEYS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(device_keys.to_string());
    device_keys
}

/// Stands up one counterparty and teaches each side about the other's
/// device, which is the precondition a verification has: neither side can
/// verify a device it has never heard of.
async fn counterparty(user_id: &str, device_id: &str) -> OlmMachine {
    let alice_device_keys = library_device_keys().await;

    let bob_user: OwnedUserId = user_id.parse().expect("a literal user id parses");
    let bob_device: OwnedDeviceId = device_id.into();
    let bob = OlmMachine::new(&bob_user, &bob_device).await;

    // The counterparty publishes its own keys, through its own machine.
    // Not this library's pump, and not what this file is proving -- only
    // how a homeserver would have obtained the keys the library is about to
    // be told about.
    let bob_batch = bob
        .outgoing_requests()
        .await
        .expect("a fresh bare machine has keys to publish");
    let bob_device_keys = bob_batch
        .iter()
        .find_map(|request| match request.request() {
            AnyOutgoingRequest::KeysUpload(upload) => upload.device_keys.clone(),
            _ => None,
        })
        .expect("a fresh machine always has device keys to upload");
    let bob_upload_id = bob_batch
        .iter()
        .find(|request| matches!(request.request(), AnyOutgoingRequest::KeysUpload(_)))
        .expect("a fresh bare machine has a key upload")
        .request_id()
        .to_owned();
    bob.mark_request_as_sent(
        &bob_upload_id,
        &keys_upload_response(r#"{"one_time_key_counts":{}}"#),
    )
    .await
    .expect("the bare machine must accept its own upload response");
    let bob_device_keys =
        serde_json::to_value(&bob_device_keys).expect("upstream device keys serialise");

    // The library learns the counterparty's device. Tracking the user is
    // what gets a device query issued at all, and sharing a scope key is
    // the only call on the shipped surface that tracks one -- see
    // `tests/two_parties.rs`, which records why.
    share_scope_key(SCOPE, &[user_id.to_string()])
        .await
        .expect("sharing a scope key must not fail");
    let query = take_outgoing_requests()
        .await
        .expect("the pump must be drainable")
        .into_iter()
        .find(|request| request.kind == "keys_query")
        .expect("the machine must ask who exists before it can verify anyone");
    let queried: Vec<String> = serde_json::from_str::<serde_json::Value>(&query.body)
        .ok()
        .and_then(|body| {
            Some(
                body.get("device_keys")?
                    .as_object()?
                    .keys()
                    .cloned()
                    .collect(),
            )
        })
        .expect("a keys-query body always carries a device_keys object");
    assert!(
        queried.iter().any(|user| user == user_id),
        "the query the pump hands out must ask about the counterparty"
    );
    mark_request_sent(&query.id, &query_body(user_id, device_id, &bob_device_keys))
        .await
        .expect("a keys-query response must be accepted");

    // And the counterparty learns the library's device, driven directly
    // since it is not the library.
    bob.mark_request_as_sent(
        &TransactionId::new(),
        &keys_query_response(&query_body(ALICE_USER, ALICE_DEVICE, &alice_device_keys)),
    )
    .await
    .expect("the bare machine must accept a keys-query response");

    // Anything the tracking above queued -- a claim, a refusal notice -- is
    // drained here so each test starts against an empty pump and its own
    // assertions describe only its own flow.
    take_outgoing_requests()
        .await
        .expect("the pump must be drainable");

    bob
}

/// The counterparty's view of a flow, once the library has started one.
fn bare_comparison(bob: &OlmMachine, flow: &FlowId) -> Sas {
    let alice: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
    *bob.get_verification(&alice, &flow.0)
        .expect("the counterparty must have been told a comparison started")
        .sas_v1()
        .expect("this library only ever starts short-string comparisons")
}

// ------------------------------------------------------------------ tests

/// The milestone in one test: the library and a machine it does not control
/// reach the same short authentication string, both say it matches, and
/// **each then reports the other's device as verified**.
#[test]
fn two_parties_complete_a_comparison() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let bob_user = "@agreeing:example.org";
        let bob_device = "COUNTERPARTYONE";
        let bob = counterparty(bob_user, bob_device).await;

        assert!(
            !library_reports_verified(bob_user, bob_device).await,
            "nothing may be verified before a comparison has happened"
        );
        assert!(
            !bare_reports_verified(&bob).await,
            "nothing may be verified before a comparison has happened"
        );

        // ---- The library asks -------------------------------------------
        let flow = request_flow(bob_user, bob_device)
            .await
            .expect("a known device can be asked to verify itself");
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Requested
        );
        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            crossed.contains(&"m.key.verification.request".to_string()),
            "the request must reach the counterparty through the pump: {crossed:?}"
        );

        // ---- The counterparty agrees ------------------------------------
        let alice: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
        let bob_request = bob
            .get_verification_request(&alice, &flow.0)
            .expect("the counterparty must have received the request");
        let ready = bob_request
            .accept_with_methods(vec![VerificationMethod::SasV1])
            .expect("a fresh request can be accepted");
        deliver_verification_request(&ready, bob_user).await;
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Ready
        );

        // ---- The library starts the comparison --------------------------
        begin_comparison(&flow)
            .await
            .expect("a ready flow can start a comparison");
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Started
        );
        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            crossed.contains(&"m.key.verification.start".to_string()),
            "the start must reach the counterparty through the pump: {crossed:?}"
        );

        let bob_sas = bare_comparison(&bob, &flow);
        let accept = bob_sas
            .accept()
            .expect("a comparison the other side started can be accepted");
        deliver_verification_request(&accept, bob_user).await;

        // Neither side has anything to show yet, and the library says so by
        // name rather than by handing back an empty record.
        assert_eq!(
            read_material(&flow).await.expect_err("no keys yet"),
            MachineError::MaterialNotReady
        );
        assert!(bob_sas.emoji().is_none());

        // ---- The keys cross, in both directions, through the pump -------
        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            crossed.contains(&"m.key.verification.key".to_string()),
            "the library's key must reach the counterparty through the pump: {crossed:?}"
        );
        let crossed = pump_bare_to_library(&bob, bob_user).await;
        assert!(
            crossed.contains(&"m.key.verification.key".to_string()),
            "the counterparty's key must reach the library: {crossed:?}"
        );

        // ---- Both sides now have a string, and it is the same one -------
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::KeysExchanged
        );
        let material = read_material(&flow)
            .await
            .expect("the string is available once the keys are exchanged");
        let bare_decimals = bob_sas
            .decimals()
            .expect("the counterparty has a string too");
        assert_eq!(
            material.decimals, bare_decimals,
            "the two sides must have computed the same digits"
        );
        let bare_emoji = bob_sas.emoji().expect("both sides negotiated the symbols");
        let library_emoji = material
            .emoji
            .as_ref()
            .expect("both sides negotiated the symbols");
        let bare_symbols: Vec<&str> = bare_emoji.iter().map(|emoji| emoji.symbol).collect();
        let library_symbols: Vec<&str> = library_emoji
            .iter()
            .map(|emoji| emoji.symbol.as_str())
            .collect();
        assert_eq!(
            library_symbols, bare_symbols,
            "the two sides must have computed the same symbols, in the same order"
        );

        // ---- Both sides say it matches ----------------------------------
        // The counterparty first, so the library's own confirmation is the
        // one that completes the flow and the one whose effect is asserted.
        let (contents, _signatures) = bob_sas
            .confirm()
            .await
            .expect("the counterparty can confirm");
        for content in &contents {
            deliver_verification_request(content, bob_user).await;
        }
        assert!(
            !bob_sas.is_done(),
            "one side confirming must not finish the flow"
        );
        assert!(
            !library_reports_verified(bob_user, bob_device).await,
            "one side confirming must not verify anything"
        );

        confirm_flow(&flow)
            .await
            .expect("a flow showing a string can be confirmed");

        // Both sides have now said the strings match, and still nothing is
        // verified: a flow started from a request finishes only once each
        // side has acknowledged the other's, which is two more messages.
        // Asserted rather than skipped over, because "confirmed" reading as
        // "verified" is exactly the sentence this milestone exists to stop
        // being told.
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Confirmed
        );
        assert!(
            !library_reports_verified(bob_user, bob_device).await,
            "confirming is not yet verifying"
        );

        // ---- And each reports the other verified ------------------------
        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            crossed.contains(&"m.key.verification.mac".to_string()),
            "the library's confirmation must reach the counterparty: {crossed:?}"
        );
        assert!(
            crossed.contains(&"m.key.verification.done".to_string()),
            "the library's acknowledgement must reach the counterparty: {crossed:?}"
        );
        assert!(
            bob_sas.is_done(),
            "the counterparty's flow must have finished"
        );
        assert!(
            bare_reports_verified(&bob).await,
            "the counterparty must report the library's device verified"
        );

        let crossed = pump_bare_to_library(&bob, bob_user).await;
        assert!(
            crossed.contains(&"m.key.verification.done".to_string()),
            "the counterparty's acknowledgement must reach the library: {crossed:?}"
        );
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Done
        );
        assert!(
            library_reports_verified(bob_user, bob_device).await,
            "the library must report the counterparty's device verified"
        );
    }));
}

/// The case the successful one cannot stand in for: the two people are
/// looking at different strings, so the comparison must be refused and
/// nothing may be verified.
///
/// Runs in the other direction as well -- the counterparty asks and the
/// library accepts -- so `accept_flow` and `cancel_flow` are exercised
/// against a flow this process did not start and does not, at first, know
/// the name of.
#[test]
fn a_disagreement_refuses() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let bob_user = "@disagreeing:example.org";
        let bob_device = "COUNTERPARTYTWO";
        let bob = counterparty(bob_user, bob_device).await;

        // ---- The counterparty asks --------------------------------------
        let alice: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
        let alice_device: OwnedDeviceId = ALICE_DEVICE.into();
        let library_device = bob
            .get_device(&alice, &alice_device, None)
            .await
            .expect("the bare machine's store must be readable")
            .expect("the bare machine knows the library's device");
        let (bob_request, asking) =
            library_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
        let flow = FlowId(bob_request.flow_id().as_str().to_string());
        deliver_verification_request(&asking, bob_user).await;

        // Nothing in this process registered that flow. It is found because
        // the library resolves an unknown identifier against the users it
        // tracks, which is the only way a flow the other side started can
        // ever be answered.
        assert_eq!(
            flow_stage(&flow)
                .await
                .expect("an incoming flow is findable"),
            FlowStage::Requested
        );

        // ---- The library agrees, and starts the comparison ---------------
        accept_flow(&flow).await.expect("a request can be accepted");
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Ready
        );
        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            crossed.contains(&"m.key.verification.ready".to_string()),
            "the acceptance must reach the counterparty: {crossed:?}"
        );

        begin_comparison(&flow)
            .await
            .expect("a ready flow can start a comparison");
        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            crossed.contains(&"m.key.verification.start".to_string()),
            "the start must reach the counterparty: {crossed:?}"
        );

        let bob_sas = bare_comparison(&bob, &flow);
        let accept = bob_sas
            .accept()
            .expect("a started comparison is acceptable");
        deliver_verification_request(&accept, bob_user).await;

        pump_to_bare(&bob, bob_user, bob_device).await;
        pump_bare_to_library(&bob, bob_user).await;

        let material = read_material(&flow)
            .await
            .expect("the string is available once the keys are exchanged");
        assert_eq!(
            material.decimals,
            bob_sas
                .decimals()
                .expect("the counterparty has a string too"),
            "the protocol itself agrees; it is the two people who do not"
        );

        // ---- The two people are not looking at the same string ----------
        // What the library's user reports having been read out to them is
        // not what the library's own screen shows: one digit differs. That
        // is real data, compared with a real `!=`, not a flag this test can
        // flip -- which is the whole difference between proving a refusal
        // and asserting one.
        let heard_from_the_other_side = (
            material.decimals.0,
            material.decimals.1,
            material.decimals.2 ^ 1,
        );
        assert_ne!(
            heard_from_the_other_side, material.decimals,
            "this test is worthless unless the two strings genuinely differ"
        );

        if heard_from_the_other_side == material.decimals {
            confirm_flow(&flow)
                .await
                .expect("matching strings are confirmed");
        } else {
            cancel_flow(&flow)
                .await
                .expect("differing strings are refused");
        }

        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            crossed.contains(&"m.key.verification.cancel".to_string()),
            "the refusal must reach the counterparty: {crossed:?}"
        );

        // ---- And neither side has verified anything ---------------------
        assert_eq!(
            flow_stage(&flow)
                .await
                .expect("a refused flow is still readable"),
            FlowStage::Cancelled
        );
        assert_eq!(
            read_material(&flow)
                .await
                .expect_err("a refused flow has nothing to show"),
            MachineError::WrongStage
        );
        assert!(
            !library_reports_verified(bob_user, bob_device).await,
            "a refused comparison must verify nothing on the library's side"
        );
        assert!(
            bob_sas.is_cancelled(),
            "the counterparty must observe the refusal"
        );
        assert!(
            !bare_reports_verified(&bob).await,
            "a refused comparison must verify nothing on the counterparty's side"
        );
    }));
}

/// The one way this flow can fail silently, made loud.
///
/// Everything is done correctly except that the key message, once drained
/// from the pump, is never reported sent. Upstream advances the comparison
/// on exactly that report, so without it the string is never produced: no
/// error, no timeout, nothing. The library must name that state instead of
/// handing back an empty record or waiting forever -- and the proof that it
/// names the *right* one is the last third of this test, where supplying
/// the missing report, and nothing else, completes the flow.
#[test]
fn a_flow_that_never_marks_requests_sent_reports_it() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let bob_user = "@unreported:example.org";
        let bob_device = "COUNTERPARTYTHREE";
        let bob = counterparty(bob_user, bob_device).await;

        let flow = request_flow(bob_user, bob_device)
            .await
            .expect("a known device can be asked to verify itself");
        pump_to_bare(&bob, bob_user, bob_device).await;

        let alice: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
        let ready = bob
            .get_verification_request(&alice, &flow.0)
            .expect("the counterparty must have received the request")
            .accept_with_methods(vec![VerificationMethod::SasV1])
            .expect("a fresh request can be accepted");
        deliver_verification_request(&ready, bob_user).await;

        begin_comparison(&flow)
            .await
            .expect("a ready flow can start a comparison");
        pump_to_bare(&bob, bob_user, bob_device).await;

        let bob_sas = bare_comparison(&bob, &flow);
        let accept = bob_sas
            .accept()
            .expect("a started comparison is acceptable");
        deliver_verification_request(&accept, bob_user).await;

        // ---- The key is drained and delivered, and never reported sent --
        let batch = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let key = batch
            .iter()
            .find(|request| {
                request.kind == "to_device"
                    && declared_event_type(&request.body) == "m.key.verification.key"
            })
            .expect("an accepted comparison produces a key message");
        let event = relay_to(&key.body, ALICE_USER, bob_user, bob_device)
            .expect("the key is addressed to the counterparty");
        deliver_to_bare(&bob, vec![event]).await;

        // The counterparty does everything right, including its own report,
        // so the only thing missing anywhere is the library caller's.
        let crossed = pump_bare_to_library(&bob, bob_user).await;
        assert!(
            crossed.contains(&"m.key.verification.key".to_string()),
            "the counterparty's key must still reach the library: {crossed:?}"
        );

        // ---- Which is a named error, not a silence ----------------------
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Started,
            "a flow whose key was never reported sent has not exchanged keys"
        );
        assert_eq!(
            read_material(&flow)
                .await
                .expect_err("there is no string to read"),
            MachineError::MaterialNotReady
        );
        assert_eq!(
            confirm_flow(&flow)
                .await
                .expect_err("there is nothing to confirm"),
            MachineError::MaterialNotReady
        );

        // ---- And the error names the actual cause -----------------------
        mark_request_sent(&key.id, "{}")
            .await
            .expect("the report can still be made");
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::KeysExchanged,
            "supplying the missing report, and nothing else, must complete the exchange"
        );
        read_material(&flow)
            .await
            .expect("the string is available once the report is made");
    }));
}

/// The registry does not grow without bound.
///
/// The outbound pump's own `pending` map had to be shown not to accumulate
/// one entry per request ever handed out, and this registry inherits the
/// question: a flow that is cancelled or completed must not be retained for
/// the life of the process. Measured the same way the pump's test measures
/// it -- how much is retained after one cycle against after three -- except
/// that an integration test cannot read the map directly, so it counts the
/// identifiers the library still answers for.
#[test]
fn a_finished_flow_is_not_retained_forever() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let bob_user = "@repeating:example.org";
        let bob_device = "COUNTERPARTYFOUR";
        let _bob = counterparty(bob_user, bob_device).await;

        async fn retained(flows: &[FlowId]) -> usize {
            let mut count = 0;
            for flow in flows {
                if flow_stage(flow).await.is_ok() {
                    count += 1;
                }
            }
            count
        }

        let mut flows: Vec<FlowId> = Vec::new();
        let mut after_one = 0;
        for cycle in 0..3 {
            let flow = request_flow(bob_user, bob_device)
                .await
                .expect("a known device can be asked to verify itself");
            cancel_flow(&flow)
                .await
                .expect("a live flow can be refused");
            assert_eq!(
                flow_stage(&flow)
                    .await
                    .expect("the newest flow is readable"),
                FlowStage::Cancelled,
                "a refused flow must stay readable until another one is started"
            );
            flows.push(flow);
            take_outgoing_requests()
                .await
                .expect("the pump must be drainable");
            if cycle == 0 {
                after_one = retained(&flows).await;
            }
        }

        let after_three = retained(&flows).await;
        assert_eq!(
            after_one, after_three,
            "repeated verifications must not accumulate in the registry: \
             {after_one} retained after one, {after_three} after three"
        );
        assert_eq!(
            after_three, 1,
            "only the flow started most recently may still be retained"
        );
        assert_eq!(
            flow_stage(&flows[0])
                .await
                .expect_err("the first flow has been released"),
            MachineError::UnknownFlow
        );
    }));
}
