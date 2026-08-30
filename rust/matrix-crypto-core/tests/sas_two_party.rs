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
//! # Every test here, one process, one machine
//!
//! Both registries this file exercises -- the machine registry in
//! `machine.rs` and the outbound pump's in `session.rs` -- are process-wide,
//! and an integration test cannot reach the `#[cfg(test)]` reset helpers
//! that let this crate's unit tests start clean. Cargo gives each file under
//! `tests/` its own process, so this file owns one machine for its whole
//! lifetime; every test in it shares that machine and serialises on
//! `SERIAL` so they cannot race each other for it.
//!
//! Deliberately not counted. These three sentences said "four tests" while
//! the file held five, from the commit that added the fifth until a review
//! caught it, because a number in prose has no way to be wrong out loud --
//! the same reason the README enumerates `gate:logger`'s reach instead of
//! counting it.
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
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use matrix_crypto_core::{
    accept_flow, begin_comparison, cancel_flow, clear_crypto_observer, confirm_flow,
    create_machine, device_statuses, flow_stage, in_runtime, mark_request_sent, read_material,
    receive_sync_changes, request_flow, set_crypto_observer, share_scope_key,
    take_outgoing_requests, with_machine, CryptoObserver, CryptoSignal, FlowId, FlowStage,
    MachineConfig, MachineError, SasMaterial, TrustState,
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

/// Serialises this file's tests over the one machine and the one pump this
/// process has. `into_inner` on a poisoned lock deliberately: a test that
/// panicked has already failed, and the remaining ones should report their
/// own outcome rather than a poisoning inherited from it.
static SERIAL: StdMutex<()> = StdMutex::new(());

/// The library machine's published device keys, captured the first time a
/// test needs them, so each counterparty can be taught who this device is.
static LIBRARY_DEVICE_KEYS: StdMutex<Option<String>> = StdMutex::new(None);

// -------------------------------------------------- the signal channel

/// What the crypto signal channel delivered to this process, in order.
///
/// A channel rather than a `Vec` a test reads whenever it likes, because
/// delivery is detached: the library hands a signal to a thread of its own
/// and it arrives when that thread runs. A vector would let a test that
/// checked at the wrong instant report an absence that was really a
/// not-yet. A channel lets a test *wait*, bounded, which is the only shape
/// that can distinguish the two.
///
/// The sender is kept alongside the receiver so a test can put the observer
/// back after clearing it and go on reading the same channel -- which is
/// what `an_invitation_that_arrives_while_nobody_listens_is_announced_on_resubscribe`
/// needs, and the reason this is not just a `Receiver`.
struct SignalChannel {
    tx: mpsc::Sender<CryptoSignal>,
    rx: mpsc::Receiver<CryptoSignal>,
}

static SIGNALS: StdMutex<Option<SignalChannel>> = StdMutex::new(None);

/// How long a signal that is coming gets to arrive.
///
/// The same number, for the same reasons, as `observer.rs`'s own
/// `DELIVERY_BOUND`: far looser than delivery actually takes, so it is not
/// a performance threshold and cannot flake under load, and tight enough
/// that a channel which has stopped delivering fails a test in seconds
/// rather than hanging it.
const DELIVERY_BOUND: Duration = Duration::from_secs(5);

/// How long a signal that must *not* come gets to prove it.
///
/// Shorter than `DELIVERY_BOUND`, and the asymmetry is deliberate: this
/// bound is paid in full by every negative assertion, on every run. What
/// keeps it honest is that no negative assertion in this file stands alone
/// -- each is followed by a positive one on the same channel, so an
/// implementation that had simply stopped delivering fails the pair.
const QUIET_BOUND: Duration = Duration::from_millis(750);

struct Recorder {
    tx: mpsc::Sender<CryptoSignal>,
}

impl CryptoObserver for Recorder {
    fn on_signal(&self, signal: CryptoSignal) {
        let _ = self.tx.send(signal);
    }
}

/// Installs this file's recorder, once, and empties whatever a previous
/// test left behind.
///
/// The observer is process-wide and there is no call to remove one, which
/// is why installation is idempotent and the draining is what gives each
/// test a known-empty start. Tests here serialise on `SERIAL`, so no two
/// are ever filling this channel at once.
///
/// **Drained until quiet rather than until empty**, and the difference is
/// not pedantry: delivery is detached, so a signal a previous test caused
/// can still be in flight when this runs. A `try_recv` loop would report
/// the channel empty and then let that signal arrive in the middle of the
/// next test -- observed exactly once, as a `TrustChanged` from
/// `@confirmingsecond` surfacing inside `a_disagreement_refuses` under
/// `--test-threads=1`, which is an ordering the default parallel run does
/// not produce.
fn subscribe_and_drain() {
    subscribe();
    let held = SIGNALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let received = &held.as_ref().expect("the recorder was just installed").rx;
    while received.recv_timeout(QUIET_BOUND).is_ok() {}
}

/// Installs this file's recorder, creating its channel the first time.
///
/// Idempotent in what it observes and deliberately *not* idempotent in what
/// it does: called again after [`unsubscribe`], it puts the same channel
/// back, which is what makes a resubscribe testable at all.
fn subscribe() {
    let mut held = SIGNALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if held.is_none() {
        let (tx, rx) = mpsc::channel();
        *held = Some(SignalChannel { tx, rx });
    }
    let tx = held
        .as_ref()
        .expect("the channel was just created")
        .tx
        .clone();
    set_crypto_observer(Arc::new(Recorder { tx }));
}

/// The last unsubscribe, from the core's point of view.
///
/// This is what `signals.ts`' unsubscribe closure calls once its listener
/// set empties. Nothing else in this file's helpers touches the observer
/// registry, so a test that calls this is in exactly the state a product is
/// in between unmounting a subscribing component and mounting the next one.
fn unsubscribe() {
    clear_crypto_observer();
}

/// The next signal, or a panic naming what was expected.
fn next_signal(expected: &str) -> CryptoSignal {
    let held = SIGNALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    held.as_ref()
        .expect("subscribe_and_drain must run first")
        .rx
        .recv_timeout(DELIVERY_BOUND)
        .unwrap_or_else(|e| panic!("{expected}: nothing reached the signal channel ({e})"))
}

/// Requires that nothing arrives, having waited for it.
fn no_signal(why: &str) {
    let held = SIGNALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Ok(signal) = held
        .as_ref()
        .expect("subscribe_and_drain must run first")
        .rx
        .recv_timeout(QUIET_BOUND)
    {
        panic!("{why}, and yet {signal:?} was delivered");
    }
}

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

/// Neither machine in this file publishes a cross-signing identity, so
/// both decrypt with upstream's most permissive trust requirement: the same
/// deliberate placeholder `session.rs`'s own `decryption_settings()`
/// documents, mirrored here so the counterparty is held to the standard the
/// library holds itself to.
///
/// This said "M3 verifies devices but publishes no cross-signing identity",
/// which stopped being true of the library when M4 landed
/// `bootstrap_identity`. It is still true of these fixtures, and the
/// setting is unchanged for the reason `session.rs` now gives: the
/// requirement became movable in M4 and was deliberately not moved.
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

/// What the library's own public surface says about that device.
///
/// `device_statuses` is the call a product makes, and the only place in
/// this milestone where a finished comparison becomes visible as a result.
/// Every assertion in this file about who is verified goes through it.
async fn library_device_status(user_id: &str, device_id: &str) -> TrustState {
    device_statuses(user_id)
        .await
        .expect("the library's machine must be live")
        .into_iter()
        .find(|status| status.device_id == device_id)
        .unwrap_or_else(|| panic!("the library must know the device this test is asking about"))
        .trust
}

/// Does the library report that device as verified?
///
/// Two answers to one question, asserted to agree: the public
/// `device_statuses` call a product would make, and the machine's own
/// `is_verified`, read through `with_machine`. Keeping both is what stops
/// this file proving only that one layer is self-consistent -- a
/// `device_statuses` that always answered `Unverified` would satisfy every
/// "nothing is verified yet" assertion here, and the final one alone would
/// be carrying the whole proof.
async fn library_reports_verified(user_id: &str, device_id: &str) -> bool {
    let user: OwnedUserId = user_id.parse().expect("a literal user id parses");
    let device: OwnedDeviceId = device_id.into();
    let machine_says = with_machine(move |machine| {
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
    .expect("the library's machine must be live");

    let surface_says = library_device_status(user_id, device_id).await;
    assert_eq!(
        surface_says == TrustState::Verified,
        machine_says,
        "the public surface and the machine it reads must not disagree about trust",
    );
    machine_says
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
        subscribe_and_drain();

        // Read and kept, not merely asserted against a constant: the claim
        // this test carries for the whole milestone is that this value
        // *changes*, and the only way to state that is to hold the earlier
        // one and compare the later one with it. A test that asserted
        // `Verified` at the end alone would also pass against a surface
        // that had answered `Verified` from the very beginning.
        let trust_before = library_device_status(bob_user, bob_device).await;
        assert_eq!(
            trust_before,
            TrustState::Unverified,
            "a device this machine merely knows the keys of is not verified"
        );
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

        // Asked again -- a double tap, or a retry after some unrelated
        // failure. Upstream would build a second comparison under the same
        // identifier and its cache would then cancel both, destroying the
        // flow while this call returned success. Refused instead, and
        // refused without side effects: everything below still works.
        assert_eq!(
            begin_comparison(&flow)
                .await
                .expect_err("a comparison already under way cannot be started again"),
            MachineError::WrongStage
        );
        assert_eq!(
            flow_stage(&flow).await.expect("the flow still exists"),
            FlowStage::Started
        );

        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            crossed.contains(&"m.key.verification.start".to_string()),
            "the start must reach the counterparty through the pump: {crossed:?}"
        );
        assert_eq!(
            crossed
                .iter()
                .filter(|kind| *kind == "m.key.verification.start")
                .count(),
            1,
            "the refused second call must not have queued a second start: {crossed:?}"
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

        // The milestone's observable claim, stated as a change rather than
        // as a value: what a product reads through `device_statuses` for
        // this device is not what it read before the comparison ran, and
        // what it now reads is the verified one.
        let trust_after = library_device_status(bob_user, bob_device).await;
        assert_ne!(
            trust_after, trust_before,
            "a completed comparison must change what this device reports"
        );
        assert_eq!(
            trust_after,
            TrustState::Verified,
            "and the value it changed to must be the verified one"
        );

        // This machine's own device, which read `Verified` before any of
        // this ran and reads it still. Upstream marks it locally trusted
        // at creation, because this process holds its private keys.
        //
        // Asserted rather than left alone for two reasons. It is the
        // control on the assertion above -- a `device_statuses` stuck on
        // `Unverified` would have satisfied every "nothing is verified
        // yet" line in this test, and the pair of them is what rules that
        // out. And it is the warning the surface itself carries: "some
        // device in the list reads verified" is true of a machine that has
        // never verified anything, so it is the *change* on another user's
        // device, above, that carries the claim.
        assert_eq!(
            library_device_status(ALICE_USER, ALICE_DEVICE).await,
            TrustState::Verified,
            "this machine's own device is trusted because it holds its own keys"
        );

        // ---- And a subscriber was told, exactly once --------------------
        // The first producer the crypto signal channel has ever had. This
        // flow was started by the library, so its identifier was never in
        // doubt and there is nothing inbound to announce: the one signal a
        // completed comparison owes a subscriber is the trust change, and
        // "exactly one" is asserted rather than "at least one" because a
        // channel that fired on every sync would satisfy the weaker claim.
        assert_eq!(
            next_signal("a completed comparison must announce the trust change"),
            CryptoSignal::TrustChanged {
                user: bob_user.to_string(),
                state: TrustState::Verified,
            },
            "the channel must name the user whose device changed, and the state it changed to"
        );

        // Synced three more times before asserting silence, and without
        // this the assertion below is free: nothing on this channel is
        // emitted except from a sync, so "no more arrived" proves nothing
        // unless the producer has since run against a flow that is still
        // `Done` in the registry. Written without it twice, on both
        // completion tests, and deleting `completion_announced` failed
        // neither -- the same vacuity this file had already found and fixed
        // twice on the inbound side. Three rather than one, so an
        // implementation that repeated on alternate syncs fails too.
        for _ in 0..3 {
            deliver_to_library(vec![]).await;
        }
        no_signal("a completed comparison announces one trust change and no more");
    }));
}

/// An invitation that arrives while nobody is listening must still reach
/// whoever subscribes next.
///
/// # The shape this exists for
///
/// `useEffect(() => onCryptoSignal(handler), [])` -- subscribe on mount,
/// unsubscribe on unmount -- is the ordinary React Native idiom, so a
/// product that subscribes at all will spend time unsubscribed. A hot
/// reload produces the same window. This is therefore the default
/// integration pattern rather than an edge case, and what happens in that
/// window decides whether the channel is usable.
///
/// # Why silence in the window is the property, not the announcement
///
/// The producer's dedup key is membership in the flow registry, and the
/// registry is only written when an observer exists. So "announce nothing
/// while nobody is listening" and "announce it to whoever subscribes next"
/// are the same statement: an invitation not consumed in the window is
/// still `Requested`, still unregistered, and the next sync after a
/// resubscribe enumerates it afresh.
///
/// Which is why the negative assertion below comes first and the positive
/// one second. Before `clear_crypto_observer` existed, an unsubscribe left
/// the observer installed with nothing behind it: the invitation was
/// registered, marked announced and delivered into an empty listener set,
/// and `register_if_absent` refused it for the rest of its life. Nothing
/// listed inbound flows, so there was no way back, and the invitation
/// expired ten minutes later. That failure was silent, permanent, and
/// reached through the most common code a consumer will write.
#[test]
fn an_invitation_that_arrives_while_nobody_listens_is_announced_on_resubscribe() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let bob_user = "@remounting:example.org";
        let bob_device = "COUNTERPARTYSIX";
        let bob = counterparty(bob_user, bob_device).await;

        // ---- Mounted, then unmounted ------------------------------------
        subscribe_and_drain();
        unsubscribe();

        // ---- The counterparty asks into the silence ---------------------
        let alice: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
        let alice_device: OwnedDeviceId = ALICE_DEVICE.into();
        let library_device = bob
            .get_device(&alice, &alice_device, None)
            .await
            .expect("the bare machine's store must be readable")
            .expect("the bare machine knows the library's device");
        let (bob_request, asking) =
            library_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
        deliver_verification_request(&asking, bob_user).await;

        // The sync that would have announced it has run. Nothing may have
        // been consumed by it, because there is nobody to consume it for.
        no_signal(
            "an invitation must not be announced while nobody is subscribed: consuming it \
             there is what made it unrecoverable, since the registry then refuses to \
             announce it ever again",
        );

        // ---- Remounted --------------------------------------------------
        subscribe();
        deliver_to_library(vec![]).await;

        let announced = next_signal(
            "an invitation still live when a subscriber returns must be announced to it",
        );
        let CryptoSignal::VerificationRequested {
            user,
            device_id,
            flow_id,
        } = announced.clone()
        else {
            panic!("a recovered invitation must announce itself as one, not as {announced:?}");
        };
        assert_eq!(user, bob_user, "the announcement must name who is asking");
        assert_eq!(
            device_id, bob_device,
            "the announcement must name which device is asking"
        );
        assert_eq!(
            flow_id,
            bob_request.flow_id().as_str(),
            "and it must name the flow, or the product has been told something happened \
             without being told what to do about it"
        );
        no_signal("one invitation is one announcement, on whichever sync delivers it");

        // ---- And it is a live flow, not a notification ------------------
        // Driven from the announced identifier, never from `bob_request`:
        // the point of the recovery is that a product which was not
        // listening when the invitation arrived can still act on it, and it
        // has no other source for the name.
        let recovered = FlowId(flow_id);
        assert_eq!(
            flow_stage(&recovered)
                .await
                .expect("the announced identifier names a live flow"),
            FlowStage::Requested
        );
        accept_flow(&recovered)
            .await
            .expect("an invitation announced after a resubscribe can be accepted");
        let crossed = take_outgoing_requests()
            .await
            .expect("the pump must be drainable")
            .iter()
            .map(|request| declared_event_type(&request.body))
            .collect::<Vec<_>>();
        assert!(
            crossed.contains(&"m.key.verification.ready".to_string()),
            "the acceptance must reach the pump: {crossed:?}"
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
        subscribe_and_drain();

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
        deliver_verification_request(&asking, bob_user).await;

        // ---- The library is told, and told which flow -------------------
        // This is the half a receiving side cannot get any other way. Until
        // this signal existed, a product had to filter the raw to-device
        // events for `m.key.verification.request` and read
        // `content.transaction_id` out of one -- a protocol detail this
        // library keeps to itself everywhere else. Every call below takes
        // the identifier from the signal, so the whole of the rest of this
        // test is the proof that a product never has to open the event.
        let announced = next_signal("an inbound invitation must be announced");
        let CryptoSignal::VerificationRequested {
            user,
            device_id,
            flow_id,
        } = announced.clone()
        else {
            panic!("an inbound invitation must announce itself as one, not as {announced:?}");
        };
        assert_eq!(user, bob_user, "the announcement must name who is asking");
        assert_eq!(
            device_id, bob_device,
            "the announcement must name which of that user's devices is asking"
        );
        assert_eq!(
            flow_id,
            bob_request.flow_id().as_str(),
            "the identifier the channel hands over must be the flow's own, the same value \
             the transaction id on the wire carries"
        );
        no_signal("one invitation is one announcement");
        let flow = FlowId(flow_id);

        // ---- And it stays one, however long the person takes ------------
        // The window that matters is the one a product actually lives in:
        // an invitation sits at `Requested` until a person answers it,
        // which is minutes, and a product syncs throughout. If the channel
        // announced whatever it found rather than whatever is new, every
        // one of those syncs would repeat this invitation, and the noise
        // would grow with how long the user thinks rather than with how
        // many verifications happen.
        //
        // Three empty syncs rather than one, because one would also pass
        // against an implementation that merely announced on alternate
        // calls.
        for _ in 0..3 {
            deliver_to_library(vec![]).await;
        }
        assert_eq!(
            flow_stage(&flow)
                .await
                .expect("the invitation is still live"),
            FlowStage::Requested,
            "this proves nothing unless the flow is still in the state that would be \
             re-announced"
        );
        no_signal("an invitation already announced must not be announced again on every sync");

        // Nothing in this process registered that flow before the sync that
        // announced it, and the announcement is now the only place its name
        // came from.
        assert_eq!(
            flow_stage(&flow)
                .await
                .expect("an announced flow is findable by the identifier the channel gave"),
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
        // What the library's user reports having been read out to them
        // differs from what the library's own screen shows by one digit.
        // The construction is deliberate and so is what it is *not*: this
        // stands in for a person, so the difference is put there rather
        // than discovered, and the branch that used to be written around it
        // was a tautology dressed as a decision. What carries the weight of
        // this test is everything after the refusal -- that it reaches the
        // counterparty, that the counterparty observes it, and that neither
        // side ends up having verified anything.
        let heard_from_the_other_side = (
            material.decimals.0,
            material.decimals.1,
            material.decimals.2 ^ 1,
        );
        assert_ne!(
            heard_from_the_other_side, material.decimals,
            "the string this test puts in the user's mouth must differ from the \
             one on the library's own screen, or there is nothing to refuse"
        );

        cancel_flow(&flow)
            .await
            .expect("a string that does not match what the user sees is refused");

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
        // Synced again first, and that is not padding: nothing on this
        // channel is emitted except from a sync, so an assertion that the
        // channel stayed quiet after a refusal proves nothing unless a sync
        // has since run. Written without this once, and it passed against a
        // producer that announced every finished flow without checking
        // whether anything had actually become verified.
        deliver_to_library(vec![]).await;
        no_signal(
            "a refused comparison changes no device's trust, so the channel has nothing \
             to say about it",
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

/// Where the receiving side's flow identifier comes from, and what happens
/// when the invitation names a device this machine has never met.
///
/// Both halves are documented on `acceptVerification` and in the README,
/// and neither was observed until this test. The first is a claim about a
/// wire field a product is being told to read; the second is a claim about
/// a silent discard, which is the one kind of claim this repository will
/// not take on a reading of upstream alone -- and rightly so, because the
/// reading was wrong. Upstream logs "ignoring it" and returns, which reads
/// as though the invitation is gone for good; what is actually gone is
/// that *arrival*. Feeding the same event again, once the device is known,
/// recovers the flow. The documentation was corrected to match this test
/// rather than the other way round.
///
/// The counterparty here is built by hand rather than through
/// `counterparty` above, because that helper's whole job is to teach both
/// sides about each other and this test needs exactly one side taught.
#[test]
fn an_invitation_from_an_unmet_device_needs_its_event_fed_again() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let bob_user = "@unmet:example.org";
        let bob_device = "COUNTERPARTYFOUR";
        let alice_device_keys = library_device_keys().await;
        subscribe_and_drain();

        let bob_user_id: OwnedUserId = bob_user.parse().expect("a literal user id parses");
        let bob_device_id: OwnedDeviceId = bob_device.into();
        let bob = OlmMachine::new(&bob_user_id, &bob_device_id).await;

        // Bob's own keys, captured before they are consumed, so the library
        // can be taught about him later in this test rather than now.
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

        // Bob learns the library's device. The library is deliberately not
        // told about Bob, which is the whole condition under test.
        bob.mark_request_as_sent(
            &TransactionId::new(),
            &keys_query_response(&query_body(ALICE_USER, ALICE_DEVICE, &alice_device_keys)),
        )
        .await
        .expect("the bare machine must accept a keys-query response");

        // ---- Bob invites a device whose owner has never heard of him ----
        let alice: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
        let alice_device: OwnedDeviceId = ALICE_DEVICE.into();
        let library_device = bob
            .get_device(&alice, &alice_device, None)
            .await
            .expect("the bare machine's store must be readable")
            .expect("the bare machine knows the library's device");
        let (bob_request, asking) =
            library_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);

        let event = relay_to(
            &verification_body(&asking),
            bob_user,
            ALICE_USER,
            ALICE_DEVICE,
        )
        .expect("the counterparty addresses the library's own device");

        // ---- The identifier a receiving product is told to read ---------
        // `content.transaction_id` of the `m.key.verification.request`
        // to-device event, which is what `acceptVerification`'s own doc
        // comment and the README both instruct a product to pick up. If
        // that field ever stops being the flow's name, both documents are
        // wrong and this fails rather than the product.
        assert_eq!(
            event
                .get("type")
                .and_then(|value| value.as_str())
                .expect("a relayed to-device event declares its type"),
            "m.key.verification.request",
            "an invitation arrives under the type the documentation tells a product to filter on"
        );
        let on_the_wire = event
            .get("content")
            .and_then(|content| content.get("transaction_id"))
            .and_then(|value| value.as_str())
            .expect("an invitation carries a transaction id")
            .to_string();
        assert_eq!(
            on_the_wire,
            bob_request.flow_id().as_str(),
            "the transaction id on the wire must be the identifier this library answers to"
        );

        // ---- Delivered, and silently discarded --------------------------
        deliver_to_library(vec![event.clone()]).await;
        assert_eq!(
            accept_flow(&FlowId(on_the_wire.clone()))
                .await
                .expect_err("the invitation was dropped as it arrived"),
            MachineError::UnknownFlow,
            "an invitation from a device this machine has never met leaves no flow behind,              and the sync that carried it reported success"
        );
        // And nothing is announced either, which is the honest behaviour
        // rather than a gap: the channel announces flows, and no flow
        // exists. Announcing off the wire event instead would hand a
        // product an identifier that every call in this library then
        // rejects with `UnknownFlow` -- worse than silence, because it
        // looks actionable. This is the one part of the retention advice
        // the announcement does not retire, and this assertion is why.
        no_signal(
            "an invitation that built no flow has no flow to announce, and announcing the \
             wire event's own identifier would name something no call here answers to",
        );

        // ---- Learning about the device, and feeding the event again ----
        // The recovery path, and the reason this test exists in the shape
        // it does: the first version of it asserted that re-delivery could
        // NOT recover a discarded invitation, which is what upstream's
        // "ignoring it" warning reads like from the source. That assertion
        // failed. The discard is of the *arrival*, not of the invitation:
        // nothing inside this library remembers the event, but nothing
        // refuses it a second time either, so a product that kept the event
        // can feed it again once it knows the device.
        share_scope_key(SCOPE, &[bob_user.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let query = take_outgoing_requests()
            .await
            .expect("the pump must be drainable")
            .into_iter()
            .find(|request| request.kind == "keys_query")
            .expect("tracking a new user queues a query about them");
        mark_request_sent(
            &query.id,
            &query_body(bob_user, bob_device, &bob_device_keys),
        )
        .await
        .expect("a keys-query response must be accepted");
        take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        assert_eq!(
            library_device_status(bob_user, bob_device).await,
            TrustState::Unverified,
            "this test proves nothing past here unless the device is now actually known"
        );

        deliver_to_library(vec![event]).await;

        // ---- The recovery announces itself, and hands over the id -------
        // The half that makes the retention advice bearable. A product
        // still has to keep the events it could not act on and feed them
        // again -- nothing here remembers them -- but it never has to
        // *read* one. It re-feeds an opaque blob and is told, by the same
        // channel and in the same shape as a first-time arrival, that a
        // flow now exists and what it is called.
        let announced = next_signal("a recovered invitation must announce itself");
        let CryptoSignal::VerificationRequested {
            user,
            device_id,
            flow_id,
        } = announced.clone()
        else {
            panic!("a recovered invitation must announce itself as one, not as {announced:?}");
        };
        assert_eq!(user, bob_user, "the announcement must name who is asking");
        assert_eq!(
            device_id, bob_device,
            "the announcement must name which device is asking"
        );
        assert_eq!(
            flow_id, on_the_wire,
            "the identifier the channel hands over for a recovered invitation must be the \
             same one the retained event carried, or a product would have to read the \
             event after all"
        );
        no_signal("one recovery is one announcement");

        // Deliberately `flow_id`, not `on_the_wire`: from here on this test
        // drives the flow with what the channel said, so nothing below can
        // be passing on a value taken out of the event.
        let recovered = FlowId(flow_id);
        assert_eq!(
            flow_stage(&recovered)
                .await
                .expect("the announced identifier names a live flow"),
            FlowStage::Requested,
            "re-feeding a retained invitation once its sender's device is known is what \
             recovers it -- there is no other route, because nothing in this library kept \
             the event"
        );

        // Accepted for real, not merely findable: the acceptance has to
        // reach the pump, or a product would be told the recovery worked
        // and the far side would still be waiting.
        accept_flow(&recovered)
            .await
            .expect("a recovered invitation can be accepted");
        assert_eq!(
            flow_stage(&recovered).await.expect("the flow exists"),
            FlowStage::Ready
        );
        let crossed = take_outgoing_requests()
            .await
            .expect("the pump must be drainable")
            .iter()
            .map(|request| declared_event_type(&request.body))
            .collect::<Vec<_>>();
        assert!(
            crossed.contains(&"m.key.verification.ready".to_string()),
            "the acceptance of a recovered invitation must reach the pump: {crossed:?}"
        );
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

/// The other interleaving: the library's user says "they match" first, and
/// the counterparty's user says it after.
///
/// This is not a variation for completeness. It is the case where the two
/// closing messages come out of *different* queues. Upstream returns the
/// confirmation and the acknowledgement together only when the peer
/// confirmed first (`verification/sas/inner_sas.rs:243`, reached from
/// `MacReceived`); when we confirm first, our confirmation is handed back
/// to us and our acknowledgement is produced later, as a reaction to the
/// peer's own confirmation, and goes into upstream's own queue
/// (`inner_sas.rs:336-346` through `verification/machine.rs:472-494`).
///
/// So the pump has to order two requests that did not come from the same
/// place, and it has to get it right: the far side drops an acknowledgement
/// that arrives before the confirmation it acknowledges
/// (`inner_sas.rs:354-363` matches `Done` only against `WaitingForDone`)
/// and then waits forever for one that has already been sent. That failure
/// is asymmetric and silent -- this side reaches `Done` and records the peer
/// verified, while the peer records nothing and reports no error.
///
/// The two are deliberately taken in one batch here rather than pumped
/// apart, because a product that pumps after every call never sees this and
/// a product that pumps on a timer always can.
#[test]
fn a_comparison_confirmed_before_the_peer_completes_on_both_sides() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let bob_user = "@confirmingsecond:example.org";
        let bob_device = "COUNTERPARTYFIVE";
        let bob = counterparty(bob_user, bob_device).await;
        subscribe_and_drain();

        // ---- Up to a string on both screens -----------------------------
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
            "both sides must be looking at the same string"
        );

        // ---- This side says it matches first, and does not pump ---------
        confirm_flow(&flow)
            .await
            .expect("a flow showing a string can be confirmed");
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Confirmed
        );

        // ---- Then the counterparty says so, and its confirmation lands --
        // This is what makes the acknowledgement appear, in the other
        // queue, behind a confirmation of ours that has not left yet.
        let (contents, _signatures) = bob_sas
            .confirm()
            .await
            .expect("the counterparty can confirm");
        assert_eq!(
            contents.len(),
            1,
            "a counterparty confirming second sends its confirmation alone"
        );
        for content in &contents {
            deliver_verification_request(content, bob_user).await;
        }

        // ---- One batch, carrying both, in the order they were produced --
        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert_eq!(
            crossed,
            vec![
                "m.key.verification.mac".to_string(),
                "m.key.verification.done".to_string()
            ],
            "one batch carrying a confirmation and the acknowledgement that \
             follows it must list them in that order, whichever queue each \
             came out of: {crossed:?}"
        );

        // ---- And both sides finish --------------------------------------
        assert!(
            bob_sas.is_done(),
            "the counterparty must have finished -- an acknowledgement it \
             receives before the confirmation it acknowledges is discarded, \
             and it then waits forever for one that was already sent"
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

        // ---- And this interleaving announces the same one thing ---------
        // Not a duplicate of the assertion in
        // `two_parties_complete_a_comparison`. There, the peer had already
        // confirmed when this side did; here this side confirmed first and
        // the completion arrives with the peer's acknowledgement, out of a
        // different queue. The channel must say the same thing either way,
        // once, and this is the pair that establishes it.
        assert_eq!(
            next_signal("the other interleaving must announce the trust change too"),
            CryptoSignal::TrustChanged {
                user: bob_user.to_string(),
                state: TrustState::Verified,
            },
        );

        // Synced three more times before asserting silence, and without
        // this the assertion below is free: nothing on this channel is
        // emitted except from a sync, so "no more arrived" proves nothing
        // unless the producer has since run against a flow that is still
        // `Done` in the registry. Written without it twice, on both
        // completion tests, and deleting `completion_announced` failed
        // neither -- the same vacuity this file had already found and fixed
        // twice on the inbound side. Three rather than one, so an
        // implementation that repeated on alternate syncs fails too.
        for _ in 0..3 {
            deliver_to_library(vec![]).await;
        }
        no_signal("one completed comparison is one trust change, whichever side confirmed first");
    }));
}

/// The counterparty opens a comparison the deprecated way: an
/// `m.key.verification.start` with no `m.key.verification.request` before
/// it, to-device only.
///
/// `Device::start_verification` is upstream's own entry point for that
/// shape and is still present in 0.18.0. It is driven on the *bare*
/// machine and never on the library, which is the whole point: this library
/// deliberately offers no way to send one, and what it has to be able to do
/// is answer one somebody else sent.
///
/// The request it produces is handed over by hand rather than drained from
/// the bare machine's pump, because upstream returns it to its caller and
/// queues nothing -- `VerificationMachine::start_sas` inserts the
/// comparison into its cache and hands the request back.
async fn bare_start_from(bob: &OlmMachine, bob_user: &str) -> Sas {
    let alice: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
    let alice_device: OwnedDeviceId = ALICE_DEVICE.into();
    let library_device = bob
        .get_device(&alice, &alice_device, None)
        .await
        .expect("the bare machine's store must be readable")
        .expect("the bare machine knows the library's device");
    let (bob_sas, start) = library_device
        .start_verification()
        .await
        .expect("the bare machine can open a comparison against a device it knows");
    let start: OutgoingVerificationRequest = start.into();
    assert_eq!(
        declared_event_type(&verification_body(&start)),
        "m.key.verification.start",
        "this helper is worthless unless what it delivers really is a bare start"
    );
    deliver_verification_request(&start, bob_user).await;
    bob_sas
}

/// The short authentication string both sides computed, asserted equal, and
/// returned so the caller can go on to agree with it or to differ from it.
async fn agreed_material(flow: &FlowId, bob_sas: &Sas) -> SasMaterial {
    let material = read_material(flow)
        .await
        .expect("the string is available once the keys are exchanged");
    assert_eq!(
        material.decimals,
        bob_sas
            .decimals()
            .expect("the counterparty has a string too"),
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
    material
}

/// Everything from the announcement to the string, for a flow that arrived
/// as a bare start: the announcement is read off the channel, checked
/// against what the counterparty actually opened, and the flow is then
/// driven to `KeysExchanged` through the public surface alone.
///
/// The identifier is taken from the signal and from nowhere else, which is
/// the property both tests below rest on: nothing in this process knew this
/// flow's name until the channel said it.
async fn announced_bare_flow(
    bob: &OlmMachine,
    bob_user: &str,
    bob_device: &str,
    bob_sas: &Sas,
) -> FlowId {
    let announced = next_signal("a comparison started without a request must be announced");
    let CryptoSignal::VerificationRequested {
        user,
        device_id,
        flow_id,
    } = announced.clone()
    else {
        panic!("a bare start must announce itself as an invitation, not as {announced:?}");
    };
    assert_eq!(user, bob_user, "the announcement must name who is asking");
    assert_eq!(
        device_id, bob_device,
        "the announcement must name which of that user's devices is asking"
    );
    assert_eq!(
        flow_id,
        bob_sas.flow_id().as_str(),
        "the identifier the channel hands over must be the comparison's own, which for \
         this shape is the transaction id the start event carried"
    );
    no_signal("one start is one announcement");
    let flow = FlowId(flow_id);

    // Announced once, and once only, however many syncs go by while a
    // person is deciding. Three empty ones rather than one, so an
    // implementation that repeated on alternate calls fails too.
    for _ in 0..3 {
        deliver_to_library(vec![]).await;
    }
    assert_eq!(
        flow_stage(&flow)
            .await
            .expect("an announced flow is findable by the identifier the channel gave"),
        FlowStage::Started,
        "this proves nothing unless the flow is still in the state that would be re-announced"
    );
    no_signal("a start already announced must not be announced again on every sync");

    // There is nothing to begin: it began before this library ever heard of
    // it. Refused rather than quietly building a second comparison under
    // the same identifier, which is what upstream's cache would then cancel
    // both halves of.
    assert_eq!(
        begin_comparison(&flow)
            .await
            .expect_err("a flow that arrived as a comparison cannot have one started"),
        MachineError::WrongStage
    );
    assert_eq!(
        read_material(&flow)
            .await
            .expect_err("no keys have crossed yet"),
        MachineError::MaterialNotReady
    );

    // The library agrees. For this shape that is upstream's `Sas::accept`
    // rather than the request's, and the message it produces is the one the
    // peer is waiting for before it will send its key.
    accept_flow(&flow)
        .await
        .expect("a comparison the other side started can be agreed to");
    let crossed = pump_to_bare(bob, bob_user, bob_device).await;
    assert!(
        crossed.contains(&"m.key.verification.accept".to_string()),
        "the agreement must reach the counterparty through the pump: {crossed:?}"
    );

    // The starting side sends its key first, and this side's own key only
    // counts once the pump has reported it sent.
    let crossed = pump_bare_to_library(bob, bob_user).await;
    assert!(
        crossed.contains(&"m.key.verification.key".to_string()),
        "the counterparty's key must reach the library: {crossed:?}"
    );
    let crossed = pump_to_bare(bob, bob_user, bob_device).await;
    assert!(
        crossed.contains(&"m.key.verification.key".to_string()),
        "the library's key must reach the counterparty through the pump: {crossed:?}"
    );

    assert_eq!(
        flow_stage(&flow).await.expect("the flow exists"),
        FlowStage::KeysExchanged
    );
    flow
}

/// The other shape a verification can arrive in, driven end to end: a bare
/// `m.key.verification.start` with no request before it.
///
/// # Why this is not an exotic case
///
/// MSC3122 deprecated the shape and this library never sends it. It is
/// nonetheless what a real third-party client sends: `matrix-nio` 0.26.0
/// implements the short-string verification **only** this way -- its event
/// vocabulary is `start`, `accept`, `key`, `mac`, `cancel` and nothing else
/// -- and `matrix-sdk-crypto` 0.18.0 still both emits it (driven here) and
/// accepts it. Until this test existed such a flow reached the library,
/// existed inside its own machine, and could be reached through no call on
/// the public surface at all: `get_verification` found the comparison while
/// `flow_stage`, `read_material`, `accept_flow` and `begin_comparison`
/// every one answered `UnknownFlow`.
///
/// # What is the same, and what is not
///
/// The same: it is announced on the same channel under the same variant,
/// and it is driven with the same calls -- agree, read the string, confirm
/// or refuse.
///
/// Different in three places, each asserted rather than described. There is
/// no `Ready` stage, so `begin_comparison` has nothing to do and says so.
/// The library's own `confirm_flow` **finishes** the flow outright instead
/// of leaving it `Confirmed`, because upstream forks on
/// `started_from_request` (`verification/sas/inner_sas.rs:243-258`) and a
/// flow that came from no request needs no acknowledgement back. And
/// consequently no `m.key.verification.done` is ever sent -- which is
/// exactly what makes the shape usable against a client that has no such
/// event, and is asserted negatively here for that reason.
#[test]
fn a_comparison_started_without_a_request_is_announced_and_completes() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let bob_user = "@starting:example.org";
        let bob_device = "COUNTERPARTYSIX";
        let bob = counterparty(bob_user, bob_device).await;
        subscribe_and_drain();

        let trust_before = library_device_status(bob_user, bob_device).await;
        assert_eq!(
            trust_before,
            TrustState::Unverified,
            "a device this machine merely knows the keys of is not verified"
        );
        assert!(
            !bare_reports_verified(&bob).await,
            "nothing may be verified before a comparison has happened"
        );

        let bob_sas = bare_start_from(&bob, bob_user).await;
        let flow = announced_bare_flow(&bob, bob_user, bob_device, &bob_sas).await;
        let material = agreed_material(&flow, &bob_sas).await;
        assert_eq!(
            material.decimals,
            bob_sas.decimals().expect("the counterparty has a string"),
            "the digits both people are about to read out must be the same ones"
        );

        // ---- Both sides say it matches ----------------------------------
        // The counterparty first, so the library's own confirmation is the
        // one that finishes the flow and the one whose effect is asserted.
        // It is also the interleaving that reaches the fork this shape
        // exists for: the library confirms from `MacReceived`, which is
        // where upstream decides between waiting for a `done` and being
        // finished.
        let (contents, _signatures) = bob_sas
            .confirm()
            .await
            .expect("the counterparty can confirm");
        for content in &contents {
            deliver_verification_request(content, bob_user).await;
        }
        assert!(
            !library_reports_verified(bob_user, bob_device).await,
            "one side confirming must not verify anything"
        );

        confirm_flow(&flow)
            .await
            .expect("a flow showing a string can be confirmed");

        // Finished here, not two messages later. This is the assertion the
        // request-shaped tests cannot make: there they hold at `Confirmed`
        // until the peer's `m.key.verification.done` arrives.
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Done,
            "a comparison that came from no request is over when both sides have said \
             the strings match; there is nothing left to acknowledge"
        );
        assert!(
            library_reports_verified(bob_user, bob_device).await,
            "the library must report the counterparty's device verified"
        );

        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            crossed.contains(&"m.key.verification.mac".to_string()),
            "the library's confirmation must reach the counterparty: {crossed:?}"
        );
        assert!(
            !crossed.contains(&"m.key.verification.done".to_string()),
            "a flow that came from no request terminates on the MAC. A `done` here would \
             be an event the clients that speak only this shape cannot send and cannot \
             answer, and its presence would mean the flow was waiting for one back: \
             {crossed:?}"
        );
        assert!(
            bob_sas.is_done(),
            "the counterparty's comparison must have finished too"
        );
        assert!(
            bare_reports_verified(&bob).await,
            "the counterparty must report the library's device verified"
        );

        let trust_after = library_device_status(bob_user, bob_device).await;
        assert_ne!(
            trust_after, trust_before,
            "a completed comparison must change what this device reports"
        );
        assert_eq!(trust_after, TrustState::Verified);

        // ---- And a subscriber was told, on the next sync ----------------
        // On the *next* sync, and not from `confirm_flow`: the channel's
        // producers run inside `receive_sync_changes` and nowhere else. For
        // this shape that is a visible delay rather than an invisible one,
        // because here the confirmation is what finished the flow. The
        // empty sync below is therefore load-bearing, not padding.
        no_signal("the channel announces from a sync, and none has run since the confirmation");
        deliver_to_library(vec![]).await;
        assert_eq!(
            next_signal("a completed comparison must announce the trust change"),
            CryptoSignal::TrustChanged {
                user: bob_user.to_string(),
                state: TrustState::Verified,
            },
            "the channel must name the user whose device changed, and the state it changed to"
        );

        for _ in 0..3 {
            deliver_to_library(vec![]).await;
        }
        no_signal("a completed comparison announces one trust change and no more");
    }));
}

/// The refusal, on the shape that has no request behind it.
///
/// The successful case above cannot stand in for this one, and a
/// verification surface that can only ever agree proves nothing at all --
/// the module's own header opens with that sentence. `cancel_flow` reaches
/// upstream through a different handle on this shape than on the requested
/// one (there is no request to cancel, only the comparison), so the
/// refusal has to be exercised here separately rather than inferred from
/// `a_disagreement_refuses`.
#[test]
fn a_disagreement_on_a_comparison_nobody_requested_refuses() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let bob_user = "@startingandrefused:example.org";
        let bob_device = "COUNTERPARTYSEVEN";
        let bob = counterparty(bob_user, bob_device).await;
        subscribe_and_drain();

        let bob_sas = bare_start_from(&bob, bob_user).await;
        let flow = announced_bare_flow(&bob, bob_user, bob_device, &bob_sas).await;
        let material = agreed_material(&flow, &bob_sas).await;

        // ---- The two people are not looking at the same string ----------
        // The difference is put here rather than discovered, for the reason
        // `a_disagreement_refuses` records: this stands in for a person,
        // and a branch written around it would be a tautology dressed as a
        // decision. What carries the weight is everything after the
        // refusal.
        let heard_from_the_other_side = (
            material.decimals.0,
            material.decimals.1,
            material.decimals.2 ^ 1,
        );
        assert_ne!(
            heard_from_the_other_side, material.decimals,
            "the string this test puts in the user's mouth must differ from the one on \
             the library's own screen, or there is nothing to refuse"
        );

        cancel_flow(&flow)
            .await
            .expect("a string that does not match what the user sees is refused");

        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            crossed.contains(&"m.key.verification.cancel".to_string()),
            "the refusal must reach the counterparty: {crossed:?}"
        );

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

        // Synced first, and that is not padding: nothing on this channel is
        // emitted except from a sync, so silence after a refusal proves
        // nothing unless a sync has since run against the refused flow.
        deliver_to_library(vec![]).await;
        no_signal(
            "a refused comparison changes no device's trust, so the channel has nothing \
             to say about it",
        );
    }));
}

/// The bare-start flow a product finds without the channel, and the one
/// property the two flow shapes do not share.
///
/// # Why a flow nobody announced still has to be answerable
///
/// A request-shaped invitation that arrives while nobody is subscribed is
/// announced on the first sync after somebody subscribes, because
/// `announce_state_changes` re-enumerates upstream's request map every
/// time. There is no such map for the other shape: `VerificationCache`
/// offers keyed lookup and no listing at all, so the sync that carried the
/// start event is the only chance to notice it. That difference is asserted
/// here rather than left in a doc comment, because it is the kind of claim
/// that stops being true quietly.
///
/// What is left is the route this test then takes: the identifier is on the
/// wire, in `content.transaction_id` of the start event the product was
/// handed, and a flow named that way must be as usable as one the channel
/// announced. That is `handles`'s fallback through
/// `OlmMachine::get_verification`, and this is the only test that reaches
/// it -- everywhere else the announcement has already put the flow in the
/// registry, so the fallback is never asked.
#[test]
fn a_comparison_nobody_requested_is_answerable_without_the_channel() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let bob_user = "@startingunheard:example.org";
        let bob_device = "COUNTERPARTYEIGHT";
        let bob = counterparty(bob_user, bob_device).await;
        // Installed and then removed, which is what a product is between
        // unmounting one subscribing component and mounting the next.
        subscribe_and_drain();
        unsubscribe();

        let bob_sas = bare_start_from(&bob, bob_user).await;
        no_signal("with no observer installed the channel produces nothing at all");

        // Back, and told nothing. This is the asymmetry, and it is the
        // reason the facade tells a product to subscribe before it syncs.
        subscribe();
        for _ in 0..3 {
            deliver_to_library(vec![]).await;
        }
        no_signal(
            "a bare start's only witness is the sync that carried it. Upstream keeps such \
             a flow where nothing can enumerate it, so unlike a request-shaped invitation \
             it cannot be re-offered to whoever subscribes next",
        );

        // The flow is nonetheless live inside the machine, and answerable
        // by the name the wire carried. Read off the counterparty's own
        // comparison here, which is the same string a product would read
        // out of `content.transaction_id`.
        let flow = FlowId(bob_sas.flow_id().as_str().to_string());
        assert_eq!(
            flow_stage(&flow)
                .await
                .expect("a flow the channel never announced is still findable by name"),
            FlowStage::Started,
            "the comparison exists inside the machine and the public surface must reach it"
        );

        // Usable, not merely readable: the surface's answer is worth
        // nothing if the flow it found cannot be driven.
        accept_flow(&flow)
            .await
            .expect("a flow found this way can be agreed to like any other");
        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            crossed.contains(&"m.key.verification.accept".to_string()),
            "the agreement must reach the counterparty: {crossed:?}"
        );
        let crossed = pump_bare_to_library(&bob, bob_user).await;
        assert!(
            crossed.contains(&"m.key.verification.key".to_string()),
            "the counterparty must have acted on that agreement by sending its key, which \
             is the only evidence from outside that the agreement was a real one: {crossed:?}"
        );
    }));
}

/// The interleaving the request-shaped tests never took: **the peer opens
/// the comparison**, rather than this library doing it.
///
/// # Why this was a stall, and not merely an untested path
///
/// Either side may start the comparison once both are ready -- the facade
/// says so, and it is true of the protocol. What the peer's start needs
/// back is an `m.key.verification.accept`, and upstream does not send one:
/// `receive_start` builds the comparison and returns
/// (`verification/requests.rs:1366-1396`), leaving the message to the
/// application. Until `accept_flow` learned to answer a comparison on a
/// flow that also has a request, no call in this library produced it. The
/// flow read `Started` forever, nothing errored anywhere, and the string
/// was never produced -- measured on this exact setup before the change:
/// `accept_flow` answered `WrongStage` and the pump handed out nothing at
/// all.
///
/// So this test is the fix's proof and the shape's only coverage at once.
/// It ends where `two_parties_complete_a_comparison` ends, on the same two
/// assertions, reached the other way round.
#[test]
fn a_comparison_the_peer_started_on_a_requested_flow_is_agreed_to_and_completes() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let bob_user = "@startingafterasking:example.org";
        let bob_device = "COUNTERPARTYNINE";
        let bob = counterparty(bob_user, bob_device).await;
        subscribe_and_drain();

        assert!(
            !library_reports_verified(bob_user, bob_device).await,
            "nothing may be verified before a comparison has happened"
        );

        // ---- The counterparty asks, and the library agrees ---------------
        let alice: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
        let alice_device: OwnedDeviceId = ALICE_DEVICE.into();
        let library_device = bob
            .get_device(&alice, &alice_device, None)
            .await
            .expect("the bare machine's store must be readable")
            .expect("the bare machine knows the library's device");
        let (bob_request, asking) =
            library_device.request_verification_with_methods(vec![VerificationMethod::SasV1]);
        deliver_verification_request(&asking, bob_user).await;

        let announced = next_signal("an inbound invitation must be announced");
        let CryptoSignal::VerificationRequested { flow_id, .. } = announced.clone() else {
            panic!("an inbound invitation must announce itself as one, not as {announced:?}");
        };
        let flow = FlowId(flow_id);

        accept_flow(&flow)
            .await
            .expect("an invitation can be agreed to");
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Ready
        );
        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            crossed.contains(&"m.key.verification.ready".to_string()),
            "the agreement must reach the counterparty: {crossed:?}"
        );

        // ---- And then the counterparty starts, not the library -----------
        let (bob_sas, start) = bob_request
            .start_sas()
            .await
            .expect("the bare machine's store must be readable")
            .expect("a ready request can start a comparison");
        deliver_verification_request(&start, bob_user).await;
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Started
        );

        // There is nothing left for this side to start, and it is told so
        // rather than building a second comparison under the same name.
        assert_eq!(
            begin_comparison(&flow)
                .await
                .expect_err("the comparison the peer opened is the one that is running"),
            MachineError::WrongStage
        );

        // ---- The library agrees a second time, to the comparison ---------
        // This is the call that was missing. Asserted on what crosses,
        // because the failure it replaces produced no error to assert on:
        // the pump simply handed out nothing.
        assert!(
            !bob_sas.has_been_accepted(),
            "this proves nothing unless the counterparty is still waiting to be answered"
        );
        accept_flow(&flow)
            .await
            .expect("a comparison the counterparty opened can be agreed to");
        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            crossed.contains(&"m.key.verification.accept".to_string()),
            "the agreement to the comparison must reach the counterparty, and its absence \
             is exactly the stall this test exists for: {crossed:?}"
        );
        assert!(
            bob_sas.has_been_accepted(),
            "and the counterparty must have observed it"
        );

        // ---- From here it is the ordinary flow ---------------------------
        let crossed = pump_bare_to_library(&bob, bob_user).await;
        assert!(
            crossed.contains(&"m.key.verification.key".to_string()),
            "the counterparty's key must reach the library: {crossed:?}"
        );
        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            crossed.contains(&"m.key.verification.key".to_string()),
            "the library's key must reach the counterparty: {crossed:?}"
        );

        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::KeysExchanged
        );
        let material = agreed_material(&flow, &bob_sas).await;
        assert_eq!(
            material.decimals,
            bob_sas.decimals().expect("the counterparty has a string"),
            "the digits both people are about to read out must be the same ones"
        );

        // ---- Both sides say it matches, and each verifies the other ------
        let (contents, _signatures) = bob_sas
            .confirm()
            .await
            .expect("the counterparty can confirm");
        for content in &contents {
            deliver_verification_request(content, bob_user).await;
        }
        confirm_flow(&flow)
            .await
            .expect("a flow showing a string can be confirmed");
        pump_to_bare(&bob, bob_user, bob_device).await;
        pump_bare_to_library(&bob, bob_user).await;

        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Done
        );
        assert!(
            library_reports_verified(bob_user, bob_device).await,
            "the library must report the counterparty's device verified"
        );
        assert!(
            bare_reports_verified(&bob).await,
            "and the counterparty must report the library's device verified"
        );
    }));
}

/// Every state in which agreeing does not apply, on both flow shapes, told
/// apart from a successful no-op.
///
/// Upstream reports all of them the same way -- by returning `None` from a
/// call whose signature cannot fail -- and "did nothing, successfully" is
/// the one answer a verification call must never give. Nothing else in this
/// file calls [`accept_flow`] in a state where upstream declines, so
/// without this the mapping is documented and unexercised.
///
/// Three states, chosen because each is a different mistake a product
/// makes: answering an invitation this device sent itself, answering the
/// same comparison twice, and answering a flow that is over.
#[test]
fn agreeing_when_there_is_nothing_to_agree_to_is_refused_on_both_shapes() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let bob_user = "@nothingtoagreeto:example.org";
        let bob_device = "COUNTERPARTYTEN";
        let bob = counterparty(bob_user, bob_device).await;
        subscribe_and_drain();

        // ---- The request shape: our own invitation ----------------------
        // `VerificationRequest::accept_with_methods` declines anything but
        // `Requested`, and a flow this device asked for is `Created`.
        let ours = request_flow(bob_user, bob_device)
            .await
            .expect("a known device can be asked to verify itself");
        assert_eq!(
            flow_stage(&ours).await.expect("the flow exists"),
            FlowStage::Requested
        );
        assert_eq!(
            accept_flow(&ours)
                .await
                .expect_err("a device cannot agree to its own invitation"),
            MachineError::WrongStage
        );
        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            !crossed.contains(&"m.key.verification.ready".to_string()),
            "a refused agreement must queue nothing: {crossed:?}"
        );
        cancel_flow(&ours)
            .await
            .expect("the invitation can be abandoned");
        pump_to_bare(&bob, bob_user, bob_device).await;

        // ---- The bare shape: agreeing twice -----------------------------
        // `Sas::accept` declines anything but `SasState::Started`, and one
        // agreement moves the comparison past it.
        let bob_sas = bare_start_from(&bob, bob_user).await;
        let flow = announced_bare_flow(&bob, bob_user, bob_device, &bob_sas).await;
        assert_eq!(
            accept_flow(&flow)
                .await
                .expect_err("a comparison already agreed to cannot be agreed to again"),
            MachineError::WrongStage
        );
        let crossed = pump_to_bare(&bob, bob_user, bob_device).await;
        assert!(
            !crossed.contains(&"m.key.verification.accept".to_string()),
            "a refused agreement must queue nothing: {crossed:?}"
        );

        // ---- And a flow that is over ------------------------------------
        cancel_flow(&flow)
            .await
            .expect("a live flow can be refused");
        pump_to_bare(&bob, bob_user, bob_device).await;
        assert_eq!(
            flow_stage(&flow).await.expect("a refused flow is readable"),
            FlowStage::Cancelled
        );
        assert_eq!(
            accept_flow(&flow)
                .await
                .expect_err("a refused flow has nothing left to agree to"),
            MachineError::WrongStage
        );
    }));
}

/// A comparison that is already over by the time the sync carrying it is
/// processed must not be announced.
///
/// # Why this is reachable, and what it would cost
///
/// A start and the cancellation that ends it can arrive in the same sync --
/// a peer that changes its mind, or a device that was offline while both
/// crossed. Upstream processes them in order, so by the time the
/// announcement runs the comparison exists and is cancelled.
///
/// Announcing it would break the one rule the channel rests on: the
/// identifier would be handed to a product that no call in this module
/// answers to, because [`handles`] refuses to adopt a finished flow. The
/// negative assertion below is therefore paired with a positive one on the
/// same identifier -- the channel says nothing, *and* the call rejects it
/// -- so an implementation that had merely stopped announcing anything at
/// all fails the pair.
#[test]
fn a_comparison_already_over_when_its_sync_is_processed_is_not_announced() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let bob_user = "@startedandwithdrawn:example.org";
        let bob_device = "COUNTERPARTYELEVEN";
        let bob = counterparty(bob_user, bob_device).await;
        subscribe_and_drain();

        let alice: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
        let alice_device: OwnedDeviceId = ALICE_DEVICE.into();
        let library_device = bob
            .get_device(&alice, &alice_device, None)
            .await
            .expect("the bare machine's store must be readable")
            .expect("the bare machine knows the library's device");
        let (bob_sas, start) = library_device
            .start_verification()
            .await
            .expect("the bare machine can open a comparison");
        let start: OutgoingVerificationRequest = start.into();
        let withdrawal = bob_sas
            .cancel()
            .expect("a comparison this side opened can be withdrawn");

        // Both in one sync, in the order the homeserver would deliver them.
        let start_event = relay_to(
            &verification_body(&start),
            bob_user,
            ALICE_USER,
            ALICE_DEVICE,
        )
        .expect("the counterparty addresses the library's own device");
        let cancel_event = relay_to(
            &verification_body(&withdrawal),
            bob_user,
            ALICE_USER,
            ALICE_DEVICE,
        )
        .expect("the counterparty addresses the library's own device");
        assert_eq!(
            declared_event_type(&verification_body(&start)),
            "m.key.verification.start",
            "this test is worthless unless what it feeds in really is a bare start"
        );
        deliver_to_library(vec![start_event, cancel_event]).await;

        no_signal(
            "a comparison that was over before this library ever looked at it has nothing \
             to announce",
        );
        let flow = FlowId(bob_sas.flow_id().as_str().to_string());
        assert_eq!(
            flow_stage(&flow)
                .await
                .expect_err("a flow that ended before it was seen is not one this library holds"),
            MachineError::UnknownFlow,
            "the pair with the silence above: the channel is quiet about this identifier \
             *because* no call here answers to it, which is the rule announcing off the \
             wire would break"
        );

        // And the channel is not merely broken: a live one still announces.
        let live = bare_start_from(&bob, bob_user).await;
        let announced = next_signal("a live comparison must still be announced");
        let CryptoSignal::VerificationRequested { flow_id, .. } = announced.clone() else {
            panic!("a bare start must announce itself as an invitation, not as {announced:?}");
        };
        assert_eq!(
            flow_id,
            live.flow_id().as_str(),
            "and it must be the live one, not the withdrawn one"
        );
        cancel_flow(&FlowId(flow_id))
            .await
            .expect("the live flow can be tidied away");
        pump_to_bare(&bob, bob_user, bob_device).await;
    }));
}
