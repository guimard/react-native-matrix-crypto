//! A second login joining the signing identity its account already has.
//!
//! # What this file is
//!
//! Two real machines belonging to the **same account**, no homeserver, and
//! the join driven through this crate's shipped surface on the new device's
//! half:
//!
//! 1. The first device holds the account's signing identity. Here it is a
//!    bare upstream `OlmMachine` that minted one, standing in for the phone
//!    its owner set up months ago.
//! 2. The second device is created, publishes its keys and fetches the
//!    account's. It now knows the identity exists and holds none of it.
//! 3. **It is refused a bootstrap**, with `IdentityAlreadyExists`. That
//!    refusal is why this file exists: serving it would mint a second
//!    identity over the first and reset the trust of every device and every
//!    user who had verified it.
//! 4. It asks its own other devices to verify it, through
//!    [`request_self_flow`], and a comparison completes.
//! 5. The seeds arrive by gossip, encrypted, inside an ordinary
//!    `receive_sync_changes`, and `identity_status().private_keys_held`
//!    turns true.
//! 6. The `trust_changed` signal announces that arrival, because nothing
//!    returns to the caller when it lands.
//!
//! # Which side is the library
//!
//! The asymmetry `tests/two_parties.rs` and `tests/verified_sender.rs` both
//! document holds here with the sides swapped: **the library is the new
//! device**, the one that has nothing, and the bare `OlmMachine` is the one
//! that already has everything. That is the shape the milestone is about.
//! This file relays between the two exactly what a homeserver would relay
//! and nothing else.
//!
//! # Why the whole comparison is driven rather than short-circuited
//!
//! Upstream sets `should_request_secrets` only inside `mark_as_done`, only
//! for `UserIdentityData::Own`, and only when the account's master key
//! actually appeared in the MAC the other side sent. Nothing on this
//! crate's surface asks for the seeds outside that path, so a test that
//! faked the comparison would be asserting against a machine that had never
//! asked for anything. The gossip is the subject; the comparison is what
//! causes it.

use std::collections::BTreeMap;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use matrix_crypto_core::{
    begin_comparison, bootstrap_identity, confirm_flow, create_machine, device_statuses,
    flow_stage, identity_status, in_runtime, mark_request_sent, read_material,
    receive_sync_changes, request_self_flow, set_crypto_observer, take_outgoing_requests,
    CryptoObserver, CryptoSignal, FlowStage, MachineConfig, MachineError, OutgoingRequest,
    TrustState,
};
use matrix_sdk_common::ruma::api::client::keys::claim_keys::v3::Response as KeysClaimResponse;
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
use matrix_sdk_crypto::types::DeviceKeys;
use matrix_sdk_crypto::{
    CrossSigningBootstrapRequests, DecryptionSettings, EncryptionSyncChanges, OlmMachine,
    TrustRequirement,
};

const ACCOUNT: &str = "@alice:example.org";
/// The library: a login that has just happened and holds nothing.
const NEW_DEVICE: &str = "NEWLOGIN";
/// The bare upstream machine: the device that set the account up.
const OLD_DEVICE: &str = "FIRSTLOGIN";
/// A second device of the account that the identity **has** signed.
///
/// It never answers anything. It is here so that "addressed to every other
/// device" is not the same assertion as "addressed to the one device this
/// file happens to have": a per-device call cannot produce an invitation
/// that names two.
const SIGNED_DEVICE: &str = "SECONDLOGIN";
/// A third device of the same account that the identity has never signed.
///
/// Present only to be *excluded*: it is the negative half of the assertion
/// about who a self-verification invitation is addressed to.
const UNSIGNED_DEVICE: &str = "STRANGER";

/// How long a signal gets to arrive before the assertion fails rather than
/// hanging. The same bound, for the same reason, as `tests/sas_two_party.rs`.
const DELIVERY_BOUND: Duration = Duration::from_secs(5);

/// How long a signal that must *not* come gets to prove it.
///
/// Shorter than [`DELIVERY_BOUND`], and the asymmetry is deliberate: this
/// bound is paid in full on every run. What keeps it honest is that the one
/// negative assertion here does not stand alone -- it follows a positive one
/// on the same channel, so an implementation that had simply stopped
/// delivering fails the pair.
const QUIET_BOUND: Duration = Duration::from_millis(750);

// ------------------------------------------------------- the signal channel

struct Recorder {
    tx: mpsc::Sender<CryptoSignal>,
}

impl CryptoObserver for Recorder {
    fn on_signal(&self, signal: CryptoSignal) {
        let _ = self.tx.send(signal);
    }
}

struct SignalChannel {
    rx: mpsc::Receiver<CryptoSignal>,
}

static SIGNALS: StdMutex<Option<SignalChannel>> = StdMutex::new(None);

/// Installs the recorder. One test in this file drives the machine, so there
/// is nothing to drain and no second subscriber to serialise against.
fn subscribe() {
    let (tx, rx) = mpsc::channel();
    *SIGNALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(SignalChannel { rx });
    set_crypto_observer(Arc::new(Recorder { tx }));
}

/// Every signal delivered so far, having waited for at least one.
///
/// Delivery is detached -- `observer::emit_crypto` hands the signal to a
/// thread of the library's own -- so a `try_recv` sweep alone would race the
/// producer and report an empty channel on a machine that had announced
/// perfectly well.
fn drain_signals(expected: &str) -> Vec<CryptoSignal> {
    let held = SIGNALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let received = &held.as_ref().expect("subscribe must run first").rx;
    let mut signals = vec![received
        .recv_timeout(DELIVERY_BOUND)
        .unwrap_or_else(|e| panic!("{expected}: nothing reached the signal channel ({e})"))];
    while let Ok(signal) = received.try_recv() {
        signals.push(signal);
    }
    signals
}

/// Empties the channel, waiting for it to fall quiet rather than merely to
/// read empty.
///
/// **The cut this makes is what stops the assertion at the end of this file
/// being vacuous**, and it was vacuous: a completed self-verification
/// announces `TrustChanged` for this very account, because the device it
/// compared a string with became verified, and that signal is
/// *indistinguishable* from the one the seeds' arrival produces. Asserting
/// that a `TrustChanged` for this account was seen at some point therefore
/// passed with the arrival producer deleted outright. Everything before the
/// gossip is drained here, so what is asserted afterwards is what the one
/// remaining sync produced.
fn drain_to_quiet() {
    let held = SIGNALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let received = &held.as_ref().expect("subscribe must run first").rx;
    while received.recv_timeout(QUIET_BOUND).is_ok() {}
}

/// Requires that nothing arrives, having waited for it.
fn no_signal(why: &str) {
    let held = SIGNALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Ok(signal) = held
        .as_ref()
        .expect("subscribe must run first")
        .rx
        .recv_timeout(QUIET_BOUND)
    {
        panic!("{why}, and yet {signal:?} was delivered");
    }
}

// ------------------------------------------------------------- wire shapes

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

fn keys_claim_response(body: &str) -> KeysClaimResponse {
    KeysClaimResponse::try_from_http_response(http_ok(body))
        .expect("this test builds its own well-formed keys-claim response")
}

/// The top-level `event_type` a to-device request's JSON body declares.
///
/// Every assertion here about what crossed the wire goes through this rather
/// than stopping at `kind == "to_device"`: the six messages a comparison
/// exchanges, the secret request and the encrypted answer to it are all
/// to-device requests, so the kind alone distinguishes none of them.
fn declared_event_type(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("event_type")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| "<no event_type in body>".to_string())
}

/// The device ids one to-device request body addresses, for `user_id`.
///
/// `"*"` is a device id here as far as this function is concerned: it is
/// ruma's own serialisation of `DeviceIdOrAllDevices::AllDevices`, which is
/// how a secret request addresses every device of the account at once.
fn addressed_devices(body: &str, user_id: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|request| {
            Some(
                request
                    .get("messages")?
                    .get(user_id)?
                    .as_object()?
                    .keys()
                    .cloned()
                    .collect(),
            )
        })
        .unwrap_or_default()
}

/// Turns one to-device request body into the to-device event the addressed
/// device would have received from its homeserver.
///
/// Reads the per-recipient content out of the request and wraps it with the
/// sender and type the request itself declares; it reaches into neither
/// machine. A request addressed to `"*"` is delivered to the named device,
/// which is what a homeserver does with `DeviceIdOrAllDevices::AllDevices`.
fn relay_to(body: &str, sender: &str, user_id: &str, device_id: &str) -> Option<serde_json::Value> {
    let request: serde_json::Value = serde_json::from_str(body).ok()?;
    let event_type = request.get("event_type")?.as_str()?;
    let per_user = request.get("messages")?.get(user_id)?;
    let content = per_user.get(device_id).or_else(|| per_user.get("*"))?;
    Some(serde_json::json!({
        "sender": sender,
        "type": event_type,
        "content": content,
    }))
}

/// The users a `/keys/query` body asks about.
fn queried_users(body: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(body)
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
        .expect("a keys-query body always carries a device_keys object")
}

/// The most permissive requirement, the same one `session.rs`'s own
/// `decryption_settings()` uses, mirrored here so the counterparty is held to
/// the standard the library holds itself to.
fn decryption_settings() -> DecryptionSettings {
    DecryptionSettings {
        sender_device_trust_requirement: TrustRequirement::Untrusted,
    }
}

// ------------------------------------------------------------ the two pumps

/// Hands events to a bare machine as a sync would.
async fn deliver_to_bare(peer: &OlmMachine, events: Vec<serde_json::Value>) {
    let to_device_events: Vec<Raw<AnyToDeviceEvent>> = events
        .into_iter()
        .map(|event| {
            Raw::from_json_string(event.to_string())
                .expect("this test builds its own well-formed event")
        })
        .collect();
    let changed_devices = DeviceLists::default();
    let counts = BTreeMap::new();

    peer.receive_sync_changes(
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

/// Hands events to the library as a sync would, through its own public entry
/// point and its own wire shape.
async fn deliver_to_library(events: Vec<serde_json::Value>) {
    let payload = serde_json::json!({ "to_device_events": events }).to_string();
    receive_sync_changes(&payload)
        .await
        .expect("the library must accept a sync it is the addressee of");
}

/// Drains the library's pump, relays every to-device request in it to the
/// first device, **marks each one sent**, and reports what crossed.
///
/// The mark is what this turns on: upstream advances a comparison only when
/// the message is reported sent, and it retires a gossip request the same
/// way.
async fn pump_to_bare(peer: &OlmMachine) -> Vec<String> {
    let batch = take_outgoing_requests()
        .await
        .expect("the pump must be drainable");

    let mut crossed = Vec::new();
    let mut events = Vec::new();
    for request in batch.iter().filter(|request| request.kind == "to_device") {
        if let Some(event) = relay_to(&request.body, ACCOUNT, ACCOUNT, OLD_DEVICE) {
            crossed.push(declared_event_type(&request.body));
            events.push(event);
        }
        mark_request_sent(&request.id, "{}")
            .await
            .expect("a to-device response must be accepted");
    }

    if !events.is_empty() {
        deliver_to_bare(peer, events).await;
    }
    crossed
}

/// The mirror image: drains the bare machine's own outbound requests, relays
/// its to-device ones to the library, and marks them sent on its side.
async fn pump_bare_to_library(peer: &OlmMachine) -> Vec<String> {
    let batch = peer
        .outgoing_requests()
        .await
        .expect("the bare machine's requests must be readable");

    let mut crossed = Vec::new();
    let mut events = Vec::new();
    for request in &batch {
        if let AnyOutgoingRequest::ToDeviceRequest(to_device) = request.request() {
            let body =
                serde_json::to_string(to_device).expect("an upstream to-device request serialises");
            if let Some(event) = relay_to(&body, ACCOUNT, ACCOUNT, NEW_DEVICE) {
                crossed.push(declared_event_type(&body));
                events.push(event);
            }
            peer.mark_request_as_sent(request.request_id(), &ToDeviceResponse::new())
                .await
                .expect("the bare machine must accept its own to-device response");
        }
    }

    if !events.is_empty() {
        deliver_to_library(events).await;
    }
    crossed
}

/// Relays one request the bare machine handed back to its caller rather than
/// queueing.
async fn deliver_verification_request(request: &OutgoingVerificationRequest) {
    let body = match request {
        OutgoingVerificationRequest::ToDevice(to_device) => {
            serde_json::to_string(to_device).expect("an upstream to-device request serialises")
        }
        // Unreachable: an in-room flow only exists if an in-room verification
        // event was fed to the machine, and this library has no entry point
        // that does that.
        OutgoingVerificationRequest::InRoom(_) => {
            panic!("this library runs to-device verification flows only")
        }
    };
    let event = relay_to(&body, ACCOUNT, ACCOUNT, NEW_DEVICE)
        .expect("the first device addresses the library's own device");
    deliver_to_library(vec![event]).await;
}

/// Every signature upload the bare machine currently owes, as JSON.
///
/// The field to watch on this side of a self-verification. Verifying
/// somebody else signs *their master key* with our user-signing key;
/// verifying our own device signs *the device*, with the self-signing key,
/// and only the side that holds the private keys can do it.
async fn signature_uploads_of(peer: &OlmMachine) -> Vec<serde_json::Value> {
    peer.outgoing_requests()
        .await
        .expect("the bare machine's requests must be readable")
        .iter()
        .filter_map(|request| match request.request() {
            AnyOutgoingRequest::SignatureUpload(upload) => Some(
                serde_json::to_value(&upload.signed_keys)
                    .expect("an upstream signature upload serialises"),
            ),
            _ => None,
        })
        .collect()
}

// ------------------------------------------------------------- the fixtures

/// The device keys a bare machine holds for its own device.
async fn device_keys_of(
    machine: &OlmMachine,
    user_id: &OwnedUserId,
    device_id: &OwnedDeviceId,
) -> DeviceKeys {
    machine
        .get_device(user_id, device_id, None)
        .await
        .expect("a machine's own store must be readable")
        .expect("a machine always knows its own device")
        .as_device_keys()
        .to_owned()
}

/// The self-signing signature a bootstrap produced over the signing device's
/// own device keys, put back onto them.
///
/// The homeserver's half and nothing more: it moves a signature the first
/// device genuinely computed, over its own genuine device keys, from the
/// request it emitted into the response the library is about to be handed.
/// Nothing is fabricated. The same helper, and the same reasoning, as
/// `tests/verified_sender.rs`.
fn with_owner_signature(
    mut device_keys: DeviceKeys,
    bootstrap: &CrossSigningBootstrapRequests,
    user_id: &OwnedUserId,
    device_id: &OwnedDeviceId,
) -> DeviceKeys {
    let self_signing_key_id = bootstrap
        .upload_signing_keys_req
        .self_signing_key
        .as_ref()
        .expect("a bootstrap always produces a self-signing key")
        .get_first_key_and_id()
        .expect("a self-signing key always carries exactly one key")
        .0
        .to_owned();
    // Looked up by device id, not taken as the first entry: this map is keyed
    // by device id *and* by cross-signing key id, because a bootstrap also
    // signs its own master key with the device.
    let signed: DeviceKeys = bootstrap
        .upload_signatures_req
        .signed_keys
        .get(user_id)
        .expect("a bootstrap signs the device of the user that ran it")
        .iter()
        .find(|(id, _)| *id == device_id.as_str())
        .map(|(_, raw)| {
            serde_json::from_str(raw.get())
                .expect("upstream's own signed device keys deserialise as device keys")
        })
        .expect("a bootstrap signs the running device, keyed by its device id");
    device_keys.signatures.add_signature(
        user_id.clone(),
        self_signing_key_id.clone(),
        signed
            .signatures
            .get_signature(user_id, &self_signing_key_id)
            .expect("the signed copy carries the signature the bootstrap just made"),
    );
    device_keys
}

/// What the first device published about the account, in the shapes a
/// `/keys/query` answer carries them in.
struct FirstDevice {
    peer: OlmMachine,
    signed_device_keys: serde_json::Value,
    master_key: serde_json::Value,
    self_signing_key: serde_json::Value,
    user_signing_key: serde_json::Value,
}

/// Stands up the device that got there first: publishes its keys, mints the
/// account's identity, and signs its own device with it.
async fn first_device() -> FirstDevice {
    let account: OwnedUserId = ACCOUNT.parse().expect("a literal user id parses");
    let device: OwnedDeviceId = OLD_DEVICE.into();

    let peer = OlmMachine::new(&account, &device).await;

    let upload_id = peer
        .outgoing_requests()
        .await
        .expect("a fresh bare machine has keys to publish")
        .iter()
        .find(|request| matches!(request.request(), AnyOutgoingRequest::KeysUpload(_)))
        .expect("a fresh bare machine has a key upload")
        .request_id()
        .to_owned();
    peer.mark_request_as_sent(
        &upload_id,
        &keys_upload_response(r#"{"one_time_key_counts":{}}"#),
    )
    .await
    .expect("the bare machine must accept its own upload response");

    // `false`, not `true`: the account has no identity yet, so this is the
    // mint, and the device keys published above are what it signs.
    let bootstrap = peer
        .bootstrap_cross_signing(false)
        .await
        .expect("a bare machine must be able to mint its account's identity");

    let signed_device_keys = serde_json::to_value(with_owner_signature(
        device_keys_of(&peer, &account, &device).await,
        &bootstrap,
        &account,
        &device,
    ))
    .expect("upstream device keys serialise");

    let published = &bootstrap.upload_signing_keys_req;
    fn key_of<T: serde::Serialize>(field: &str, key: &Option<T>) -> serde_json::Value {
        serde_json::to_value(
            key.as_ref()
                .unwrap_or_else(|| panic!("a minted identity must carry a {field} entry")),
        )
        .expect("an upstream cross-signing key serialises")
    }

    FirstDevice {
        signed_device_keys,
        master_key: key_of("master_keys", &published.master_key),
        self_signing_key: key_of("self_signing_keys", &published.self_signing_key),
        user_signing_key: key_of("user_signing_keys", &published.user_signing_key),
        peer,
    }
}

/// The device keys of a second device the account's identity has signed.
///
/// Signed for real, by the same private identity, rather than by a hand-made
/// signature: the machine is told what the account published, imports the
/// first device's own export, and runs a bootstrap, which is upstream's way
/// of signing the running device with the account's self-signing key.
/// Upstream verifies that signature before it stores anything, so a
/// fabricated one would be dropped and the assertion this fixture exists for
/// would hold for the wrong reason.
///
/// **The key query comes first and is not optional.**
/// `Store::import_cross_signing_keys` does nothing at all when the machine
/// holds no public identity for the account -- it warns and returns
/// (`store/mod.rs:961-999`) -- and the bootstrap that follows would then find
/// an empty private identity and mint a **second** one. That fixture looks
/// identical from the outside and is worthless: the device would be signed by
/// an identity the library has never heard of. The assertions below are what
/// stop it passing for that reason.
async fn signed_device_keys(first: &FirstDevice) -> serde_json::Value {
    let account: OwnedUserId = ACCOUNT.parse().expect("a literal user id parses");
    let device: OwnedDeviceId = SIGNED_DEVICE.into();
    let sibling = OlmMachine::new(&account, &device).await;

    sibling
        .mark_request_as_sent(
            &TransactionId::new(),
            &keys_query_response(
                &serde_json::json!({
                    "device_keys": { ACCOUNT: {} },
                    "master_keys": { ACCOUNT: first.master_key },
                    "self_signing_keys": { ACCOUNT: first.self_signing_key },
                    "user_signing_keys": { ACCOUNT: first.user_signing_key },
                })
                .to_string(),
            ),
        )
        .await
        .expect("the sibling must accept a keys-query response");

    let export = first
        .peer
        .export_cross_signing_keys()
        .await
        .expect("the first device's store must be readable")
        .expect("the first device minted the identity, so it holds its private keys");
    let status = sibling
        .import_cross_signing_keys(export)
        .await
        .expect("a genuine export of this account's own identity must import");
    assert!(
        status.is_complete(),
        "the import must have taken; an incomplete one means the bootstrap below \
         mints a second identity and this fixture proves nothing: {status:?}"
    );

    let bootstrap = sibling
        .bootstrap_cross_signing(false)
        .await
        .expect("a device holding the complete private identity republishes it");
    // Compared on `keys` alone, not on the whole object: a republication
    // carries no signatures, because upstream's `as_upload_request` rebuilds
    // the public keys from the private ones and the homeserver is what holds
    // the signatures. The key itself is the whole question here.
    let republished = serde_json::to_value(
        bootstrap
            .upload_signing_keys_req
            .master_key
            .as_ref()
            .expect("a republication carries the master key"),
    )
    .expect("an upstream cross-signing key serialises");
    assert_eq!(
        republished.get("keys"),
        first.master_key.get("keys"),
        "the sibling must have republished the account's own identity rather than \
         minted a second one"
    );

    serde_json::to_value(with_owner_signature(
        device_keys_of(&sibling, &account, &device).await,
        &bootstrap,
        &account,
        &device,
    ))
    .expect("upstream device keys serialise")
}

/// The device keys of a device of this account that nothing has ever signed.
///
/// A real bare machine's real keys rather than a hand-written object:
/// upstream stores a device only if its own self-signature checks out, so a
/// fabricated one would simply be dropped and the exclusion asserted below
/// would hold for the wrong reason.
async fn unsigned_device_keys() -> serde_json::Value {
    let account: OwnedUserId = ACCOUNT.parse().expect("a literal user id parses");
    let device: OwnedDeviceId = UNSIGNED_DEVICE.into();
    let stranger = OlmMachine::new(&account, &device).await;
    serde_json::to_value(device_keys_of(&stranger, &account, &device).await)
        .expect("upstream device keys serialise")
}

/// The `/keys/query` answer a homeserver returns to a device of this account
/// asking about this account.
///
/// `user_signing_keys` is returned only to the account's own devices, which
/// is exactly the request being answered. Field names are ruma's own
/// (`ruma-client-api-0.24.0/src/keys/get_keys.rs`).
fn account_keys_answer(
    first: &FirstDevice,
    signed: &serde_json::Value,
    unsigned: &serde_json::Value,
) -> String {
    serde_json::json!({
        "device_keys": {
            ACCOUNT: {
                OLD_DEVICE: first.signed_device_keys,
                SIGNED_DEVICE: signed,
                UNSIGNED_DEVICE: unsigned,
            }
        },
        "master_keys": { ACCOUNT: first.master_key },
        "self_signing_keys": { ACCOUNT: first.self_signing_key },
        "user_signing_keys": { ACCOUNT: first.user_signing_key },
    })
    .to_string()
}

/// Finds the one request of `kind` in a batch, or panics saying what was
/// there instead.
fn one_of<'a>(batch: &'a [OutgoingRequest], kind: &str, why: &str) -> &'a OutgoingRequest {
    batch
        .iter()
        .find(|request| request.kind == kind)
        .unwrap_or_else(|| {
            panic!(
                "{why}; the batch carried {:?}",
                batch
                    .iter()
                    .map(|request| request.kind.as_str())
                    .collect::<Vec<_>>()
            )
        })
}

// ------------------------------------------------------------------- tests

/// A new login joins the identity, receives the seeds, and says so.
///
/// One test, not several, because the machine and the pump are process-wide
/// and an integration test cannot reset them: everything this file has to
/// say about a device that has joined is said about the device this test
/// joined. The refusals that keep it out are driven from their own files,
/// each of which needs a differently-shaped machine of its own.
#[test]
fn a_second_device_joins_the_identity_by_verifying_itself() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(in_runtime(async move {
        let account: OwnedUserId = ACCOUNT.parse().expect("a literal user id parses");
        let new_device: OwnedDeviceId = NEW_DEVICE.into();

        // ---- The device that got there first ----------------------------
        let first = first_device().await;
        let signed = signed_device_keys(&first).await;
        let unsigned = unsigned_device_keys().await;

        // ---- The new login ----------------------------------------------
        //
        // Subscribed before the first sync, which is what the facade tells a
        // product to do and what this test needs: the arrival below is
        // announced from inside `receive_sync_changes` and consumed there.
        subscribe();

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

        // Matched on the user it asks about, not on its kind: `keys_query` is
        // one wire tag for this account's own query and everybody else's, so
        // a kind-only match could lift the gate below with an answer about
        // somebody else.
        let account_query = batch
            .iter()
            .find(|request| {
                request.kind == "keys_query"
                    && queried_users(&request.body).iter().any(|u| u == ACCOUNT)
            })
            .expect("a fresh machine must owe a key query for its own account");
        mark_request_sent(
            &account_query.id,
            &account_keys_answer(&first, &signed, &unsigned),
        )
        .await
        .expect("answering the account key query must not fail");

        // ---- The state a second login is actually in --------------------
        let before = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            before.account_keys_fetched,
            "the account key query was answered: {before:?}"
        );
        assert!(
            before.identity_known,
            "the answer named an identity, so upstream must have stored one. If this \
             fails, the answer was rejected and every assertion below would pass for \
             the wrong reason: {before:?}"
        );
        assert!(
            !before.private_keys_held,
            "this device did not mint that identity and has not joined it yet: {before:?}"
        );

        // ---- The gate, which this milestone must not weaken -------------
        //
        // Asserted here rather than left to
        // `tests/identity_bootstrap_existing.rs` alone, because this is the
        // exact device that would be tempted to call it: a new login with an
        // empty private identity, one call away from replacing the account's
        // identity and resetting the trust of everyone who had verified it.
        // What follows is the remedy that refusal points at, and it must not
        // become a way around it.
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::IdentityAlreadyExists),
            "a new login must be refused a bootstrap; joining the identity is what \
             the rest of this test does instead"
        );
        assert_eq!(
            identity_status()
                .await
                .expect("reading the identity status must not fail"),
            before,
            "a refused bootstrap must leave the account exactly as it found it"
        );

        // ---- The first device learns the new one ------------------------
        //
        // The account's own cross-signing keys are repeated in this answer,
        // exactly as a homeserver repeats them: a `/keys/query` naming this
        // account is how upstream checks its private identity is still the
        // account's, and an answer that named none would be a different
        // fixture.
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

        // The first device opens an Olm session with the new one before it is
        // asked for anything. Upstream will not answer a secret request it
        // has no session for: it parks the request in a wait queue and asks
        // for one-time keys, which is a longer road to the same place and not
        // this test's subject. A real first device is in this state already,
        // having shared keys with its owner's other devices for months.
        let (claim_id, claim) = first
            .peer
            .get_missing_sessions(std::iter::once(account.as_ref()))
            .await
            .expect("the bare machine's session manager must be readable")
            .expect(
                "the first device knows a device of this account it has no session with, \
                 so it must want to claim a one-time key",
            );
        assert!(
            claim
                .one_time_keys
                .get(&account)
                .is_some_and(|devices| devices.contains_key(&new_device)),
            "the claim must name the new login; if it does not, the session below \
             belongs to some other device and the gossip would never arrive"
        );
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

        // ---- The comparison ---------------------------------------------
        //
        // `request_self_flow`, not `request_flow`: a new login does not know
        // which of its owner's devices is to hand, and this call names none.
        let flow = request_self_flow()
            .await
            .expect("an account with an identity can be asked to verify a new device");

        // The fan-out, observed on the wire rather than argued from the call
        // it was made with. `request_flow` cannot be called without naming a
        // device; this was called with nothing, and the recipients came from
        // the account's own identity. The stranger is the negative half: a
        // device of this same account, in this same store, which the identity
        // has never signed and which upstream therefore excludes
        // (`OwnUserIdentityData::filter_devices_to_request`,
        // `identities/user.rs:1167-1178`). Without it, "addressed to every
        // other device" and "addressed to the one device this file happens to
        // have" would be the same assertion.
        let invitation = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let invitation = one_of(
            &invitation,
            "to_device",
            "the invitation must be queued for the pump",
        );
        let mut recipients = addressed_devices(&invitation.body, ACCOUNT);
        recipients.sort();
        assert_eq!(
            recipients,
            vec![OLD_DEVICE.to_string(), SIGNED_DEVICE.to_string()],
            "both devices the identity signed, and only those. Two recipients is what \
             a per-device call cannot produce; excluding the stranger is upstream's \
             own filter (`OwnUserIdentityData::filter_devices_to_request`, \
             `identities/user.rs:1167-1178`), and it matters because a device of this \
             account the identity has never signed is not one of our devices for this \
             purpose: inviting it would be inviting whoever logged it in"
        );
        mark_request_sent(&invitation.id, "{}")
            .await
            .expect("a to-device response must be accepted");
        let event = relay_to(&invitation.body, ACCOUNT, ACCOUNT, OLD_DEVICE)
            .expect("the invitation addresses the first device");
        deliver_to_bare(&first.peer, vec![event]).await;

        let peer_request = first
            .peer
            .get_verification_request(&account, &flow.0)
            .expect("the first device must have received the invitation");
        let ready = peer_request
            .accept_with_methods(vec![VerificationMethod::SasV1])
            .expect("a fresh invitation can be accepted");
        deliver_verification_request(&ready).await;

        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Ready,
            "the other device agreed, so the flow is ready to compare"
        );

        begin_comparison(&flow)
            .await
            .expect("a ready flow can start a comparison");
        let crossed = pump_to_bare(&first.peer).await;
        assert!(
            crossed.contains(&"m.key.verification.start".to_string()),
            "the start must reach the first device through the pump: {crossed:?}"
        );

        let peer_sas = *first
            .peer
            .get_verification(&account, &flow.0)
            .expect("the first device must have been told a comparison started")
            .sas_v1()
            .expect("a flow this test started through begin_comparison is a comparison, not a code. It said this library only ever starts short-string comparisons, which was a claim about the library and stopped being true when it learned to scan");
        let accept = peer_sas
            .accept()
            .expect("a comparison the other side started can be accepted");
        deliver_verification_request(&accept).await;

        pump_to_bare(&first.peer).await;
        pump_bare_to_library(&first.peer).await;

        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::KeysExchanged
        );
        let material = read_material(&flow)
            .await
            .expect("the string is available once the keys are exchanged");
        assert_eq!(
            material.decimals,
            peer_sas
                .decimals()
                .expect("the first device has a string too"),
            "the two sides must have computed the same digits; a comparison whose \
             sides disagree is not a comparison, and everything below it would be \
             resting on nothing"
        );

        let (contents, _signatures) = peer_sas
            .confirm()
            .await
            .expect("the first device can confirm");
        for content in &contents {
            deliver_verification_request(content).await;
        }
        confirm_flow(&flow)
            .await
            .expect("a flow showing a string can be confirmed");

        let crossed = pump_to_bare(&first.peer).await;
        assert!(
            crossed.contains(&"m.key.verification.mac".to_string()),
            "the new device's confirmation must reach the first one: {crossed:?}"
        );
        let crossed = pump_bare_to_library(&first.peer).await;
        assert!(
            crossed.contains(&"m.key.verification.done".to_string()),
            "the first device's acknowledgement must reach the new one: {crossed:?}"
        );
        assert_eq!(
            flow_stage(&flow).await.expect("the flow exists"),
            FlowStage::Done,
            "the comparison must have finished; nothing is gossiped until it does"
        );

        // ---- The signature made with the other key ----------------------
        //
        // The first of the three differences the design names, observed
        // rather than argued. Verifying somebody else signs their master key
        // with our user-signing key; verifying our own device signs the
        // *device*, with the self-signing key, and only the side that already
        // holds the private keys can make it. That side is the first device
        // here, so this is what it owes.
        let uploads = signature_uploads_of(&first.peer).await;
        assert!(
            uploads.iter().any(|upload| upload
                .get(ACCOUNT)
                .and_then(|keys| keys.get(NEW_DEVICE))
                .is_some()),
            "the first device must have signed the new device with its self-signing \
             key; it owes {uploads:?}"
        );

        // ---- The gossip -------------------------------------------------
        //
        // Asserted absent first. Without this, the assertion further down
        // would pass on a machine that had held the keys since before the
        // comparison, which is precisely the false pass this repository keeps
        // finding.
        assert!(
            !identity_status()
                .await
                .expect("reading the identity status must not fail")
                .private_keys_held,
            "a completed comparison is not itself the seeds; asking for them is what \
             comes next"
        );

        // Everything the comparison itself announced is taken off the
        // channel here, so that the assertion after the gossip describes the
        // gossip. See `drain_to_quiet`: the two signals are the same value,
        // and only which sync produced it tells them apart. Nothing below
        // delivers a sync to the library until the encrypted answer arrives.
        drain_to_quiet();

        // Marking our own identity verified is what sets upstream's
        // `should_request_secrets`, and this is that request arriving on this
        // crate's ordinary outbound pump: no new transport and no new request
        // class, which is the second of the three differences.
        let crossed = pump_to_bare(&first.peer).await;
        assert!(
            crossed.contains(&"m.secret.request".to_string()),
            "verifying our own identity must have asked our other devices for the \
             seeds this device lacks: {crossed:?}"
        );

        let crossed = pump_bare_to_library(&first.peer).await;
        assert!(
            crossed.contains(&"m.room.encrypted".to_string()),
            "the first device must answer the secret request, encrypted to the new \
             device: {crossed:?}"
        );

        // ---- What the new device can now say about itself ---------------
        let after = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            after.private_keys_held,
            "the seeds arrived by gossip inside an ordinary sync, so this device now \
             holds the account's private signing keys and can sign with the identity \
             rather than only recognise it: {after:?}"
        );
        assert!(
            after.identity_known && after.account_keys_fetched,
            "joining an identity must not disturb what was already known about it: \
             {after:?}"
        );

        // Joining is not minting, and this is how that shows: the same call
        // that was refused above is now served, because the account still has
        // the identity the first device published and this device holds its
        // private keys rather than a second set. That is `may_mint`'s third
        // row, and reaching it is what joining is for.
        assert_eq!(
            bootstrap_identity().await,
            Ok(()),
            "a device that holds the account's private keys republishes them rather \
             than being refused"
        );

        // ---- The signal -------------------------------------------------
        //
        // Every signal the sync that carried the secret produced, and only
        // those: the channel was emptied immediately before it. `assert_eq`
        // on the whole vector rather than a `contains`, because a `contains`
        // is what made this assertion vacuous once already.
        let signals = drain_signals("the private signing keys arrived");
        assert_eq!(
            signals,
            vec![CryptoSignal::TrustChanged {
                user: ACCOUNT.to_string(),
                state: TrustState::Verified,
            }],
            "a product has no other way to learn that its new device can sign: \
             nothing returns to the caller when the seeds land, and polling is what \
             this channel exists to avoid"
        );

        // Announced once, not on every sync from here on. A standing report
        // is indistinguishable from an arrival to anything acting on it, and
        // this channel's whole purpose is to be the thing a product acts on
        // rather than polls. The sync below carries nothing, so the only
        // thing that could produce a signal is a producer with no latch.
        deliver_to_library(Vec::new()).await;
        no_signal("the private signing keys arrived once and have not arrived again");

        // ---- And the device that vouched for it -------------------------
        let statuses = device_statuses(ACCOUNT)
            .await
            .expect("reading device statuses must not fail");
        assert!(
            statuses.iter().any(
                |status| status.device_id == OLD_DEVICE && status.trust == TrustState::Verified
            ),
            "the device this one compared a string with must read verified: {statuses:?}"
        );
    }));
}
