//! The seven-step chain that makes a decrypted event read `Verified`, and
//! the one step of it that is silent when it is left out.
//!
//! # What this file is
//!
//! Two real machines, no homeserver, and the whole chain driven through
//! this crate's shipped surface on the library's half:
//!
//! 1. **We hold a private signing identity.** [`bootstrap_identity`], and
//!    the account key query that unlocks it.
//! 2. **Our own public identity is marked verified.** A side effect of (1)
//!    upstream, read back here rather than assumed.
//! 3. **The sender published their identity and signed their own device.**
//!    Theirs to do, not ours: without it every value below is
//!    `UnsignedDevice` whatever we do.
//! 4. **We fetched the sender's keys.** The `keys_query` the pump hands
//!    out, answered with what a homeserver would have returned.
//! 5. **We signed the sender's master key with our user-signing key.** A
//!    completed comparison does this inside upstream's `mark_as_done`, and
//!    the resulting signature upload reaches this crate's pump as an
//!    ordinary outgoing request.
//! 6. **We uploaded that signature.** The `signature_upload` the pump hands
//!    out, resolved through [`mark_request_sent`].
//! 7. **We fetched the sender's keys again**, so that our own signature is
//!    on the master key in our own store.
//!
//! # Step seven is the trap, and it is why the second test exists
//!
//! Nothing caches the outgoing signature. Upstream carries a
//! `// TODO: store the signature upload request as well.` at exactly the
//! point where the local copy would go
//! (`matrix-sdk-crypto-0.18.0/src/verification/mod.rs`), so a signature we
//! computed, uploaded and never fetched back is a signature our own store
//! has never seen. Upstream's second gate,
//! `Device::is_cross_signing_trusted`, reads the store and nothing else.
//!
//! So a chain that stops at step six looks complete from the outside --
//! every call returned `Ok`, the comparison finished, the device reads
//! verified, the signature really was uploaded -- and events from that
//! sender sit one rung below where a product would expect them, with
//! nothing anywhere reporting a problem. That is a defect a comment cannot
//! defend against, because a refactor deletes comments and keeps behaviour.
//! [`omitting_the_second_key_fetch_leaves_the_sender_below_verified`] is
//! the guard, and it is deliberately the mirror image of the chain test:
//! one `bool`, one difference, both halves of the pair asserted.
//!
//! # Which side is the library
//!
//! The asymmetry `tests/two_parties.rs` and `tests/cross_signed_peer.rs`
//! both document holds here too. **Alice is the library**, driven only
//! through this crate's public surface against the one process-wide
//! machine. The counterparties are bare upstream `OlmMachine`s standing in
//! for third-party clients, and this file relays between them exactly what
//! a homeserver would relay and nothing else.
//!
//! # The rule this file discharges
//!
//! M3 forbade any test that *appears* to produce `Verified`, because a
//! fixture faking it would teach precisely the false belief the rule
//! existed to prevent. Reaching the value through the real chain is what
//! discharges that rule rather than breaking it, and the complement keeps
//! its value under a new name: what must stay true is not "nothing
//! produces `Verified`" but **"nothing except the real chain does"**. The
//! second test here is the first instance of that replacement -- a chain
//! missing one step produces a value below it -- and
//! `tests/cross_signed_peer.rs` and `tests/two_parties.rs` hold the other
//! two rungs.

use matrix_crypto_core::{
    begin_comparison, bootstrap_identity, confirm_flow, create_machine, decrypt_event,
    device_statuses, flow_stage, identity_status, in_runtime, mark_request_sent, read_material,
    receive_sync_changes, request_flow, share_scope_key, take_outgoing_requests, with_machine,
    FlowId, FlowStage, MachineConfig, OutgoingRequest, SenderVerification, TrustState,
};
use matrix_sdk_common::ruma::api::client::keys::claim_keys::v3::Response as KeysClaimResponse;
use matrix_sdk_common::ruma::api::client::keys::get_keys::v3::Response as KeysQueryResponse;
use matrix_sdk_common::ruma::api::client::keys::upload_keys::v3::Response as KeysUploadResponse;
use matrix_sdk_common::ruma::api::client::sync::sync_events::DeviceLists;
use matrix_sdk_common::ruma::api::client::to_device::send_event_to_device::v3::Response as ToDeviceResponse;
use matrix_sdk_common::ruma::api::IncomingResponse;
use matrix_sdk_common::ruma::events::key::verification::VerificationMethod;
use matrix_sdk_common::ruma::events::{AnyMessageLikeEventContent, AnyToDeviceEvent};
// `exports::http`, not a direct `http` dependency: the exact version ruma's
// own `IncomingResponse::try_from_http_response` requires, reached through
// ruma's re-export -- the same reasoning `session.rs` documents for itself.
use matrix_sdk_common::ruma::exports::http;
use matrix_sdk_common::ruma::serde::Raw;
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId, TransactionId};
use matrix_sdk_crypto::types::requests::{AnyOutgoingRequest, OutgoingVerificationRequest};
use matrix_sdk_crypto::types::DeviceKeys;
use matrix_sdk_crypto::{
    CrossSigningBootstrapRequests, DecryptionSettings, EncryptionSettings, EncryptionSyncChanges,
    OlmMachine, TrustRequirement,
};
use std::collections::BTreeMap;
use std::sync::Mutex as StdMutex;

const ALICE_USER: &str = "@alice:example.org";
const ALICE_DEVICE: &str = "ALICEDEVICE";
/// A scope only ever used to make the library ask who a user's devices are
/// and to carry one event. Nothing about it is read back.
const SCOPE: &str = "!verified-sender:example.org";

/// The counterparty of the complete chain.
const REFETCHED_USER: &str = "@refetched:example.org";
const REFETCHED_DEVICE: &str = "PEERREFETCHED";
const REFETCHED_PAYLOAD: &str = r#"{"body":"sent after the whole chain ran","msgtype":"m.text"}"#;

/// The counterparty whose chain stops one step short.
const UNFETCHED_USER: &str = "@unfetched:example.org";
const UNFETCHED_DEVICE: &str = "PEERUNFETCHED";
const UNFETCHED_PAYLOAD: &str =
    r#"{"body":"sent after a chain missing its last step","msgtype":"m.text"}"#;

/// A `/keys/query` answer naming no identity for this account: the server
/// has been asked and has said there is none. Every field of ruma's own
/// response type is `#[serde(default)]`, so an empty object says exactly
/// that, and it is what lifts `bootstrap_identity`'s gate.
const NO_IDENTITY: &str = r#"{"device_keys":{}}"#;

/// Serialises this file's tests over the one machine and the one pump this
/// process has. `into_inner` on a poisoned lock deliberately: a test that
/// panicked has already failed, and the other should report its own
/// outcome rather than a poisoning inherited from it.
static SERIAL: StdMutex<()> = StdMutex::new(());

/// What the library published about itself, captured once.
///
/// The one-time keys are handed out one per counterparty: a single key
/// would be consumed by the first claim and the second counterparty would
/// silently fall back to some other means of establishing a session, so the
/// two halves of this file would no longer be comparable.
struct Library {
    device_keys: String,
    one_time_keys: Vec<(String, String)>,
}

static LIBRARY: StdMutex<Option<Library>> = StdMutex::new(None);

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
/// Every assertion here about what crossed the wire goes through this
/// rather than stopping at `kind == "to_device"`: all six messages a
/// comparison exchanges are to-device requests, and so is a withheld
/// notice, so the kind alone distinguishes nothing.
fn declared_event_type(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("event_type")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| "<no event_type in body>".to_string())
}

/// Turns one to-device request body into the to-device event the addressed
/// device would have received from its homeserver. Reads the per-recipient
/// content out of the request and wraps it with the sender and type the
/// request itself declares; it reaches into neither machine.
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
        // no entry point that does that.
        OutgoingVerificationRequest::InRoom(_) => {
            panic!("this library runs to-device verification flows only")
        }
    }
}

/// Wraps an encrypted content in the surrounding event a homeserver would
/// have delivered.
fn scoped_event(sender: &str, event_id: &str, content: &str) -> String {
    let content: serde_json::Value =
        serde_json::from_str(content).expect("an encrypted content is well-formed JSON");
    serde_json::json!({
        "sender": sender,
        "event_id": event_id,
        "origin_server_ts": 1_700_000_000_000u64,
        "content": content,
    })
    .to_string()
}

/// The most permissive requirement, the same one `session.rs`'s own
/// `decryption_settings()` uses, mirrored here so the counterparty is held
/// to the standard the library holds itself to and no difference between
/// the two can explain a result.
fn decryption_settings() -> DecryptionSettings {
    DecryptionSettings {
        sender_device_trust_requirement: TrustRequirement::Untrusted,
    }
}

// ------------------------------------------------------------ the two pumps

/// Drains the library's pump and returns the one request of `kind` in it,
/// leaving everything else pending.
async fn drain_for(kind: &str, why: &str) -> OutgoingRequest {
    take_outgoing_requests()
        .await
        .expect("the pump must be drainable")
        .into_iter()
        .find(|request| request.kind == kind)
        .unwrap_or_else(|| panic!("{why}"))
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

/// Drains the library's pump and returns the key query that asks about
/// `user_id`.
///
/// **Not `drain_for("keys_query", ..)`**, and the difference is not
/// defensive. `PendingKind::tag` is deliberately not injective: a query for
/// this account and a query for anyone else are one endpoint with one wire
/// tag, distinguished only inside `session.rs`. Taking whichever came first
/// would let a run in which the pump happened to owe an own-account query
/// answer *that* one with this counterparty's keys, and the counterparty's
/// real query would go unanswered while every assertion below still read
/// plausibly.
async fn drain_for_query_about(user_id: &str, why: &str) -> OutgoingRequest {
    take_outgoing_requests()
        .await
        .expect("the pump must be drainable")
        .into_iter()
        .find(|request| {
            request.kind == "keys_query"
                && queried_users(&request.body).iter().any(|u| u == user_id)
        })
        .unwrap_or_else(|| panic!("{why}"))
}

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

/// Hands events to the library as a sync would, through its own public
/// entry point and its own wire shape.
async fn deliver_to_library(events: Vec<serde_json::Value>) {
    let payload = serde_json::json!({ "to_device_events": events }).to_string();
    receive_sync_changes(&payload)
        .await
        .expect("the library must accept a sync it is the addressee of");
}

/// Drains the library's pump, relays every to-device request in it to the
/// counterparty, **marks each one sent**, and reports what crossed.
///
/// The mark is what this turns on: upstream advances a comparison only when
/// the key message is reported sent.
async fn pump_to_bare(peer: &OlmMachine, user_id: &str, device_id: &str) -> Vec<String> {
    let batch = take_outgoing_requests()
        .await
        .expect("the pump must be drainable");

    let mut crossed = Vec::new();
    let mut events = Vec::new();
    for request in batch.iter().filter(|request| request.kind == "to_device") {
        if let Some(event) = relay_to(&request.body, ALICE_USER, user_id, device_id) {
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

/// The mirror image: drains the bare machine's own outbound requests,
/// relays its to-device ones to the library, and marks them sent on its
/// side.
async fn pump_bare_to_library(peer: &OlmMachine, user_id: &str) -> Vec<String> {
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
            if let Some(event) = relay_to(&body, user_id, ALICE_USER, ALICE_DEVICE) {
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

/// Relays one request the bare machine handed back to its caller.
async fn deliver_verification_request(request: &OutgoingVerificationRequest, sender: &str) {
    let body = verification_body(request);
    let event = relay_to(&body, sender, ALICE_USER, ALICE_DEVICE)
        .expect("the counterparty addresses the library's own device");
    deliver_to_library(vec![event]).await;
}

// ------------------------------------------------------------- the fixtures

/// The device keys a bare machine holds for its own device.
///
/// Read from the store rather than from the key upload request, because the
/// upload was built before the bootstrap below and a bootstrap does not
/// retroactively change what an already-built request carried.
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

/// The self-signing signature a bootstrap produced over the peer's own
/// device, put back onto that device's keys.
///
/// # Why this is not cheating
///
/// A bootstrap does **not** write this signature into the signing machine's
/// own store copy of its device. It emits it in an `upload_signatures_req`,
/// and the homeserver is what stores it and hands it back on the next
/// `/keys/query`. So this function is the homeserver's half and nothing
/// more: it moves a signature the peer genuinely computed, over its own
/// genuine device keys, from the request the peer emitted into the response
/// the library is about to be handed. Nothing is fabricated.
///
/// The same helper, and the same reasoning, as `tests/cross_signed_peer.rs`.
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
    // Looked up by device id, not taken as the first entry: this map is
    // keyed by device id *and* by cross-signing key id, because a bootstrap
    // also signs its own master key with the device.
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

/// The signatures the library's own signature upload carries over the
/// counterparty's master key.
///
/// The wire body of a `signature_upload` **is** the `signed_keys` map, so
/// this reads `{ user: { master key: signed key } }` and returns the
/// `signatures` object of the one entry inside.
///
/// Only the signatures are taken, never the key object around them.
/// Upstream's `sign_user` *replaces* the master key's signature map with
/// its own single signature rather than adding to it
/// (`olm/signing/pk_signing.rs`: `master_key.signatures = signatures`), so
/// posting that object verbatim as the master key would silently drop the
/// signature the counterparty's own device made over it. [`with_our_signature`]
/// merges instead, which is what a homeserver does with this endpoint's body.
fn uploaded_signatures(body: &str, user_id: &str) -> serde_json::Value {
    let parsed: serde_json::Value =
        serde_json::from_str(body).expect("the pump's own body is well-formed JSON");
    let per_user = parsed
        .get(user_id)
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| {
            panic!("the signature upload must name the counterparty it signed: {body}")
        });
    assert_eq!(
        per_user.len(),
        1,
        "a user signature covers exactly the master key, so exactly one entry \
         is expected here; more means this upload is not the one this test \
         thinks it is: {body}"
    );
    per_user
        .values()
        .next()
        .and_then(|signed| signed.get("signatures"))
        .cloned()
        .expect("a signed master key always carries the signature that signed it")
}

/// How many signatures, across every signing user, a cross-signing key
/// carries.
fn signature_count(key: &serde_json::Value) -> usize {
    key.get("signatures")
        .and_then(serde_json::Value::as_object)
        .map(|users| {
            users
                .values()
                .filter_map(serde_json::Value::as_object)
                .map(serde_json::Map::len)
                .sum()
        })
        .unwrap_or(0)
}

/// Merges the signatures the library uploaded into the counterparty's
/// master key, as a homeserver would.
///
/// Asserts the merge actually added one. A `/keys/query` body is just JSON,
/// and one describing an unsigned master key reads exactly like one
/// describing a signed master key, so the fixture that makes step seven
/// meaningful has to be checked rather than trusted -- the same reasoning
/// `tests/cross_signed_peer.rs` gives for counting device signatures.
fn with_our_signature(
    mut master_key: serde_json::Value,
    signatures: &serde_json::Value,
) -> serde_json::Value {
    let before = signature_count(&master_key);

    let target = master_key
        .get_mut("signatures")
        .and_then(serde_json::Value::as_object_mut)
        .expect("a published master key always carries its own device's signature");
    for (user, keys) in signatures
        .as_object()
        .expect("an uploaded signature map is an object")
    {
        let slot = target
            .entry(user.clone())
            .or_insert_with(|| serde_json::json!({}));
        let slot = slot
            .as_object_mut()
            .expect("a per-user signature map is an object");
        for (key_id, signature) in keys
            .as_object()
            .expect("a per-user signature map is an object")
        {
            slot.insert(key_id.clone(), signature.clone());
        }
    }

    let after = signature_count(&master_key);
    assert!(
        after > before,
        "merging the uploaded signature must add one: the master key carried \
         {before} signatures before and {after} after. Equal means this \
         response is indistinguishable from the one step seven was skipped \
         with, and the chain test would be asserting nothing"
    );
    master_key
}

/// Creates the one library machine this process has, performs steps 1 and 2
/// of the chain on it, and returns its published device keys.
///
/// Called by both tests; the second one gets the machine the first left
/// behind, which is the only shape available -- the machine registry and
/// the pump are process-wide and an integration test cannot reset them.
async fn library() -> serde_json::Value {
    if let Some(library) = LIBRARY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
    {
        return serde_json::from_str(&library.device_keys)
            .expect("this test stored well-formed JSON");
    }

    // `keep()`: the store outlives the test that created it, because the
    // second test in this file shares the machine it belongs to.
    let dir = tempfile::tempdir().expect("temp dir").keep();
    create_machine(MachineConfig {
        user_id: ALICE_USER.to_string(),
        device_id: ALICE_DEVICE.to_string(),
        store_path: dir.join("store").to_string_lossy().into_owned(),
        store_passphrase: Some("test-passphrase".to_string()),
    })
    .await
    .expect("the library's machine must be creatable");

    // ---- The library publishes its own keys -----------------------------
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
    let one_time_keys: Vec<(String, String)> = body
        .get("one_time_keys")
        .and_then(serde_json::Value::as_object)
        .map(|keys| {
            keys.iter()
                .take(2)
                .map(|(id, key)| (id.clone(), key.to_string()))
                .collect()
        })
        .expect("a fresh machine's upload carries one-time keys");
    assert!(
        one_time_keys.len() >= 2,
        "this file stands up two counterparties and claims one key each; with \
         fewer, the second counterparty's session would be established by some \
         other means and the two halves would not be comparable"
    );
    mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
        .await
        .expect("a keys-upload response must be accepted");

    // ---- Step 1: we hold a private signing identity ---------------------
    //
    // The account key query first: `bootstrap_identity` refuses until this
    // process has asked the server about this account and been answered,
    // which is the gate `tests/identity_bootstrap_ordering.rs` drives.
    // Matched on the user it asks about, not on its kind: `keys_query` is
    // one wire tag for the account's own query and everyone else's, so a
    // kind-only match would answer whichever came first and could lift this
    // gate with somebody else's answer.
    let account_query = batch
        .iter()
        .find(|request| {
            request.kind == "keys_query"
                && queried_users(&request.body).iter().any(|u| u == ALICE_USER)
        })
        .expect("a fresh machine must owe a key query for its own account");
    mark_request_sent(&account_query.id, NO_IDENTITY)
        .await
        .expect("answering the account key query must not fail");

    bootstrap_identity()
        .await
        .expect("bootstrapping after the account keys have been fetched must be served");

    let status = identity_status()
        .await
        .expect("reading the identity status must not fail");
    assert!(
        status.private_keys_held,
        "step 1 of the chain is this device holding the private signing keys, \
         and every step after it is blocked without them: {status:?}"
    );

    // The requests the bootstrap queued are drained and answered, so the
    // pump each test drives afterwards carries only that test's own
    // traffic. Answering them is also what a product does; leaving an
    // identity unpublished would be a different fixture.
    let published = take_outgoing_requests()
        .await
        .expect("the pump must be drainable");
    for request in &published {
        mark_request_sent(&request.id, "{}")
            .await
            .expect("a bootstrap publication response must be accepted");
    }

    // ---- Step 2: our own public identity is marked verified -------------
    //
    // Automatic upstream: `to_public_identity()` marks it at bootstrap.
    // Read back rather than assumed, because it is the first half of
    // upstream's second gate -- `is_identity_verified` is
    // `self.is_verified() && user_signing_key.verify_master_key(theirs)` --
    // and if it were ever false, every `Verified` below would be
    // unreachable for a reason that has nothing to do with step seven.
    let own_identity_verified = with_machine(|machine| {
        Box::pin(async move {
            machine
                .get_identity(machine.user_id(), None)
                .await
                .expect("the store must be readable")
                .expect("a bootstrapped machine knows its own identity")
                .own()
                .expect("this machine's own identity is an own identity")
                .is_verified()
        })
    })
    .await
    .expect("the library's machine must be live");
    assert!(
        own_identity_verified,
        "step 2 of the chain is our own public identity being marked verified, \
         which a bootstrap does by itself"
    );

    *LIBRARY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Library {
        device_keys: device_keys.to_string(),
        one_time_keys,
    });
    device_keys
}

/// Takes one of the library's published one-time keys, so each counterparty
/// opens its session with a key no other counterparty used.
fn claim_one_time_key() -> (String, serde_json::Value) {
    let mut held = LIBRARY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let library = held
        .as_mut()
        .expect("the library fixture is built before any counterparty");
    let (id, key) = library
        .one_time_keys
        .pop()
        .expect("this file claims one key per counterparty and publishes enough for both");
    (
        id,
        serde_json::from_str(&key).expect("this test stored well-formed JSON"),
    )
}

/// What one run of the chain produced.
struct Outcome {
    /// What the library reported about the sender of the event it decrypted.
    verification: Option<SenderVerification>,
    /// The plaintext the library recovered. The control on every
    /// authenticity assertion: if decryption itself broke, the value above
    /// is meaningless rather than wrong, and this says which of the two
    /// happened.
    recovered: Vec<u8>,
    /// Whether the library's own view of the counterparty's *identity* is
    /// verified. Upstream's second gate is
    /// `own_identity.is_identity_verified(theirs) && theirs.is_device_signed(device)`,
    /// and this is its first half -- the half step seven is what moves.
    identity_verified: bool,
    /// What the shipped `device_statuses` call reports for the
    /// counterparty's device.
    device_trust: TrustState,
}

/// Drives the whole chain against one counterparty and decrypts one event
/// from it.
///
/// `refetch` is the single axis the two tests differ on: with it, step
/// seven happens; without it, everything up to and including step six
/// happens and the chain stops there.
async fn chain(
    user_id: &str,
    device_id: &str,
    payload: &str,
    refetch: bool,
    alice_device_keys: &serde_json::Value,
) -> Outcome {
    let peer_user: OwnedUserId = user_id.parse().expect("a literal user id parses");
    let peer_device: OwnedDeviceId = device_id.into();
    let alice_user: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
    let scope_id: OwnedRoomId = SCOPE.parse().expect("a literal scope id parses");

    let peer = OlmMachine::new(&peer_user, &peer_device).await;

    // ---- The counterparty publishes its device keys ---------------------
    let batch = peer
        .outgoing_requests()
        .await
        .expect("a fresh bare machine has keys to publish");
    let upload_id = batch
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

    // ---- Step 3: the sender publishes an identity and signs its device --
    //
    // `false`, not `true`: the device keys were published above, and what
    // this bootstrap is wanted for is the identity and the signature it
    // puts on that device.
    let bootstrap = peer
        .bootstrap_cross_signing(false)
        .await
        .expect("a bare machine must be able to bootstrap its own identity");
    let signed_device_keys = with_owner_signature(
        device_keys_of(&peer, &peer_user, &peer_device).await,
        &bootstrap,
        &peer_user,
        &peer_device,
    );
    let signed_device_keys =
        serde_json::to_value(&signed_device_keys).expect("upstream device keys serialise");
    let master_key = serde_json::to_value(&bootstrap.upload_signing_keys_req.master_key)
        .expect("an upstream master key serialises");
    let self_signing_key =
        serde_json::to_value(&bootstrap.upload_signing_keys_req.self_signing_key)
            .expect("an upstream self-signing key serialises");

    // The fixture must actually be the fixture: two signatures on the
    // device, its own and its owner's self-signing key. One means the
    // bootstrap did not sign the device, and gate one would fail for a
    // reason that has nothing to do with anything below.
    assert_eq!(
        signature_count(&signed_device_keys),
        2,
        "a bootstrapped counterparty's device carries two signatures, its own \
         and its owner's self-signing key"
    );

    // ---- Step 4: we fetch the sender's keys -----------------------------
    //
    // `share_scope_key` first, because it is what makes the library track
    // the user at all: upstream's `mark_tracked_users_as_changed` skips
    // every user it has never seen, so without this no call on the shipped
    // surface could get a `/keys/query` issued for them.
    share_scope_key(SCOPE, &[user_id.to_string()])
        .await
        .expect("sharing a scope key must not fail");
    let query = drain_for_query_about(
        user_id,
        "the machine must ask who exists before it can verify anyone",
    )
    .await;
    let first_answer = serde_json::json!({
        "device_keys": { user_id: { device_id: signed_device_keys } },
        "master_keys": { user_id: master_key },
        "self_signing_keys": { user_id: self_signing_key },
    });
    mark_request_sent(&query.id, &first_answer.to_string())
        .await
        .expect("a keys-query response must be accepted");

    // The mirror image on the bare side: the counterparty learns the
    // library's device, so it can claim a one-time key and open a session
    // to carry its own group key later.
    peer.mark_request_as_sent(
        &TransactionId::new(),
        &keys_query_response(
            &serde_json::json!({
                "device_keys": { ALICE_USER: { ALICE_DEVICE: alice_device_keys } }
            })
            .to_string(),
        ),
    )
    .await
    .expect("the bare machine must accept a keys-query response");

    // Anything the tracking above queued is drained so the assertions
    // below describe only this chain's own traffic.
    take_outgoing_requests()
        .await
        .expect("the pump must be drainable");

    // ---- Step 5: a completed comparison signs the sender's master key ---
    //
    // Nothing else on this crate's surface signs another user's identity,
    // and nothing here reaches past that surface to do it: upstream's
    // `mark_as_done` calls `sign_user` for the other party as part of
    // finishing the comparison, and the signature upload it produces is
    // what the pump hands out below.
    let flow = request_flow(user_id, device_id)
        .await
        .expect("a known device can be asked to verify itself");
    let crossed = pump_to_bare(&peer, user_id, device_id).await;
    assert!(
        crossed.contains(&"m.key.verification.request".to_string()),
        "the request must reach the counterparty through the pump: {crossed:?}"
    );

    let peer_request = peer
        .get_verification_request(&alice_user, &flow.0)
        .expect("the counterparty must have received the request");
    let ready = peer_request
        .accept_with_methods(vec![VerificationMethod::SasV1])
        .expect("a fresh request can be accepted");
    deliver_verification_request(&ready, user_id).await;

    begin_comparison(&flow)
        .await
        .expect("a ready flow can start a comparison");
    let crossed = pump_to_bare(&peer, user_id, device_id).await;
    assert!(
        crossed.contains(&"m.key.verification.start".to_string()),
        "the start must reach the counterparty through the pump: {crossed:?}"
    );

    let peer_sas = bare_comparison(&peer, &flow);
    let accept = peer_sas
        .accept()
        .expect("a comparison the other side started can be accepted");
    deliver_verification_request(&accept, user_id).await;

    pump_to_bare(&peer, user_id, device_id).await;
    pump_bare_to_library(&peer, user_id).await;

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
            .expect("the counterparty has a string too"),
        "the two sides must have computed the same digits; a comparison whose \
         sides disagree is not a comparison, and everything below it would be \
         resting on nothing"
    );

    let (contents, _signatures) = peer_sas
        .confirm()
        .await
        .expect("the counterparty can confirm");
    for content in &contents {
        deliver_verification_request(content, user_id).await;
    }
    confirm_flow(&flow)
        .await
        .expect("a flow showing a string can be confirmed");

    let crossed = pump_to_bare(&peer, user_id, device_id).await;
    assert!(
        crossed.contains(&"m.key.verification.mac".to_string()),
        "the library's confirmation must reach the counterparty: {crossed:?}"
    );
    let crossed = pump_bare_to_library(&peer, user_id).await;
    assert!(
        crossed.contains(&"m.key.verification.done".to_string()),
        "the counterparty's acknowledgement must reach the library: {crossed:?}"
    );
    assert_eq!(
        flow_stage(&flow).await.expect("the flow exists"),
        FlowStage::Done,
        "the comparison must have finished; nothing signs an identity until it \
         does"
    );

    // ---- Step 6: we upload that signature -------------------------------
    //
    // The completion above was driven by the counterparty's own
    // acknowledgement arriving in a sync, so upstream queued the signature
    // upload for itself and it reaches this crate's pump as an ordinary
    // outgoing request. Asserted by name: a comparison that finished
    // without producing one would mean the identity was never signed, and
    // every step after this would be moot for a reason no assertion below
    // would name.
    let signature_upload = drain_for(
        "signature_upload",
        "a completed comparison with a cross-signed counterparty must produce \
         a signature over their master key",
    )
    .await;
    let signatures = uploaded_signatures(&signature_upload.body, user_id);
    mark_request_sent(&signature_upload.id, "{}")
        .await
        .expect("a signature-upload response must be accepted");

    // ---- Step 7: we fetch the sender's keys again -----------------------
    //
    // Only when this run is the one that does. The homeserver notices the
    // master key gained a signature and reports the user in a sync's
    // changed device lists, which is what gets a second `/keys/query`
    // issued at all -- so the sync below is not a shortcut around anything,
    // it is the mechanism.
    if refetch {
        receive_sync_changes(
            &serde_json::json!({ "changed_devices": { "changed": [user_id] } }).to_string(),
        )
        .await
        .expect("the library must accept a sync naming a changed device list");

        let requery = drain_for_query_about(
            user_id,
            "a sync naming the counterparty as changed must get a second key \
             query issued",
        )
        .await;
        let second_answer = serde_json::json!({
            "device_keys": { user_id: { device_id: first_answer["device_keys"][user_id][device_id] } },
            "master_keys": {
                user_id: with_our_signature(
                    first_answer["master_keys"][user_id].clone(),
                    &signatures,
                )
            },
            "self_signing_keys": { user_id: first_answer["self_signing_keys"][user_id] },
        });
        mark_request_sent(&requery.id, &second_answer.to_string())
            .await
            .expect("a keys-query response must be accepted");
    }

    // ---- The counterparty sends, and the library decrypts ---------------
    //
    // After the chain, not before it. Upstream fixes an inbound session's
    // sender data when the key arrives and recalculates it later only from
    // `UnknownDevice`, `DeviceInfo` or `VerificationViolation`
    // (`SenderData::should_recalculate`) -- never from `SenderUnverified`.
    // So a session received *before* its sender was verified keeps reading
    // `UnverifiedIdentity` for its whole life, and this file would be
    // measuring that instead of what it says it measures.
    let (claim_id, _request) = peer
        .get_missing_sessions(std::iter::once(alice_user.as_ref()))
        .await
        .expect("the bare machine must be able to report missing sessions")
        .expect("the bare machine has no session to the library's device yet");
    let (key_id, key) = claim_one_time_key();
    peer.mark_request_as_sent(
        &claim_id,
        &keys_claim_response(
            &serde_json::json!({
                "one_time_keys": { ALICE_USER: { ALICE_DEVICE: { key_id: key } } }
            })
            .to_string(),
        ),
    )
    .await
    .expect("the bare machine must accept a keys-claim response");

    let shares = peer
        .share_room_key(
            &scope_id,
            std::iter::once(alice_user.as_ref()),
            EncryptionSettings::default(),
        )
        .await
        .expect("the bare machine must be able to share its own group key");
    let key_events: Vec<serde_json::Value> = shares
        .iter()
        .map(|request| {
            serde_json::to_string(request.as_ref())
                .expect("an upstream to-device request serialises")
        })
        .filter(|body| declared_event_type(body) == "m.room.encrypted")
        .filter_map(|body| relay_to(&body, user_id, ALICE_USER, ALICE_DEVICE))
        .collect();
    assert_eq!(
        key_events.len(),
        1,
        "the bare machine must produce exactly one to-device message carrying \
         its session key to the library's device; zero means it produced a \
         withheld notice instead, which is an ordering failure and not \
         anything this test is about"
    );
    deliver_to_library(key_events).await;

    let content = Raw::<AnyMessageLikeEventContent>::from_json_string(payload.to_owned())
        .expect("a literal payload is well-formed JSON");
    let encrypted = peer
        .encrypt_room_event_raw(&scope_id, "m.room.message", &content)
        .await
        .expect("the bare machine must be able to encrypt for its own session");
    let event = scoped_event(
        user_id,
        &format!("$from-{device_id}:example.org"),
        encrypted.content.json().get(),
    );
    let envelope = decrypt_event(SCOPE, &event)
        .await
        .expect("the library must decrypt what the bare machine encrypted");

    let identity_verified = with_machine({
        let peer_user = peer_user.clone();
        move |machine| {
            Box::pin(async move {
                machine
                    .get_identity(&peer_user, None)
                    .await
                    .expect("the store must be readable")
                    .expect("the counterparty's identity was fetched in step four")
                    .other()
                    .expect("another user's identity is an other identity")
                    .is_verified()
            })
        }
    })
    .await
    .expect("the library's machine must be live");

    let device_trust = device_statuses(user_id)
        .await
        .expect("the counterparty's devices must be readable")
        .into_iter()
        .find(|status| status.device_id == device_id)
        .expect("the library must know the device it just verified")
        .trust;

    Outcome {
        verification: envelope.sender_verification,
        recovered: envelope.ciphertext,
        identity_verified,
        device_trust,
    }
}

/// The counterparty's view of a flow the library started.
fn bare_comparison(peer: &OlmMachine, flow: &FlowId) -> matrix_sdk_crypto::Sas {
    let alice: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
    *peer
        .get_verification(&alice, &flow.0)
        .expect("the counterparty must have been told a comparison started")
        .sas_v1()
        .expect("this library only ever starts short-string comparisons")
}

// ------------------------------------------------------------------ tests

/// All seven steps, and an event that reads `Verified` at the end.
///
/// This is the first test in this repository to reach that value, and it
/// reaches it the only way the milestone permits: by performing every step
/// of the chain against a counterparty this process does not control, with
/// no fixture anywhere asserting or fabricating the value on the way.
#[test]
fn the_whole_chain_makes_an_event_read_verified() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let alice_device_keys = library().await;
        let outcome = chain(
            REFETCHED_USER,
            REFETCHED_DEVICE,
            REFETCHED_PAYLOAD,
            true,
            &alice_device_keys,
        )
        .await;

        // The control on every authenticity assertion below, stated first.
        // If decryption itself broke, the value under test would be
        // meaningless rather than wrong, and this is what says which of the
        // two happened.
        assert_eq!(
            outcome.recovered,
            REFETCHED_PAYLOAD.as_bytes(),
            "the library must recover the counterparty's payload byte for byte"
        );

        // Upstream's second gate, read at its own level rather than only
        // through the value it produces: our user-signing key over their
        // master key, present in our store because step seven fetched it
        // back.
        assert!(
            outcome.identity_verified,
            "after the chain, the library's own view of the counterparty's \
             identity is verified -- this is the half of upstream's second \
             gate that step seven moves"
        );

        // The claim.
        assert_eq!(
            outcome.verification,
            Some(SenderVerification::Verified),
            "an event from a device whose owner we have signed, uploaded and \
             fetched back reads `Verified`. `UnverifiedIdentity` here means \
             the second key fetch did not take effect; `UnsignedDevice` means \
             the counterparty's own signature was never seen"
        );

        // And the device-level surface agrees. Not a restatement: this
        // reads `Device::is_verified()`, which is local trust *or*
        // cross-signing trust, while the value above reads only the second
        // of those. They are two answers from two upstream predicates, and
        // asserting both is what stops one of them carrying the whole
        // proof.
        assert_eq!(
            outcome.device_trust,
            TrustState::Verified,
            "the shipped device surface must agree that this device is trusted"
        );
    }));
}

/// The same chain, missing only its last step, produces a value below
/// `Verified`.
///
/// **The most valuable test in this file.** Everything up to and including
/// the signature upload happens exactly as in the test above: the
/// comparison completes, the device reads verified, the signature is
/// genuinely produced and genuinely uploaded. The only difference is that
/// the library never fetches the counterparty's keys again, so its own
/// store never sees the signature it just made -- and nothing anywhere
/// reports a problem.
///
/// Asserted as a value and not merely as "not `Verified`": the rung it
/// falls to is `UnverifiedIdentity`, one step down, which is what makes
/// this a silent defect rather than a loud one. A product reading it would
/// see the ordinary state of an unverified peer, with no indication that a
/// verification it performed had failed to take effect.
#[test]
fn omitting_the_second_key_fetch_leaves_the_sender_below_verified() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let alice_device_keys = library().await;
        let outcome = chain(
            UNFETCHED_USER,
            UNFETCHED_DEVICE,
            UNFETCHED_PAYLOAD,
            false,
            &alice_device_keys,
        )
        .await;

        // Green here, and green in the test above. Whatever the chain does
        // to authenticity, it does nothing to decryption, and this pair is
        // what says so.
        assert_eq!(
            outcome.recovered,
            UNFETCHED_PAYLOAD.as_bytes(),
            "omitting the second key fetch must not stop the library decrypting"
        );

        // The trap, at the level it happens: the signature exists and was
        // uploaded, and our own store has never seen it, so upstream's
        // second gate is still shut.
        assert!(
            !outcome.identity_verified,
            "a signature we made and uploaded but never fetched back is a \
             signature our own store has never seen: nothing caches it, and \
             upstream reads the store"
        );

        // The value, named exactly. `assert_ne!(.., Verified)` would also
        // pass if the chain had collapsed to `NoDeviceMissing` or
        // `UnsignedDevice`, which would mean this test was measuring some
        // other breakage entirely.
        assert_eq!(
            outcome.verification,
            Some(SenderVerification::UnverifiedIdentity),
            "a chain missing only its last step lands one rung below \
             `Verified`, silently. `Verified` here means the value is not \
             derived from what the store holds; `UnsignedDevice` means this \
             run failed somewhere earlier and is not testing step seven"
        );

        // The half of the surface that does *not* fall back, and the reason
        // this defect is invisible: the comparison really did verify the
        // device, so a product watching device trust sees success while
        // every event from that device still reads unverified.
        assert_eq!(
            outcome.device_trust,
            TrustState::Verified,
            "the comparison verified the device locally whatever happened to \
             the identity, which is exactly why omitting step seven looks \
             like success"
        );
    }));
}
