//! The wire between the library and a bare upstream machine, for the four
//! test binaries that drive verification by scanning a code.
//!
//! # Why this is a module and not four copies
//!
//! This library holds one crypto machine per process and Cargo gives each
//! file under `tests/` its own binary, so the three modes the protocol
//! defines cannot share a file: each needs a differently shaped machine,
//! and which mode a flow uses is decided by which device is holding up its
//! screen. What they do share is the homeserver's whole job -- relaying a
//! to-device request to its addressee, answering a key query, marking a
//! request sent -- none of which is the thing being proven.
//!
//! Included with `#[path]`, the same way `interop/harness.rs` is, and for
//! the same reason: it is scaffolding for particular test binaries rather
//! than a fixture the whole suite shares.
//!
//! # Nothing here asserts anything about cryptography
//!
//! Every assertion in this file is about the harness: that a response
//! parsed, that a machine accepted a sync it is the addressee of. The
//! claims the milestone rests on are in the test files themselves, on
//! purpose -- a proof whose load-bearing assertion lives in shared
//! scaffolding is a proof nobody reads. The one exception is
//! [`mode_of`], which reads a byte off a payload and checks the two fields
//! in front of it before it does; that is a decoder, not a claim, and every
//! claim made *with* it is in a test file.

// Each test binary compiles its own copy of this module and uses a subset
// of it: only the self-verification files gossip secrets, only the
// cross-user file claims one-time keys. Allowed here rather than split
// further, for `interop/harness.rs`'s reason.
#![allow(dead_code)]

use std::collections::BTreeMap;

use matrix_crypto_core::{mark_request_sent, receive_sync_changes, take_outgoing_requests};
use matrix_sdk_common::ruma::api::client::keys::claim_keys::v3::Response as KeysClaimResponse;
use matrix_sdk_common::ruma::api::client::keys::get_keys::v3::Response as KeysQueryResponse;
use matrix_sdk_common::ruma::api::client::keys::upload_keys::v3::Response as KeysUploadResponse;
use matrix_sdk_common::ruma::api::client::sync::sync_events::DeviceLists;
use matrix_sdk_common::ruma::api::client::to_device::send_event_to_device::v3::Response as ToDeviceResponse;
use matrix_sdk_common::ruma::api::IncomingResponse;
// `exports::http`, not a direct `http` dependency: the exact version ruma's
// own `IncomingResponse::try_from_http_response` requires, reached through
// ruma's re-export -- the same reasoning `session.rs` documents for itself.
use matrix_sdk_common::ruma::events::AnyToDeviceEvent;
use matrix_sdk_common::ruma::exports::http;
use matrix_sdk_common::ruma::serde::Raw;
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId};
use matrix_sdk_crypto::types::requests::{AnyOutgoingRequest, OutgoingVerificationRequest};
use matrix_sdk_crypto::types::DeviceKeys;
use matrix_sdk_crypto::{
    CrossSigningBootstrapRequests, DecryptionSettings, EncryptionSyncChanges, OlmMachine,
    TrustRequirement,
};

// ------------------------------------------------------------- wire shapes

/// A fixed-shape 200 response, the form ruma's own
/// `IncomingResponse::try_from_http_response` expects.
pub fn http_ok(body: &str) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(200)
        .body(body.as_bytes().to_vec())
        .expect("a fixed-shape http::Response with no custom headers cannot fail to build")
}

pub fn keys_upload_response(body: &str) -> KeysUploadResponse {
    KeysUploadResponse::try_from_http_response(http_ok(body))
        .expect("this harness builds its own well-formed keys-upload response")
}

pub fn keys_query_response(body: &str) -> KeysQueryResponse {
    KeysQueryResponse::try_from_http_response(http_ok(body))
        .expect("this harness builds its own well-formed keys-query response")
}

pub fn keys_claim_response(body: &str) -> KeysClaimResponse {
    KeysClaimResponse::try_from_http_response(http_ok(body))
        .expect("this harness builds its own well-formed keys-claim response")
}

/// The top-level `event_type` a to-device request's JSON body declares.
///
/// Every assertion about what crossed the wire goes through this rather than
/// stopping at `kind == "to_device"`: every message a verification exchanges
/// is a to-device request, so the kind alone distinguishes none of them.
pub fn declared_event_type(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("event_type")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| "<no event_type in body>".to_string())
}

/// The device ids one to-device request body addresses, for `user_id`.
pub fn addressed_devices(body: &str, user_id: &str) -> Vec<String> {
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

/// The users a `/keys/query` body asks about.
pub fn queried_users(body: &str) -> Vec<String> {
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

/// Turns one to-device request body into the to-device event the addressed
/// device would have received from its homeserver.
///
/// Reads the per-recipient content out of the request and wraps it with the
/// sender and type the request itself declares; it reaches into neither
/// machine. A request addressed to `"*"` is delivered to the named device,
/// which is what a homeserver does with `DeviceIdOrAllDevices::AllDevices`.
pub fn relay_to(
    body: &str,
    sender: &str,
    user_id: &str,
    device_id: &str,
) -> Option<serde_json::Value> {
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

/// The most permissive requirement, the same one `session.rs`'s own
/// `decryption_settings()` uses, mirrored here so a counterparty is held to
/// the standard the library holds itself to.
pub fn decryption_settings() -> DecryptionSettings {
    DecryptionSettings {
        sender_device_trust_requirement: TrustRequirement::Untrusted,
    }
}

// ------------------------------------------------------------ the two pumps

/// Hands events to a bare machine as a sync would.
pub async fn deliver_to_bare(peer: &OlmMachine, events: Vec<serde_json::Value>) {
    let to_device_events: Vec<Raw<AnyToDeviceEvent>> = events
        .into_iter()
        .map(|event| {
            Raw::from_json_string(event.to_string())
                .expect("this harness builds its own well-formed event")
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
pub async fn deliver_to_library(events: Vec<serde_json::Value>) {
    let payload = serde_json::json!({ "to_device_events": events }).to_string();
    receive_sync_changes(&payload)
        .await
        .expect("the library must accept a sync it is the addressee of");
}

/// Drains the library's pump, relays every to-device request in it to the
/// bare machine, **marks each one sent**, and reports what crossed.
///
/// The mark is what this turns on: upstream advances a flow only when the
/// message is reported sent.
pub async fn pump_to_bare(
    peer: &OlmMachine,
    library_user: &str,
    peer_user: &str,
    peer_device: &str,
) -> Vec<String> {
    let batch = take_outgoing_requests()
        .await
        .expect("the pump must be drainable");

    let mut crossed = Vec::new();
    let mut events = Vec::new();
    for request in batch.iter().filter(|request| request.kind == "to_device") {
        if let Some(event) = relay_to(&request.body, library_user, peer_user, peer_device) {
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
pub async fn pump_bare_to_library(
    peer: &OlmMachine,
    peer_user: &str,
    library_user: &str,
    library_device: &str,
) -> Vec<String> {
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
            if let Some(event) = relay_to(&body, peer_user, library_user, library_device) {
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

/// Relays one request a bare machine handed back to its caller rather than
/// queueing.
pub async fn deliver_verification_request(
    request: &OutgoingVerificationRequest,
    sender: &str,
    library_user: &str,
    library_device: &str,
) {
    let body = match request {
        OutgoingVerificationRequest::ToDevice(to_device) => {
            serde_json::to_string(to_device).expect("an upstream to-device request serialises")
        }
        // Unreachable: an in-room flow only exists if an in-room
        // verification event was fed to the machine, and this library has no
        // entry point that does that.
        OutgoingVerificationRequest::InRoom(_) => {
            panic!("this library runs to-device verification flows only")
        }
    };
    let event = relay_to(&body, sender, library_user, library_device)
        .expect("the bare machine addresses the library's own device");
    deliver_to_library(vec![event]).await;
}

// ------------------------------------------------------------- the fixtures

/// The device keys a bare machine holds for its own device.
pub async fn device_keys_of(
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
/// The homeserver's half and nothing more: it moves a signature the device
/// genuinely computed, over its own genuine device keys, from the request it
/// emitted into the response another machine is about to be handed. Nothing
/// is fabricated. The same helper, and the same reasoning, as
/// `tests/self_verification.rs`.
pub fn with_owner_signature(
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

/// What one bare machine published about its account, in the shapes a
/// `/keys/query` answer carries them in.
pub struct Published {
    pub peer: OlmMachine,
    pub signed_device_keys: serde_json::Value,
    pub master_key: serde_json::Value,
    pub self_signing_key: serde_json::Value,
    pub user_signing_key: serde_json::Value,
}

/// Stands up a bare machine that publishes its keys, mints its account's
/// signing identity, and signs its own device with it.
pub async fn cross_signed_machine(user_id: &str, device_id: &str) -> Published {
    let account: OwnedUserId = user_id.parse().expect("a literal user id parses");
    let device: OwnedDeviceId = device_id.into();

    let peer = OlmMachine::new(&account, &device).await;
    settle_key_upload(&peer).await;

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

    Published {
        signed_device_keys,
        master_key: key_of("master_keys", &published.master_key),
        self_signing_key: key_of("self_signing_keys", &published.self_signing_key),
        user_signing_key: key_of("user_signing_keys", &published.user_signing_key),
        peer,
    }
}

/// Answers a bare machine's own key upload, so its device keys are published
/// as far as it is concerned.
pub async fn settle_key_upload(peer: &OlmMachine) {
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
}

// ------------------------------------------ the homeserver's signature half

/// The signatures the library's own signature upload carries over another
/// user's master key.
///
/// The wire body of a `signature_upload` **is** the `signed_keys` map, so
/// this reads `{ user: { master key: signed key } }` and returns the
/// `signatures` object of the one entry inside.
///
/// Only the signatures are taken, never the key object around them.
/// Upstream's `sign_user` *replaces* the master key's signature map with its
/// own single signature rather than adding to it
/// (`olm/signing/pk_signing.rs`: `master_key.signatures = signatures`), so
/// posting that object verbatim as the master key would silently drop the
/// signature the other user's own device made over it. The same helper, and
/// the same reasoning, as `tests/verified_sender.rs`.
pub fn uploaded_signatures(body: &str, user_id: &str) -> serde_json::Value {
    let parsed: serde_json::Value =
        serde_json::from_str(body).expect("the pump's own body is well-formed JSON");
    let per_user = parsed
        .get(user_id)
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| panic!("the signature upload must name the user it signed: {body}"));
    assert_eq!(
        per_user.len(),
        1,
        "a user signature covers exactly the master key, so exactly one entry is \
         expected here; more means this upload is not the one this test thinks it \
         is: {body}"
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

/// Merges the signatures the library uploaded into another user's master
/// key, as a homeserver would.
///
/// Asserts the merge actually added one. A `/keys/query` body is just JSON,
/// and one describing an unsigned master key reads exactly like one
/// describing a signed master key, so a fixture that depends on the merge
/// has to check it rather than trust it.
pub fn with_our_signature(
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
         {before} signatures before and {after} after. Equal means this response is \
         indistinguishable from one where the signature was never made"
    );
    master_key
}

// ---------------------------------------------------------- reading a code

/// The mode a scannable payload declares, having checked the two fields in
/// front of it.
///
/// The specification puts a fixed header, then a version, then the mode, in
/// the first eight bytes, and upstream decodes them in exactly that order
/// (`matrix-sdk-qrcode-0.18.0/src/types.rs:206-217`). Read here rather than
/// through upstream's own decoder on purpose: a test that asked upstream
/// which mode upstream had just produced would agree with itself whatever
/// upstream did. This reads the bytes a foreign scanner would read.
///
/// `0x00` verifies another user, `0x01` verifies our own account with the
/// device that holds its keys showing, `0x02` verifies our own account with
/// the device that does not showing.
pub fn mode_of(payload: &[u8]) -> u8 {
    assert!(
        payload.len() > 8,
        "a payload shorter than its own header is not one: {} bytes",
        payload.len()
    );
    assert_eq!(
        &payload[..6],
        b"MATRIX",
        "the payload must carry the specification's header"
    );
    assert_eq!(
        payload[6], 2,
        "this library speaks version 2 of the format and nothing else"
    );
    payload[7]
}

/// Verifying another user. Both master signing keys travel in the payload.
pub const MODE_CROSS_USER: u8 = 0x00;
/// Verifying our own account, shown by the device that holds its private
/// signing keys.
pub const MODE_SELF_TRUSTED: u8 = 0x01;
/// Verifying our own account, shown by the device that does not.
pub const MODE_SELF_UNTRUSTED: u8 = 0x02;

/// Finds the one request of `kind` in a batch, or panics saying what was
/// there instead.
pub fn one_of<'a>(
    batch: &'a [matrix_crypto_core::OutgoingRequest],
    kind: &str,
    why: &str,
) -> &'a matrix_crypto_core::OutgoingRequest {
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

/// Every verification method this library announces, which a counterparty
/// must answer with if a code is to be produced at all.
///
/// Named here so that a test which deliberately answers with *less* than
/// this -- to drive the refusal a peer that cannot scan produces -- is
/// visibly doing something different from the ones that do not.
pub fn every_method() -> Vec<matrix_sdk_common::ruma::events::key::verification::VerificationMethod>
{
    use matrix_sdk_common::ruma::events::key::verification::VerificationMethod;
    vec![
        VerificationMethod::SasV1,
        VerificationMethod::QrCodeShowV1,
        VerificationMethod::QrCodeScanV1,
        VerificationMethod::ReciprocateV1,
    ]
}
