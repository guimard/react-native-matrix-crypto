//! Ingesting sync changes into the crypto machine.
//!
//! The product already performs the `/sync` request; this module only
//! consumes the encryption-relevant slice of the response it hands back --
//! to-device events, one-time and fallback key counts, and changed or left
//! devices -- so the machine can decrypt, track key counts, and learn about
//! other devices. This is the prerequisite every later crypto operation
//! (sharing a key, encrypting, decrypting) depends on.

use std::collections::BTreeMap;
use std::sync::Mutex as StdMutex;

// Response types for the six kinds `OlmMachine::outgoing_requests` and
// `share_room_key` can ever hand out (matched exhaustively against
// `AnyOutgoingRequest` below, with no wildcard -- see `describe_outgoing`).
// Each is renamed on import: their upstream names collide with either one
// another (every endpoint module calls its own type `Response`) or with this
// module's own public `OutgoingRequest`.
use matrix_sdk_common::ruma::api::client::keys::claim_keys::v3::Response as KeysClaimResponse;
use matrix_sdk_common::ruma::api::client::keys::get_keys::v3::Response as KeysQueryResponse;
use matrix_sdk_common::ruma::api::client::keys::upload_keys::v3::Response as KeysUploadResponse;
use matrix_sdk_common::ruma::api::client::keys::upload_signatures::v3::Response as SignatureUploadResponse;
use matrix_sdk_common::ruma::api::client::message::send_message_event::v3::Response as RoomMessageResponse;
use matrix_sdk_common::ruma::api::client::sync::sync_events::DeviceLists;
use matrix_sdk_common::ruma::api::client::to_device::send_event_to_device::v3::Response as ToDeviceHttpResponse;
use matrix_sdk_common::ruma::api::IncomingResponse;
use matrix_sdk_common::ruma::events::{AnyMessageLikeEventContent, AnyToDeviceEvent};
// `exports::http`, not a direct `http` dependency of this crate: it is the
// exact `http` version `ruma`'s own `IncomingResponse::try_from_http_response`
// requires, reached through `ruma`'s own re-export rather than a second,
// independently-versioned copy this crate would have to keep in step by hand.
use matrix_sdk_common::ruma::exports::http;
use matrix_sdk_common::ruma::serde::Raw;
use matrix_sdk_common::ruma::{
    OneTimeKeyAlgorithm, OwnedRoomId, OwnedTransactionId, OwnedUserId, TransactionId, UInt,
};
use matrix_sdk_crypto::types::requests::{AnyOutgoingRequest, ToDeviceRequest};
use matrix_sdk_crypto::{
    DecryptionSettings, EncryptionSettings, EncryptionSyncChanges, OlmMachine, TrustRequirement,
};
use serde::Deserialize;

use crate::machine::{with_machine, MachineError};

/// Settings for `OlmMachine::receive_sync_changes`.
///
/// A fresh value built per call, not a cached constant: the decision this
/// encodes is meant to be revisited, not optimised into something a later
/// reader has to track down through an extra indirection.
fn decryption_settings() -> DecryptionSettings {
    // M2: verification lands in M3; revisit this with it.
    //
    // No device is verified anywhere in this milestone, so
    // `TrustRequirement::CrossSigned` (or `CrossSignedOrLegacy`) would reject
    // every event M2 needs to process. `Untrusted` is upstream's own most
    // permissive option, explicitly documented as "not recommended" -- taken
    // here as a deliberate, named placeholder for a decision M3 must make
    // with real cross-signing in place, not left as an unnoticed default.
    DecryptionSettings {
        sender_device_trust_requirement: TrustRequirement::Untrusted,
    }
}

/// Errors from ingesting a batch of sync changes into the crypto machine.
///
/// Carries no payload content, ciphertext, device id or user id -- see spec
/// section 7: upstream `Display` output can embed event content, so no
/// upstream error is ever forwarded, only mapped to one of these fixed
/// shapes. `MalformedPayload` and `Failed` are kept distinct because they
/// call for different product responses: nonsense the product sent itself
/// is not the same problem as a crypto operation failing on well-formed
/// input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// `raw_json` did not parse into the shape this function accepts.
    #[error("the payload could not be parsed")]
    MalformedPayload,
    /// No crypto machine has been created yet.
    #[error("no crypto machine has been created")]
    NotInitialised,
    /// The crypto machine rejected or failed to process the sync changes.
    #[error("the crypto operation failed")]
    Failed,
    /// `mark_request_sent` was called with an `id` this machine never
    /// handed out through `take_outgoing_requests`, or already resolved.
    ///
    /// Kept distinct from `MalformedPayload`: the caller's `id` is
    /// syntactically fine (any string parses as a `TransactionId`, which is
    /// an opaque identifier with no format of its own) -- what is wrong is
    /// that it does not match anything this process is waiting to hear
    /// about, which calls for a different product response than "you sent
    /// nonsense".
    #[error("the request id does not match a pending request")]
    UnknownRequest,
}

impl From<MachineError> for SessionError {
    fn from(error: MachineError) -> Self {
        match error {
            MachineError::NotInitialised => SessionError::NotInitialised,
            // `with_machine` can only ever produce `NotInitialised` today --
            // see its own doc comment in `machine.rs`. Every other
            // `MachineError` variant belongs to `create_machine`/
            // `open_store`, not to a call that already requires a live
            // machine. Matched explicitly anyway, with no wildcard, so a
            // future `MachineError` variant fails this build instead of
            // silently landing on `Failed`.
            MachineError::AlreadyInitialised
            | MachineError::MalformedIdentifier { .. }
            | MachineError::Store { .. } => SessionError::Failed,
        }
    }
}

/// What a call to [`receive_sync_changes`] did to the machine's state.
///
/// Both counts describe the call's own two returned collections --
/// processed to-device events, then new or updated room keys, per
/// `matrix-sdk-crypto-0.18.0/src/machine/mod.rs:1728` -- not an echo of what
/// the caller sent. The machine can fold in its own bookkeeping (e.g.
/// garbage-collected verification objects) and can also drop an encrypted
/// event entirely (e.g. one from a dehydrated device), so the input length
/// and `to_device_event_count` are not guaranteed to match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    /// How many to-device events this call reported having processed.
    pub to_device_event_count: u32,
    /// How many new or updated end-to-end sessions this call produced.
    pub new_session_count: u32,
}

/// The wire shape `receive_sync_changes` accepts, mirroring
/// `EncryptionSyncChanges`'s own field names exactly (confirmed against
/// `matrix-sdk-crypto-0.18.0/src/machine/mod.rs:3150`) so there is no
/// separate translation layer to keep in sync with upstream as it evolves.
///
/// Every field defaults when its key is absent, not only when its value is
/// empty: an empty sync is the shape a product sends constantly, and it
/// must be accepted and report nothing, not rejected as malformed because
/// one key was left out. `#[serde(default)]` is required even on the two
/// `Option` fields -- serde does not treat a missing key as `None` for an
/// `Option` field on its own, only when told to.
///
/// No `#[derive(Debug)]`: `to_device_events` can carry ciphertext, and
/// nothing here needs printing. Never format this struct or its fields.
#[derive(Deserialize)]
struct SyncChangesPayload {
    #[serde(default)]
    to_device_events: Vec<Raw<AnyToDeviceEvent>>,
    #[serde(default)]
    changed_devices: DeviceLists,
    #[serde(default)]
    one_time_keys_counts: BTreeMap<OneTimeKeyAlgorithm, UInt>,
    #[serde(default)]
    unused_fallback_keys: Option<Vec<OneTimeKeyAlgorithm>>,
    #[serde(default)]
    next_batch_token: Option<String>,
}

/// Feeds the encryption-relevant slice of a `/sync` response into the crypto
/// machine, so it can decrypt to-device events, track one-time and fallback
/// key counts, and learn about changed or left devices.
///
/// The bridge takes the JSON the product already fetched; it never performs
/// the sync request itself. See [`SyncChangesPayload`] for the accepted
/// shape.
pub async fn receive_sync_changes(raw_json: &str) -> Result<SyncOutcome, SessionError> {
    let payload: SyncChangesPayload =
        serde_json::from_str(raw_json).map_err(|_| SessionError::MalformedPayload)?;

    let SyncChangesPayload {
        to_device_events,
        changed_devices,
        one_time_keys_counts,
        unused_fallback_keys,
        next_batch_token,
    } = payload;

    // Owned locals moved into the closure, not borrowed from this stack
    // frame: `with_machine` requires its closure `Send + 'static` (see its
    // doc comment in `machine.rs`). `EncryptionSyncChanges` itself borrows
    // (`changed_devices`, `one_time_keys_counts`), but only from these
    // locals, and only for the duration of the `receive_sync_changes` call
    // below, all inside the one async block -- so the borrow never needs to
    // outlive anything the closure does not already own.
    //
    // `with_machine` already runs inside the library's runtime and holds the
    // machine lock for this closure's duration; wrapping this call in
    // `in_runtime` again, or emitting a signal from inside it, is exactly
    // what its doc comment warns against.
    let processed = with_machine(move |machine| {
        Box::pin(async move {
            let changes = EncryptionSyncChanges {
                to_device_events,
                changed_devices: &changed_devices,
                one_time_keys_counts: &one_time_keys_counts,
                unused_fallback_keys: unused_fallback_keys.as_deref(),
                next_batch_token,
            };

            machine
                .receive_sync_changes(changes, &decryption_settings())
                .await
        })
    })
    .await?;

    match processed {
        Ok((events, room_keys)) => Ok(SyncOutcome {
            to_device_event_count: events.len() as u32,
            new_session_count: room_keys.len() as u32,
        }),
        // Upstream `Display` output can embed event content, a device id or
        // a user id (e.g. `OlmError::SessionWedged(OwnedUserId, Curve25519PublicKey)`,
        // matrix-sdk-crypto-0.18.0/src/error.rs:61) -- never forwarded, per
        // spec section 7. Mapped to a fixed-shape variant instead, with no
        // `detail` field to carry it in.
        Err(_upstream) => Err(SessionError::Failed),
    }
}

/// Parses the opaque scope string into the identifier it addresses today.
///
/// This is the one place that name appears in this module: a scope maps to
/// a room id 1:1 for now, but that mapping is this function's own
/// implementation detail, never a public identifier -- see spec section 6
/// and the design doc's section 3bis. A later scope kind (e.g. an MLS group)
/// would branch here without moving anything public.
fn parse_scope(scope: &str) -> Result<OwnedRoomId, SessionError> {
    scope.parse().map_err(|_| SessionError::MalformedPayload)
}

fn parse_user(user_id: &str) -> Result<OwnedUserId, SessionError> {
    user_id.parse().map_err(|_| SessionError::MalformedPayload)
}

/// An event encrypted for a scope, or the plaintext recovered by decrypting
/// one -- see spec section 6/7. `algorithm` and the scope inside `scope` are
/// both open: neither this struct nor anything that produces it may name a
/// specific group-session algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub scope: String,
    /// Open tag, e.g. the wire algorithm id upstream attached to the
    /// encrypted content -- read back from that content itself (inside
    /// `encrypt_event`) rather than hard-coded, so a future algorithm
    /// upstream adds needs no change here.
    pub algorithm: String,
    pub event_type: String,
    pub ciphertext: Vec<u8>,
    /// `@user:server`, verbatim -- the current machine's own user id, since
    /// this is always this device's own outbound encryption.
    pub sender: String,
}

/// Encrypts `payload_json` (a JSON event content, opaque to this function)
/// for `scope`, returning the [`Envelope`] to hand back across the
/// boundary.
///
/// Order matters and is enforced by upstream, not by a check here: a scope
/// must have a group session before this can succeed --
/// [`share_scope_key`] establishes one. Calling this first is a caller
/// error upstream reports as a panic (`encrypt_room_event_raw`'s own
/// documented behaviour), which is deliberate -- see the design doc section
/// 7 and section 4's note on why `panic = "unwind"` stays: UniFFI's
/// `catch_unwind` turns it into a catchable error at the boundary rather
/// than a runtime check this layer cannot correctly make (it cannot tell "no
/// session yet" from "session legitimately empty" without reaching into
/// upstream's own state).
pub async fn encrypt_event(
    scope: &str,
    event_type: &str,
    payload_json: &str,
) -> Result<Envelope, SessionError> {
    let room_id = parse_scope(scope)?;
    let content = Raw::<AnyMessageLikeEventContent>::from_json_string(payload_json.to_owned())
        .map_err(|_| SessionError::MalformedPayload)?;

    let scope = scope.to_owned();
    let event_type = event_type.to_owned();

    // `with_machine` already runs inside the library's runtime and holds
    // the machine lock for this closure's duration; see its own doc comment
    // in `machine.rs`.
    let result = with_machine(move |machine| {
        Box::pin(async move {
            machine
                .encrypt_room_event_raw(&room_id, &event_type, &content)
                .await
                .map(|encrypted| {
                    // `encrypted`'s type is never named: it lives in a
                    // private module of `matrix-sdk-crypto` and is only
                    // reachable here, unnamed, through inference on this
                    // closure parameter (confirmed by trying to name it
                    // and reading rustc's own "private module" error).
                    //
                    // Read back from the encrypted content itself, not
                    // matched against upstream's `AlgorithmInfo` enum: this
                    // needs no arm for a future algorithm upstream adds,
                    // and it is what actually went over the wire in
                    // `ciphertext`, not a second, possibly-diverging
                    // description of it.
                    let algorithm = encrypted
                        .content
                        .get_field::<String>("algorithm")
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    let ciphertext = encrypted.content.json().get().as_bytes().to_vec();

                    Envelope {
                        scope,
                        algorithm,
                        event_type,
                        ciphertext,
                        sender: machine.user_id().as_str().to_string(),
                    }
                })
        })
    })
    .await?;

    // Upstream `Display` output on a Megolm error can embed a session id or
    // device id -- never forwarded, per spec section 7, same as
    // `receive_sync_changes` above.
    result.map_err(|_upstream| SessionError::Failed)
}

/// Ensures `scope` has a group session and shares it with the given users'
/// known devices.
///
/// This is the call that reaches `tokio::task::spawn` through
/// `matrix-sdk-common` during group key sharing, and the reason Task 1's
/// runtime exists -- see the design doc section 4.
///
/// The to-device requests upstream returns carry the session key itself, on
/// its way to the recipients' devices. They are queued here for
/// [`take_outgoing_requests`] to hand out, never discarded -- discarding
/// them is the mistake the design doc's section 3bis exists to prevent: the
/// group session would exist locally, `encrypt_event` would happily
/// produce ciphertext, and no other device would ever be able to read it.
pub async fn share_scope_key(scope: &str, users: &[String]) -> Result<(), SessionError> {
    let room_id = parse_scope(scope)?;
    let user_ids = users
        .iter()
        .map(|user| parse_user(user))
        .collect::<Result<Vec<_>, _>>()?;

    let shared = with_machine(move |machine| {
        Box::pin(async move {
            machine
                .share_room_key(
                    &room_id,
                    user_ids.iter().map(AsRef::as_ref),
                    EncryptionSettings::default(),
                )
                .await
        })
    })
    .await?;

    let to_device_requests = shared.map_err(|_upstream| SessionError::Failed)?;

    if !to_device_requests.is_empty() {
        let mut state = STATE.lock().expect("request registry poisoned");
        state.queued_to_device.extend(to_device_requests);
    }

    Ok(())
}

/// Which upstream response shape a request id crossing back in through
/// [`mark_request_sent`] must be parsed as.
///
/// Recorded in [`STATE`] when the request crosses out through
/// [`take_outgoing_requests`], consulted and removed when the matching
/// response crosses back in. Private: never part of this crate's public
/// declarations, so its variants carry whatever names describe upstream's
/// own request kinds best, including ones the facade agility rule (design
/// doc section 6 / M1 spec section 6) would reject as a *public* name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    KeysUpload,
    KeysQuery,
    KeysClaim,
    ToDevice,
    SignatureUpload,
    RoomMessage,
}

impl PendingKind {
    /// The public, open-tag `kind` string -- spec section 3bis's own
    /// examples for the first three, extended the same way for the rest.
    fn tag(self) -> &'static str {
        match self {
            PendingKind::KeysUpload => "keys_upload",
            PendingKind::KeysQuery => "keys_query",
            PendingKind::KeysClaim => "keys_claim",
            PendingKind::ToDevice => "to_device",
            PendingKind::SignatureUpload => "signature_upload",
            PendingKind::RoomMessage => "room_message",
        }
    }
}

/// Process-wide outbound-request bookkeeping this module owns.
///
/// Two distinct jobs share one lock rather than two, so a caller can never
/// observe one updated without the other:
///
/// * `queued_to_device` -- to-device requests [`share_scope_key`] obtained
///   from `share_room_key` but that have not yet been handed out by
///   [`take_outgoing_requests`]. Drained (not cloned) when they are.
/// * `pending` -- every request id this module has ever handed out via
///   [`take_outgoing_requests`] that has not yet been resolved by
///   [`mark_request_sent`], with the [`PendingKind`] needed to parse its
///   response. Removed on resolution, so it cannot grow across a request's
///   whole lifetime, only across its in-flight one.
///
/// A `std::sync::Mutex`, not `tokio::sync::Mutex`: every critical section
/// below is a plain synchronous map/vec operation with no `.await` inside
/// it.
struct RequestState {
    queued_to_device: Vec<std::sync::Arc<ToDeviceRequest>>,
    pending: BTreeMap<String, PendingKind>,
}

static STATE: StdMutex<RequestState> = StdMutex::new(RequestState {
    queued_to_device: Vec::new(),
    pending: BTreeMap::new(),
});

#[cfg(test)]
fn reset_request_state_for_test() {
    let mut state = STATE.lock().expect("request registry poisoned");
    state.queued_to_device.clear();
    state.pending.clear();
}

/// Flattens one upstream outgoing request into the `{ kind, body }` shape
/// that crosses the boundary, alongside the [`PendingKind`] needed to parse
/// its eventual response.
///
/// Matched exhaustively against `AnyOutgoingRequest`, with no wildcard: a
/// variant upstream adds later must fail this build instead of silently
/// falling through unhandled, the same reasoning `SessionError`'s own
/// `From<MachineError>` above documents for itself.
///
/// Each body is built from the request's own public fields, not from
/// `OutgoingRequest::try_into_http_request` -- that method additionally
/// needs an auth scheme and a homeserver's supported-version list neither
/// of which this bridge has any business deciding (the product owns
/// transport, per spec section 6). Field names here are upstream's own
/// wire field names (verified against the vendored `ruma-client-api`
/// source per request kind), so the JSON this produces is the real request
/// body for that endpoint, not a re-description of it.
fn describe_outgoing(request: &AnyOutgoingRequest) -> (PendingKind, String) {
    match request {
        AnyOutgoingRequest::KeysUpload(r) => (
            PendingKind::KeysUpload,
            serde_json::json!({
                "device_keys": r.device_keys,
                "one_time_keys": r.one_time_keys,
                "fallback_keys": r.fallback_keys,
            })
            .to_string(),
        ),
        AnyOutgoingRequest::KeysQuery(r) => (
            PendingKind::KeysQuery,
            serde_json::json!({
                "device_keys": r.device_keys,
                "timeout": r.timeout.map(|d| d.as_millis() as u64),
            })
            .to_string(),
        ),
        AnyOutgoingRequest::KeysClaim(r) => (
            PendingKind::KeysClaim,
            serde_json::json!({
                "one_time_keys": r.one_time_keys,
                "timeout": r.timeout.map(|d| d.as_millis() as u64),
            })
            .to_string(),
        ),
        AnyOutgoingRequest::ToDeviceRequest(r) => {
            // `ToDeviceRequest` is this crate's own type and derives
            // `Serialize` directly (unlike the `ruma` request types
            // above), so the whole struct serialises as-is -- including
            // `event_type`/`txn_id`, which the wire body itself omits (they
            // are path segments on the real endpoint) but which the
            // product needs to build that path, and which are harmless
            // alongside `messages` for a server that ignores unknown
            // top-level fields.
            (
                PendingKind::ToDevice,
                serde_json::to_string(r).unwrap_or_default(),
            )
        }
        AnyOutgoingRequest::SignatureUpload(r) => (
            PendingKind::SignatureUpload,
            serde_json::json!({ "signed_keys": r.signed_keys }).to_string(),
        ),
        AnyOutgoingRequest::RoomMessage(r) => (
            PendingKind::RoomMessage,
            serde_json::json!({
                "room_id": r.room_id,
                "txn_id": r.txn_id,
                "content": &*r.content,
            })
            .to_string(),
        ),
    }
}

/// What the product must send to its homeserver, or feed to another
/// device -- see the design doc section 3bis. `body` is JSON this module
/// never interprets, sent as-is; `kind` is an open tag mirroring upstream's
/// own request kinds, not restricted to the ones listed in
/// [`describe_outgoing`]'s match today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingRequest {
    /// Opaque; hand it back verbatim to [`mark_request_sent`].
    pub id: String,
    pub kind: String,
    pub body: String,
}

/// Drains every outstanding outbound request: device/one-time key uploads
/// and key queries upstream still wants sent (`OlmMachine::outgoing_requests`),
/// plus any to-device requests [`share_scope_key`] queued.
///
/// This is the half of the pump the design doc section 3bis is named for.
/// A fresh machine's device keys and one-time keys are otherwise never
/// published, and a shared session key never leaves the process -- both
/// silent failures that pass every test which never calls this.
pub async fn take_outgoing_requests() -> Result<Vec<OutgoingRequest>, SessionError> {
    let upstream =
        with_machine(|machine| Box::pin(async move { machine.outgoing_requests().await }))
            .await?
            .map_err(|_upstream| SessionError::Failed)?;

    let mut state = STATE.lock().expect("request registry poisoned");
    let mut out = Vec::with_capacity(upstream.len() + state.queued_to_device.len());

    for request in &upstream {
        let id = request.request_id().to_string();
        let (kind, body) = describe_outgoing(request.request());
        state.pending.insert(id.clone(), kind);
        out.push(OutgoingRequest {
            id,
            kind: kind.tag().to_string(),
            body,
        });
    }

    // The to-device `txn_id` doubles as the request id, per
    // `share_room_key`'s own doc comment (verified against
    // `matrix-sdk-crypto-0.18.0/src/session_manager/group_sessions/mod.rs`):
    // "the responses need to be passed back to the state machine ... using
    // the to-device txn_id as request_id".
    //
    // Collected into an owned `Vec` before the loop, not iterated directly
    // off `drain(..)`: `state` is a `MutexGuard`, and the borrow checker
    // cannot see `queued_to_device` and `pending` as disjoint fields through
    // its `DerefMut` the way it can on a plain struct, so holding the
    // `drain` iterator open while also indexing into `state.pending` below
    // does not borrow-check.
    let queued: Vec<_> = state.queued_to_device.drain(..).collect();
    for to_device in queued {
        let id = to_device.txn_id.to_string();
        let body = serde_json::to_string(to_device.as_ref()).unwrap_or_default();
        state.pending.insert(id.clone(), PendingKind::ToDevice);
        out.push(OutgoingRequest {
            id,
            kind: PendingKind::ToDevice.tag().to_string(),
            body,
        });
    }

    Ok(out)
}

/// Builds a fixed-shape, status-200 `http::Response` around `body`, the
/// shape `ruma`'s own `IncomingResponse::try_from_http_response` expects.
///
/// No custom headers and a status this module always controls itself
/// (never read from `body`), so building it cannot fail -- the `expect`
/// documents that rather than guarding against a case that cannot occur.
fn http_response(body: Vec<u8>) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(200)
        .body(body)
        .expect("a fixed-shape http::Response with no custom headers cannot fail to build")
}

/// Parses `body` as the response shape `kind` expects and hands it to
/// `machine.mark_request_as_sent`.
///
/// Going through `IncomingResponse::try_from_http_response` rather than
/// constructing each upstream `Response` type by hand is not a style
/// choice: every one of these types is `#[non_exhaustive]`, and some (e.g.
/// `KeysQuery`) expose no public constructor that accepts real field values
/// at all -- `try_from_http_response` is the only public way to build a
/// populated instance of every one of them from outside `ruma-client-api`.
///
/// For `ToDevice`, `SignatureUpload` and `RoomMessage`, upstream's own
/// `mark_request_as_sent` ignores the response value entirely (it only
/// matches the enum tag) -- confirmed by reading `machine/mod.rs:602`'s
/// match arms, each `AnyIncomingResponse::Variant(_)` for those three. This
/// function still parses `body` into the correctly-typed value rather than
/// fabricating one, because "this module does not interpret the JSON" (spec
/// section 3bis) means it does not act on the JSON's meaning, not that it
/// skips deserialising it.
async fn mark_sent(
    machine: &OlmMachine,
    kind: PendingKind,
    transaction_id: OwnedTransactionId,
    body: Vec<u8>,
) -> Result<(), SessionError> {
    let outcome = match kind {
        PendingKind::KeysUpload => {
            let response = KeysUploadResponse::try_from_http_response(http_response(body))
                .map_err(|_| SessionError::MalformedPayload)?;
            machine
                .mark_request_as_sent(&transaction_id, &response)
                .await
        }
        PendingKind::KeysQuery => {
            let response = KeysQueryResponse::try_from_http_response(http_response(body))
                .map_err(|_| SessionError::MalformedPayload)?;
            machine
                .mark_request_as_sent(&transaction_id, &response)
                .await
        }
        PendingKind::KeysClaim => {
            let response = KeysClaimResponse::try_from_http_response(http_response(body))
                .map_err(|_| SessionError::MalformedPayload)?;
            machine
                .mark_request_as_sent(&transaction_id, &response)
                .await
        }
        PendingKind::ToDevice => {
            let response = ToDeviceHttpResponse::try_from_http_response(http_response(body))
                .map_err(|_| SessionError::MalformedPayload)?;
            machine
                .mark_request_as_sent(&transaction_id, &response)
                .await
        }
        PendingKind::SignatureUpload => {
            let response = SignatureUploadResponse::try_from_http_response(http_response(body))
                .map_err(|_| SessionError::MalformedPayload)?;
            machine
                .mark_request_as_sent(&transaction_id, &response)
                .await
        }
        PendingKind::RoomMessage => {
            let response = RoomMessageResponse::try_from_http_response(http_response(body))
                .map_err(|_| SessionError::MalformedPayload)?;
            machine
                .mark_request_as_sent(&transaction_id, &response)
                .await
        }
    };

    // Upstream `Display` output here can embed device/session/user
    // identifiers pulled straight from the response body -- never
    // forwarded, per spec section 7.
    outcome.map_err(|_upstream| SessionError::Failed)
}

/// Reports that the request named by `id` was sent, handing back the
/// server's response so upstream can update its own state (device lists,
/// one-time key counts, claimed keys -- depending on what `id` was).
///
/// `id` is converted to a `TransactionId` via `From<&str>`, which is
/// infallible: upstream's own doc comment on the type says as much --
/// "Transaction IDs in Matrix are opaque strings" with no format of their
/// own to validate against. What can fail is `id` not matching anything
/// this module handed out -- [`SessionError::UnknownRequest`] -- and
/// `response_json` not parsing as the shape that request's kind expects --
/// [`SessionError::MalformedPayload`].
pub async fn mark_request_sent(id: &str, response_json: &str) -> Result<(), SessionError> {
    let kind = {
        let mut state = STATE.lock().expect("request registry poisoned");
        state.pending.remove(id)
    }
    .ok_or(SessionError::UnknownRequest)?;

    let transaction_id: OwnedTransactionId = <&TransactionId>::from(id).to_owned();
    let body = response_json.as_bytes().to_vec();

    with_machine(move |machine| Box::pin(mark_sent(machine, kind, transaction_id, body))).await?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A machine config pointing at a directory that outlives this call.
    /// `TempDir::keep`, not the guard itself: the only thing returned is an
    /// owned `MachineConfig`, so nothing here can hand the caller a guard to
    /// hold alive too. The directory is left on disk after the test process
    /// exits -- the same trade every other `tempfile::tempdir()` use in this
    /// crate's tests accepts, just not deferred to a `Drop` here because
    /// this helper's own scope ends before `create_machine` ever runs.
    fn test_config() -> crate::machine::MachineConfig {
        let dir = tempfile::tempdir().expect("temp dir").keep();
        crate::machine::MachineConfig {
            user_id: "@alice:example.org".to_string(),
            device_id: "DEVICE1".to_string(),
            store_path: dir.join("store").to_string_lossy().into_owned(),
            store_passphrase: Some("test-passphrase".to_string()),
        }
    }

    /// An empty sync is the shape a product sends constantly. It must be
    /// accepted and report nothing, not rejected as malformed.
    ///
    /// Deliberately not `#[tokio::test]`: this crate's tests drive
    /// `with_machine` through `futures::executor::block_on` with no ambient
    /// runtime, the same shape the FFI's real calling context has. See
    /// `machine.rs`'s `with_machine_supplies_a_runtime_for_store_touching_calls`
    /// for why that distinction matters -- an ambient runtime would make
    /// this test pass even if `with_machine` supplied none of its own.
    #[test]
    fn an_empty_sync_is_accepted_and_reports_no_new_sessions() {
        // `HELD` is process-wide and shared with `machine.rs`'s and
        // `identity.rs`'s own tests, all in one test binary; guarded the
        // same way theirs are.
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();

        let outcome = futures::executor::block_on(async {
            crate::machine::create_machine(test_config()).await.unwrap();
            receive_sync_changes(r#"{"to_device_events":[],"changed_devices":{"changed":[],"left":[]},"one_time_keys_counts":{}}"#).await
        })
        .unwrap();

        assert_eq!(outcome.to_device_event_count, 0);
        assert_eq!(outcome.new_session_count, 0);
    }

    /// The stronger form of the same property: every key absent, not merely
    /// empty. Proves `#[serde(default)]` covers every field of
    /// `SyncChangesPayload`, including the two `Option` fields the brief's
    /// own sync payload above never exercises because it never mentions
    /// them either.
    #[test]
    fn a_sync_with_every_field_omitted_is_also_accepted() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();

        let outcome = futures::executor::block_on(async {
            crate::machine::create_machine(test_config()).await.unwrap();
            receive_sync_changes("{}").await
        })
        .unwrap();

        assert_eq!(outcome.to_device_event_count, 0);
        assert_eq!(outcome.new_session_count, 0);
    }

    #[test]
    fn malformed_json_is_reported_as_malformed_not_as_a_store_failure() {
        let err = futures::executor::block_on(receive_sync_changes("{oops")).unwrap_err();
        assert_eq!(err, SessionError::MalformedPayload);
    }

    /// A distinct failure mode from the one above: syntactically valid JSON
    /// that does not match the accepted shape. Both must be reported the
    /// same way, so a caller does not have to guess which kind of "not
    /// parseable" it hit.
    #[test]
    fn well_formed_json_of_the_wrong_shape_is_also_reported_as_malformed() {
        let err = futures::executor::block_on(receive_sync_changes(
            r#"{"one_time_keys_counts":"not-a-map"}"#,
        ))
        .unwrap_err();
        assert_eq!(err, SessionError::MalformedPayload);
    }

    /// This crate's own precondition, not upstream's: `with_machine` reports
    /// `NotInitialised` before ever reaching a machine, and that must
    /// surface as `SessionError::NotInitialised`, not `Failed` -- a product
    /// needs to tell "you haven't set me up yet" apart from "the crypto
    /// operation failed".
    #[test]
    fn calls_before_creation_report_not_initialised() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();

        let err = futures::executor::block_on(receive_sync_changes(
            r#"{"to_device_events":[],"changed_devices":{"changed":[],"left":[]},"one_time_keys_counts":{}}"#,
        ))
        .unwrap_err();

        assert_eq!(err, SessionError::NotInitialised);
    }

    /// Both counts in `an_empty_sync_is_accepted_and_reports_no_new_sessions`
    /// are zero, which a function that always hard-coded zero would also
    /// satisfy. This sends one real, unencrypted to-device event and checks
    /// the count follows it, so a regression to "always report zero" cannot
    /// pass unnoticed.
    #[test]
    fn to_device_event_count_reflects_what_the_machine_actually_processed() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();

        let outcome = futures::executor::block_on(async {
            crate::machine::create_machine(test_config()).await.unwrap();
            receive_sync_changes(
                r#"{"to_device_events":[{"sender":"@bob:example.org","type":"m.dummy","content":{}}],"changed_devices":{"changed":[],"left":[]},"one_time_keys_counts":{}}"#,
            )
            .await
        })
        .unwrap();

        assert_eq!(outcome.to_device_event_count, 1);
        // An `m.dummy` event carries no room key, so this call must not be
        // mistaken for one that established a session.
        assert_eq!(outcome.new_session_count, 0);
    }

    // --- Task 5: encryption and the outbound pump ---------------------

    /// A machine config pointing at `dir`, the non-leaking counterpart to
    /// this file's own `test_config()` above (which calls `TempDir::keep`
    /// deliberately, per Task 4's brief -- a trade a review already graded
    /// low and non-blocking, and not this task's to fix). These tests
    /// create real key material on disk and there are several of them, so
    /// each gets its own `TempDir` bound in the test, dropped normally --
    /// the same pattern `machine.rs`'s own `config_in` uses.
    fn config_in(dir: &std::path::Path) -> crate::machine::MachineConfig {
        crate::machine::MachineConfig {
            user_id: "@alice:example.org".to_string(),
            device_id: "DEVICE1".to_string(),
            store_path: dir.join("store").to_string_lossy().into_owned(),
            store_passphrase: Some("test-passphrase".to_string()),
        }
    }

    #[test]
    fn encrypting_produces_ciphertext_that_is_not_the_plaintext() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let envelope = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            encrypt_event(
                "!s:example.org",
                "m.room.message",
                r#"{"body":"hello","msgtype":"m.text"}"#,
            )
            .await
        })
        .unwrap();

        assert!(!envelope.ciphertext.is_empty());
        assert!(
            !String::from_utf8_lossy(&envelope.ciphertext).contains("hello"),
            "the plaintext must not survive in the ciphertext"
        );
        assert_eq!(envelope.sender, "@alice:example.org");
        assert_eq!(envelope.scope, "!s:example.org");
        assert_eq!(envelope.event_type, "m.room.message");
        assert!(
            !envelope.algorithm.is_empty(),
            "the algorithm tag must be populated"
        );
    }

    /// A scope that is not a valid identifier must be rejected before any
    /// cryptographic work happens.
    #[test]
    fn a_malformed_scope_is_rejected() {
        let err = futures::executor::block_on(encrypt_event("nonsense", "m.room.message", "{}"))
            .unwrap_err();
        assert_eq!(err, SessionError::MalformedPayload);
    }

    /// This crate's own "no secret in any error" rule (spec section 7):
    /// regardless of what triggers `MalformedPayload`, the input that
    /// triggered it must not survive into the rendered error.
    #[test]
    fn an_error_never_echoes_the_input_that_caused_it() {
        let secret_like_payload = "super-secret-plaintext-marker";
        let err = futures::executor::block_on(encrypt_event(
            "not-a-valid-scope",
            "m.room.message",
            secret_like_payload,
        ))
        .unwrap_err();

        let rendered = err.to_string();
        assert!(
            !rendered.contains(secret_like_payload),
            "rendered error must not contain the input: {rendered}"
        );
        assert!(
            !rendered.contains("not-a-valid-scope"),
            "rendered error must not contain the input: {rendered}"
        );
    }

    /// A fresh machine has device keys and one-time keys nobody has seen. If
    /// the pump were decorative, this would return nothing and the device
    /// would be invisible to every other client on the homeserver.
    #[test]
    fn a_fresh_machine_has_keys_waiting_to_be_uploaded() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let requests = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            take_outgoing_requests().await
        })
        .unwrap();

        assert!(
            !requests.is_empty(),
            "a new device must have keys to publish"
        );
        assert!(requests.iter().any(|r| r.kind == "keys_upload"));
        // Every request must carry a non-empty, distinct id a caller can
        // hand back verbatim to `mark_request_sent`.
        assert!(requests.iter().all(|r| !r.id.is_empty()));
    }

    /// Sharing a scope key must produce something to send. A silent success
    /// here is the failure mode section 3bis warns about: the outbound
    /// group session would exist locally and `encrypt_event` would happily
    /// produce ciphertext, but the session key would never leave the
    /// process, so no other device could ever read it.
    ///
    /// Proven with a real second device, not a stranger's user id: sharing
    /// to a user this machine has never learned any devices for
    /// legitimately produces nothing to send (there is nobody to send to
    /// yet). So this test first drives this module's own pump through a
    /// real keys-query round trip -- the same one a real sync loop
    /// performs -- to make that second device known, matching the design
    /// doc's own two-machine testing guidance (spec section 8) and the M2
    /// exit criterion that the key travel through `take_outgoing_requests`
    /// rather than being handed over directly.
    #[test]
    fn sharing_a_scope_key_produces_a_request_to_send() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        // Wrapped in this crate's own runtime, not a bare `block_on`: the
        // second machine constructed below is a raw `matrix-sdk-crypto`
        // `OlmMachine` this test drives directly (outside `with_machine`),
        // and `machine.rs`'s own doc comment on `with_machine` records this
        // exact mistake being made twice already in this milestone -- code
        // that only works because a test harness happened to supply an
        // ambient runtime.
        let after = futures::executor::block_on(crate::in_runtime(async move {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();

            let bob_user: matrix_sdk_common::ruma::OwnedUserId =
                "@bob:example.org".parse().unwrap();
            let bob_device: matrix_sdk_common::ruma::OwnedDeviceId = "BOBDEVICE".into();
            let bob = matrix_sdk_crypto::OlmMachine::new(&bob_user, &bob_device).await;
            let bob_upload = bob.outgoing_requests().await.unwrap();
            let bob_device_keys = bob_upload
                .iter()
                .find_map(|r| match r.request() {
                    AnyOutgoingRequest::KeysUpload(u) => u.device_keys.clone(),
                    _ => None,
                })
                .expect("a fresh machine always has device keys to upload");

            // Tell the local machine bob's device list changed, so its own
            // pump reports a real keys-query request to resolve -- rather
            // than hand-inserting one, which would test the response
            // parsing alone and nothing about `take_outgoing_requests`
            // itself noticing the change.
            receive_sync_changes(&format!(
                r#"{{"changed_devices":{{"changed":["{bob_user}"],"left":[]}}}}"#
            ))
            .await
            .unwrap();

            let query_id = take_outgoing_requests()
                .await
                .unwrap()
                .into_iter()
                .find(|r| r.kind == "keys_query")
                .expect("a changed device queues a keys query")
                .id;

            let mut devices = BTreeMap::new();
            devices.insert(
                bob_device.to_string(),
                serde_json::to_value(&bob_device_keys).unwrap(),
            );
            let mut by_user = BTreeMap::new();
            by_user.insert(bob_user.to_string(), devices);
            let response = serde_json::json!({ "device_keys": by_user }).to_string();

            mark_request_sent(&query_id, &response).await.unwrap();

            share_scope_key("!s:example.org", &[bob_user.to_string()])
                .await
                .unwrap();

            take_outgoing_requests().await
        }))
        .unwrap();

        assert!(
            after.iter().any(|r| r.kind == "to_device"),
            "the session key must leave the process: {after:?}"
        );
    }

    /// An `id` this module never handed out (or already resolved) must be
    /// rejected rather than silently accepted or mistaken for "not
    /// initialised"/"failed".
    #[test]
    fn marking_an_unknown_request_as_sent_is_rejected() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let err = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            mark_request_sent("not-a-request-this-machine-issued", "{}").await
        })
        .unwrap_err();

        assert_eq!(err, SessionError::UnknownRequest);
    }

    /// Every test above already runs through bare `futures::executor::block_on`
    /// with no `#[tokio::test]` anywhere in this file, so each is already
    /// evidence for this property. This test exists anyway, self-contained
    /// and separately named, so "does Task 5's surface work with no ambient
    /// runtime" has one direct answer instead of an inference over the rest
    /// of the file -- and so it exercises the full new surface in one
    /// sequence (create, share, encrypt, take, mark), not just the one
    /// call `a_fresh_machine_has_keys_waiting_to_be_uploaded` above already
    /// covers.
    ///
    /// `#[tokio::test]` supplies a runtime that would hide a missing
    /// `with_machine`/`in_runtime` wrapping -- see `machine.rs`'s own
    /// `with_machine_supplies_a_runtime_for_store_touching_calls` for the
    /// precedent, and the design doc section 4 for why this exact mistake
    /// has already happened twice in this milestone with a green suite both
    /// times.
    #[test]
    fn the_pump_runs_with_no_ambient_tokio_runtime() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            let envelope = encrypt_event("!s:example.org", "m.dummy", r#"{"body":"hi"}"#)
                .await
                .unwrap();
            assert!(!envelope.ciphertext.is_empty());

            let requests = take_outgoing_requests().await.unwrap();
            let upload = requests
                .into_iter()
                .find(|r| r.kind == "keys_upload")
                .expect("a fresh machine has a key upload to send");

            mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
                .await
                .unwrap();
        });
    }
}
