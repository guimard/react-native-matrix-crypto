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

// Already a direct dependency of this crate (see the Cargo.toml comment on
// the `matrix-sdk-common` entry, written for reaching `ruma` the same way):
// this is the type `MegolmError::MissingRoomKey`'s own `Option<_>` carries,
// reached through the crate that defines it rather than through
// `matrix-sdk-crypto`, which does not re-export it.
use matrix_sdk_common::deserialized_responses::WithheldCode;
// Response types for the six kinds `OlmMachine::outgoing_requests` and
// `share_room_key` can ever hand out (matched exhaustively against
// `AnyOutgoingRequest` below, with no wildcard -- see `describe_outgoing`).
// Each is renamed on import: their upstream names collide with either one
// another (every endpoint module calls its own type `Response`) or with this
// module's own public `OutgoingRequest`.
use matrix_sdk_common::ruma::api::client::keys::claim_keys::v3::{
    Request as KeysClaimRequest, Response as KeysClaimResponse,
};
use matrix_sdk_common::ruma::api::client::keys::get_keys::v3::Response as KeysQueryResponse;
use matrix_sdk_common::ruma::api::client::keys::upload_keys::v3::Response as KeysUploadResponse;
use matrix_sdk_common::ruma::api::client::keys::upload_signatures::v3::Response as SignatureUploadResponse;
use matrix_sdk_common::ruma::api::client::message::send_message_event::v3::Response as RoomMessageResponse;
use matrix_sdk_common::ruma::api::client::sync::sync_events::DeviceLists;
use matrix_sdk_common::ruma::api::client::to_device::send_event_to_device::v3::Response as ToDeviceHttpResponse;
use matrix_sdk_common::ruma::api::IncomingResponse;
use matrix_sdk_common::ruma::events::{
    AnyMessageLikeEventContent, AnyToDeviceEvent, MessageLikeEventContent,
};
// `exports::http`, not a direct `http` dependency of this crate: it is the
// exact `http` version `ruma`'s own `IncomingResponse::try_from_http_response`
// requires, reached through `ruma`'s own re-export rather than a second,
// independently-versioned copy this crate would have to keep in step by hand.
use matrix_sdk_common::ruma::exports::http;
use matrix_sdk_common::ruma::serde::Raw;
use matrix_sdk_common::ruma::{
    OneTimeKeyAlgorithm, OwnedRoomId, OwnedTransactionId, OwnedUserId, TransactionId, UInt,
};
use matrix_sdk_crypto::types::events::room::encrypted::EncryptedEvent;
use matrix_sdk_crypto::types::requests::{AnyOutgoingRequest, ToDeviceRequest};
// Reached through `matrix_sdk_crypto`'s own `pub use vodozemac;` re-export
// rather than a direct `vodozemac` dependency this crate would then have to
// keep version-matched by hand -- the same reasoning `machine.rs` documents
// for reaching `ruma` through `matrix-sdk-common` rather than depending on
// it directly.
use matrix_sdk_crypto::vodozemac::megolm::DecryptionError;
use matrix_sdk_crypto::{
    DecryptionSettings, EncryptionSettings, EncryptionSyncChanges, MegolmError, OlmMachine,
    TrustRequirement,
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

/// Errors from operating on the crypto machine: ingesting sync changes,
/// encrypting, decrypting, and pumping outbound requests.
///
/// Carries no payload content, ciphertext, device id or user id -- see spec
/// section 7: upstream `Display` output can embed event content, so no
/// upstream error is ever forwarded, only mapped to one of these fixed
/// shapes. `MalformedPayload` and `Failed` are kept distinct because they
/// call for different product responses: nonsense the product sent itself
/// is not the same problem as a crypto operation failing on well-formed
/// input.
///
/// The five decryption kinds below (`MissingKey` through `Undecryptable`)
/// exist for the same reason, one level more specific: decryption failure
/// is normal Matrix operation, not a single exceptional condition, and
/// collapsing all five into `Failed` would tell a product nothing about
/// which of "retry", "request the key again", "warn about an untrusted
/// device" or "show a placeholder" applies. See [`classify_megolm_error`]
/// for exactly which upstream condition maps to which.
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
    /// [`decrypt_event`] either found no record at all of the group
    /// session that encrypted this event, or found the session but could
    /// not use it because its ratchet has already advanced past this
    /// message's index (the ordinary "you joined the room after this was
    /// sent" case). Worth a retry either way: the key may simply not have
    /// arrived yet, or an earlier ratchet state may still arrive, e.g. a
    /// later sync or a key request may bring in what is missing.
    #[error("no key is available to decrypt this event")]
    MissingKey,
    /// [`decrypt_event`] found a record that the group session was
    /// explicitly withheld, or never shared with this device, for a
    /// *circumstantial* reason: `m.unavailable` (the sender did not have
    /// the key yet) or `m.no_olm` (the sender could not reach this
    /// device), or any withheld code this crate does not specifically
    /// classify. Distinct from `MissingKey`: this is a known fact about
    /// the session rather than the mere absence of one. Worth requesting
    /// again -- the circumstance that produced it can change on a later
    /// attempt.
    ///
    /// The two withheld codes that are a deliberate *policy* refusal
    /// instead of a circumstance -- `m.blacklisted`, `m.unauthorised` --
    /// are [`SessionRefused`](Self::SessionRefused), not this kind; see
    /// its own doc comment for why retrying those is never productive.
    /// This kind does not distinguish which of its own remaining reasons
    /// applies -- the reason itself is sender-supplied wire content this
    /// crate deliberately does not carry into any error, per the
    /// no-payload-content rule.
    #[error("the session that encrypted this event was not shared with this device")]
    UnsharedSession,
    /// [`decrypt_event`] found a record that the group session's sender
    /// deliberately refused to share it with this device: `m.blacklisted`
    /// (the sender has blocked this device) or `m.unauthorised` (this
    /// device was not entitled to the key -- for example, it asked for a
    /// key to a message sent before it joined the room). Split out from
    /// [`UnsharedSession`](Self::UnsharedSession) rather than folded into
    /// it, and rather than adding a field to either: G26 in the
    /// milestone's own ledger ruled that a product treating every
    /// `UnsharedSession` occurrence as retriable would retry one of these
    /// two forever, for no possible gain, at real cost in battery and
    /// network, since both are the sender's own decision and nothing this
    /// device does changes it.
    ///
    /// Fieldless like every other kind here, and not by discipline but by
    /// construction: the split happens by matching upstream's `WithheldCode`
    /// *variant* to choose between two already-existing, already-fixed
    /// kinds, never by reading it into a field, so which of the two codes
    /// produced this is still sender-supplied wire content this crate does
    /// not carry across the boundary. This kind never distinguishes which
    /// of the two applies.
    #[error("the session that encrypted this event was refused by its sender's policy")]
    SessionRefused,
    /// [`decrypt_event`] could not trust the device that supposedly
    /// encrypted this event, for either of two different reasons this
    /// kind does not currently distinguish: its identity does not match
    /// what this machine has on record (unfixable -- nothing the user
    /// does changes a room key whose own embedded identity disagrees with
    /// itself), or it does not meet the trust level this call requires
    /// (fixable by the user verifying the device). The second reason is
    /// unreachable in M2, which always decrypts with the most permissive
    /// trust requirement -- see `decryption_settings()` -- so only the
    /// unfixable case is reachable today. M3, which makes the trust
    /// requirement configurable, is expected to give these two reasons
    /// separate kinds; until then, do not assume this kind is always
    /// fixable by verification.
    #[error("the device that encrypted this event is not trusted")]
    UnknownDevice,
    /// [`decrypt_event`] ran the cryptographic operation and it did not
    /// produce a usable plaintext: a corrupted or tampered ciphertext, a
    /// malformed event, or a decrypted payload that is not a well-formed
    /// Matrix event. Not worth retrying: the same input fails the same way
    /// every time.
    #[error("this event could not be decrypted")]
    Undecryptable,
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
            | MachineError::Store { .. }
            | MachineError::MismatchedAccount => SessionError::Failed,
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
///
/// No `#[derive(Debug)]`: `ciphertext` is, depending on which function
/// produced this, either the wire ciphertext or the plaintext this call
/// just recovered, and `sender` is a user id -- both are exactly what the
/// global "no ciphertext, no plaintext, no user id in any Debug output"
/// rule names. `Debug` is hand-written below instead, redacting both, the
/// same pattern `machine.rs`'s `MachineConfig` already uses and for the
/// same reason: a future `{:?}`, a panic message that formats this struct,
/// or a `#[derive(Debug)]` on something that embeds it would otherwise
/// print either verbatim.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    pub scope: String,
    /// Open tag, e.g. the wire algorithm id upstream attached to the
    /// encrypted content. From [`encrypt_event`], read back from the
    /// content that call itself just produced, so a future algorithm
    /// upstream adds needs no change here.
    ///
    /// From [`decrypt_event`], read from the *input* event's own content
    /// before decryption runs -- unauthenticated, the same caveat as
    /// `sender` below: this is what the event claims about itself on the
    /// wire, not a value independently confirmed by upstream's own
    /// `EncryptionInfo::algorithm_info`. A mismatch between the two is
    /// exactly what makes `decrypt_room_event` fail in the first place,
    /// so they necessarily agree whenever this field is populated by a
    /// successful decrypt -- but the *source* of this value is still the
    /// untrusted side of that check, not the authenticated one.
    pub algorithm: String,
    pub event_type: String,
    /// The wire ciphertext from [`encrypt_event`], or the plaintext
    /// [`decrypt_event`] recovered -- see this struct's own doc comment
    /// above for why `Debug` is hand-written to redact this regardless of
    /// which one it is. Do not assume the field name on the decrypt path:
    /// code that logs, persists, or otherwise handles this value needs
    /// the same care any other plaintext gets.
    pub ciphertext: Vec<u8>,
    /// `@user:server`, verbatim. From [`encrypt_event`], the current
    /// machine's own user id, since that call is always this device's own
    /// outbound encryption -- authenticated by definition, it is this
    /// process's own identity.
    ///
    /// From [`decrypt_event`], this is the *outer, server-supplied*
    /// sender of the `m.room.encrypted` event, copied verbatim into the
    /// reconstructed decrypted event by upstream itself
    /// (`matrix-sdk-crypto-0.18.0/src/olm/group_sessions/inbound.rs`) --
    /// the Megolm plaintext carries no independent sender claim of its
    /// own to cross-check it against. This is not a corner this function
    /// cut: upstream's own `DecryptedRoomEvent::encryption_info` carries
    /// the identical value in its own `sender` field (confirmed by
    /// reading `OlmMachine::get_encryption_info`, which literally echoes
    /// back the `&UserId` it was called with -- `sender:
    /// sender.to_owned()`), so there is no more-authenticated alternative
    /// available to substitute here. What *does* say how much to trust
    /// this value is `EncryptionInfo::verification_state`, which this
    /// function does not read or expose -- deliberately deferred, not
    /// overlooked: it needs a real design decision about what shape to
    /// surface on a public struct, not a field bolted on in a fix round,
    /// and M2's `TrustRequirement::Untrusted` decrypts regardless of it
    /// either way (see `decryption_settings()`). Treat this field as
    /// unauthenticated transport metadata on the decrypt path, not as a
    /// cryptographically established sender, until a later milestone
    /// surfaces verification state.
    pub sender: String,
}

impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, not field-accessed: a field added later must fail
        // this to compile rather than be silently printed unredacted, the
        // same discipline `MachineConfig::fmt` documents for itself.
        let Envelope {
            scope,
            algorithm,
            event_type,
            ciphertext,
            sender: _,
        } = self;
        f.debug_struct("Envelope")
            .field("scope", scope)
            .field("algorithm", algorithm)
            .field("event_type", event_type)
            .field("ciphertext_len", &ciphertext.len())
            .field("sender", &"[redacted]")
            .finish()
    }
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

/// The fields [`decrypt_event`] reads out of a successfully decrypted
/// event's raw JSON. Private: this shape is this function's own
/// implementation detail, never part of this crate's public declarations.
/// `content` is captured as a `RawValue`, not a `serde_json::Value`, so it
/// survives into the returned [`Envelope`] exactly as it came off the wire
/// rather than round-tripping through a value tree that could reorder its
/// keys.
#[derive(Deserialize)]
struct DecryptedEventFields {
    #[serde(rename = "type")]
    event_type: String,
    sender: String,
    content: Box<serde_json::value::RawValue>,
}

/// Maps an upstream Megolm decryption failure onto one of [`SessionError`]'s
/// five dedicated kinds, by matching on the variant -- never on its
/// rendered text, which can embed a session id or key material (e.g.
/// `MismatchedIdentityKeys`'s own `Display` impl serialises the keys
/// involved). Exhaustive, no wildcard, for the same reason
/// `From<MachineError>` above is: a future `MegolmError` variant must fail
/// this build instead of silently landing on one of these five.
fn classify_megolm_error(error: MegolmError) -> SessionError {
    match error {
        // No record of the room key that encrypted this event. `None` --
        // no explanation offered -- is the "just don't have it yet" case a
        // product can retry or wait out.
        MegolmError::MissingRoomKey(None) => SessionError::MissingKey,

        // `Some(code)` means the sending device explicitly told us, via an
        // `m.room_key.withheld` to-device message, that this session was
        // withheld or never shared -- a distinct fact worth a distinct
        // kind, split further by `code` itself (G26 in the milestone's own
        // ledger, ruled but never dispatched until now): `m.blacklisted`
        // and `m.unauthorised` are the sender's own deliberate policy
        // decision to refuse this device, which no retry from this device
        // can ever change, so they get `SessionRefused`, never
        // `UnsharedSession`. Every other code, named here or not
        // (`m.unavailable`, `m.no_olm`, and anything this crate does not
        // specifically classify) is circumstantial, so it stays
        // `UnsharedSession`.
        //
        // Matching on `code` still never *reads* it into an error: this
        // only chooses between two kinds that already exist regardless of
        // which specific code arrived, and neither carries a field for it.
        // The sender-supplied wire content a withheld code is has nowhere
        // to flow into -- structurally, per the no-payload-content rule,
        // not by the discipline of an arm that declines to look.
        MegolmError::MissingRoomKey(Some(
            WithheldCode::Blacklisted | WithheldCode::Unauthorised,
        )) => SessionError::SessionRefused,
        MegolmError::MissingRoomKey(Some(_)) => SessionError::UnsharedSession,

        // The session is present -- this is not `MissingRoomKey` -- but its
        // ratchet has already advanced past this message's index. The
        // ordinary shape of that is joining a room after this message was
        // sent, or a key shared from a later index than this message needs:
        // the same input succeeds the moment an earlier ratchet state
        // arrives (e.g. from a device that still holds it, via a key
        // request), so this is exactly the "not yet, ask again" case
        // `MissingKey` exists for, not a permanent failure. Fix for a
        // review finding: this used to fall through to the general
        // `Decryption(_)` arm below and land on `Undecryptable`, which
        // upstream's own behaviour contradicts -- the only place upstream
        // acts on this classification, it pairs this exact case with
        // `MissingRoomKey` and issues a key re-request for both
        // (`matrix-sdk-crypto-0.18.0/src/machine/mod.rs`'s
        // `MegolmError::MissingRoomKey(_) | MegolmError::Decryption(DecryptionError::UnknownMessageIndex(_, _))`
        // arm). Carved out here, ahead of the general `Decryption(_)` arm,
        // so the remaining match keeps working: a `match` picks the first
        // pattern that fits, so this specific pattern intercepts exactly
        // this one case and leaves every other `Decryption` variant to
        // fall through unchanged.
        MegolmError::Decryption(DecryptionError::UnknownMessageIndex(_, _)) => {
            SessionError::MissingKey
        }

        // The device that sent this session's room key does not match the
        // identity keys recorded in the room key's own to-device message --
        // a spoofing-shaped condition about *who* encrypted this, not
        // about the ciphertext itself. Unfixable: nothing the user does,
        // including verifying the device, changes the fact that the room
        // key's own embedded identity disagrees with itself.
        MegolmError::MismatchedIdentityKeys(_) => SessionError::UnknownDevice,

        // `decryption_settings()` always passes `TrustRequirement::Untrusted`
        // in M2 (see its own doc comment), under which upstream's
        // `check_sender_trust_requirement` unconditionally returns `Ok`
        // (`matrix-sdk-crypto-0.18.0/src/machine/mod.rs`'s own match arm
        // `TrustRequirement::Untrusted => true`) -- so this arm is
        // unreachable today, unlike the arm above it. Matched anyway, with
        // no wildcard, for when M3 tightens that requirement and makes it
        // reachable.
        //
        // Grouped with `MismatchedIdentityKeys` above under the same kind
        // for now, but the two are not the same shape of failure: this one
        // is a *policy* gap ("this device is fine, but does not clear the
        // trust bar this call requires"), fixed by the user verifying the
        // device -- exactly the opposite of the arm above, which no
        // verification can fix. `UnknownDevice`'s own doc comment is
        // written to be true of both rather than implying either fixes the
        // other. Revisit this merge in M3: once this arm is reachable, a
        // product needs to tell "verify this person to read this" apart
        // from "this event's provenance is broken, never trust it", and
        // one shared kind cannot say which.
        MegolmError::SenderIdentityNotTrusted(_) => SessionError::UnknownDevice,

        // The event or its decrypted content was malformed, or the
        // ciphertext itself could not be decoded or decrypted -- every
        // remaining case where this crate ran the operation and did not
        // produce a usable plaintext, as opposed to knowing exactly which
        // key is absent. `Decryption`'s own `UnknownMessageIndex` case is
        // carved out above, ahead of this arm; what is left of it here --
        // `Signature`, `InvalidMAC`, `InvalidMACLength`, `InvalidPadding`
        // -- is a genuine tampering or corruption failure with no "just
        // wait" exception.
        MegolmError::EventError(_)
        | MegolmError::JsonError(_)
        | MegolmError::Decode(_)
        | MegolmError::Decryption(_) => SessionError::Undecryptable,

        // A storage failure, not a fact about this event's decryptability --
        // the same bucket `machine.rs`'s own `Store` variant already falls
        // into via `From<MachineError>` above.
        MegolmError::Store(_) => SessionError::Failed,
    }
}

/// Decrypts an event received for `scope`, returning the [`Envelope`]
/// carrying the plaintext recovered from it.
///
/// `raw_json` is the `m.room.encrypted` event as received, verbatim.
/// Decryption failure is normal Matrix operation -- a key that has not
/// arrived yet, a session withheld, a device this machine does not
/// recognise -- not an exceptional condition, which is why this can return
/// four distinct [`SessionError`] kinds instead of one opaque failure; see
/// [`classify_megolm_error`].
pub async fn decrypt_event(scope: &str, raw_json: &str) -> Result<Envelope, SessionError> {
    let room_id = parse_scope(scope)?;
    let raw = Raw::<EncryptedEvent>::from_json_string(raw_json.to_owned())
        .map_err(|_| SessionError::MalformedPayload)?;

    // Read back from the event's own content, not hard-coded -- the same
    // reasoning `encrypt_event` documents for its own `algorithm` field
    // above. Falls back to empty, like that field, rather than failing the
    // whole call over a display tag: an absent or non-string `algorithm`
    // here does not stop `decrypt_room_event` below succeeding or failing
    // on its own terms.
    let algorithm = raw
        .get_field::<serde_json::Value>("content")
        .ok()
        .flatten()
        .and_then(|content| content.get("algorithm")?.as_str().map(str::to_owned))
        .unwrap_or_default();

    let scope = scope.to_owned();

    // `with_machine` already runs inside the library's runtime and holds
    // the machine lock for this closure's duration; see its own doc
    // comment in `machine.rs`.
    let result = with_machine(move |machine| {
        Box::pin(async move {
            machine
                .decrypt_room_event(&raw, &room_id, &decryption_settings())
                .await
        })
    })
    .await?;

    let decrypted = result.map_err(classify_megolm_error)?;

    // Pulled out with a small `Deserialize` helper, not the full
    // `AnyTimelineEvent` enum: this crate needs exactly these three fields
    // and nothing about which of Matrix's many event types this is. Every
    // field required, not defaulted: a successfully decrypted event
    // missing any of them is not a display-tag gap the way a missing
    // `algorithm` above is -- it means the Megolm layer authenticated a
    // plaintext that is not a well-formed Matrix event, which this
    // function reports as `Undecryptable` rather than handing the product
    // a half-populated `Envelope`.
    let DecryptedEventFields {
        event_type,
        sender,
        content,
    } = decrypted
        .event
        .deserialize_as_unchecked::<DecryptedEventFields>()
        .map_err(|_upstream| SessionError::Undecryptable)?;

    Ok(Envelope {
        scope,
        algorithm,
        event_type,
        ciphertext: content.get().as_bytes().to_vec(),
        sender,
    })
}

/// Ensures `scope` has a group session and shares it with the given users'
/// known devices, and makes those users' device lists tracked so they can
/// become known in the first place.
///
/// The tracking is not a convenience. Upstream only learns that a user's
/// devices exist by issuing a `/keys/query` for them, and it only issues one
/// for a user it is *tracking*: `mark_tracked_users_as_changed`
/// (matrix-sdk-crypto-0.18.0/src/store/mod.rs:291) opens with
/// `if tracked_users.contains(user_id)` and silently skips everyone else,
/// and a sync's `changed_devices` list routes nowhere but there
/// (`receive_sync_changes` -> `receive_device_changes`). Without this call,
/// no function on this crate's shipped surface could get a `/keys/query`
/// issued for a user this device has not already encrypted to, and
/// [`take_outgoing_requests`] would keep handing out upstream's own-user
/// fallback query instead -- a silent failure whose only symptom is
/// encrypting to nobody.
///
/// It is implicit rather than a separate `track_users` call because "share
/// this scope's key with these users" already means "these users' devices
/// matter to me". A separate call would add public surface and add a way to
/// hold the API wrong: forgetting it fails silently, exactly like the
/// mistake design doc section 3bis is named for.
///
/// Repeated calls are cheap: upstream's `update_tracked_users` flags only
/// users it has not seen before (`if tracked_users.insert(...)`), so calling
/// this every time a product sends is not a per-send key query.
///
/// **A first call for a never-seen user necessarily delivers nothing.** It
/// has no device of theirs to encrypt to yet; what it does is cause the
/// `/keys/query` that makes a *later* call able to. The full loop is
/// therefore share, pump, share, pump, share -- see the ordering note below
/// and `tests/two_parties.rs`, which walks it.
///
/// This is the call that reaches `tokio::task::spawn` through
/// `matrix-sdk-common` during group key sharing, and the reason Task 1's
/// runtime exists -- see the design doc section 4.
///
/// Two upstream calls, not one, per the design doc's section 3ter.
/// `share_room_key` alone is not enough: encrypting a room key *to* a
/// device requires an Olm session with it, and an Olm session cannot exist
/// until this device has claimed one of the other device's one-time keys
/// (a `/keys/claim` round trip). Skip that and `share_room_key` still
/// "succeeds" -- but every to-device request it produces is an
/// `m.room_key.withheld` notice with code `m.no_olm`, a message whose
/// content is "I could not send you the key", not the key itself. That
/// failure is silent and looks exactly like success from inside this
/// process, which is exactly the class of mistake section 3bis's own
/// discarded-requests story is about, one layer deeper.
///
/// So `get_missing_sessions` is called first and, if it reports a missing
/// session, queues the `/keys/claim` request [`take_outgoing_requests`]
/// must hand out before a *subsequent* `share_scope_key` call can actually
/// deliver the key to that device -- this call still attempts
/// `share_room_key` regardless, so any device that already has a session
/// (or belongs to a different, already-established user) is not held back
/// waiting on one that does not.
///
/// The to-device requests `share_room_key` returns carry the session key
/// itself, on its way to the recipients' devices. They are queued here for
/// [`take_outgoing_requests`] to hand out, never discarded -- discarding
/// them is the mistake the design doc's section 3bis exists to prevent: the
/// group session would exist locally, `encrypt_event` would happily
/// produce ciphertext, and no other device would ever be able to read it.
pub async fn share_scope_key(scope: &str, users: &[String]) -> Result<(), SessionError> {
    let room_id = parse_scope(scope)?;
    let user_ids: Vec<OwnedUserId> = users
        .iter()
        .map(|user| parse_user(user))
        .collect::<Result<_, _>>()?;

    let (tracked, missing, shared) = with_machine(move |machine| {
        Box::pin(async move {
            let missing = machine
                .get_missing_sessions(user_ids.iter().map(AsRef::as_ref))
                .await;
            let shared = machine
                .share_room_key(
                    &room_id,
                    user_ids.iter().map(AsRef::as_ref),
                    // M2: verification lands in M3; revisit this with it.
                    //
                    // `EncryptionSettings::default()` carries
                    // `CollectStrategy::AllDevices`, which upstream marks "not
                    // recommended, per the guidance of MSC4153" because it
                    // shares with every unblacklisted device rather than only
                    // devices signed by their owner. It is named here rather
                    // than inherited silently: it is the outbound mirror of
                    // this milestone's `TrustRequirement::Untrusted`, and it is
                    // forced by the same absence. The recommended
                    // identity-based strategy gives room keys to nobody whose
                    // identity is unpublished, and no identity is published
                    // until cross-signing exists, which is M3's work.
                    EncryptionSettings::default(),
                )
                .await;
            // Tracked *after* `share_room_key`, not before, and the
            // order is load-bearing rather than incidental. Upstream's
            // `get_user_devices_for_encryption`
            // (identities/manager.rs:924) waits up to a hard-coded
            // `KEYS_QUERY_WAIT_TIME` of 5 seconds for an outstanding
            // `/keys/query` to complete, for any user it is asked to
            // encrypt to that has no known device and is flagged for a
            // query. Flagging first would arm exactly that wait, on this
            // call, for a request the product has not been handed yet --
            // `take_outgoing_requests` is a *separate* call the caller
            // makes after this one returns, so the query cannot possibly
            // complete while this wait runs. Worse, `with_machine` holds
            // the machine lock for this closure's whole duration, so no
            // concurrent library call could satisfy the wait either: it
            // would block every other caller for the full five seconds
            // before timing out and proceeding to do exactly what it does
            // now. Measured on this crate's own two-party test: 7.47s
            // flagging first, 2.47s flagging last, for an identical
            // outcome. Flagging last arms nothing -- the flag is set for
            // the *pump*, which runs after this returns, which is the only
            // thing that can act on it.
            let tracked = machine
                .update_tracked_users(user_ids.iter().map(AsRef::as_ref))
                .await;
            (tracked, missing, shared)
        })
    })
    .await?;

    // Checked, and queued, before `shared`'s own result is even inspected:
    // this is progress worth keeping regardless of whether the share
    // attempt below succeeds, since it is the only way a *later*
    // `share_scope_key` call can do better.
    //
    // Both queues below are written under one `STATE.lock()` acquisition,
    // not two: `pending_claim` and `queued_to_device` are two of the three
    // fields `RequestState`'s own doc comment says share a lock precisely
    // so a caller can never observe one updated without the others (N1 in
    // the milestone's own ledger -- parked, not fixed, until now). Neither
    // write here is preceded or followed by an `.await`: `missing` and
    // `shared` are already-resolved `Result`s by this point, taken from the
    // tuple `with_machine` handed back above, not futures still to be
    // polled -- so holding the guard across both is exactly as cheap as the
    // two separate acquisitions it replaces, and cannot deadlock the
    // executor the way holding a lock across an `.await` already has once
    // in this crate (see `machine.rs`).
    let mut state = STATE.lock().expect("request registry poisoned");

    if let Some(claim) = missing.map_err(|_upstream| SessionError::Failed)? {
        state.pending_claim = Some(claim);
    }

    let to_device_requests = shared.map_err(|_upstream| SessionError::Failed)?;

    if !to_device_requests.is_empty() {
        // Keyed by `txn_id`, not appended to a growing `Vec`:
        // `share_room_key` returns the *entire* persisted
        // `to_share_with_set` on every call
        // (matrix-sdk-crypto-0.18.0/src/session_manager/group_sessions/mod.rs:785,
        // upstream's own comment: "The to-device requests get added to the
        // outbound group session, this way we're making sure that they are
        // persisted and scoped to the session"), so a second
        // `share_scope_key` call before the first is marked sent would
        // otherwise queue an identical request under a second `Vec` slot --
        // the same message sent to the product twice, and the second
        // `mark_request_sent` failing with `UnknownRequest` once the first
        // consumes its id. Keying by `txn_id` makes the second call
        // idempotent instead: same key, equivalent value, one entry.
        for request in to_device_requests {
            state
                .queued_to_device
                .insert(request.txn_id.to_string(), request);
        }
    }

    // Dropped explicitly, rather than left to fall out of scope at the
    // function's end: nothing below needs it, and the whole point of this
    // block is to hold it no longer than the two writes actually require.
    drop(state);

    // Reported last, after both queues above have kept whatever progress
    // this call made: a tracking failure is a store failure, and a store
    // this broken will have failed the other two as well -- but it is not
    // swallowed, because the users this call named would then never be
    // queried and encryption to them would silently reach nobody.
    tracked.map_err(|_upstream| SessionError::Failed)?;

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

    /// Whether a fresh request of this kind, just handed out by
    /// [`take_outgoing_requests`], makes any *previously* handed-out,
    /// still-unresolved id of the same kind permanently unresolvable.
    ///
    /// True for the three kinds where upstream re-derives "is this still
    /// needed" from scratch on every call, minting a new, uncorrelated id
    /// each time and forgetting whatever id it handed out last:
    /// `keys_for_upload` recomputes from the account's current state
    /// (`machine/mod.rs:825`); `users_for_key_query`'s own comment says
    /// "Forget about any previous key queries in flight"
    /// (`identities/manager.rs:832`); and `get_missing_sessions` documents
    /// the identical single-slot behaviour on its own
    /// `current_key_claim_request` ("there should only be one such request
    /// active at a time", `session_manager/sessions.rs`). A stale id of one
    /// of these three kinds names nothing upstream is tracking any more, so
    /// it is evicted from [`RequestState::pending`] the moment a fresh one
    /// of the same kind is handed out (see `take_outgoing_requests`) rather
    /// than accumulating for the life of the process.
    ///
    /// False for `to_device` (each entry is a distinct, independently
    /// resolvable message to a distinct recipient -- see
    /// `queued_to_device`'s own `txn_id`-keyed de-duplication instead) and
    /// for `signature_upload`/`room_message` (independent, per-flow
    /// verification requests upstream does not describe as superseding one
    /// another; unreachable in M2, since verification is deferred to M3,
    /// but not given a blanket eviction rule that would be wrong once it
    /// is reachable).
    fn superseded_by_a_fresh_request(self) -> bool {
        matches!(
            self,
            PendingKind::KeysUpload | PendingKind::KeysQuery | PendingKind::KeysClaim
        )
    }
}

/// Process-wide outbound-request bookkeeping this module owns.
///
/// Three distinct jobs share one lock rather than three, so a caller can
/// never observe one updated without the others:
///
/// * `queued_to_device` -- to-device requests [`share_scope_key`] obtained
///   from `share_room_key`, keyed by `txn_id`, that have not yet been
///   handed out by [`take_outgoing_requests`]. Drained (not cloned) when
///   they are; keyed rather than appended to a `Vec` so a second
///   `share_scope_key` call before the first is marked sent cannot queue
///   the same persisted request twice (see `share_scope_key`'s own
///   comment).
/// * `pending_claim` -- at most one outstanding `/keys/claim` request
///   [`share_scope_key`] obtained from `get_missing_sessions`, not yet
///   handed out. A single slot, not a queue, mirroring upstream's own
///   "only one such request active at a time" model for the same request
///   (see `PendingKind::superseded_by_a_fresh_request`'s doc comment): a
///   second `share_scope_key` call before the first claim is taken
///   overwrites it rather than accumulating a second one describing
///   overlapping or stale missing-session state.
/// * `pending` -- every request id this module has ever handed out via
///   [`take_outgoing_requests`] that has not yet been resolved by
///   [`mark_request_sent`], with the [`PendingKind`] needed to parse its
///   response. Removed on successful resolution only (a failed
///   `mark_request_sent` leaves the entry in place, so the same id can be
///   retried with corrected input); also evicted early for the three kinds
///   `PendingKind::superseded_by_a_fresh_request` names, since a stale id
///   of one of those can never be resolved regardless.
///
/// A `std::sync::Mutex`, not `tokio::sync::Mutex`: every critical section
/// below is a plain synchronous map/vec operation with no `.await` inside
/// it.
struct RequestState {
    queued_to_device: BTreeMap<String, std::sync::Arc<ToDeviceRequest>>,
    pending_claim: Option<(OwnedTransactionId, KeysClaimRequest)>,
    pending: BTreeMap<String, PendingKind>,
}

static STATE: StdMutex<RequestState> = StdMutex::new(RequestState {
    queued_to_device: BTreeMap::new(),
    pending_claim: None,
    pending: BTreeMap::new(),
});

#[cfg(test)]
fn reset_request_state_for_test() {
    let mut state = STATE.lock().expect("request registry poisoned");
    state.queued_to_device.clear();
    state.pending_claim = None;
    state.pending.clear();
}

/// Serialises `value`, mapping a failure to [`SessionError::Failed`] rather
/// than swallowing it into an empty or default JSON value. `serde_json`'s
/// own `json!` macro cannot fail this way (it panics internally instead, on
/// the rare types whose `Serialize` impl can fail at all), but the several
/// direct `serde_json::to_value`/`to_string` calls below are not routed
/// through it -- this is their one shared, fallible chokepoint, so none of
/// them is tempted to reach for `.unwrap_or_default()` and quietly hand out
/// a `body` that looks like a valid request but carries none of its data.
fn to_json<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, SessionError> {
    serde_json::to_value(value).map_err(|_| SessionError::Failed)
}

/// The wire body of a `/keys/claim` request: exactly `one_time_keys`, plus
/// `timeout` when upstream set one. Upstream's own `Request` marks
/// `timeout` `#[serde(skip_serializing_if = "Option::is_none")]` and
/// `one_time_keys` with no such attribute (verified against
/// `ruma-client-api-0.24.0/src/keys/claim_keys/v3.rs`); matched here rather
/// than serialising `r.timeout` as an explicit `null` the way an earlier
/// version of this function did for every optional field (finding 9: ruma
/// omits these, so this does too, now that the fix is this cheap alongside
/// the rest of this function's rewrite).
///
/// Shared between [`describe_outgoing`]'s `KeysClaim` arm (reachable only
/// if a future upstream version starts returning one from
/// `outgoing_requests()` itself -- see `PendingKind`'s own doc comment) and
/// [`take_outgoing_requests`]'s draining of `RequestState::pending_claim`,
/// the actual source of every `keys_claim` request this crate hands out
/// today.
fn describe_keys_claim(r: &KeysClaimRequest) -> Result<String, SessionError> {
    let mut body = serde_json::Map::new();
    body.insert("one_time_keys".to_string(), to_json(&r.one_time_keys)?);
    if let Some(ms) = r.timeout.map(|d| d.as_millis() as u64) {
        body.insert("timeout".to_string(), serde_json::json!(ms));
    }
    Ok(serde_json::Value::Object(body).to_string())
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
/// transport, per spec section 6).
///
/// `keys_upload`, `keys_query`, `keys_claim` and `signature_upload` are
/// exactly that endpoint's real wire body: field names, and which fields
/// are omitted when absent or empty, checked field-by-field against the
/// vendored `ruma-client-api-0.24.0` source for that endpoint (`keys_upload`:
/// `keys/upload_keys/v3.rs`; `keys_query`: `keys/get_keys/v3.rs`;
/// `keys_claim`: see [`describe_keys_claim`]; `signature_upload`:
/// `keys/upload_signatures/v3.rs`, whose `Request` marks `signed_keys`
/// `#[ruma_api(body)]` -- the wire body *is* that map at the top level, not
/// a wrapper around it, which an earlier version of this function got
/// wrong).
///
/// `to_device` and `room_message` are the two disclosed exceptions:
/// alongside their real body field(s), each also carries the values ruma
/// marks `#[ruma_api(path)]` for that endpoint (`event_type`/`txn_id` for
/// `to_device`; `room_id`/`event_type`/`txn_id` for `room_message`), which
/// the real endpoint's URL needs and the wire body itself omits. The
/// product has no other way to obtain them from this crate, and an extra
/// top-level JSON field is harmless to a server that ignores unknown keys.
/// `room_message` previously omitted `event_type` here, which left the
/// product no way to build that URL at all; that is fixed below.
fn describe_outgoing(request: &AnyOutgoingRequest) -> Result<(PendingKind, String), SessionError> {
    match request {
        AnyOutgoingRequest::KeysUpload(r) => {
            let mut body = serde_json::Map::new();
            if let Some(device_keys) = &r.device_keys {
                body.insert("device_keys".to_string(), to_json(device_keys)?);
            }
            if !r.one_time_keys.is_empty() {
                body.insert("one_time_keys".to_string(), to_json(&r.one_time_keys)?);
            }
            if !r.fallback_keys.is_empty() {
                body.insert("fallback_keys".to_string(), to_json(&r.fallback_keys)?);
            }
            Ok((
                PendingKind::KeysUpload,
                serde_json::Value::Object(body).to_string(),
            ))
        }
        AnyOutgoingRequest::KeysQuery(r) => {
            let mut body = serde_json::Map::new();
            // Always present, even when empty: ruma's own `Request` has no
            // `skip_serializing_if` on `device_keys`.
            body.insert("device_keys".to_string(), to_json(&r.device_keys)?);
            if let Some(ms) = r.timeout.map(|d| d.as_millis() as u64) {
                body.insert("timeout".to_string(), serde_json::json!(ms));
            }
            Ok((
                PendingKind::KeysQuery,
                serde_json::Value::Object(body).to_string(),
            ))
        }
        AnyOutgoingRequest::KeysClaim(r) => Ok((PendingKind::KeysClaim, describe_keys_claim(r)?)),
        AnyOutgoingRequest::ToDeviceRequest(r) => {
            // `ToDeviceRequest` is this crate's own type and derives
            // `Serialize` directly (unlike the `ruma` request types
            // above), so the whole struct serialises as-is -- see this
            // function's own doc comment for why `event_type`/`txn_id`
            // alongside `messages` is deliberate, not a wire-accuracy bug.
            let body = serde_json::to_string(r).map_err(|_| SessionError::Failed)?;
            Ok((PendingKind::ToDevice, body))
        }
        AnyOutgoingRequest::SignatureUpload(r) => Ok((
            PendingKind::SignatureUpload,
            to_json(&r.signed_keys)?.to_string(),
        )),
        AnyOutgoingRequest::RoomMessage(r) => {
            let mut body = serde_json::Map::new();
            body.insert("room_id".to_string(), to_json(&r.room_id)?);
            body.insert("event_type".to_string(), to_json(&r.content.event_type())?);
            body.insert("txn_id".to_string(), to_json(&r.txn_id)?);
            body.insert("content".to_string(), to_json(&*r.content)?);
            Ok((
                PendingKind::RoomMessage,
                serde_json::Value::Object(body).to_string(),
            ))
        }
    }
}

/// What the product must send to its homeserver, or feed to another
/// device -- see the design doc section 3bis. `body` is JSON this module
/// never interprets, sent as-is; `kind` is an open tag mirroring upstream's
/// own request kinds, not restricted to the ones listed in
/// [`describe_outgoing`]'s match today.
///
/// No `#[derive(Debug)]`: `body` is a to-device request's Olm-encrypted
/// payload, or a key-upload/key-claim body carrying device keys and
/// one-time keys, alongside user ids and device ids throughout -- exactly
/// what the global no-secret rule forbids from any `Debug` output or panic
/// message. `Debug` is hand-written below, printing `body`'s length rather
/// than its content, the same pattern `Envelope` and `MachineConfig` use.
#[derive(Clone, PartialEq, Eq)]
pub struct OutgoingRequest {
    /// Opaque; hand it back verbatim to [`mark_request_sent`].
    pub id: String,
    pub kind: String,
    pub body: String,
}

impl std::fmt::Debug for OutgoingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let OutgoingRequest { id, kind, body } = self;
        f.debug_struct("OutgoingRequest")
            .field("id", id)
            .field("kind", kind)
            .field("body_len", &body.len())
            .finish()
    }
}

/// Drains every outstanding outbound request: device/one-time key uploads
/// and key queries upstream still wants sent (`OlmMachine::outgoing_requests`),
/// any to-device requests [`share_scope_key`] queued, and any `/keys/claim`
/// request it queued (design doc section 3ter).
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

    // Every `(id, kind, body)` this call will hand out, built in full
    // before `state.pending` is touched: a serialisation failure partway
    // through must not leave `pending` holding an id this call never
    // actually returned to the caller, which nothing could ever resolve.
    let mut fresh: Vec<(String, PendingKind, String)> = Vec::with_capacity(upstream.len() + 2);

    for request in &upstream {
        let id = request.request_id().to_string();
        let (kind, body) = describe_outgoing(request.request())?;
        fresh.push((id, kind, body));
    }

    let mut state = STATE.lock().expect("request registry poisoned");

    // Read, not drained, until every serialisation below has already
    // succeeded: draining first (`mem::take`/`Option::take`) and only then
    // discovering a serialisation failure would strand those items
    // nowhere -- removed from the queue, but never reaching `pending` or
    // the caller either, the same "no state change on a failure partway
    // through" reasoning this function's own opening comment gives for
    // building `fresh` before touching `state` at all.
    //
    // The to-device `txn_id` doubles as the request id, per
    // `share_room_key`'s own doc comment (verified against
    // `matrix-sdk-crypto-0.18.0/src/session_manager/group_sessions/mod.rs`):
    // "the responses need to be passed back to the state machine ... using
    // the to-device txn_id as request_id" -- already true by construction
    // here, since `queued_to_device` is itself keyed by `txn_id`. Cloned,
    // not iterated by reference and drained afterwards in the same pass:
    // `Arc<ToDeviceRequest>` clones are cheap (a refcount bump, not the
    // request's own content), so this is not the deep copy it might look
    // like.
    let queued_to_device = state.queued_to_device.clone();
    for (id, to_device) in &queued_to_device {
        let body = serde_json::to_string(to_device.as_ref()).map_err(|_| SessionError::Failed)?;
        fresh.push((id.clone(), PendingKind::ToDevice, body));
    }

    if let Some((txn_id, claim_request)) = &state.pending_claim {
        let body = describe_keys_claim(claim_request)?;
        fresh.push((txn_id.to_string(), PendingKind::KeysClaim, body));
    }

    // Every fallible step above has now succeeded, so the two queues can
    // safely be drained for real.
    state.queued_to_device.clear();
    state.pending_claim = None;

    // Evict every existing `pending` entry whose kind this batch is about
    // to refresh, once per call rather than once per item -- per-item
    // eviction would be wrong for `keys_query`, which can legitimately
    // hand out *several* requests in the same batch when upstream splits a
    // large user list across multiple `/keys/query` calls
    // (`identities/manager.rs`'s own "convert the set of users into
    // multiple /keys/query requests" comment): evicting after inserting
    // the first of those siblings would discard the second. See
    // `PendingKind::superseded_by_a_fresh_request`'s own doc comment for
    // why eviction is correct here at all.
    let refreshed_kinds: Vec<PendingKind> = fresh
        .iter()
        .map(|(_, kind, _)| *kind)
        .filter(|kind| kind.superseded_by_a_fresh_request())
        .collect();
    if !refreshed_kinds.is_empty() {
        state
            .pending
            .retain(|_, kind| !refreshed_kinds.contains(kind));
    }

    let mut out = Vec::with_capacity(fresh.len());
    for (id, kind, body) in fresh {
        state.pending.insert(id.clone(), kind);
        out.push(OutgoingRequest {
            id,
            kind: kind.tag().to_string(),
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
///
/// The `pending` entry is looked up, not removed, before the mark is
/// attempted, and removed only once it succeeds: a caller who sent a
/// malformed `response_json` (or hit a transient upstream failure) can
/// retry the same `id` with corrected input instead of being told
/// `UnknownRequest` for a request that is, in fact, still exactly as
/// pending as before this call.
pub async fn mark_request_sent(id: &str, response_json: &str) -> Result<(), SessionError> {
    let kind = {
        let state = STATE.lock().expect("request registry poisoned");
        state.pending.get(id).copied()
    }
    .ok_or(SessionError::UnknownRequest)?;

    let transaction_id: OwnedTransactionId = <&TransactionId>::from(id).to_owned();
    let body = response_json.as_bytes().to_vec();

    let result =
        with_machine(move |machine| Box::pin(mark_sent(machine, kind, transaction_id, body)))
            .await?;

    if result.is_ok() {
        let mut state = STATE.lock().expect("request registry poisoned");
        state.pending.remove(id);
    }

    result
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

    /// Parses `body` as JSON and returns its top-level `event_type` string.
    /// Test-only: lets a test decode what an `OutgoingRequest.body` actually
    /// says, the way a real product's transport code would, rather than
    /// only checking `kind` -- see
    /// `sharing_a_scope_key_delivers_the_key_only_after_a_keys_claim_round_trip`,
    /// where checking `kind` alone is exactly the gap a review found.
    fn decoded_event_type(body: &str) -> String {
        serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|value| value.get("event_type")?.as_str().map(str::to_owned))
            .unwrap_or_else(|| "<no event_type in body>".to_string())
    }

    /// Sharing a scope key must actually deliver the session key, not
    /// merely produce *something* to send -- design doc section 3ter. A
    /// review found this test's original form asserted only
    /// `kind == "to_device"`, which passes on an `m.room_key.withheld`
    /// notice with code `m.no_olm`: a message whose content is "I could
    /// not send you the key", not the key itself. That is exactly what
    /// `share_room_key` produces for a device this machine has learned the
    /// *identity* keys for (via `/keys/query`) but has no Olm session with
    /// yet -- which is every device, the first time, since an Olm session
    /// requires its own `/keys/claim` round trip.
    ///
    /// This test reproduces both halves of that finding as one permanent
    /// regression: share *before* any session exists and assert the
    /// withheld notice (proving the failure mode is real, and that this
    /// test would have caught it as originally written), then complete the
    /// `/keys/claim` round trip through this module's own pump and share
    /// *again*, asserting the decoded `event_type` is `m.room.encrypted` --
    /// the session key, not a notice that one could not be sent. Both
    /// round trips (`/keys/query` then `/keys/claim`) are driven through
    /// `take_outgoing_requests`/`mark_request_sent` themselves, not
    /// short-circuited, matching the M2 exit criterion that the key travel
    /// through the pump rather than being handed over directly.
    #[test]
    fn sharing_a_scope_key_delivers_the_key_only_after_a_keys_claim_round_trip() {
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
        let (before_claim, after_claim) =
            futures::executor::block_on(crate::in_runtime(async move {
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
                let bob_one_time_key = bob_upload
                    .iter()
                    .find_map(|r| match r.request() {
                        AnyOutgoingRequest::KeysUpload(u) => u
                            .one_time_keys
                            .iter()
                            .next()
                            .map(|(id, key)| (id.clone(), key.clone())),
                        _ => None,
                    })
                    .expect("a fresh machine always has one-time keys to upload");

                // Step 1, `/keys/query`: tell the local machine bob's device
                // list changed, so its own pump reports a real keys-query
                // request to resolve -- rather than hand-inserting one, which
                // would test response parsing alone and nothing about
                // `take_outgoing_requests` itself noticing the change.
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
                let query_response = serde_json::json!({ "device_keys": by_user }).to_string();
                mark_request_sent(&query_id, &query_response).await.unwrap();

                // Share now, before any Olm session exists: this is the case
                // the review's finding 1 is about. Both `before_claim` and
                // `claim_id` are read from this one `take_outgoing_requests`
                // call, not two separate ones: `pending_claim` is drained
                // (taken, not cloned) the first time it is asked for, so a
                // second call here would find nothing left to drain and prove
                // nothing.
                share_scope_key("!s:example.org", &[bob_user.to_string()])
                    .await
                    .unwrap();
                let taken = take_outgoing_requests().await.unwrap();
                let before_claim: Vec<String> = taken
                    .iter()
                    .filter(|r| r.kind == "to_device")
                    .map(|r| decoded_event_type(&r.body))
                    .collect();

                // Step 2, `/keys/claim`: `share_scope_key` above queued the
                // request for the session it found missing; resolve it with
                // one of bob's own genuinely self-signed one-time keys.
                let claim_id = taken
                    .into_iter()
                    .find(|r| r.kind == "keys_claim")
                    .expect("sharing to a device with no session queues a keys claim")
                    .id;

                let (otk_id, otk_key) = bob_one_time_key;
                let mut otk_map = BTreeMap::new();
                otk_map.insert(otk_id.to_string(), serde_json::to_value(&otk_key).unwrap());
                let mut claim_devices = BTreeMap::new();
                claim_devices.insert(
                    bob_device.to_string(),
                    serde_json::to_value(&otk_map).unwrap(),
                );
                let mut claim_by_user = BTreeMap::new();
                claim_by_user.insert(
                    bob_user.to_string(),
                    serde_json::to_value(&claim_devices).unwrap(),
                );
                let claim_response =
                    serde_json::json!({ "one_time_keys": claim_by_user }).to_string();
                mark_request_sent(&claim_id, &claim_response).await.unwrap();

                // Step 3, `/sendToDevice`: share again, now that a session
                // exists.
                share_scope_key("!s:example.org", &[bob_user.to_string()])
                    .await
                    .unwrap();
                let after_claim: Vec<String> = take_outgoing_requests()
                    .await
                    .unwrap()
                    .into_iter()
                    .filter(|r| r.kind == "to_device")
                    .map(|r| decoded_event_type(&r.body))
                    .collect();

                (before_claim, after_claim)
            }));

        assert_eq!(
            before_claim,
            vec!["m.room_key.withheld".to_string()],
            "sharing before a session exists must be a withheld notice, not silently nothing and not the key"
        );
        // Not `assert_eq!` against a single-element vec: upstream does not
        // retract the first attempt's withheld notice just because a
        // second attempt can now succeed -- it was never marked sent, so
        // `share_room_key` still considers it pending and this second
        // `share_scope_key` call hands it out again alongside the new,
        // genuinely encrypted request, both under distinct ids (proven by
        // `queued_to_device`'s own `txn_id` keying not collapsing them into
        // one). That stale-notice accumulation is upstream's own choice,
        // not a defect this test is about; what matters here is that the
        // real key is *among* what this call produces, not that it is the
        // only thing.
        assert!(
            after_claim.contains(&"m.room.encrypted".to_string()),
            "sharing after a keys-claim round trip must deliver the session key: {after_claim:?}"
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

    // --- Fix round 1: keys-claim wiring, body accuracy, dedup, redaction,
    //     bounded pending, retriable marks ---------------------------

    /// `describe_outgoing`'s own doc comment claims every body is that
    /// endpoint's real wire body except the two disclosed exceptions
    /// (`to_device`, `room_message`, both augmented with path-segment
    /// values). Proven directly, one kind at a time, by constructing each
    /// `AnyOutgoingRequest` variant by hand -- every field involved is
    /// public, so no live machine is needed. A review found two kinds did
    /// not match this claim before this fix: `signature_upload`'s body was
    /// wrapped in an extra `{"signed_keys": ...}` layer ruma's own
    /// `#[ruma_api(body)]` attribute says does not exist on the wire, and
    /// `room_message` omitted `event_type` entirely, leaving the product
    /// no way to build that endpoint's URL at all.
    #[test]
    fn describe_outgoing_produces_the_real_wire_body_for_every_kind() {
        // keys_upload: device_keys/one_time_keys/fallback_keys all
        // omitted, not `null`/`{}`, when absent or empty (finding 9).
        // `Request::new()` is the only public constructor a
        // `#[non_exhaustive]` ruma request type like this one has, and it
        // always gives the all-absent/all-empty case.
        let upload = matrix_sdk_common::ruma::api::client::keys::upload_keys::v3::Request::new();
        let (kind, body) = describe_outgoing(&AnyOutgoingRequest::KeysUpload(upload)).unwrap();
        assert_eq!(kind.tag(), "keys_upload");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            value.get("device_keys").is_none(),
            "device_keys must be omitted when absent: {body}"
        );
        assert!(
            value.get("one_time_keys").is_none(),
            "one_time_keys must be omitted when empty: {body}"
        );
        assert!(
            value.get("fallback_keys").is_none(),
            "fallback_keys must be omitted when empty: {body}"
        );

        // keys_query: device_keys always present, even empty (ruma's own
        // `Request` has no `skip_serializing_if` on it); timeout omitted
        // when absent. Not `#[non_exhaustive]` (it is matrix-sdk-crypto's
        // own type, not generated by ruma's request macro), so a struct
        // literal works directly.
        let query = matrix_sdk_crypto::types::requests::KeysQueryRequest {
            timeout: None,
            device_keys: BTreeMap::new(),
        };
        let (kind, body) = describe_outgoing(&AnyOutgoingRequest::KeysQuery(query)).unwrap();
        assert_eq!(kind.tag(), "keys_query");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            value.get("device_keys").is_some(),
            "device_keys must always be present, even empty: {body}"
        );
        assert!(
            value.get("timeout").is_none(),
            "timeout must be omitted when absent: {body}"
        );

        // keys_claim: `describe_keys_claim`'s own doc comment covers this;
        // proven again here through the `AnyOutgoingRequest` match arm
        // specifically, currently unreachable in practice (see
        // `PendingKind::superseded_by_a_fresh_request`'s doc comment) but
        // matched exhaustively anyway. `KeysClaimRequest::new` is the only
        // public constructor this `#[non_exhaustive]` type has, and it
        // always sets a 10-second timeout -- there is no public way to
        // build one with `timeout: None`, so only the always-present case
        // is checked directly here.
        let claim = KeysClaimRequest::new(BTreeMap::new());
        let (kind, body) = describe_outgoing(&AnyOutgoingRequest::KeysClaim(claim)).unwrap();
        assert_eq!(kind.tag(), "keys_claim");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(value.get("one_time_keys").is_some());
        assert_eq!(
            value.get("timeout").and_then(serde_json::Value::as_u64),
            Some(10_000)
        );

        // signature_upload: the wire body *is* the signed_keys map, not a
        // wrapper around it -- an empty map still proves the shape, since
        // a wrapped body would render as `{"signed_keys":{}}`, not `{}`.
        let signature =
            matrix_sdk_common::ruma::api::client::keys::upload_signatures::v3::Request::new(
                BTreeMap::new(),
            );
        let (kind, body) =
            describe_outgoing(&AnyOutgoingRequest::SignatureUpload(signature)).unwrap();
        assert_eq!(kind.tag(), "signature_upload");
        assert_eq!(
            body, "{}",
            "signed_keys is the whole body, not wrapped: {body}"
        );

        // room_message: room_id, event_type, txn_id and content all
        // present -- `event_type` is the one finding 3 found missing.
        let content: matrix_sdk_common::ruma::events::AnyMessageLikeEventContent =
            matrix_sdk_common::ruma::events::room::message::RoomMessageEventContent::text_plain(
                "hi",
            )
            .into();
        let room_message = matrix_sdk_crypto::types::requests::RoomMessageRequest {
            room_id: "!s:example.org".parse().unwrap(),
            txn_id: matrix_sdk_common::ruma::TransactionId::new(),
            content: Box::new(content),
        };
        let (kind, body) =
            describe_outgoing(&AnyOutgoingRequest::RoomMessage(Box::new(room_message))).unwrap();
        assert_eq!(kind.tag(), "room_message");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            value.get("room_id").and_then(|v| v.as_str()),
            Some("!s:example.org")
        );
        assert_eq!(
            value.get("event_type").and_then(|v| v.as_str()),
            Some("m.room.message"),
            "event_type must be present -- the product has no other way to build this endpoint's URL: {body}"
        );
        assert!(value.get("txn_id").is_some());
        assert!(value.get("content").is_some());
    }

    /// Calling `share_scope_key` twice for the same scope before either
    /// to-device request is marked sent must not queue the same persisted
    /// request twice. A review measured the pre-fix behaviour producing
    /// two entries with the same content and only one distinct id, so the
    /// second `mark_request_sent` for it -- there being only one real id
    /// to mark -- failed with `UnknownRequest` for what looks like a
    /// perfectly ordinary double call.
    ///
    /// Uses the same withheld-notice-before-a-session-exists setup as
    /// `sharing_a_scope_key_delivers_the_key_only_after_a_keys_claim_round_trip`
    /// above, not a full keys-claim round trip: any to-device request is
    /// subject to the same `queued_to_device` de-duplication, and a
    /// withheld notice is the cheaper one to produce.
    #[test]
    fn sharing_the_same_scope_key_twice_before_marking_does_not_duplicate_the_request() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let to_device: Vec<OutgoingRequest> =
            futures::executor::block_on(crate::in_runtime(async move {
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
                    .unwrap()
                    .id;
                let mut devices = BTreeMap::new();
                devices.insert(
                    bob_device.to_string(),
                    serde_json::to_value(&bob_device_keys).unwrap(),
                );
                let mut by_user = BTreeMap::new();
                by_user.insert(bob_user.to_string(), devices);
                mark_request_sent(
                    &query_id,
                    &serde_json::json!({ "device_keys": by_user }).to_string(),
                )
                .await
                .unwrap();

                // Two calls, same scope and users, neither result ever
                // marked sent.
                share_scope_key("!s:example.org", &[bob_user.to_string()])
                    .await
                    .unwrap();
                share_scope_key("!s:example.org", &[bob_user.to_string()])
                    .await
                    .unwrap();

                take_outgoing_requests().await
            }))
            .unwrap()
            .into_iter()
            .filter(|r| r.kind == "to_device")
            .collect();

        assert_eq!(
            to_device.len(),
            1,
            "two share_scope_key calls before marking must not duplicate the queued request: {to_device:?}"
        );
    }

    /// A stale `keys_upload`/`keys_query`/`keys_claim` id from an earlier
    /// `take_outgoing_requests` call must not linger in `STATE.pending`
    /// forever just because it was never marked sent -- upstream mints a
    /// fresh, uncorrelated id for the same standing need on every call
    /// (see `PendingKind::superseded_by_a_fresh_request`'s own doc
    /// comment). A review measured three idle calls on a fresh machine
    /// leaving six stale entries behind with no eviction at all; this
    /// asserts the count after three calls is no larger than after one,
    /// rather than a specific number, so it does not depend on exactly
    /// which kinds an idle machine happens to report.
    #[test]
    fn a_stale_keys_upload_id_does_not_accumulate_across_repeated_calls() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let (after_one, after_three) = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();

            take_outgoing_requests().await.unwrap();
            let after_one = STATE
                .lock()
                .expect("request registry poisoned")
                .pending
                .len();

            take_outgoing_requests().await.unwrap();
            take_outgoing_requests().await.unwrap();
            let after_three = STATE
                .lock()
                .expect("request registry poisoned")
                .pending
                .len();

            (after_one, after_three)
        });

        assert_eq!(
            after_one, after_three,
            "repeated idle calls must not grow STATE.pending: {after_one} entries after one call, {after_three} after three"
        );
    }

    /// A `mark_request_sent` call that fails (malformed `response_json`)
    /// must not remove the request from `pending` -- the caller should be
    /// able to retry the same id with corrected input. A review found the
    /// pre-fix version removed the entry unconditionally, before even
    /// attempting the mark, so a failed first attempt made every
    /// subsequent retry fail with `UnknownRequest` regardless of how
    /// well-formed the retry's own input was.
    #[test]
    fn a_failed_mark_can_be_retried_with_the_same_id() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            let upload_id = take_outgoing_requests()
                .await
                .unwrap()
                .into_iter()
                .find(|r| r.kind == "keys_upload")
                .expect("a fresh machine has a key upload to send")
                .id;

            let first = mark_request_sent(&upload_id, "not valid json at all").await;
            assert_eq!(first, Err(SessionError::MalformedPayload));

            // Same id, corrected input: must succeed, not `UnknownRequest`.
            mark_request_sent(&upload_id, r#"{"one_time_key_counts":{}}"#)
                .await
                .unwrap();
        });
    }

    /// `Envelope` and `OutgoingRequest`'s hand-written `Debug` impls must
    /// never print ciphertext, plaintext, or a user id -- the global
    /// no-secret rule extends explicitly to `Debug` output and panic
    /// messages, and a review found the derived `Debug` this replaces
    /// printed exactly these fields, including into a panic message in
    /// this file's own decisive pump test.
    #[test]
    fn envelope_and_outgoing_request_debug_output_never_contains_the_secret_fields() {
        let envelope = Envelope {
            scope: "!s:example.org".to_string(),
            algorithm: "m.megolm.v1.aes-sha2".to_string(),
            event_type: "m.room.message".to_string(),
            ciphertext: b"super-secret-ciphertext-marker".to_vec(),
            sender: "@alice:example.org".to_string(),
        };
        let rendered = format!("{envelope:?}");
        assert!(
            !rendered.contains("super-secret-ciphertext-marker"),
            "{rendered}"
        );
        assert!(!rendered.contains("@alice:example.org"), "{rendered}");
        // Non-secret fields still appear, so this is not just an
        // empty/panicking `Debug` impl standing in for a real one.
        assert!(rendered.contains("!s:example.org"));
        assert!(rendered.contains("m.room.message"));

        let request = OutgoingRequest {
            id: "some-transaction-id".to_string(),
            kind: "to_device".to_string(),
            body: r#"{"messages":{"@bob:example.org":{"BOBDEVICE":{"ciphertext":"secret-payload-marker"}}}}"#
                .to_string(),
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("secret-payload-marker"), "{rendered}");
        assert!(!rendered.contains("@bob:example.org"), "{rendered}");
        assert!(rendered.contains("some-transaction-id"));
        assert!(rendered.contains("to_device"));
    }

    // --- Task 6: decryption and error classification ------------------

    /// The test that matters most here: not merely that `decrypt_event`
    /// returns `Ok`, but that what comes back is the *exact* payload
    /// `encrypt_event` started from. A round trip that only checked for
    /// success would pass whether or not the cryptography did anything at
    /// all.
    ///
    /// `share_scope_key`'s own upstream call creates a matching inbound
    /// group session alongside the outbound one it shares
    /// (`matrix-sdk-crypto-0.18.0/src/session_manager/group_sessions/mod.rs`'s
    /// own doc comment on `create_outbound_group_session`: "This also
    /// creates a matching inbound group session"), which is why one
    /// machine can decrypt what it just encrypted for itself without a
    /// second device anywhere in this test.
    #[test]
    fn decrypting_recovers_the_exact_payload_encrypt_event_started_from() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        // Keys in ascending byte order, like every other JSON literal this
        // file's tests hand to `encrypt_event`: not load-bearing for
        // encryption, but it is what makes the byte-for-byte assertion
        // below meaningful without this test also having to reverse
        // whatever key order `serde_json::Value` happens to use internally.
        let payload = r#"{"body":"hello","msgtype":"m.text"}"#;

        let envelope = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            let encrypted = encrypt_event("!s:example.org", "m.room.message", payload)
                .await
                .unwrap();

            let content: serde_json::Value = serde_json::from_slice(&encrypted.ciphertext)
                .expect("encrypt_event's own ciphertext is well-formed JSON");
            let raw_event = serde_json::json!({
                "sender": encrypted.sender,
                "event_id": "$event1:example.org",
                "origin_server_ts": 1_700_000_000_000u64,
                "content": content,
            })
            .to_string();

            decrypt_event("!s:example.org", &raw_event).await
        })
        .unwrap();

        assert_eq!(
            envelope.ciphertext,
            payload.as_bytes(),
            "the recovered plaintext must round-trip byte for byte"
        );
        assert_eq!(envelope.event_type, "m.room.message");
        assert_eq!(envelope.sender, "@alice:example.org");
        assert_eq!(envelope.scope, "!s:example.org");
        assert!(
            !envelope.algorithm.is_empty(),
            "the algorithm tag must be populated"
        );
    }

    /// The discriminating half of the round-trip test above: a decryptor
    /// that always returned success (or always the same bytes) regardless
    /// of the ciphertext would still pass a test that only checks the
    /// happy path. Flipping one character of the base64 `ciphertext`
    /// string -- same length, same alphabet -- must make decryption fail
    /// rather than silently succeed or return the wrong bytes.
    ///
    /// The flipped character is chosen a quarter of the way into the
    /// string, not the first: a vodozemac Megolm message is
    /// `version(1) || message_index || ciphertext || mac || signature`
    /// (`vodozemac-0.10.0/src/megolm/message.rs`), all base64-encoded
    /// together, so the leading few characters encode the version and
    /// ratchet-index header, not the ciphertext body. A review finding
    /// caught this by mutation: this test used to flip the *first*
    /// character, which corrupts that header and makes the whole message
    /// fail to decode as a well-formed `MegolmMessage` before any
    /// session lookup or cryptography runs at all
    /// (`event.deserialize()?`, the first line of upstream's
    /// `decrypt_room_event_inner`) -- proving only that malformed input is
    /// rejected, not that the MAC check catches tampering. A quarter of
    /// the way in falls inside the ciphertext body for any payload this
    /// test's size or larger, well clear of both the leading header and
    /// the fixed-size MAC-and-signature suffix at the end, so corrupting
    /// it can only be caught by the actual decrypt step.
    #[test]
    fn corrupting_the_ciphertext_makes_decryption_fail_rather_than_succeed_silently() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let err = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            let encrypted = encrypt_event("!s:example.org", "m.room.message", r#"{"body":"hi"}"#)
                .await
                .unwrap();

            let mut content: serde_json::Value = serde_json::from_slice(&encrypted.ciphertext)
                .expect("encrypt_event's own ciphertext is well-formed JSON");
            let original = content["ciphertext"]
                .as_str()
                .expect("a Megolm content always carries a ciphertext string")
                .to_string();
            // A quarter of the way into the string, not the first
            // character -- see this test's own doc comment for why.
            let mut bytes = original.into_bytes();
            let target = bytes.len() / 4;
            bytes[target] = if bytes[target] == b'A' { b'B' } else { b'A' };
            let flipped =
                String::from_utf8(bytes).expect("flipping one base64 byte stays valid UTF-8");
            content["ciphertext"] = serde_json::Value::String(flipped);

            let raw_event = serde_json::json!({
                "sender": encrypted.sender,
                "event_id": "$event2:example.org",
                "origin_server_ts": 1_700_000_000_000u64,
                "content": content,
            })
            .to_string();

            decrypt_event("!s:example.org", &raw_event).await
        })
        .unwrap_err();

        assert_eq!(err, SessionError::Undecryptable);
    }

    /// An event referring to a session this machine has no record of at
    /// all -- the ordinary shape of "the key has not arrived yet" -- must
    /// be reported as `MissingKey`, not folded into a generic failure a
    /// product cannot act on differently from any other error.
    #[test]
    fn decrypting_an_event_for_a_session_never_shared_reports_missing_key() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let err = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            let encrypted = encrypt_event("!s:example.org", "m.room.message", r#"{"body":"hi"}"#)
                .await
                .unwrap();

            let mut content: serde_json::Value = serde_json::from_slice(&encrypted.ciphertext)
                .expect("encrypt_event's own ciphertext is well-formed JSON");
            assert!(
                content["session_id"].is_string(),
                "a Megolm content always carries a session_id string"
            );
            content["session_id"] =
                serde_json::Value::String("AN_UNKNOWN_SESSION_NOBODY_SHARED".to_string());

            let raw_event = serde_json::json!({
                "sender": encrypted.sender,
                "event_id": "$event3:example.org",
                "origin_server_ts": 1_700_000_000_000u64,
                "content": content,
            })
            .to_string();

            decrypt_event("!s:example.org", &raw_event).await
        })
        .unwrap_err();

        assert_eq!(err, SessionError::MissingKey);
    }

    /// The other half of the split `MissingRoomKey` provides, and a
    /// review finding: reachable today, unlike `UnknownDevice`, through
    /// the same public surface a real sync loop uses -- feed a real
    /// `m.room_key.withheld` to-device event through `receive_sync_changes`
    /// (the machine's own `AnyToDeviceEvent` dispatch routes it to
    /// `add_withheld_info`, which records it against its `(room_id,
    /// session_id)`, per `matrix-sdk-crypto-0.18.0/src/machine/mod.rs`),
    /// then decrypt an event for that same room and session id, for which
    /// this machine has no actual inbound session. Distinct from
    /// `decrypting_an_event_for_a_session_never_shared_reports_missing_key`
    /// above only in that a withheld record now exists for the same kind
    /// of absent session, which is exactly the fact `UnsharedSession` is
    /// for.
    #[test]
    fn decrypting_an_event_for_a_withheld_session_reports_unshared_session() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let err = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();

            // A real curve25519 key, not a fabricated string: the withheld
            // content's `sender_key` must deserialize as one, and this
            // machine's own identity key is guaranteed to.
            let keys = crate::device_identity_keys("@alice:example.org", "DEVICE1")
                .await
                .unwrap();

            let withheld_session_id = "WITHHELD_SESSION_NOBODY_GOT";
            let withheld_event = serde_json::json!({
                "sender": "@bob:example.org",
                "type": "m.room_key.withheld",
                "content": {
                    "algorithm": "m.megolm.v1.aes-sha2",
                    "code": "m.unavailable",
                    "reason": "the requested key was not found",
                    "room_id": "!s:example.org",
                    "session_id": withheld_session_id,
                    "sender_key": keys.curve25519,
                },
            });
            receive_sync_changes(
                &serde_json::json!({ "to_device_events": [withheld_event] }).to_string(),
            )
            .await
            .unwrap();

            // A real content shape (borrowed from a real encrypt, then
            // repointed at the withheld session id), the same technique
            // the `MissingKey` test above uses -- so this exercises the
            // withheld-record branch specifically, not a shape rejection.
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            let encrypted = encrypt_event("!s:example.org", "m.room.message", r#"{"body":"hi"}"#)
                .await
                .unwrap();
            let mut content: serde_json::Value = serde_json::from_slice(&encrypted.ciphertext)
                .expect("encrypt_event's own ciphertext is well-formed JSON");
            content["session_id"] = serde_json::Value::String(withheld_session_id.to_string());

            let raw_event = serde_json::json!({
                "sender": encrypted.sender,
                "event_id": "$event5:example.org",
                "origin_server_ts": 1_700_000_000_000u64,
                "content": content,
            })
            .to_string();

            decrypt_event("!s:example.org", &raw_event).await
        })
        .unwrap_err();

        assert_eq!(err, SessionError::UnsharedSession);
    }

    /// The half of the split `MissingRoomKey` handling that G26 in the
    /// milestone's own ledger ruled on and this change dispatches:
    /// `m.blacklisted` is not a circumstance a retry can resolve, it is the
    /// sender's own decision to refuse this device, so it must report
    /// `SessionRefused`, not `UnsharedSession`. Structured identically to
    /// `decrypting_an_event_for_a_withheld_session_reports_unshared_session`
    /// above -- same wire event shape, same real dispatch path through
    /// `receive_sync_changes` and `add_withheld_info` -- and differs only
    /// in the withheld `code`, so the contrast this pair of tests proves is
    /// the split itself, not some other difference between the two tests.
    #[test]
    fn decrypting_an_event_for_a_policy_refused_session_reports_session_refused() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let err = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();

            // A real curve25519 key, not a fabricated string: the withheld
            // content's `sender_key` must deserialize as one, and this
            // machine's own identity key is guaranteed to.
            let keys = crate::device_identity_keys("@alice:example.org", "DEVICE1")
                .await
                .unwrap();

            let withheld_session_id = "REFUSED_SESSION_NOBODY_GOT";
            let withheld_event = serde_json::json!({
                "sender": "@bob:example.org",
                "type": "m.room_key.withheld",
                "content": {
                    "algorithm": "m.megolm.v1.aes-sha2",
                    "code": "m.blacklisted",
                    "reason": "The sender has blocked you.",
                    "room_id": "!s:example.org",
                    "session_id": withheld_session_id,
                    "sender_key": keys.curve25519,
                },
            });
            receive_sync_changes(
                &serde_json::json!({ "to_device_events": [withheld_event] }).to_string(),
            )
            .await
            .unwrap();

            // A real content shape (borrowed from a real encrypt, then
            // repointed at the withheld session id), the same technique
            // the sibling `UnsharedSession` test above uses -- so this
            // exercises the withheld-record branch specifically, not a
            // shape rejection.
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            let encrypted = encrypt_event("!s:example.org", "m.room.message", r#"{"body":"hi"}"#)
                .await
                .unwrap();
            let mut content: serde_json::Value = serde_json::from_slice(&encrypted.ciphertext)
                .expect("encrypt_event's own ciphertext is well-formed JSON");
            content["session_id"] = serde_json::Value::String(withheld_session_id.to_string());

            let raw_event = serde_json::json!({
                "sender": encrypted.sender,
                "event_id": "$event6:example.org",
                "origin_server_ts": 1_700_000_000_000u64,
                "content": content,
            })
            .to_string();

            decrypt_event("!s:example.org", &raw_event).await
        })
        .unwrap_err();

        assert_eq!(err, SessionError::SessionRefused);
    }

    /// The split itself, proven directly against `classify_megolm_error`
    /// rather than through the full machine the pair of tests above uses:
    /// the two policy withheld codes (`m.blacklisted`, `m.unauthorised`)
    /// must classify as the new `SessionRefused`, and the two
    /// circumstantial ones this crate names explicitly in its own doc
    /// comments (`m.unavailable`, `m.no_olm`) must still classify as
    /// `UnsharedSession`, which stays retriable. A swap of either pairing
    /// -- a policy code classified as `UnsharedSession`, or a
    /// circumstantial one moved to `SessionRefused` -- turns this test
    /// red, which is the property a fieldless, same-shaped pair of kinds
    /// cannot get from the compiler and must get from a test instead.
    #[test]
    fn a_policy_withheld_code_is_not_retriable_and_a_circumstantial_one_stays_unshared() {
        assert_eq!(
            classify_megolm_error(MegolmError::MissingRoomKey(Some(WithheldCode::Blacklisted))),
            SessionError::SessionRefused,
        );
        assert_eq!(
            classify_megolm_error(MegolmError::MissingRoomKey(Some(
                WithheldCode::Unauthorised
            ))),
            SessionError::SessionRefused,
        );

        assert_eq!(
            classify_megolm_error(MegolmError::MissingRoomKey(Some(WithheldCode::Unavailable))),
            SessionError::UnsharedSession,
        );
        assert_eq!(
            classify_megolm_error(MegolmError::MissingRoomKey(Some(WithheldCode::NoOlm))),
            SessionError::UnsharedSession,
        );
    }

    /// This crate's own "no secret in any error" rule (spec section 7),
    /// for decryption specifically: regardless of which of the five kinds
    /// a failure is classified as, no fragment of the ciphertext that
    /// caused it may survive into the rendered error. The five decryption
    /// variants of `SessionError` are fieldless with fixed literal
    /// messages precisely so this holds structurally; this test proves it
    /// rather than leaving it to be trusted by inspection, reusing the
    /// same "unknown session" shape as the `MissingKey` test above.
    #[test]
    fn no_decryption_error_carries_a_fragment_of_the_ciphertext() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let (err, ciphertext_fragment) = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            let encrypted = encrypt_event("!s:example.org", "m.room.message", r#"{"body":"hi"}"#)
                .await
                .unwrap();

            let mut content: serde_json::Value = serde_json::from_slice(&encrypted.ciphertext)
                .expect("encrypt_event's own ciphertext is well-formed JSON");
            let ciphertext_fragment = content["ciphertext"]
                .as_str()
                .expect("a Megolm content always carries a ciphertext string")[..16]
                .to_string();
            content["session_id"] =
                serde_json::Value::String("AN_UNKNOWN_SESSION_NOBODY_SHARED".to_string());

            let raw_event = serde_json::json!({
                "sender": encrypted.sender,
                "event_id": "$event4:example.org",
                "origin_server_ts": 1_700_000_000_000u64,
                "content": content,
            })
            .to_string();

            let err = decrypt_event("!s:example.org", &raw_event)
                .await
                .unwrap_err();
            (err, ciphertext_fragment)
        });

        assert_eq!(err, SessionError::MissingKey);
        let rendered = err.to_string();
        assert!(
            !rendered.contains(&ciphertext_fragment),
            "rendered error must not contain a fragment of the ciphertext: {rendered}"
        );
        assert!(!rendered.contains("ciphertext"));
        assert!(!rendered.contains("!s:example.org"));
    }

    /// A malformed `raw_json` must be rejected before any cryptographic
    /// work happens, the same precondition `a_malformed_scope_is_rejected`
    /// already asserts for `encrypt_event`.
    #[test]
    fn malformed_raw_json_is_rejected_before_any_decryption_is_attempted() {
        let err =
            futures::executor::block_on(decrypt_event("!s:example.org", "{oops")).unwrap_err();
        assert_eq!(err, SessionError::MalformedPayload);
    }

    /// Mirrors `a_malformed_scope_is_rejected`: an invalid scope must be
    /// rejected before this function ever reaches the machine, for
    /// `decrypt_event` exactly as for `encrypt_event`.
    #[test]
    fn a_malformed_scope_is_rejected_for_decryption_too() {
        let err = futures::executor::block_on(decrypt_event("nonsense", "{}")).unwrap_err();
        assert_eq!(err, SessionError::MalformedPayload);
    }

    // --- Fix round 1: sharing tracks the users it was given -----------

    /// The property that makes every later step reachable at all, and the
    /// one nothing on this surface could do before: naming a user in
    /// `share_scope_key` must make the pump ask the homeserver who that
    /// user's devices are.
    ///
    /// Upstream only issues a `/keys/query` for a user it is *tracking* --
    /// `mark_tracked_users_as_changed` (store/mod.rs:291) opens with
    /// `if tracked_users.contains(user_id)` and silently skips everyone
    /// else -- and a sync's `changed_devices` list routes nowhere but
    /// there. So before `share_scope_key` tracked its users, a product
    /// could name a brand-new user here forever and the pump would keep
    /// handing out upstream's own-user fallback query instead: encrypting
    /// to nobody, with no error anywhere. A review found this while
    /// checking why `tests/two_parties.rs` needed a back door to set the
    /// precondition; the back door is gone and this asserts the shipped
    /// behaviour that replaced it.
    ///
    /// Asserts on the parsed `device_keys` keys, not on a substring of the
    /// body: those keys *are* the set of users the request asks about, and
    /// a structural check survives a body-shape change upstream that a
    /// substring match would silently keep passing.
    #[test]
    fn sharing_a_scope_key_makes_the_pump_ask_about_the_users_it_was_given() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let queried: Vec<String> = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();

            // A user this machine has never seen, named here for the
            // first time.
            share_scope_key("!s:example.org", &["@bob:example.org".to_string()])
                .await
                .unwrap();

            let query = take_outgoing_requests()
                .await
                .unwrap()
                .into_iter()
                .find(|r| r.kind == "keys_query")
                .expect("naming a user must queue a query for that user");

            serde_json::from_str::<serde_json::Value>(&query.body)
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
        });

        assert!(
            queried.iter().any(|user| user == "@bob:example.org"),
            "share_scope_key must make the users it was given queryable -- \
             nothing else on this crate's surface can"
        );
    }
}
