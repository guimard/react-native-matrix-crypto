//! Ingesting sync changes into the crypto machine.
//!
//! The product already performs the `/sync` request; this module only
//! consumes the encryption-relevant slice of the response it hands back --
//! to-device events, one-time and fallback key counts, and changed or left
//! devices -- so the machine can decrypt, track key counts, and learn about
//! other devices. This is the prerequisite every later crypto operation
//! (sharing a key, encrypting, decrypting) depends on.

use std::collections::BTreeMap;

use matrix_sdk_common::ruma::api::client::sync::sync_events::DeviceLists;
use matrix_sdk_common::ruma::events::AnyToDeviceEvent;
use matrix_sdk_common::ruma::serde::Raw;
use matrix_sdk_common::ruma::{OneTimeKeyAlgorithm, UInt};
use matrix_sdk_crypto::{DecryptionSettings, EncryptionSyncChanges, TrustRequirement};
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
}
