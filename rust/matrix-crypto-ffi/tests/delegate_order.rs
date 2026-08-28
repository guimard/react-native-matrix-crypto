//! Argument order across the FFI boundary.
//!
//! Every `#[uniffi::export]` in this crate is a delegate: it takes owned
//! `String`s and forwards them to `matrix-crypto-core` as `&str`. Nothing in
//! the type system distinguishes one `&str` from another, so **transposing
//! two of a delegate's arguments compiles, passes `clippy -D warnings`, and
//! passes every other test in this repository** -- a review measured exactly
//! that for `encrypt_event`, `decrypt_event` and `mark_request_sent`, across
//! `cargo check`, the ffi crate's own tests, and all 39 TypeScript tests.
//! The delegates are correct today; before this file, nothing kept them that
//! way.
//!
//! So this test drives the *exported* functions -- `matrix_crypto_ffi::…`,
//! not `matrix_crypto_core::…` -- with values chosen so that a transposition
//! changes the outcome rather than merely the labelling:
//!
//! * `encrypt_event(scope, event_type, payload_json)` -- the scope is a room
//!   id, the event type is not one, and the payload is JSON that is neither.
//!   Any of the three transpositions makes the core reject the call
//!   (`parse_scope` fails on a non-room-id, `Raw::from_json_string` fails on
//!   a non-JSON event type), and the two returned fields asserted below pin
//!   which value arrived where even where a transposition happened to parse.
//! * `decrypt_event(scope, raw_json)` -- transposed, the core parses a whole
//!   event as a scope and fails.
//! * `mark_request_sent(id, response_json)` -- transposed, the core looks up
//!   a response body in its pending-request set and reports `UnknownRequest`.
//!
//! It pins the same property on the argument order of
//! `device_identity_keys(user_id, device_id)` (the core checks both against
//! the live machine), and on the field mappings of the record mirrors this
//! crate hand-writes, where the same "two values, one type" hazard applies:
//! `CryptoMachineConfig` into the core's config (a transposed
//! `user_id`/`device_id`/`store_path` makes `create_crypto_machine` fail
//! outright), every same-typed pair of `Envelope`, all three fields of
//! `OutgoingRequest`, both counts of `SyncOutcome`, and the two
//! indistinguishable base64 fields of `IdentityKeys` -- the last pinned
//! against the algorithm-named keys the device's own upload publishes,
//! since nothing else at this boundary can tell them apart.
//!
//! What this file does **not** cover, stated rather than implied:
//! `share_scope_key(scope, users)` and `receive_sync_changes(raw_json)` have
//! no same-typed argument pair to transpose in the first place;
//! `create_crypto_machine`/`open_crypto_store` delegate to two core
//! functions that are deliberately the same operation, so swapping them
//! changes nothing observable; and a *mis-mapped error variant* in
//! `From<SessionError>`/`From<MachineError>` is a different hazard from
//! argument order, reachable only on failure paths this test does not take.

use matrix_crypto_ffi::{
    create_crypto_machine, decrypt_event, device_identity_keys, encrypt_event, mark_request_sent,
    receive_sync_changes, share_scope_key, take_outgoing_requests, CryptoMachineConfig,
};

const SCOPE: &str = "!delegate-order:example.org";
const EVENT_TYPE: &str = "m.room.message";
const PAYLOAD: &str = r#"{"body":"delegate order","msgtype":"m.text"}"#;
const USER_ID: &str = "@alice:example.org";
const DEVICE_ID: &str = "DEVICE1";

/// Deliberately driven by `futures::executor::block_on` rather than
/// `#[tokio::test]`: the FFI's real calling context supplies no ambient
/// runtime, and this crate's exports are where that context begins. An
/// ambient runtime here would let a missing `in_runtime` in the core pass
/// unnoticed -- the mistake `matrix-crypto-core`'s own
/// `with_machine_supplies_a_runtime_for_store_touching_calls` exists to
/// catch, made twice already in this milestone with a green suite both
/// times.
///
/// One `#[test]` fn: the crypto machine is process-wide, and this file gets
/// its own test process from cargo, so it owns that machine for its whole
/// lifetime and cannot race a sibling for it.
#[test]
fn the_exported_functions_pass_their_arguments_to_the_core_in_order() {
    // Bound here and dropped when this function returns, so the store does
    // not outlive the test.
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(async move {
        create_crypto_machine(CryptoMachineConfig {
            user_id: USER_ID.to_string(),
            device_id: DEVICE_ID.to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect(
            "creating the machine must succeed -- a transposed field in the config \
             mirror would land a device id, or a store path, where a user id belongs",
        );

        // `device_identity_keys(user_id, device_id)`: the core rejects a
        // pair that does not match the live machine, so a transposition
        // here fails rather than returning the wrong keys.
        let keys = device_identity_keys(USER_ID.to_string(), DEVICE_ID.to_string())
            .await
            .expect(
                "device_identity_keys must receive the user id first and the device id \
                 second -- the core checks both against the live machine",
            );
        assert_eq!(
            keys.curve25519.len(),
            43,
            "an identity key is a 32-byte public key in unpadded base64"
        );

        share_scope_key(SCOPE.to_string(), vec![USER_ID.to_string()])
            .await
            .expect("sharing a scope key with this machine's own user must succeed");

        // --- encrypt_event(scope, event_type, payload_json) -------------
        let envelope = encrypt_event(
            SCOPE.to_string(),
            EVENT_TYPE.to_string(),
            PAYLOAD.to_string(),
        )
        .await
        .expect(
            "encrypt_event must receive scope, event type and payload in that order \
             -- any transposition hands the core a scope it cannot parse, or a \
             payload that is not JSON",
        );
        assert!(
            envelope.scope == SCOPE,
            "the first argument of encrypt_event must reach the core as the scope"
        );
        assert!(
            envelope.event_type == EVENT_TYPE,
            "the second argument of encrypt_event must reach the core as the event type"
        );
        assert!(
            envelope.sender == USER_ID,
            "an outbound envelope's sender is this machine's own user id, so a \
             transposed sender/algorithm pair in the record mirror shows up here"
        );
        assert!(
            !envelope.algorithm.is_empty() && envelope.algorithm != envelope.sender,
            "the algorithm tag must be populated, and must not be carrying the sender"
        );

        // --- decrypt_event(scope, raw_json) -----------------------------
        // Wrapped as the homeserver would deliver it. Built by
        // interpolation rather than a JSON library so this crate needs no
        // extra dev-dependency for one string: the ciphertext is already
        // JSON text, and the two other values are literals from this file.
        let content = String::from_utf8(envelope.ciphertext)
            .expect("an encrypted content is well-formed UTF-8 JSON");
        let raw_event = format!(
            r#"{{"sender":"{}","event_id":"$delegate-order:example.org","origin_server_ts":1700000000000,"content":{}}}"#,
            envelope.sender, content
        );

        let decrypted = decrypt_event(SCOPE.to_string(), raw_event).await.expect(
            "decrypt_event must receive the scope first and the event second -- \
                 transposed, the core tries to parse a whole event as a scope",
        );
        assert!(
            decrypted.ciphertext == PAYLOAD.as_bytes(),
            "the recovered payload must be the one encrypt_event was given, byte for \
             byte (recovered {} bytes, sent {} bytes)",
            decrypted.ciphertext.len(),
            PAYLOAD.len()
        );

        // --- mark_request_sent(id, response_json) -----------------------
        let requests = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let upload = requests
            .into_iter()
            .find(|r| r.kind == "keys_upload")
            .expect("a fresh machine must have keys to publish");

        // Checked before the two assertions below, so that a transposed
        // `OutgoingRequest` field fails here, where the message is true,
        // rather than in the identity-key check, where it would read as an
        // `IdentityKeys` problem it is not.
        assert!(
            upload.body.starts_with('{'),
            "an outgoing request's body must be the JSON body, not another of its \
             same-typed fields"
        );

        // The upload body is the one thing at this boundary that says which
        // identity key is which: a key upload names each key by algorithm
        // (`"<algorithm>:<device>": "<base64>"`), which is the canonical
        // wire shape rather than a deprecated field. Without this pair of
        // checks nothing distinguishes `IdentityKeys`' two fields -- both
        // are 43-character base64 -- so transposing them in this crate's
        // record mirror would be invisible.
        assert!(
            upload.body.contains(&format!(
                r#""curve25519:{DEVICE_ID}":"{}""#,
                keys.curve25519
            )),
            "the curve25519 field of IdentityKeys must carry the curve25519 key the \
             device publishes under that name"
        );
        assert!(
            upload
                .body
                .contains(&format!(r#""ed25519:{DEVICE_ID}":"{}""#, keys.ed25519)),
            "the ed25519 field of IdentityKeys must carry the ed25519 key the device \
             publishes under that name"
        );

        mark_request_sent(upload.id, r#"{"one_time_key_counts":{}}"#.to_string())
            .await
            .expect(
                "mark_request_sent must receive the request id first and the response \
                 body second -- transposed, the core looks a response body up in its \
                 pending-request set and reports an unknown request",
            );

        // --- receive_sync_changes -> SyncOutcome ------------------------
        // One plain to-device event that carries no room key, so the two
        // counts differ (1 and 0) and a transposed pair in the record
        // mirror flips them. Equal counts would prove nothing.
        let outcome = receive_sync_changes(
            r#"{"to_device_events":[{"sender":"@bob:example.org","type":"m.dummy","content":{}}]}"#
                .to_string(),
        )
        .await
        .expect("an ordinary sync must be accepted");
        assert_eq!(
            outcome.to_device_event_count, 1,
            "the processed to-device count must not be carrying the new-session count"
        );
        assert_eq!(
            outcome.new_session_count, 0,
            "an event carrying no room key establishes no session"
        );
    });
}
