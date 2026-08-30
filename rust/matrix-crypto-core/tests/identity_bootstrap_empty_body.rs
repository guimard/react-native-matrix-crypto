//! A completely empty body reported as sent is accepted, and does **not**
//! answer the account key query.
//!
//! One subject, in its own process, because it is the one branch of
//! `session::refuse_a_non_response` that four shipped documents rested on and
//! nothing exercised. `mark_request_sent` with an empty string returns early
//! before the JSON parse, on the grounds that ruma substitutes an empty
//! object for a completely empty body before parsing ("If the body is
//! completely empty, pretend it is an empty JSON object instead",
//! `ruma-macros-0.19.0/src/api/common.rs:365-371`), so `""` and `{}` are the
//! same input by the time anything downstream looks at either.
//!
//! # What changed here, and why it is the point rather than a regression
//!
//! This file used to assert the opposite of its second half: that `""` lifted
//! the bootstrap gate, on the stated grounds that "a homeserver that answers a
//! key query with 200 and no body must not leave a product unable to
//! bootstrap". That premise was never measured. It has been now, directly
//! over HTTP, against three homeservers and on accounts holding no
//! cross-signing identity and no uploaded device keys at all:
//!
//! * **Synapse 1.159.0** and **Dendrite 0.15.2** answer
//!   `{"device_keys":{"@user:…":{}},"failures":{},"master_keys":{},`
//!   `"self_signing_keys":{},"user_signing_keys":{}}`.
//! * **Continuwuity v26.7.2** answers `{"device_keys":{"@user:…":{}}}`.
//!
//! All three name the account. None answers `{}`, and all three name even a
//! local user that does not exist on the server. So the case this file was
//! protecting is not a case any measured homeserver produces, while the
//! bytes it was accepting are exactly the bytes a 503 that carried no body
//! arrives as. `session::answer_about_this_account` now requires that, once
//! upstream has consumed the answer, upstream's own store says whether this
//! account has an identity; the empty object leaves it saying nothing at
//! all. This file pins both halves of what that means here.
//!
//! **Acceptance is unchanged, and that separation is deliberate.** `""` is
//! still a well-formed thing to report: `mark_request_sent` returns `Ok`,
//! upstream sees the response, and the request stops being pending. Only the
//! gate is narrowed. Narrowing acceptance instead would refuse a key query
//! answer that legitimately carries other users' keys, which is a worse bug
//! than the one being fixed.
//!
//! The second half of this test is the control, and without it the first
//! half proves only that this file can break bootstrapping: a real
//! homeserver's real answer, on a fresh query, must lift the gate and the
//! bootstrap must be served.
//!
//! Its own process, for the reason `tests/pump_eviction.rs` gives: the machine
//! registry and the pump's bookkeeping are process-wide, and the gate is
//! monotonic, so the answer that lifts it has to come last.

use matrix_crypto_core::{
    bootstrap_identity, create_identity, create_machine, identity_status, mark_request_sent,
    take_outgoing_requests, MachineConfig, MachineError, OutgoingRequest,
};

const ACCOUNT: &str = "@alice:example.org";

/// Continuwuity v26.7.2's real answer for an account with no cross-signing
/// identity, measured over HTTP. Synapse and Dendrite send the same thing
/// with `"failures":{}` and the three empty cross-signing maps beside it.
const REAL_ANSWER: &str = r#"{"device_keys":{"@alice:example.org":{}}}"#;

#[test]
fn a_completely_empty_body_does_not_answer_the_account_key_query() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(async move {
        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: "DEVICE1".to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        let batch = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let query = find(&batch, "keys_query", names_the_account);

        assert!(
            !identity_status()
                .await
                .expect("reading the identity status must not fail")
                .account_keys_fetched,
            "the gate must start shut, or the assertions below prove nothing"
        );

        mark_request_sent(&query.id, "").await.expect(
            "a completely empty body is the same input as `{}`, which ruma substitutes for it \
             before parsing, and an object with no keys is inside the shape \
             `refuse_a_non_response` accepts. Acceptance is not what this change narrows",
        );

        assert!(
            !identity_status()
                .await
                .expect("reading the identity status must not fail")
                .account_keys_fetched,
            "an empty body names nobody, so it says nothing about this account and must not \
             lift the gate. No measured homeserver answers a key query this way; a 503 that \
             carried no body arrives as exactly these bytes"
        );
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::AccountKeysNotFetched),
            "and the mint it would have authorised must be refused. Served here, an empty \
             body from a dead gateway mints a fresh identity over whatever this account \
             already has and silently invalidates every verification anyone has made of it"
        );

        // --- The control: a real homeserver's real answer ------------------
        //
        // The refusal above queued a fresh out-of-band key query, which is
        // how `signing::bootstrap_identity` makes that refusal recoverable.
        // Answering it the way a homeserver really does must lift the gate,
        // or the assertions above prove only that this file can break the
        // common case.
        let batch = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let query = find(&batch, "keys_query", names_the_account);

        mark_request_sent(&query.id, REAL_ANSWER)
            .await
            .expect("a real homeserver's real answer must be accepted");
        assert!(
            identity_status()
                .await
                .expect("reading the identity status must not fail")
                .account_keys_fetched,
            "an answer upstream could read must lift the gate"
        );
        create_identity()
            .await
            .expect("and the creation it authorises must be served");
    });
}

/// The first request of `kind` matching `predicate`, or a failure naming what
/// was in the batch instead.
fn find<'a>(
    batch: &'a [OutgoingRequest],
    kind: &str,
    predicate: impl Fn(&str) -> bool,
) -> &'a OutgoingRequest {
    batch
        .iter()
        .find(|request| request.kind == kind && predicate(&request.body))
        .unwrap_or_else(|| {
            panic!(
                "no matching {kind} in the batch; got {:?}",
                batch.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>()
            )
        })
}

/// Whether a `/keys/query` body's `device_keys` map names this account.
fn names_the_account(body: &str) -> bool {
    let parsed: serde_json::Value = serde_json::from_str(body).expect("a pump body must be JSON");
    parsed
        .get("device_keys")
        .and_then(|users| users.get(ACCOUNT))
        .is_some()
}
