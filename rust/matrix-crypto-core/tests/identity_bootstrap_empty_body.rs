//! A completely empty body reported as sent is accepted, and answers the
//! account key query.
//!
//! One assertion, in its own process, because it is the one branch of
//! `session::refuse_a_non_response` that four shipped documents rest on and
//! nothing exercised. `mark_request_sent` with an empty string returns early
//! before the JSON parse, on the grounds that ruma substitutes an empty
//! object for a completely empty body before parsing ("If the body is
//! completely empty, pretend it is an empty JSON object instead",
//! `ruma-macros-0.19.0/src/api/common.rs:365-371`), so `""` and `{}` are the
//! same input by the time anything downstream looks at either.
//!
//! Deleting that early return leaves the rest of this crate's suite green:
//! `""` is not valid JSON, so it would fall through to the parse and be
//! refused, and every other test either drives `{}` instead or reports the
//! empty body through `mark_request_failed`, which never reaches this branch.
//! That direction fails *closed*, so it was never a live hole. It is still a
//! branch that decides whether a product whose homeserver answers a key query
//! with 200 and no body can bootstrap at all, and the answer must be yes.
//!
//! **This is the dangerous acceptance, not a safe one, and it is deliberate.**
//! Accepting `""` here is exactly what lets a 503 that carried no body be
//! reported as a successful key query naming no identity. That cannot be
//! fixed by inspecting the body, because there is no body to inspect and the
//! bytes are identical to a real answer. It is fixed by the caller branching
//! on the status and calling `mark_request_failed` instead, which
//! `identity_bootstrap_non_response.rs` drives. This file pins the other
//! direction: the honest 200 must still work.
//!
//! Its own process, for the reason `tests/pump_eviction.rs` gives: the machine
//! registry and the pump's bookkeeping are process-wide, and answering the
//! account key query here retires it for everything else in the binary.

use matrix_crypto_core::{
    bootstrap_identity, create_machine, identity_status, mark_request_sent, take_outgoing_requests,
    MachineConfig, OutgoingRequest,
};

const ACCOUNT: &str = "@alice:example.org";

#[test]
fn a_completely_empty_body_answers_the_account_key_query() {
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
            "the gate must start shut, or the assertion below proves nothing"
        );

        mark_request_sent(&query.id, "").await.expect(
            "a completely empty body is the same input as `{}`, which ruma substitutes for \
                 it before parsing. A homeserver that answers a key query with 200 and no body \
                 must not leave a product unable to bootstrap",
        );

        assert!(
            identity_status()
                .await
                .expect("reading the identity status must not fail")
                .account_keys_fetched,
            "an empty body is an answer, so it must lift the gate exactly as `{{}}` does"
        );

        bootstrap_identity()
            .await
            .expect("bootstrapping after an empty-bodied answer must be served");
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
