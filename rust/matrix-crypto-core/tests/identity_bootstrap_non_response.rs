//! A response that is neither a success nor a conforming Matrix error must
//! not open the bootstrap gate.
//!
//! Task 1 refused the two shapes the Matrix specification defines: a standard
//! error body, which must carry a top-level `errcode`, and a user-interactive
//! authentication challenge, which carries `flows` instead. That covers every
//! conforming Matrix error and nothing else, and a probe against the vendored
//! crate then measured what still got through. This file is that measured
//! list, one case at a time.
//!
//! For `/keys/query`, which is the endpoint the bootstrap gate reads:
//! `{}`, a completely empty body, a gateway's own JSON error carrying no
//! `errcode` such as `{"error":"Bad Gateway"}`, and a JSON **array** were all
//! accepted and all lifted the gate. The array is the one reasoning gets
//! wrong: serde reads a struct from a sequence positionally, and every field
//! of that response is `#[serde(default)]`, so `[]` deserialises into a
//! flawless empty success.
//!
//! For `signing_keys_upload` and `to_device`, whose response types are
//! `Response {}` with no fields, ruma emits no body parse at all, so
//! literally every one of those bodies was accepted, HTML error pages and
//! `not json at all !!!` included. Accepting one marks the account's identity
//! *published* when the server holds nothing.
//!
//! # What is refusable, and what is not
//!
//! Most of that list is refusable from the body alone at no cost, because no
//! success body of any endpoint this crate handles is anything other than a
//! JSON **object**, and none of them declares `errcode`, `error` or `flows`
//! at the top level. Verified against the vendored response types rather than
//! assumed. That is what both acts below drive.
//!
//! Two are not refusable and never will be: `{}` and a completely empty body,
//! which ruma substitutes `{}` for before parsing. Those bytes are a genuine
//! `/keys/query` success meaning "the server answered and knows no identity
//! for this account", which is the exact fact that authorises minting one.
//! The library cannot tell that success from a 502 whose body happened to be
//! empty, because the only thing that separates them is the HTTP status and
//! no status crosses this boundary. They are deliberately absent from the
//! cases below: there is no body a check could reject them by, and asserting
//! that they are accepted is what the last act of this file already does.
//!
//! Its own process, for the reason `tests/pump_eviction.rs` gives: the
//! machine registry and the pump's bookkeeping are process-wide. The acts run
//! in one test and in this order because a refusal changes no state, so every
//! rejection can be driven against the same still-pending request before the
//! one accepted body finally lifts the gate.

use matrix_crypto_core::{
    bootstrap_identity, create_machine, identity_status, mark_request_sent, take_outgoing_requests,
    MachineConfig, MachineError, OutgoingRequest, SessionError,
};

const ACCOUNT: &str = "@alice:example.org";

/// A gateway's own JSON error. Not a Matrix error: no `errcode`, so Task 1's
/// check cannot see it. Measured as accepted, and it lifted the gate.
const GATEWAY_JSON: &str = r#"{"error":"Bad Gateway"}"#;

/// A JSON array. Measured as accepted for `/keys/query`, because serde reads
/// a struct from a sequence positionally and every field is defaulted. Both
/// shapes, because an empty sequence and a non-empty one take different paths
/// through that deserialiser.
const JSON_ARRAY_EMPTY: &str = "[]";
const JSON_ARRAY_NONEMPTY: &str = r#"[{"device_keys":{}}]"#;

/// Bodies with no JSON object anywhere in them. All measured as accepted for
/// `signing_keys_upload`, which has no body parse behind this check at all.
const HTML_502: &str = "<html><body>502 Bad Gateway</body></html>";
const GARBAGE: &str = "not json at all !!!";
const WHITESPACE_ONLY: &str = "   ";
const BARE_STRING: &str = r#""nope""#;
const JSON_NULL: &str = "null";
const JSON_NUMBER: &str = "42";

/// A real `/keys/query` success whose per-server `failures` map carries both
/// an `errcode` and an `error` **nested** inside it, once per unreachable
/// server. This must be accepted: only the top level is inspected, and
/// refusing this would break every key query that touches a server that is
/// down. This is the half of the new `error` rule that has to be right.
const FAILURE_WITH_NESTED_ERROR: &str =
    r#"{"device_keys":{},"failures":{"example.org":{"errcode":"M_UNKNOWN","error":"boom"}}}"#;

#[test]
fn a_body_that_is_not_a_response_cannot_open_the_bootstrap_gate() {
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

        // --- Act 1: the key query, where a wrong accept mints an identity ---

        let batch = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let query = find(&batch, "keys_query", names_the_account);

        for (body, what) in [
            (
                GATEWAY_JSON,
                "a gateway's own JSON error carries no `errcode`, so the Matrix error rule \
                 cannot see it. No success shape of any endpoint here declares a top-level \
                 `error`, so refusing it costs nothing",
            ),
            (
                JSON_ARRAY_EMPTY,
                "a JSON array is not a response body. serde reads a struct from a sequence \
                 positionally and every field of this one is defaulted, so `[]` deserialises \
                 into a flawless empty success and lifts the gate",
            ),
            (
                JSON_ARRAY_NONEMPTY,
                "same, with a non-empty sequence, which takes a different path through that \
                 deserialiser",
            ),
        ] {
            assert_eq!(
                mark_request_sent(&query.id, body).await,
                Err(SessionError::MalformedPayload),
                "reported for a key query, {what}"
            );
            assert!(
                !identity_status()
                    .await
                    .expect("reading the identity status must not fail")
                    .account_keys_fetched,
                "a refused body must leave the gate exactly as closed as it was, for {body:?}"
            );
            assert_eq!(
                bootstrap_identity().await,
                Err(MachineError::AccountKeysNotFetched),
                "this is the assertion the file exists for: served here, {body:?} mints a \
                 second identity for the account and silently invalidates every verification \
                 anyone has ever made of it"
            );
        }

        // --- Act 3, driven early: the same rules on a still-pending id ------
        //
        // These were already refused for this endpoint before this task,
        // because `/keys/query` has fields and its own parse rejects them.
        // Asserted anyway: the check that now refuses them is a different one,
        // and a rule that used to be enforced downstream must not quietly stop
        // being enforced when it moves upstream.
        for body in [
            HTML_502,
            GARBAGE,
            WHITESPACE_ONLY,
            BARE_STRING,
            JSON_NULL,
            JSON_NUMBER,
        ] {
            assert_eq!(
                mark_request_sent(&query.id, body).await,
                Err(SessionError::MalformedPayload),
                "{body:?} is not a key query response and must stay refused"
            );
        }

        // --- The half that has to be right: no false refusal ---------------

        mark_request_sent(&query.id, FAILURE_WITH_NESTED_ERROR)
            .await
            .expect(
                "a success whose `failures` map carries a nested `errcode` and `error` must be \
                 accepted; refusing it would break every key query that touches an unreachable \
                 server, which is a worse bug than the one being fixed",
            );

        assert!(
            identity_status()
                .await
                .expect("reading the identity status must not fail")
                .account_keys_fetched,
            "a real answer must still lift the gate. If this fails the cure is worse than the \
             disease: no product could ever bootstrap"
        );

        bootstrap_identity()
            .await
            .expect("bootstrapping after a real answer must be served");

        // --- Act 3: the fieldless kind, where this check is the only one ---
        //
        // `signing_keys_upload`'s success response is `Response {}`, so ruma
        // emits no body parse and nothing downstream of this check exists.
        // Every one of these was measured as accepted, and accepting one marks
        // the identity published while the server holds nothing.

        let published = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let upload = find(&published, "signing_keys_upload", |_| true);

        for body in [
            HTML_502,
            GARBAGE,
            WHITESPACE_ONLY,
            BARE_STRING,
            JSON_NULL,
            JSON_NUMBER,
            JSON_ARRAY_EMPTY,
            JSON_ARRAY_NONEMPTY,
            GATEWAY_JSON,
        ] {
            assert_eq!(
                mark_request_sent(&upload.id, body).await,
                Err(SessionError::MalformedPayload),
                "{body:?} is not a signing keys upload response. This endpoint has no body \
                 parse at all, so accepting it marks the account's identity published while \
                 the server holds nothing, and nothing afterwards disagrees"
            );
        }

        // And the real success, which is an empty object, must still be taken:
        // the id survived every refusal above, by the same rule that makes the
        // authentication retry an ordinary second send.
        mark_request_sent(&upload.id, "{}")
            .await
            .expect("the endpoint's real success response is `{}` and must be accepted");
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
