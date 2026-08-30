//! A request that was sent and *failed* must not satisfy the ordering gate.
//!
//! No HTTP status crosses this library's boundary: `markRequestSent` takes an
//! id and a body, and the body is wrapped in a hardcoded status-200
//! `http::Response` before it is parsed. Every field of every response shape
//! this crate handles is `#[serde(default)]`. Put those two together and a
//! homeserver **error** body deserialises into a flawless, empty, successful
//! `/keys/query` response -- which the gate in `signing.rs` reads as "the
//! server answered, and this account has no identity", the one fact that
//! authorises minting a new one.
//!
//! That is not an exotic misuse. `markRequestSent(id, await res.text())`
//! without branching on the status is the shape of a first-draft fetch
//! wrapper, and the outcome is that a rate-limited or 502'd key query mints
//! a second identity and silently invalidates every verification anyone has
//! ever made of this account. Exactly the catastrophe the gate exists to
//! prevent, reached through an ordinary server error rather than misuse.
//!
//! Two acts, because the same root cause has two victims with different
//! shapes:
//!
//! 1. A standard Matrix error body reported for a key query.
//! 2. A user-interactive authentication challenge reported for the
//!    signing-keys upload. That endpoint's success response is `Response {}`,
//!    so a reported challenge would succeed and mark an identity *published*
//!    that never was -- undetectably, because nothing afterwards disagrees.
//!    This one carries no `errcode` at all, so it is caught by a different
//!    test than act 1 and both need driving.
//!
//! Its own process, for the reason `tests/pump_eviction.rs` gives: the
//! machine registry and the pump's bookkeeping are process-wide.

use matrix_crypto_core::{
    bootstrap_identity, create_machine, identity_status, mark_request_sent, take_outgoing_requests,
    MachineConfig, MachineError, OutgoingRequest, SessionError,
};

const ACCOUNT: &str = "@alice:example.org";

/// What a rate-limited homeserver actually returns. The specification
/// requires every error response to carry a top-level `errcode`, which is
/// what makes this recognisable without a status.
const RATE_LIMITED: &str =
    r#"{"errcode":"M_LIMIT_EXCEEDED","error":"Too Many Requests","retry_after_ms":2000}"#;

/// The 401 body the signing-keys upload always draws on its first attempt.
/// No `errcode`: a first user-interactive challenge is not an error
/// response, it is a challenge, and `flows` is what says so.
const CHALLENGE: &str =
    r#"{"flows":[{"stages":["m.login.password"]}],"params":{},"session":"a-session-handle"}"#;

/// A `/keys/query` answer naming no identity for this account.
const NO_IDENTITY: &str = r#"{"device_keys":{}}"#;

#[test]
fn a_failed_request_reported_as_sent_neither_lifts_the_gate_nor_publishes() {
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

        // --- Act 1: an error body must not answer the account key query ---

        let batch = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let account_query = find(&batch, "keys_query", names_the_account);

        let refused = mark_request_sent(&account_query.id, RATE_LIMITED).await;
        assert_eq!(
            refused,
            Err(SessionError::MalformedPayload),
            "an error body is not this endpoint's response and must be refused. Accepted, it \
             deserialises into a successful empty key query and tells the gate the account has \
             no identity"
        );

        let after_error = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            !after_error.account_keys_fetched,
            "a request that failed was not answered: {after_error:?}"
        );

        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::AccountKeysNotFetched),
            "a failed key query must leave the gate exactly as closed as it was. This is the \
             assertion the whole file exists for: served here, a server error mints a second \
             identity for the account"
        );

        // The refusal is retriable, not terminal: the entry survives, so the
        // caller that got a 429 sends again and reports the real answer.
        mark_request_sent(&account_query.id, NO_IDENTITY)
            .await
            .expect("the same id must still be resolvable after a refused body");
        assert!(
            identity_status()
                .await
                .expect("reading the identity status must not fail")
                .account_keys_fetched,
            "a real answer, on the same id, must lift the gate"
        );

        bootstrap_identity()
            .await
            .expect("bootstrapping after a real answer must be served");

        // --- Act 2: a challenge must not publish the identity ---

        let published = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let signing_keys = find(&published, "signing_keys_upload", |_| true);

        let refused = mark_request_sent(&signing_keys.id, CHALLENGE).await;
        assert_eq!(
            refused,
            Err(SessionError::MalformedPayload),
            "a user-interactive authentication challenge is not this endpoint's response. \
             Accepted, it marks the identity published while the server still holds nothing, \
             and nothing later disagrees"
        );

        // And the ordinary retry after a 401 still works on the same id,
        // which is the whole reason a refusal here has to leave the entry in
        // place rather than consume it.
        mark_request_sent(&signing_keys.id, "{}")
            .await
            .expect("the same id must still be resolvable after a refused challenge");
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
