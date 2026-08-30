//! Self-verification against an account that has no identity at all.
//!
//! The second of the two refusals `request_self_flow` keeps apart, and the
//! one no retry fixes: the server *has* been asked and named no identity for
//! this account. There is nothing to join, and the answer is
//! `bootstrap_identity` rather than another attempt.
//!
//! Every field of ruma's own `/keys/query` response type is
//! `#[serde(default)]`, so the empty object below says exactly "this account
//! has no identity" -- which is the real answer a homeserver returns for an
//! account nobody has ever set cross-signing up on, and the same fixture
//! `tests/identity_bootstrap.rs` uses to open the bootstrap gate.
//!
//! Its own file for the reason `tests/self_verification_unasked.rs` gives:
//! the machine and the pump are process-wide, and each of these refusals
//! needs a differently-shaped one.

use matrix_crypto_core::{
    create_machine, identity_status, mark_request_sent, request_self_flow, take_outgoing_requests,
    MachineConfig, MachineError,
};

const ACCOUNT: &str = "@alice:example.org";

/// A `/keys/query` answer naming no identity for this account: the server has
/// been asked and has said there is none.
const NO_IDENTITY: &str = r#"{"device_keys":{}}"#;

/// Whether a `/keys/query` body's `device_keys` map names this account.
fn names_the_account(body: &str) -> bool {
    let parsed: serde_json::Value = serde_json::from_str(body).expect("a pump body must be JSON");
    parsed
        .get("device_keys")
        .and_then(|users| users.get(ACCOUNT))
        .is_some()
}

#[test]
fn self_verification_is_refused_when_the_account_has_no_identity_to_join() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(async move {
        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: "NEWLOGIN".to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        // Matched on the user it asks about, not on its kind: `keys_query` is
        // one wire tag for this account's own query and everybody else's.
        let batch = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let account_query = batch
            .iter()
            .find(|request| request.kind == "keys_query" && names_the_account(&request.body))
            .expect("a fresh machine must owe a key query for its own account");
        mark_request_sent(&account_query.id, NO_IDENTITY)
            .await
            .expect("answering the account key query must not fail");

        let status = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            status.account_keys_fetched,
            "the account key query was answered: {status:?}"
        );
        assert!(
            !status.identity_known,
            "the answer named no identity. If this fails the fixture is wrong and the \
             refusal below would be the other one: {status:?}"
        );

        assert_eq!(
            request_self_flow().await.err(),
            Some(MachineError::IdentityNotKnown),
            "there is no identity to verify against, and saying so is what sends a \
             caller to `bootstrap_identity` instead of round the pump loop again"
        );
    });
}
