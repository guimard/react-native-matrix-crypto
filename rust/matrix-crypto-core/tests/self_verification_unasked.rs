//! Self-verification before anybody has asked the server anything.
//!
//! The first of the two refusals `request_self_flow` keeps apart, and the
//! one that is nothing more than an ordering problem: this process has not
//! yet asked what identity the account has, so it cannot know whether there
//! is one to join. The key query that lifts it is already in the very first
//! batch the pump hands out.
//!
//! The distinction from `tests/self_verification_no_identity.rs` is the whole
//! point of both files, and it is the same distinction
//! `tests/identity_bootstrap_ordering.rs` and
//! `tests/identity_bootstrap_existing.rs` draw for the bootstrap gate: "we do
//! not know" and "we know, and the answer is none" are different facts with
//! different remedies. Collapsing them would send a caller to create an
//! identity on the strength of a question never put.
//!
//! Its own file, and not a second test inside
//! `tests/self_verification.rs`, because the machine and the pump are
//! process-wide: a machine that has answered its account key query cannot be
//! made to un-answer it, and an integration test cannot reset the registry.
//! `tests/identity_bootstrap_*.rs` are split the same way for the same
//! reason.

use matrix_crypto_core::{
    create_machine, identity_status, request_self_flow, MachineConfig, MachineError,
};

const ACCOUNT: &str = "@alice:example.org";

#[test]
fn self_verification_is_refused_before_the_account_keys_have_been_fetched() {
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

        // Deliberately not drained and deliberately not answered. The pump
        // owes an account key query at this point; leaving it unanswered is
        // the state this test is about.
        let status = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            !status.account_keys_fetched,
            "nothing has been answered, so nothing has been asked as far as this \
             process is concerned: {status:?}"
        );

        assert_eq!(
            request_self_flow().await.err(),
            Some(MachineError::AccountKeysNotFetched),
            "a device that has not asked cannot know whether the account has an \
             identity to join, and must say so rather than guess"
        );

        assert_eq!(
            identity_status()
                .await
                .expect("reading the identity status must not fail"),
            status,
            "a refused request must leave the account exactly as it found it"
        );
    });
}
