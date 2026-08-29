//! The ordering gate, which is the whole reason `bootstrap_identity` is not
//! a one-line wrapper.
//!
//! `bootstrap_cross_signing(false)` is idempotent once this device holds a
//! complete private identity: called twice it yields the same master key.
//! The trap is neither that call nor its `reset` sibling. It is a **fresh
//! login that calls it before an own-account key query has completed**:
//! upstream branches on `identity.is_empty()`
//! (`matrix-sdk-crypto-0.18.0/src/machine/mod.rs:676`), finds the local
//! identity empty, mints a *second* identity, and publishing it silently
//! invalidates every verification every other device of this account ever
//! made. No error, no warning, and the damage is to other people's trust in
//! this user rather than to anything this process can later notice.
//!
//! So the gate this test drives is deliberately **not** "is the local
//! identity empty". That is the question upstream already asks, and asking
//! it again would refuse nothing upstream does not already accept. The gate
//! is "have we asked the server for this account's keys, and did the answer
//! say there is no identity" -- two facts, neither of which an empty local
//! identity implies.
//!
//! Its own file, not a second `#[test]` beside the others: the machine
//! registry and the pump's bookkeeping are process-wide, cargo gives each
//! file under `tests/` its own process, and "this machine has never fetched
//! its own account's keys" is a property of a whole process that no other
//! test in the same one could be allowed to disturb.

use matrix_crypto_core::{
    bootstrap_identity, create_machine, identity_status, take_outgoing_requests, MachineConfig,
    MachineError,
};

const ACCOUNT: &str = "@alice:example.org";

#[test]
fn bootstrapping_before_the_account_keys_have_been_fetched_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    // A bare `futures::executor::block_on`, no `#[tokio::test]`: every call
    // below is a library call responsible for reaching for the runtime it
    // needs, so this test enters with genuinely no runtime context anywhere
    // and a library function that forgot its own `in_runtime` panics here
    // rather than being carried by a context this test supplied. Same
    // reasoning as `tests/pump_eviction.rs`.
    futures::executor::block_on(async move {
        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: "DEVICE1".to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        // The state the trap needs: nothing asked, nothing known, nothing
        // held. Asserted rather than assumed, because a status that reported
        // `account_keys_fetched` for a machine that has never sent a request
        // would make the refusal below unreachable and this test vacuous.
        let before = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            !before.account_keys_fetched,
            "a machine that has resolved no request has asked the server nothing: {before:?}"
        );
        assert!(
            !before.identity_known,
            "nothing can be known about an account nobody has asked about: {before:?}"
        );
        assert!(
            !before.private_keys_held,
            "a fresh store holds no private signing keys: {before:?}"
        );

        // The refusal. This is the assertion the milestone exists for.
        let refusal = bootstrap_identity().await;
        assert_eq!(
            refusal,
            Err(MachineError::AccountKeysNotFetched),
            "bootstrapping before the account's keys have been fetched must be refused, \
             not served: upstream would mint a second identity and invalidate every \
             verification on the account"
        );

        // And it must refuse *without* minting anything, which is a separate
        // claim: a gate that refused after calling upstream would have done
        // the damage and then reported it.
        let after = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert_eq!(
            after, before,
            "a refused bootstrap must leave the account exactly as it found it"
        );

        // The refusal is actionable rather than a dead end. A caller told
        // "the account's keys have not been fetched" has no other way to
        // fetch them: upstream only volunteers an own-account key query
        // while this account is not yet tracked
        // (`identities/manager.rs:836-852`), so after a process restart on a
        // machine that has already tracked itself, nothing would ever ask
        // again and the gate could never be satisfied. So the refusal queues
        // the question it is refusing for.
        let batch = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let account_queries: Vec<_> = batch
            .iter()
            .filter(|request| request.kind == "keys_query")
            .filter(|request| names_the_account(&request.body))
            .collect();
        assert!(
            !account_queries.is_empty(),
            "the refusal must queue the key query that lifts it, or a caller has no way \
             to satisfy the gate; got {:?}",
            batch.iter().map(|r| &r.kind).collect::<Vec<_>>()
        );
    });
}

/// Whether a `/keys/query` body's `device_keys` map names this account.
///
/// Read out of the wire body the pump actually hands the product, not out
/// of any internal state: what matters is that the request the caller will
/// send asks about this account, and the body is the only thing the caller
/// sends.
fn names_the_account(body: &str) -> bool {
    let parsed: serde_json::Value = serde_json::from_str(body).expect("a pump body must be JSON");
    parsed
        .get("device_keys")
        .and_then(|users| users.get(ACCOUNT))
        .is_some()
}
