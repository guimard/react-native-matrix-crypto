//! `request_self_flow` must read the gate before it broadcasts anything,
//! including on a store that already holds an identity.
//!
//! # The fourth instance of one shape
//!
//! `recovery.rs`'s `restore` documents and repairs it: an
//! `account_keys_fetched` check nested inside `!identity_known`, so a store
//! that already holds a public identity skips it entirely. The seventh round
//! repaired that one call and did not look for the others.
//!
//! `request_self_flow` had it. **Measured on the shipping tree**, a store
//! holding a *stale* identity in a process that had asked the server
//! nothing: `bootstrap_identity`, `create_identity`, `create_recovery` and
//! `recover_identity` all refused with `AccountKeysNotFetched`, and this
//! call returned a flow id and queued a to-device verification invitation to
//! every other device of the account, begun under the stale identity, with
//! the gate never consulted.
//!
//! It is a write, not a read, which is why the gate belongs in front of it.
//! By the call's own documentation, completing the flow signs the other
//! device with this device's self-signing key and asks the account's other
//! devices for the cross-signing seeds, and both act under whatever identity
//! this store happens to hold.
//!
//! Three doc comments claimed the call carried the gate: its own, at
//! `verification.rs`; `recovery.rs`'s list of the calls that check it first;
//! and `matrix-crypto-ffi`'s note that this call "is not, and must not
//! become, a way around `bootstrap_identity`'s gate". None of them was true,
//! and **deleting the whole guard left the suite green**, which is why this
//! file exists rather than a comment.
//!
//! # Why the store is built by a bare machine
//!
//! The window needs a store holding an identity while
//! `account_keys_answered()` is false. Inside one process those cannot be
//! arranged through this library's own surface, for the reason
//! `tests/recovery_stale_identity.rs` gives at length. So the earlier
//! process is built rather than simulated.

use matrix_crypto_core::{
    bootstrap_identity, create_identity, create_machine, create_recovery, identity_status,
    in_runtime, recover_identity, request_self_flow, share_scope_key, take_outgoing_requests,
    MachineConfig, MachineError,
};
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId};
use matrix_sdk_crypto::OlmMachine;
use matrix_sdk_sqlite::SqliteCryptoStore;

const ACCOUNT: &str = "@alice:example.org";
const DEVICE: &str = "DEVICEONE";
const SOMEBODY_ELSE: &str = "@bob:example.org";
const PASSPHRASE: &str = "recovery-test-passphrase";
const STORE_PASSPHRASE: &str = "test-passphrase";

#[test]
fn a_self_verification_is_not_a_way_around_the_gate() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    // ---- The earlier process: a store with an identity in it -----------
    {
        let store_path = store_path.clone();
        futures::executor::block_on(in_runtime(async move {
            let user: OwnedUserId = ACCOUNT.parse().expect("a literal user id parses");
            let device: OwnedDeviceId = DEVICE.into();
            let store = SqliteCryptoStore::open(&store_path, Some(STORE_PASSPHRASE))
                .await
                .expect("a store must be creatable at a temporary path");
            let machine = OlmMachine::with_store(&user, &device, store, None)
                .await
                .expect("a bare machine must open over that store");
            machine
                .bootstrap_cross_signing(false)
                .await
                .expect("a bare machine can bootstrap its own identity");
            drop(machine);
        }));
    }

    futures::executor::block_on(in_runtime(async move {
        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: DEVICE.to_string(),
            store_path,
            store_passphrase: Some(STORE_PASSPHRASE.to_string()),
        })
        .await
        .expect("the library must reopen the store the earlier process wrote");

        let premise = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            premise.identity_known && premise.private_keys_held,
            "the premise is a store that already holds an identity: {premise:?}"
        );
        assert!(
            !premise.account_keys_fetched,
            "and a process that has asked the server nothing: {premise:?}"
        );

        // Upstream must have another user to ask about, so that the queries
        // counted below can only have come from this library's refusals.
        share_scope_key("!s:example.org", &[SOMEBODY_ELSE.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let _ = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");

        // The four that already refused, asserted here so this file states
        // the whole shape rather than only the half it repairs.
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::AccountKeysNotFetched)
        );
        assert_eq!(
            create_identity().await,
            Err(MachineError::AccountKeysNotFetched)
        );
        assert_eq!(
            create_recovery(PASSPHRASE, &[]).await.err(),
            Some(MachineError::AccountKeysNotFetched)
        );
        assert_eq!(
            recover_identity(PASSPHRASE, &[]).await,
            Err(MachineError::AccountKeysNotFetched)
        );

        // ---- The fifth, which used to be served ------------------------
        assert_eq!(
            request_self_flow().await.err(),
            Some(MachineError::AccountKeysNotFetched),
            "THIS is the assertion the file exists for. Served here, this call broadcasts a \
             verification invitation to every other device of the account, begun under an \
             identity the server has never been asked about, and completing it signs another \
             device with this device's self-signing key and imports the account's \
             cross-signing seeds under that same identity"
        );

        // And the refusal is recoverable in the same way the others are:
        // it queues the query that lifts it.
        let batch = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert!(
            batch
                .iter()
                .any(|request| request.kind == "keys_query" && names_the_account(&request.body)),
            "the refusal must queue the key query that lifts it, or a store that already \
             holds an identity can never self-verify at all. Got {:?}",
            batch.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>()
        );
        assert!(
            !batch.iter().any(|request| request.kind == "to_device"),
            "and nothing may have gone out to the account's other devices. Got {:?}",
            batch.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>()
        );
    }));
}

/// Whether a `/keys/query` body's `device_keys` map names this account.
fn names_the_account(body: &str) -> bool {
    let parsed: serde_json::Value = serde_json::from_str(body).expect("a pump body must be JSON");
    parsed
        .get("device_keys")
        .and_then(|users| users.get(ACCOUNT))
        .is_some()
}
