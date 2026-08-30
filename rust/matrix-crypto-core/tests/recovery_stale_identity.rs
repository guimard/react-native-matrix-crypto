//! Writing a recovery for private signing keys the account has already
//! replaced, and the gate that stops it.
//!
//! # The window, and why it is not theoretical
//!
//! `signing.rs` states this repository's position at length: a store
//! restored from a backup, or one whose account had its identity reset from
//! another device, holds a **complete** private identity the server has
//! already thrown away. Nothing local can tell that apart from a healthy
//! store, because completeness is exactly what both look like. Only a
//! `/keys/query` dislodges it: upstream's `check_private_identity` compares
//! the public identity the answer carries against the private one in the
//! store and drops what disagrees.
//!
//! `bootstrap_identity` and `recover_identity` both refuse until that query
//! has been answered. `create_recovery` did not, and the consequence is
//! quieter than the one the bootstrap gate prevents and lasts longer: the
//! recovery it writes is well formed, opens with the passphrase, and
//! restores an identity the account no longer has. The user finds out at the
//! other end of the round trip, on a device that has lost its store, and
//! what they are told there is that their stored recovery cannot be read.
//!
//! # Why this file exists rather than a unit test
//!
//! The window needs a store that holds private cross-signing keys while
//! `account_keys_answered()` is false. Inside one process those two cannot
//! be arranged through this library's own surface: holding the keys means
//! something bootstrapped or recovered, and both refuse until a key query
//! has been answered, after which the flag is true for the process lifetime
//! and has no reset. The review that found this could not demonstrate it for
//! exactly that reason.
//!
//! So the earlier process is built rather than simulated: a bare upstream
//! `OlmMachine` over a real `SqliteCryptoStore` at a path of this test's
//! choosing, bootstrapped and then dropped. What it leaves on disk is what a
//! previous run of a real product leaves, and the library then opens it
//! having asked the server nothing. That is the shape a relaunch takes, and
//! it is the only construction in this repository that produces it.
//!
//! # The three acts
//!
//! 1. **The premise, asserted rather than assumed**: the reopened store
//!    holds the complete private keys and this process has asked nothing.
//! 2. **The gate**: `create_recovery` refuses, and queues the query that
//!    lifts it. The query is not one upstream volunteered; a key is shared
//!    with somebody else first so that upstream's own-account fallback never
//!    fires, the same construction
//!    `tests/identity_bootstrap_recovery.rs` documents.
//! 3. **What the gate was protecting**: the answer names a *different*
//!    identity, because the account was reset from another device while this
//!    store sat on disk. Upstream drops the stale private keys, and
//!    `create_recovery` then says this device holds none, which is true.
//!    Without the gate the same run would have written a recovery for the
//!    keys of an identity that no longer exists, and said nothing.

use matrix_crypto_core::{
    create_machine, create_recovery, identity_status, in_runtime, mark_request_sent,
    share_scope_key, take_outgoing_requests, MachineConfig, MachineError, OutgoingRequest,
};
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId};
use matrix_sdk_crypto::OlmMachine;
use matrix_sdk_sqlite::SqliteCryptoStore;

const ACCOUNT: &str = "@alice:example.org";
const DEVICE: &str = "DEVICEONE";
const SOMEBODY_ELSE: &str = "@bob:example.org";

/// A literal with no account behind it, like the `store_passphrase` every
/// other test in this crate hands to `MachineConfig`.
const PASSPHRASE: &str = "recovery-test-passphrase";
const STORE_PASSPHRASE: &str = "test-passphrase";

/// The identity a bare machine published, in the shape a `/keys/query`
/// answer carries it.
fn published_identity(bootstrap: &matrix_sdk_crypto::CrossSigningBootstrapRequests) -> String {
    let request = &bootstrap.upload_signing_keys_req;
    serde_json::json!({
        "master_keys": { ACCOUNT: request.master_key },
        "self_signing_keys": { ACCOUNT: request.self_signing_key },
        "user_signing_keys": { ACCOUNT: request.user_signing_key },
    })
    .to_string()
}

/// Whether a `/keys/query` body's `device_keys` map names this account.
fn names_the_account(body: &str) -> bool {
    let parsed: serde_json::Value = serde_json::from_str(body).expect("a pump body must be JSON");
    parsed
        .get("device_keys")
        .and_then(|users| users.get(ACCOUNT))
        .is_some()
}

/// How many `/keys/query` requests in this batch name this account.
fn account_queries(batch: &[OutgoingRequest]) -> usize {
    batch
        .iter()
        .filter(|request| request.kind == "keys_query" && names_the_account(&request.body))
        .count()
}

fn kinds(batch: &[OutgoingRequest]) -> Vec<&str> {
    batch.iter().map(|request| request.kind.as_str()).collect()
}

#[test]
fn a_recovery_is_not_written_for_keys_the_server_has_not_been_asked_about() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    // ---- The earlier process ------------------------------------------
    //
    // A bare upstream machine over a real store at this path, bootstrapped
    // and dropped. Nothing of this library is involved, which is the point:
    // what is left on disk is what a previous run leaves, not something this
    // process arranged through a surface that would have set the flag.
    let replacement_identity = {
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

            // The identity the account has *now*, minted somewhere else
            // while the store above sat on disk. A second machine for the
            // same user, in memory, so the two identities are genuinely
            // different rather than a copy with a field edited.
            let other_device: OwnedDeviceId = "DEVICETWO".into();
            let elsewhere = OlmMachine::new(&user, &other_device).await;
            let reset = elsewhere
                .bootstrap_cross_signing(false)
                .await
                .expect("a second machine can mint the identity that replaces the first");

            // Dropped inside the runtime: the store's pooled connections
            // close through `spawn_blocking` and need a runtime context to
            // do it, exactly as opening it did.
            drop(machine);
            published_identity(&reset)
        }))
    };

    futures::executor::block_on(in_runtime(async move {
        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: DEVICE.to_string(),
            store_path,
            store_passphrase: Some(STORE_PASSPHRASE.to_string()),
        })
        .await
        .expect("the library must reopen the store the earlier process wrote");

        // ---- Act one: the premise ------------------------------------
        let status = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            status.private_keys_held,
            "this test is about a store that already holds the account's \
             private signing keys; without them there is nothing to write a \
             recovery for and nothing below is about anything: {status:?}"
        );
        assert!(
            !status.account_keys_fetched,
            "and about a process that has asked the server nothing. If this \
             is true the window under test does not exist in this run: \
             {status:?}"
        );

        // Give upstream something else to ask about, so its own-account
        // fallback stops firing and the query in act two can only have come
        // from the refusal. The same construction, and the same reason, as
        // `tests/identity_bootstrap_recovery.rs`.
        share_scope_key("!s:example.org", &[SOMEBODY_ELSE.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let before = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert_eq!(
            account_queries(&before),
            0,
            "premise broken: upstream volunteered an own-account key query on \
             a machine that already has another user to ask about, so act two \
             can no longer tell the refusal's own query apart from upstream's. \
             Got {:?}",
            kinds(&before)
        );

        // ---- Act two: the gate ---------------------------------------
        assert_eq!(
            create_recovery(PASSPHRASE, &[]).await.err(),
            Some(MachineError::AccountKeysNotFetched),
            "the private keys this store holds may belong to an identity the \
             account has already replaced, and only a key query can say. \
             Writing a recovery for them produces account data that opens \
             perfectly and restores an identity that no longer exists, and \
             says nothing at the time"
        );

        let after = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert_eq!(
            account_queries(&after),
            1,
            "the refusal must queue the key query that lifts it. Nothing else \
             can here, and without it the refusal is permanent for every \
             process that encrypted anything before writing a recovery. Got \
             {:?}",
            kinds(&after)
        );
        let account_query = after
            .iter()
            .find(|request| request.kind == "keys_query" && names_the_account(&request.body))
            .expect("just counted one");

        // ---- Act three: what the gate was protecting -----------------
        //
        // The answer names the identity the account has now, which is not
        // the one this store holds the private keys for. Upstream compares
        // and drops them.
        mark_request_sent(&account_query.id, &replacement_identity)
            .await
            .expect("answering the account key query must not fail");

        let status = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            status.account_keys_fetched && status.identity_known,
            "the answer must have landed: {status:?}"
        );
        assert!(
            !status.private_keys_held,
            "upstream drops a private identity a key query has contradicted, \
             which is the whole reason the gate above is not a formality: \
             before the query this device looked able to write a recovery, \
             and after it there is nothing to write: {status:?}"
        );

        assert_eq!(
            create_recovery(PASSPHRASE, &[]).await.err(),
            Some(MachineError::PrivateKeysNotHeld),
            "and the honest answer arrives instead of a recovery for keys the \
             account replaced. This is the assertion the gate buys: the same \
             call, one key query later, tells the truth"
        );
    }));
}
