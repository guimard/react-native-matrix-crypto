//! An answer carrying the identity that replaced this store's, which
//! upstream could not read, must not be treated as the comparison that
//! never happened.
//!
//! # The window, and why "upstream holds an identity" is not enough
//!
//! `tests/recovery_stale_identity.rs` builds the case this file extends: a
//! store left on disk by an earlier process holds a **complete** private
//! cross-signing identity, and the account has since been reset from another
//! device, so those private keys belong to an identity the server has thrown
//! away. Nothing local can tell that apart from a healthy store. Only a
//! `/keys/query` dislodges it, because upstream's `check_private_identity`
//! compares the public identity the answer carries against the private one
//! in the store and drops what disagrees.
//!
//! That store also holds the **public** identity the earlier process
//! published. So `machine.get_identity(account)` answers `Some` from the
//! first moment, before this process has asked anything. A rule that lifted
//! the gate on "upstream holds an identity for this account" would therefore
//! lift it on an answer upstream had just thrown away, and
//! `create_recovery` would go on to write a recovery for private keys the
//! comparison never reached. It opens perfectly, restores an identity the
//! account no longer has, and says nothing at the time.
//!
//! `session::answer_about_this_account` requires the stronger thing:
//! upstream must hold **the identity this answer asserted**, compared by
//! master key. That is what this file pins, and it is the only test in this
//! repository that can: every other one starts from a store with no identity
//! in it, where `Some` and "the answer's" are the same condition.
//!
//! # The three acts
//!
//! 1. **The premise**: the reopened store holds the complete private keys
//!    *and* a public identity, and this process has asked nothing.
//! 2. **The corrupted replacement**: the answer carries the identity the
//!    account has now, with one character of one base64 signature changed.
//!    Upstream cannot assemble it, keeps the old public identity, and never
//!    reaches the private-key comparison. The gate must stay shut, and
//!    `create_recovery` must still refuse.
//! 3. **The control**: the same answer, untouched. Upstream stores the new
//!    identity, drops the private keys that disagree with it, and
//!    `create_recovery` says this device holds none, which is true.

use matrix_crypto_core::{
    create_machine, create_recovery, identity_status, in_runtime, mark_request_sent,
    share_scope_key, take_outgoing_requests, MachineConfig, MachineError, OutgoingRequest,
};
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId};
use matrix_sdk_crypto::OlmMachine;
use matrix_sdk_sqlite::SqliteCryptoStore;
use serde_json::{json, Value};

const ACCOUNT: &str = "@alice:example.org";
const DEVICE: &str = "DEVICEONE";
const SOMEBODY_ELSE: &str = "@bob:example.org";

/// Literals with no account behind them, like the `store_passphrase` every
/// other test in this crate hands to `MachineConfig`.
const PASSPHRASE: &str = "recovery-test-passphrase";
const STORE_PASSPHRASE: &str = "test-passphrase";

/// The identity a bare machine published, in the shape a homeserver sends
/// it: the account named under `device_keys`, and all three cross-signing
/// keys.
fn published_identity(bootstrap: &matrix_sdk_crypto::CrossSigningBootstrapRequests) -> Value {
    let request = &bootstrap.upload_signing_keys_req;
    json!({
        "device_keys": { ACCOUNT: {} },
        "failures": {},
        "master_keys": { ACCOUNT: request.master_key },
        "self_signing_keys": { ACCOUNT: request.self_signing_key },
        "user_signing_keys": { ACCOUNT: request.user_signing_key },
    })
}

/// One base64 character of the self-signing key's signature, changed to a
/// different one. Nothing else about the answer moves: the master key it
/// asserts is still the replacement identity's, and still deserialises.
fn flip_a_signature_character(answer: &Value) -> String {
    let mut body = answer.clone();
    let signatures = body["self_signing_keys"][ACCOUNT]["signatures"][ACCOUNT]
        .as_object_mut()
        .expect("a minted self-signing key carries a signature from the master key");
    let key_id = signatures
        .keys()
        .next()
        .expect("at least one signature")
        .clone();
    let signature = signatures[&key_id]
        .as_str()
        .expect("a signature is a string")
        .to_string();
    let mut characters: Vec<char> = signature.chars().collect();
    characters[0] = if characters[0] == 'A' { 'B' } else { 'A' };
    signatures[&key_id] = Value::String(characters.into_iter().collect());
    body.to_string()
}

#[test]
fn an_unreadable_replacement_does_not_pass_for_the_comparison_it_prevented() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    // ---- The earlier process ------------------------------------------
    //
    // A bare upstream machine over a real store at this path, bootstrapped
    // and dropped, exactly as `tests/recovery_stale_identity.rs` does it and
    // for the same reason: what it leaves on disk is what a previous run of
    // a real product leaves, not something this process arranged through a
    // surface that would have set the gate.
    let replacement = {
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
            // while the store above sat on disk.
            let other_device: OwnedDeviceId = "DEVICETWO".into();
            let elsewhere = OlmMachine::new(&user, &other_device).await;
            let reset = elsewhere
                .bootstrap_cross_signing(false)
                .await
                .expect("a second machine can mint the identity that replaces the first");

            // Dropped inside the runtime: the store's pooled connections
            // close through `spawn_blocking`.
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
            "this test is about a store that already holds the account's private signing \
             keys: {status:?}"
        );
        assert!(
            status.identity_known,
            "AND about one that already holds a PUBLIC identity, which is what makes \
             `get_identity` answer `Some` before anything has been asked. Without this the \
             rule under test here is indistinguishable from the weaker one: {status:?}"
        );
        assert!(
            !status.account_keys_fetched,
            "and about a process that has asked the server nothing: {status:?}"
        );

        // Give upstream another user to ask about, so its own-account
        // fallback never fires and the queries below can only have come
        // from the refusals. Same construction as
        // `tests/recovery_stale_identity.rs`.
        share_scope_key("!s:example.org", &[SOMEBODY_ELSE.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let before = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert_eq!(
            account_queries(&before),
            0,
            "premise broken: upstream volunteered an own-account key query, so the acts \
             below can no longer tell a refusal's own query apart from upstream's. Got {:?}",
            kinds(&before)
        );

        // ---- Act two: the corrupted replacement ----------------------
        let query = fresh_account_key_query().await;
        mark_request_sent(&query.id, &flip_a_signature_character(&replacement))
            .await
            .expect("the answer must still be accepted");

        let status = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            !status.account_keys_fetched,
            "THIS is the assertion the file exists for. Upstream holds an identity for this \
             account, and it is not the one this answer asserted: it is the one this store \
             arrived with. Reading `get_identity` as `Some` and stopping there would lift \
             the gate on an answer upstream threw away: {status:?}"
        );
        assert!(
            status.account_keys_answer_unsettled,
            "and the caller must be able to see that an answer arrived and settled nothing: \
             {status:?}"
        );
        assert!(
            status.private_keys_held,
            "upstream never reached the private-key comparison, because it could not \
             assemble the identity that would have triggered it. That is exactly why this \
             answer must not count: {status:?}"
        );
        assert_eq!(
            create_recovery(PASSPHRASE, &[]).await.err(),
            Some(MachineError::AccountKeysNotFetched),
            "so a recovery written now would be written for private keys that belong to an \
             identity the account has already replaced, and would open perfectly onto \
             nothing on the far side of the round trip"
        );

        // ---- Act three: the control ----------------------------------
        //
        // The same replacement identity, uncorrupted. Upstream stores it,
        // the comparison happens, and the stale private keys go.
        let query = fresh_account_key_query().await;
        mark_request_sent(&query.id, &replacement.to_string())
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
            !status.account_keys_answer_unsettled,
            "and the diagnosis must clear: {status:?}"
        );
        assert!(
            !status.private_keys_held,
            "upstream drops a private identity a key query has contradicted, which is the \
             comparison act two prevented: {status:?}"
        );
        assert_eq!(
            create_recovery(PASSPHRASE, &[]).await.err(),
            Some(MachineError::PrivateKeysNotHeld),
            "and the honest answer arrives instead of a recovery for keys the account \
             replaced"
        );
    }));
}

/// Refuses a `create_recovery` to have a fresh account key query queued,
/// drains the pump, and returns that query.
async fn fresh_account_key_query() -> OutgoingRequest {
    assert_eq!(
        create_recovery(PASSPHRASE, &[]).await.err(),
        Some(MachineError::AccountKeysNotFetched),
        "the refusal is what queues the out-of-band query this returns"
    );
    let batch = take_outgoing_requests()
        .await
        .expect("draining the pump must not fail");
    batch
        .iter()
        .find(|request| request.kind == "keys_query" && names_the_account(&request.body))
        .unwrap_or_else(|| {
            panic!(
                "no key query naming this account in the batch; got {:?}",
                kinds(&batch)
            )
        })
        .clone()
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

/// Whether a `/keys/query` body's `device_keys` map names this account.
fn names_the_account(body: &str) -> bool {
    let parsed: Value = serde_json::from_str(body).expect("a pump body must be JSON");
    parsed
        .get("device_keys")
        .and_then(|users| users.get(ACCOUNT))
        .is_some()
}
