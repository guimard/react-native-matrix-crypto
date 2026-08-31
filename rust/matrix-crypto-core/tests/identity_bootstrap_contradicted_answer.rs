//! An answer that says this account has no identity, arriving at a store
//! that already holds one, settles nothing.
//!
//! # The case, and why the previous rule let it through
//!
//! A store restored from a backup holds a **complete** private cross-signing
//! identity that the account may have replaced since. `signing.rs` states
//! this library's position on it at length, and
//! `tests/recovery_stale_identity.rs` proves the protection: a key query
//! carrying the replacement identity makes upstream compare it against the
//! private one in the store and drop what disagrees
//! (`check_private_identity` calling `clear_if_differs`,
//! `identities/manager.rs:418-443`).
//!
//! **That comparison is reached only from inside upstream's `master_keys`
//! loop.** An answer with no master key for this account never enters the
//! loop, so it never fires. Before this file existed, such an answer lifted
//! the gate through the negative branch, left the stale private keys reading
//! as held, and both `bootstrap_identity` and `create_recovery` then
//! proceeded. Measured on the shipped tree at the time:
//!
//! ```text
//! B4 S1 (after omitting answer): account_keys_fetched: true,
//!     identity_known: true, private_keys_held: true
//! B4 create_recovery AFTER omit: Ok(wrote a recovery)
//! B4 bootstrap_identity AFTER omit: Ok(republished)
//! ```
//!
//! A republication of a stale identity over the account's newer one, and a
//! recovery written for keys the account had already replaced. That is the
//! exact destruction `recovery_stale_identity.rs` exists to prevent, in the
//! one case that file never exercised, because its answer always carries the
//! replacement.
//!
//! # The rule
//!
//! `session::answer_about_this_account`'s negative branch now settles the
//! question only when upstream holds **no public identity** for this
//! account. A store that holds one is a store saying "this account has an
//! identity" while the answer says it has none, and those cannot both be
//! current: the Matrix protocol has no way to unpublish an identity, so an
//! account that had one still has one. The answer is stale, or from a server
//! that omitted the account, and it settles nothing.
//!
//! The rule was first written as "no public identity **and** no complete
//! private identity", and the private half was removed because sabotaging it
//! away turned no test red and the state it guarded turns out to be one
//! nothing writes: upstream stores private cross-signing keys only alongside
//! a public identity, and `Store::import_cross_signing_keys` imports nothing
//! at all when there is no public identity to check against
//! (`matrix-sdk-crypto-0.18.0/src/store/mod.rs:961-1002`). The check here is
//! what the private half would have caught anyway, one field earlier.
//!
//! The cost is a device whose store holds an identity meeting a server that
//! genuinely reports none. It refuses rather than republishing, and says so
//! through `account_keys_answer_unsettled`, which is the same trade this
//! gate is argued in throughout.
//!
//! # The two acts
//!
//! 1. **The omitting answer**: the gate stays shut, all three gated calls go
//!    on refusing, and the caller is told the answer settled nothing.
//! 2. **The control**: the same store, an answer that carries the identity
//!    the account really has. The gate lifts, upstream drops the stale
//!    private keys, and the honest refusals arrive instead.

use matrix_crypto_core::{
    bootstrap_identity, create_identity, create_machine, create_recovery, identity_status,
    in_runtime, mark_request_sent, recover_identity, share_scope_key, take_outgoing_requests,
    MachineConfig, MachineError, OutgoingRequest,
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

/// A real homeserver's real answer for an account it holds no identity for.
/// Synapse 1.159.0 and Dendrite 0.15.2, byte for byte with the account
/// substituted. Nothing about this body is malformed or unusual; what makes
/// it wrong here is the store it arrives at.
const OMITS_THE_IDENTITY: &str = r#"{"device_keys":{"@alice:example.org":{}},"failures":{},"master_keys":{},"self_signing_keys":{},"user_signing_keys":{}}"#;

#[test]
fn an_answer_contradicted_by_this_store_cannot_open_the_gate() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    // ---- The earlier process -------------------------------------------
    //
    // A bare upstream machine over a real store, bootstrapped and dropped:
    // what a previous run of a real product leaves on disk, and what a
    // restored backup looks like. A second machine mints the identity that
    // replaced it while this store sat there. Same construction as
    // `tests/recovery_stale_identity.rs`.
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

            let other_device: OwnedDeviceId = "DEVICETWO".into();
            let elsewhere = OlmMachine::new(&user, &other_device).await;
            let reset = elsewhere
                .bootstrap_cross_signing(false)
                .await
                .expect("a second machine can mint the identity that replaces the first");

            drop(machine);
            let request = &reset.upload_signing_keys_req;
            json!({
                "device_keys": { ACCOUNT: {} },
                "failures": {},
                "master_keys": { ACCOUNT: request.master_key },
                "self_signing_keys": { ACCOUNT: request.self_signing_key },
                "user_signing_keys": { ACCOUNT: request.user_signing_key },
            })
            .to_string()
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

        let premise = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            premise.private_keys_held && premise.identity_known,
            "this test is about a store that already holds both halves of an identity, which \
             is what a restored backup is: {premise:?}"
        );
        assert!(
            !premise.account_keys_fetched,
            "and about a process that has asked the server nothing: {premise:?}"
        );

        // Give upstream another user to ask about so its own-account
        // fallback never fires, and every account key query below is one
        // this library queued.
        share_scope_key("!s:example.org", &[SOMEBODY_ELSE.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let before = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert_eq!(
            account_queries(&before),
            0,
            "premise broken: upstream volunteered an own-account key query. Got {:?}",
            kinds(&before)
        );

        // ---- Act one: the omitting answer -----------------------------
        let query = fresh_account_key_query().await;
        mark_request_sent(&query.id, OMITS_THE_IDENTITY)
            .await
            .expect(
                "the body must still be accepted: it is a well-formed answer and \
                     upstream has to see it",
            );

        let status = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            !status.account_keys_fetched,
            "THIS is the assertion the file exists for. Lifted here, the stale private keys \
             this store holds are never put in front of a server answer, and the two calls \
             below republish an identity the account replaced and write a recovery for keys \
             it replaced: {status:?}"
        );
        assert!(
            status.account_keys_answer_unsettled,
            "and the caller must be told which refusal it is in, or it loops: {status:?}"
        );
        assert!(
            status.private_keys_held,
            "the stale keys are still held, and that is the point rather than a side effect: \
             nothing has compared them with anything, so nothing may act on them: {status:?}"
        );

        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::AccountKeysNotFetched),
            "republishing here puts a stale identity back over the account's newer one"
        );
        assert_eq!(
            create_identity().await,
            Err(MachineError::AccountKeysNotFetched),
            "and creating is refused by the same flag, checked rather than assumed to follow"
        );
        assert_eq!(
            create_recovery(PASSPHRASE, &[]).await.err(),
            Some(MachineError::AccountKeysNotFetched),
            "and a recovery written now opens perfectly onto an identity that no longer \
             exists, on a device that has lost its store, months later"
        );
        assert_eq!(
            recover_identity(PASSPHRASE, &[]).await,
            Err(MachineError::AccountKeysNotFetched),
            "and restoring is gated by the same flag"
        );

        // ---- Act two: the control -------------------------------------
        //
        // The same store, an answer that carries the identity the account
        // really has. Without this every refusal above proves only that this
        // file can break a restored device permanently.
        let query = fresh_account_key_query().await;
        mark_request_sent(&query.id, &replacement)
            .await
            .expect("answering the account key query must not fail");

        let status = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            status.account_keys_fetched && status.identity_known,
            "an answer that carries the account's identity must settle the question: \
             {status:?}"
        );
        assert!(
            !status.account_keys_answer_unsettled,
            "and the diagnosis must clear: {status:?}"
        );
        assert!(
            !status.private_keys_held,
            "and upstream must have dropped the private keys that disagree with it, which is \
             the comparison act one prevented: {status:?}"
        );
        assert_eq!(
            create_recovery(PASSPHRASE, &[]).await.err(),
            Some(MachineError::PrivateKeysNotHeld),
            "so the honest answer arrives instead of a recovery for replaced keys"
        );
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::IdentityAlreadyExists),
            "and this device is told to join the account's identity rather than republish \
             over it"
        );
    }));
}

/// Refuses a creation to have a fresh account key query queued, drains the
/// pump, and returns that query.
async fn fresh_account_key_query() -> OutgoingRequest {
    assert_eq!(
        create_identity().await,
        Err(MachineError::AccountKeysNotFetched),
        "the refusal is what queues the out-of-band query this returns"
    );
    let batch = take_outgoing_requests()
        .await
        .expect("draining the pump must not fail");
    batch
        .iter()
        .find(|request| request.kind == "keys_query" && names_the_account(&request.body))
        .unwrap_or_else(|| panic!("no account key query in the batch; got {:?}", kinds(&batch)))
        .clone()
}

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
