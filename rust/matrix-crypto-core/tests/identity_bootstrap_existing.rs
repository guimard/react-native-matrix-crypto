//! The other half of the gate: asked, and the answer named an identity.
//!
//! `tests/identity_bootstrap_ordering.rs` drives the case where nothing has
//! been asked. This one drives the case that makes the distinction load
//! bearing: this device **has** asked, the server **has** answered, and the
//! answer named an identity whose private keys this device does not hold.
//!
//! A gate written as "is the local identity empty" would serve this call,
//! because the local *private* identity is empty here -- and serving it is
//! precisely the destruction the milestone exists to prevent. The two
//! questions differ by exactly this scenario, which is also the ordinary
//! shape of a second login: the account has an identity, this device has
//! just not joined it yet. Joining it is self-verification, not a fresh
//! mint.
//!
//! The identity in the answer is a **real** one, minted by a second,
//! bare upstream `OlmMachine` for the same account and serialised into the
//! `/keys/query` response shape a homeserver would return. Not a hand-written
//! fixture: upstream validates that the self- and user-signing keys are
//! signed by the master key before it stores an identity at all, so a
//! fabricated one would be dropped and this test would then be asserting
//! against an account with no identity -- passing for the wrong reason, and
//! passing even with the gate removed.
//!
//! Only Alice's DEVICE1 is the library. The second machine is a bare
//! `matrix_sdk_crypto::OlmMachine` standing in for the other device of the
//! same account, exactly the asymmetry `tests/two_parties.rs` documents.
//!
//! # This file changed door without saying so, and this section is that
//!
//! `keys_query_answer` below builds a body with an **empty** `device_keys`
//! map, naming the account only in the three cross-signing maps. Under the
//! rule this file was written against, "the answer names this account in any
//! of the four maps a key query answer keys by user id", it lifted the gate
//! because those three maps name it. Under
//! `session::answer_about_this_account` it lifts the gate through the
//! **positive branch**: the answer asserts a master key for the account and
//! upstream, having consumed the answer, now holds the identity it asserted.
//! Same outcome, different door, and nothing here said so.
//!
//! It is recorded now for the reason `tests/recovery_stale_identity.rs`
//! records the same thing about itself: the co-witness relationship was
//! written down in that file's header and not in this one, so a reader of
//! this file had no way to know. **Measured**: appending
//! `&& response.device_keys.contains_key(account)` to the positive branch
//! turns both files red, this one at "the account key query was answered"
//! with `IdentityStatus { account_keys_fetched: false, identity_known: true,
//! private_keys_held: false, account_keys_answer_unsettled: true }`.
//!
//! The change is benign, and that is stated rather than assumed: both files
//! land on the safe half of the rule, where `identity_known` is true, and
//! nothing on that half can authorise a mint. What was wrong was the
//! silence, not the door.
//!
//! No measured homeserver sends a body shaped like this one. It is kept
//! because the two files are what watch that branch, and a branch with no
//! witness is the thing this project's rules forbid.

use matrix_crypto_core::{
    bootstrap_identity, create_machine, identity_status, in_runtime, mark_request_sent,
    take_outgoing_requests, MachineConfig, MachineError, OutgoingRequest,
};
use matrix_sdk_common::ruma::{DeviceId, OwnedUserId};
use matrix_sdk_crypto::OlmMachine;

const ACCOUNT: &str = "@alice:example.org";

#[test]
fn bootstrapping_is_refused_when_the_account_already_has_an_identity_this_device_lacks() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(async move {
        let account: OwnedUserId = ACCOUNT.parse().expect("a well-formed account identifier");

        // The other device of this same account, which got there first.
        // Inside `in_runtime` because upstream's own store work expects a
        // tokio context and this crate owns the only runtime in the process.
        let answer = in_runtime({
            let account = account.clone();
            async move {
                let other_device = OlmMachine::new(&account, <&DeviceId>::from("OTHERDEV")).await;
                let published = other_device
                    .bootstrap_cross_signing(false)
                    .await
                    .expect("the other device must be able to mint an identity")
                    .upload_signing_keys_req;
                keys_query_answer(ACCOUNT, &published)
            }
        })
        .await;

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
        let account_query = batch
            .iter()
            .find(|request| request.kind == "keys_query" && names_the_account(&request.body))
            .unwrap_or_else(|| {
                panic!(
                    "a fresh machine must owe a key query for its own account; got {:?}",
                    batch
                        .iter()
                        .map(|r: &OutgoingRequest| r.kind.as_str())
                        .collect::<Vec<_>>()
                )
            });
        mark_request_sent(&account_query.id, &answer)
            .await
            .expect("answering the account key query must not fail");

        // The state that makes this test worth having: asked, answered, an
        // identity is known, and this device holds none of its private keys.
        let asked = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            asked.account_keys_fetched,
            "the account key query was answered: {asked:?}"
        );
        assert!(
            asked.identity_known,
            "the answer named an identity, so upstream must have stored one. If this \
             fails, the answer was rejected and every assertion below would pass for the \
             wrong reason: {asked:?}"
        );
        assert!(
            !asked.private_keys_held,
            "this device did not mint that identity and has not joined it: {asked:?}"
        );

        let refusal = bootstrap_identity().await;
        assert_eq!(
            refusal,
            Err(MachineError::IdentityAlreadyExists),
            "minting over an identity the account already has is the destruction this \
             gate exists to prevent; joining it is self-verification, not a bootstrap"
        );

        let after = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert_eq!(
            after, asked,
            "a refused bootstrap must leave the account exactly as it found it"
        );
    });
}

/// The `/keys/query` response a homeserver returns for an account that
/// already has an identity, built from the request upstream would have
/// published for it. Field names are ruma's own
/// (`ruma-client-api-0.24.0/src/keys/get_keys.rs`): `master_keys`,
/// `self_signing_keys` and `user_signing_keys`, each a map from account to
/// key. `user_signing_keys` is returned only to the account's own devices,
/// which is exactly the request being answered here.
fn keys_query_answer(
    account: &str,
    published: &matrix_sdk_crypto::types::requests::UploadSigningKeysRequest,
) -> String {
    let mut answer = serde_json::Map::new();
    answer.insert("device_keys".to_string(), serde_json::json!({}));
    for (field, key) in [
        ("master_keys", &published.master_key),
        ("self_signing_keys", &published.self_signing_key),
        ("user_signing_keys", &published.user_signing_key),
    ] {
        let key = key
            .as_ref()
            .unwrap_or_else(|| panic!("a minted identity must carry a {field} entry"));
        answer.insert(
            field.to_string(),
            serde_json::json!({ account: serde_json::to_value(key).expect("a key serialises") }),
        );
    }
    serde_json::Value::Object(answer).to_string()
}

/// Whether a `/keys/query` body's `device_keys` map names this account.
fn names_the_account(body: &str) -> bool {
    let parsed: serde_json::Value = serde_json::from_str(body).expect("a pump body must be JSON");
    parsed
        .get("device_keys")
        .and_then(|users| users.get(ACCOUNT))
        .is_some()
}
