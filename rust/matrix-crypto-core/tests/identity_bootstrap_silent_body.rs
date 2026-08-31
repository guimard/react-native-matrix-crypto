//! A `/keys/query` answered with a body that says nothing about **this**
//! account must not open the bootstrap gate.
//!
//! The gate `signing.rs` reads is two facts, and this file is about the
//! first: has a key query naming this account been sent and answered. Until
//! this test existed, that fact was recorded from the *request* alone.
//! `session::account_scoped` classified the outgoing query as an account
//! query because its user list named this account, and any body at all that
//! `session::refuse_a_non_response` let through then lifted the gate.
//!
//! Measured, five bodies in five fresh processes, each answering a request
//! that really did name this account: another account's real, upstream-minted
//! cross-signing identity lifted the gate and the next `bootstrap_identity`
//! minted; `{"device_keys":{"@bob:…":{}}}` lifted it and minted; a body whose
//! entire content was a `failures` map lifted it and minted. Only a body
//! carrying this account's own identity produced the correct refusal. So the
//! gate was lifting on the strength of *which request was answered*, and
//! never looking at whether the answer said anything about this account.
//!
//! Each of those bodies is an answer to somebody else's question, or to
//! nobody's, read as "the server says this account has no identity" -- which
//! is the one fact that authorises minting a new identity over the account's
//! existing one, resetting the trust of every device and every person who
//! ever verified it, with nothing afterwards able to detect it.
//!
//! # Why presence, and not "reports nothing about anybody"
//!
//! Every body below asserts no cross-signing key for this account, so the
//! half of `session::answer_about_this_account` they all meet is the one
//! about a *negative* answer: the account has no identity, and that settles
//! the question only if the answer covered the account at all, which is
//! `device_keys` naming it. The weaker rule -- also accept a body that
//! reports nothing about anybody, on the grounds that a server with nothing
//! to say answers `{}` -- was rejected on measurement rather than on taste.
//! Probed directly over HTTP against three homeservers, on accounts holding
//! no cross-signing identity and no uploaded device keys at all, Synapse
//! 1.159.0 and Dendrite 0.15.2 both answer
//! `{"device_keys":{"@user:…":{}},"failures":{},"master_keys":{},`
//! `"self_signing_keys":{},"user_signing_keys":{}}`, and continuwuity
//! v26.7.2 answers `{"device_keys":{"@user:…":{}}}`. Every one of them names
//! the account. None of them answers `{}`. That measurement is what makes
//! the strong rule affordable.
//!
//! The other half -- an answer that *does* assert a cross-signing key for
//! this account, and that upstream could not read -- is
//! `tests/identity_bootstrap_unreadable_identity.rs`, and it is the one that
//! defeated the rule this file was written for.
//!
//! The last body below is Synapse's and Dendrite's real answer, byte for
//! byte with the account substituted, and it is the control: it must lift
//! the gate and it must mint. Without it every refusal above proves only
//! that this file can break bootstrapping.
//!
//! Its own process, for the reason `tests/pump_eviction.rs` gives: the
//! machine registry and the pump's bookkeeping are process-wide, and the gate
//! is monotonic, so the one body that lifts it has to come last.

use matrix_crypto_core::{
    bootstrap_identity, create_identity, create_machine, identity_status, in_runtime,
    mark_request_sent, take_outgoing_requests, MachineConfig, MachineError, OutgoingRequest,
};
use matrix_sdk_common::ruma::{DeviceId, OwnedUserId};
use matrix_sdk_crypto::OlmMachine;

const ACCOUNT: &str = "@alice:example.org";
const STRANGER: &str = "@bob:example.org";

/// The shape this library's own documentation used to call "the real answer
/// for an account the server knows no identity for". No measured homeserver
/// produces it: all three name the account even when they have nothing to
/// report about it.
const NO_USER_NAMED: &str = r#"{"device_keys":{}}"#;

/// The empty object, and the body that is the same input by the time
/// anything looks at it: ruma substitutes `{}` for a completely empty body
/// before parsing. This is also exactly what a 503 that carried no body
/// arrives as, which is the collision `mark_request_failed` exists for --
/// and which refusing to lift the gate on now closes from this side too.
const EMPTY_OBJECT: &str = "{}";
const EMPTY_BODY: &str = "";

/// Another account's devices, and another account's devices alongside an
/// empty `failures` map. Both name a user; neither names this one.
const STRANGER_DEVICES: &str = r#"{"device_keys":{"@bob:example.org":{}}}"#;
const STRANGER_DEVICES_AND_NO_FAILURES: &str =
    r#"{"device_keys":{"@bob:example.org":{}},"failures":{}}"#;

/// A 200 whose entire content is a federation failure. `failures` is a
/// declared field of this response, and its nested `errcode` is deliberately
/// untouched by `session::refuse_a_non_response` because real `failures`
/// maps carry real errors -- so this passes every check that looks at the
/// body's shape, and it reports that a server did not answer, which is the
/// opposite of an answer about anyone that server hosts.
const FAILURES_ONLY: &str =
    r#"{"failures":{"example.org":{"errcode":"M_UNKNOWN","error":"boom"}}}"#;

/// The same, keyed by this **account's user id** rather than by a server
/// name -- and the reason it is here rather than in a comment saying no such
/// body exists.
///
/// The round that introduced the previous rule excluded `failures` from it
/// on the stated grounds that it is keyed by server name, and recorded that
/// no body could distinguish the exclusion, so it was "sound by construction
/// rather than pinned by a run". **That was a reading standing in for a
/// measurement, and it is false.** Upstream types the map
/// `BTreeMap<String, JsonValue>` (`ruma-client-api`'s `get_keys`), not
/// `OwnedServerName`, and nothing validates the key, so a user id sits in it
/// happily. The other four maps are keyed by `OwnedUserId` and would reject
/// this at parse time; this one does not. Adding `"failures"` to that rule's
/// field list turned both of these bodies into mints, which is what makes
/// them a witness.
///
/// The rule they now meet cannot consult `failures` at all -- it reads
/// `device_keys` and the three cross-signing maps off ruma's parse of the
/// response, and there is no list to add a fifth name to. These two stay
/// anyway: what is pinned is the outcome, not the shape of the code that
/// produces it.
const FAILURES_NAMES_THE_ACCOUNT: &str =
    r#"{"failures":{"@alice:example.org":{"errcode":"M_UNKNOWN","error":"boom"}}}"#;
const FAILURES_NAMES_THE_ACCOUNT_EMPTY: &str = r#"{"failures":{"@alice:example.org":{}}}"#;

#[test]
fn a_body_that_says_nothing_about_this_account_cannot_open_the_bootstrap_gate() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(async move {
        // Built before the machine exists, from a bare upstream machine that
        // really minted it. A hand-written identity is dropped by upstream
        // before it is stored, which would make every assertion below pass
        // for the wrong reason: the gate would stay shut because nothing was
        // learned, rather than because the answer was about a stranger.
        let strangers_identity = in_runtime(real_identity_answer(STRANGER)).await;

        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: "DEVICE1".to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        for (body, what) in [
            (
                NO_USER_NAMED,
                "a `device_keys` map naming nobody. This is the body four shipped documents \
                 called the genuine answer for an account with no identity, and no measured \
                 homeserver sends it",
            ),
            (
                EMPTY_OBJECT,
                "the empty object, which is byte-identical to a 502 that carried no body and \
                 which no measured homeserver sends for a key query either",
            ),
            (
                EMPTY_BODY,
                "a completely empty body, which ruma turns into the empty object before \
                 parsing, so it is the same input as the case above",
            ),
            (
                STRANGER_DEVICES,
                "another account's devices. The request named this account; the answer names \
                 somebody else and is silent about us",
            ),
            (
                STRANGER_DEVICES_AND_NO_FAILURES,
                "the same, with an empty `failures` map alongside it, so the rule cannot be \
                 satisfied by a declared field being merely present",
            ),
            (
                FAILURES_ONLY,
                "a 200 whose whole content is a federation failure, keyed by a server name. \
                 An entry in `failures` says a server did not answer, which is the opposite \
                 of an answer about anyone it hosts",
            ),
            (
                FAILURES_NAMES_THE_ACCOUNT,
                "the same, keyed by this account's own user id. Upstream types `failures` as \
                 a plain string map, so this parses, and the previous round's claim that no \
                 body could distinguish the `failures` exclusion was wrong",
            ),
            (
                FAILURES_NAMES_THE_ACCOUNT_EMPTY,
                "and with an empty value, so the refusal cannot be coming from the nested \
                 error rather than from where the account was named",
            ),
            (
                strangers_identity.as_str(),
                "another account's real, upstream-minted cross-signing identity. This is the \
                 dangerous one: every key in it validates, upstream stores it happily against \
                 that other account, and nothing about this account was learned at all",
            ),
        ] {
            let query = fresh_account_key_query().await;

            mark_request_sent(&query.id, body)
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "the body must still be *accepted*: it is a well-formed key query \
                     response and upstream has to see it. Only the gate is narrowed here, \
                     and narrowing acceptance instead would refuse an answer that carries \
                     other users' keys this machine needs. Reported for {what}, got {error:?}"
                    )
                });

            assert!(
                !identity_status()
                    .await
                    .expect("reading the identity status must not fail")
                    .account_keys_fetched,
                "the gate must stay shut for {what}"
            );
            assert_eq!(
                bootstrap_identity().await,
                Err(MachineError::AccountKeysNotFetched),
                "this is the assertion the file exists for: served here, {what} mints a fresh \
                 identity over whatever the account already has and silently invalidates every \
                 verification anyone has ever made of it"
            );
        }

        // --- The control, and it is a real homeserver's real answer --------
        //
        // Synapse 1.159.0 and Dendrite 0.15.2, byte for byte with this
        // account's id substituted, for an account that has no cross-signing
        // identity and has never uploaded a device key. It must lift the gate
        // and the bootstrap must be served, or every refusal above proves
        // only that this file can break the common case.
        let answer = format!(
            r#"{{"device_keys":{{"{ACCOUNT}":{{}}}},"failures":{{}},"master_keys":{{}},"self_signing_keys":{{}},"user_signing_keys":{{}}}}"#
        );
        let query = fresh_account_key_query().await;
        mark_request_sent(&query.id, &answer)
            .await
            .expect("a real homeserver's real answer must be accepted");

        assert!(
            identity_status()
                .await
                .expect("reading the identity status must not fail")
                .account_keys_fetched,
            "an answer that covers this account must lift the gate. If this fails the cure is \
             worse than the disease: no product on any measured homeserver could ever bootstrap"
        );
        create_identity()
            .await
            .expect("and the creation it authorises must be served");
    });
}

/// Refuses a bootstrap to have a fresh account key query queued, drains the
/// pump, and returns that query.
///
/// The refusal is what queues it: `signing::bootstrap_identity` asks
/// out-of-band whenever it refuses for want of an answer, precisely so the
/// refusal is recoverable through the ordinary pump loop. A successful
/// `mark_request_sent` consumes the entry it resolves, so each body above
/// needs its own, and this is the only way to get one after the first.
async fn fresh_account_key_query() -> OutgoingRequest {
    assert_eq!(
        bootstrap_identity().await,
        Err(MachineError::AccountKeysNotFetched),
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
                batch.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>()
            )
        })
        .clone()
}

/// Whether a `/keys/query` body's `device_keys` map names this account.
fn names_the_account(body: &str) -> bool {
    let parsed: serde_json::Value = serde_json::from_str(body).expect("a pump body must be JSON");
    parsed
        .get("device_keys")
        .and_then(|users| users.get(ACCOUNT))
        .is_some()
}

/// A real `/keys/query` answer for `account`, built from an identity a bare
/// upstream machine really minted.
async fn real_identity_answer(account: &str) -> String {
    let user: OwnedUserId = account.parse().expect("well-formed");
    let machine = OlmMachine::new(&user, <&DeviceId>::from("MINTER")).await;
    let published = machine
        .bootstrap_cross_signing(false)
        .await
        .expect("a bare machine must be able to mint an identity")
        .upload_signing_keys_req;

    let mut answer = serde_json::Map::new();
    answer.insert("device_keys".to_string(), serde_json::json!({}));
    for (field, key) in [
        ("master_keys", &published.master_key),
        ("self_signing_keys", &published.self_signing_key),
        ("user_signing_keys", &published.user_signing_key),
    ] {
        let key = key.as_ref().expect("a minted identity carries every key");
        answer.insert(
            field.to_string(),
            serde_json::json!({ account: serde_json::to_value(key).expect("serialises") }),
        );
    }
    serde_json::Value::Object(answer).to_string()
}
