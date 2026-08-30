//! An answer that *carries* this account's identity but that upstream could
//! not read must not open the bootstrap gate.
//!
//! # The defeat this file exists for
//!
//! The rule before this one was "the answer names this account in one of the
//! four maps a key query answer keys by user id". It tested the map **key**
//! and never the value, and upstream drops what it cannot use in silence, so
//! the two came apart exactly where it is most expensive.
//!
//! Measured, against a live Synapse 1.159.0 in a throwaway container, with
//! the answers taken verbatim from the server:
//!
//! * An account that had published a master key **and** a self-signing key
//!   but no user-signing key answered its own `/keys/query` with a body
//!   carrying its published master key. The gate lifted,
//!   `identity_status` reported `identity_known: false`, and
//!   `bootstrap_identity` minted a second identity over the published one.
//! * An account that had published a master key alone did the same.
//! * Starting from an account that had published all three -- whose
//!   untouched answer refuses correctly with `IdentityAlreadyExists` --
//!   **flipping one character of one base64 signature** turned that refusal
//!   into a mint. So did deleting a `signatures` block, changing `usage` to
//!   something other than `master`, emptying `user_signing_keys`, and
//!   changing a master key's inner `user_id`.
//!
//! Minting a second identity over an existing one resets the trust of every
//! device and every person who ever verified the account, silently, and
//! nothing afterwards can detect it. One byte of base64 was the difference.
//!
//! # Why upstream is where the answer comes from now
//!
//! `IdentityManager::handle_cross_signing_keys` iterates `master_keys`
//! alone; `get_minimal_set_of_keys` needs a master key *and* a matching
//! `self_signing_keys` entry; our own user needs a `user_signing_keys` entry
//! as well. Anything missing or unreadable is dropped with a `warn!` and no
//! identity is stored. Every value in all four maps is a
//! `Raw<CrossSigningKey>`, so ruma accepts any JSON at all under a valid
//! user id and leaves the judgement to upstream.
//!
//! `session::answer_about_this_account` therefore asks upstream rather than
//! the bytes: when the answer asserts a cross-signing key for this account,
//! the gate lifts only if upstream's store now holds the identity that
//! answer asserted. Each body below asserts one, and none of them survives
//! the trip into upstream, so none of them lifts the gate.
//!
//! # The order, and the control
//!
//! The gate is monotonic and process-wide, so every body that must **not**
//! lift it comes first and the one that must comes last. The control is the
//! complete, untouched, correctly signed answer: it must lift the gate, and
//! `bootstrap_identity` must then refuse with `IdentityAlreadyExists`. Every
//! refusal above it is worthless without it, because a rule that refuses
//! everything would pass all of them.

use matrix_crypto_core::{
    bootstrap_identity, create_machine, create_recovery, identity_status, in_runtime,
    mark_request_sent, recover_identity, take_outgoing_requests, MachineConfig, MachineError,
    OutgoingRequest,
};
use matrix_sdk_common::ruma::{DeviceId, OwnedUserId};
use matrix_sdk_crypto::OlmMachine;
use serde_json::{json, Value};

const ACCOUNT: &str = "@alice:example.org";

/// A literal with no account behind it, like the `store_passphrase` every
/// other test in this crate hands to `MachineConfig`.
const PASSPHRASE: &str = "recovery-test-passphrase";

#[test]
fn an_identity_upstream_could_not_read_cannot_open_the_bootstrap_gate() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(async move {
        // Minted by a bare upstream machine, so the key material and every
        // signature on it are real. A hand-written identity would be dropped
        // by upstream before it was stored, and then every refusal below
        // would pass for the wrong reason -- the gate would stay shut
        // because nothing was ever readable, rather than because *this*
        // corruption made it unreadable. The control at the end is what
        // holds that distinction, and it needs genuine keys to exist.
        let complete = in_runtime(real_identity_answer()).await;

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
                without(&complete, &["self_signing_keys", "user_signing_keys"]),
                "this account's real, published master key alone, with the account named \
                 under `device_keys` beside it. Synapse 1.159.0 answers exactly this for an \
                 account that has uploaded a master key and nothing else, and this is the \
                 body that minted",
            ),
            (
                without(&complete, &["user_signing_keys"]),
                "this account's real master and self-signing keys, no user-signing key. \
                 Synapse's answer for an account that uploaded two of the three, which the \
                 endpoint accepts with a 200. Upstream needs all three for its own user",
            ),
            (
                flip_a_signature_character(&complete),
                "the complete, correct answer with ONE character of ONE base64 signature \
                 changed. This is the sharpest form of the defeat: the same bytes that \
                 refuse correctly, one byte different, used to mint",
            ),
            (
                without_the_signatures(&complete),
                "the complete answer with the self-signing key's `signatures` block \
                 removed, so upstream cannot check that the master key signed it",
            ),
            (
                with_master_usage(&complete, "not_master"),
                "the complete answer with the master key's `usage` changed. Upstream's own \
                 `MasterPubkey` deserialisation is what rejects this, which is the point: \
                 this rule does not re-implement that judgement, it reads the result of it",
            ),
            (
                with_master_inner_user_id(&complete, "@somebodyelse:example.org"),
                "the complete answer with the master key's inner `user_id` changed, so the \
                 key claims to belong to somebody else while filed under this account",
            ),
        ] {
            let query = fresh_account_key_query().await;

            mark_request_sent(&query.id, &body)
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "the body must still be *accepted*: it is a well-formed key query \
                         response and upstream has to see it. Only the gate is narrowed \
                         here. Reported for {what}, got {error:?}"
                    )
                });

            let status = identity_status()
                .await
                .expect("reading the identity status must not fail");
            assert!(
                !status.account_keys_fetched,
                "the gate must stay shut for {what}: {status:?}"
            );
            assert!(
                !status.identity_known,
                "and upstream must genuinely be holding nothing, or this row proves \
                 something else entirely: {status:?}"
            );
            assert!(
                status.account_keys_answer_unsettled,
                "and the caller must be able to see that it was answered and told nothing, \
                 rather than being left to conclude that nobody has asked: {status:?}"
            );
            assert_eq!(
                bootstrap_identity().await,
                Err(MachineError::AccountKeysNotFetched),
                "this is the assertion the file exists for: served here, {what} mints a \
                 fresh identity over the one that answer is carrying, and silently \
                 invalidates every verification anyone has ever made of this account"
            );

            // The same flag gates all three callers, so all three are
            // checked rather than one being taken as evidence for the
            // others.
            assert_eq!(
                create_recovery(PASSPHRASE, &[]).await.err(),
                Some(MachineError::AccountKeysNotFetched),
                "a recovery written now is written for private keys that may belong to an \
                 identity the account has already replaced, and this answer did not say. \
                 Reported for {what}"
            );
            assert_eq!(
                recover_identity(PASSPHRASE, &[]).await,
                Err(MachineError::AccountKeysNotFetched),
                "and a restore checks the key it imports against the published identity, \
                 which is exactly what upstream has not got. Reported for {what}"
            );
        }

        // --- The control: the same identity, complete and untouched -------
        //
        // Without this every refusal above proves only that this file can
        // break bootstrapping. With it, the difference between the last
        // refusal and this success is one character of base64.
        let query = fresh_account_key_query().await;
        mark_request_sent(&query.id, &complete.to_string())
            .await
            .expect("a complete, correctly signed answer must be accepted");

        let status = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            status.account_keys_fetched,
            "an answer upstream could read must lift the gate. If this fails the cure is \
             worse than the disease: no product could ever learn that its account has an \
             identity: {status:?}"
        );
        assert!(
            status.identity_known,
            "and upstream must be holding the identity the answer asserted: {status:?}"
        );
        assert!(
            !status.account_keys_answer_unsettled,
            "and the diagnosis must clear once the question is settled, or it is a latch \
             rather than a description of now: {status:?}"
        );
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::IdentityAlreadyExists),
            "and the refusal must move to the one that says the account has an identity \
             this device does not hold, which is the answer with a remedy"
        );
    });
}

/// Refuses a bootstrap to have a fresh account key query queued, drains the
/// pump, and returns that query.
///
/// The refusal is what queues it: `signing::bootstrap_identity` asks
/// out-of-band whenever it refuses for want of an answer, precisely so the
/// refusal is recoverable through the ordinary pump loop. A successful
/// `mark_request_sent` consumes the entry it resolves, so each body above
/// needs its own.
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
    let parsed: Value = serde_json::from_str(body).expect("a pump body must be JSON");
    parsed
        .get("device_keys")
        .and_then(|users| users.get(ACCOUNT))
        .is_some()
}

/// A complete, real `/keys/query` answer for this account, in the shape a
/// homeserver sends it: the account named under `device_keys`, and all three
/// cross-signing keys, minted and signed by a bare upstream machine.
async fn real_identity_answer() -> Value {
    let user: OwnedUserId = ACCOUNT.parse().expect("well-formed");
    let machine = OlmMachine::new(&user, <&DeviceId>::from("MINTER")).await;
    let published = machine
        .bootstrap_cross_signing(false)
        .await
        .expect("a bare machine must be able to mint an identity")
        .upload_signing_keys_req;

    let key = |k: &Option<_>| {
        serde_json::to_value(k.as_ref().expect("a minted identity carries every key"))
            .expect("serialises")
    };
    json!({
        "device_keys": { ACCOUNT: {} },
        "failures": {},
        "master_keys": { ACCOUNT: key(&published.master_key) },
        "self_signing_keys": { ACCOUNT: key(&published.self_signing_key) },
        "user_signing_keys": { ACCOUNT: key(&published.user_signing_key) },
    })
}

/// The same answer with whole cross-signing maps emptied, which is what a
/// homeserver sends for an account that published only some of the three.
fn without(answer: &Value, fields: &[&str]) -> String {
    let mut body = answer.clone();
    for field in fields {
        body[*field] = json!({});
    }
    body.to_string()
}

/// One base64 character of the self-signing key's signature, changed to a
/// different one. Nothing else about the answer moves.
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

fn without_the_signatures(answer: &Value) -> String {
    let mut body = answer.clone();
    body["self_signing_keys"][ACCOUNT]
        .as_object_mut()
        .expect("an object")
        .remove("signatures");
    body.to_string()
}

fn with_master_usage(answer: &Value, usage: &str) -> String {
    let mut body = answer.clone();
    body["master_keys"][ACCOUNT]["usage"] = json!([usage]);
    body.to_string()
}

fn with_master_inner_user_id(answer: &Value, user_id: &str) -> String {
    let mut body = answer.clone();
    body["master_keys"][ACCOUNT]["user_id"] = json!(user_id);
    body.to_string()
}
