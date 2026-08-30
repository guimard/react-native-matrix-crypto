//! A server that answers without covering this account leaves a refusal the
//! product can **see**, rather than a loop it cannot get out of.
//!
//! # The case, which the specification prescribes rather than merely permits
//!
//! `matrix-spec`, `data/api/client-server/keys.yaml`, on the `/keys/query`
//! 200 response's `failures` field:
//!
//! > If any remote homeservers could not be reached, they are recorded here.
//! > **If the homeserver could be reached, but the user or device was
//! > unknown, no failure is recorded. Instead, the corresponding user or
//! > device is missing from the `device_keys` result.**
//!
//! So absence from `device_keys` is the specification's own way of saying
//! "unknown user", and `session::answer_about_this_account` reads it as "we
//! were told nothing" and keeps the gate shut. Refusing beats minting a
//! second identity over the account's existing one, which resets the trust
//! of every device and every person who ever verified it with nothing
//! afterwards able to detect it. That direction is not in question here.
//!
//! # What was wrong with it, which is not the refusal
//!
//! The refusal was defended as "a loud, inspectable stop". Measured, the
//! documented remedy for `AccountKeysNotFetched` -- drain, send, report
//! sent, call again -- run five times against a 200 that omits the account:
//! five refusals, five `Ok(())`s from `mark_request_sent`, gate shut every
//! round, and no public call able to clear or force it. That is a loop that
//! does not terminate, and the library said nothing at the one moment it
//! held both the question and the answer. The error also named the wrong
//! cause: `AccountKeysNotFetched` is documented as "this process has not yet
//! asked the server", and the process had asked, been answered, and reported
//! the answer successfully.
//!
//! # What this file pins
//!
//! The refusal is unchanged and must be. What is new is that
//! `identity_status` now reports `account_keys_answer_unsettled`, so the two
//! shut-gate situations are told apart:
//!
//! * both false -- nobody has asked, and the documented remedy works;
//! * this true -- we asked, we were answered, and asking again will do the
//!   same thing.
//!
//! A product that reads it stops looping and looks at the account id it
//! created the machine with, which is the reachable cause: measured against
//! a live Synapse 1.159.0, a mixed-case server name in the account's own
//! identifier makes the server treat the account as remote, federate to
//! itself, fail, and answer with an empty `device_keys` and an entry under
//! `failures`. `create_machine` accepts such an identifier, because ruma
//! does not normalise a server name.
//!
//! # The order, and the control
//!
//! The gate is monotonic and process-wide, so the rounds that must not lift
//! it come first and the answer that must lift it comes last. Without that
//! control every assertion here would pass on a library that had simply
//! stopped working.

use matrix_crypto_core::{
    bootstrap_identity, create_machine, create_recovery, identity_status, in_runtime,
    mark_request_sent, recover_identity, take_outgoing_requests, MachineConfig, MachineError,
    OutgoingRequest,
};

const ACCOUNT: &str = "@alice:example.org";

/// A literal with no account behind it, like the `store_passphrase` every
/// other test in this crate hands to `MachineConfig`.
const PASSPHRASE: &str = "recovery-test-passphrase";

/// The specification's prescribed answer for a user a reachable homeserver
/// does not know: every map present, every map empty, no failure recorded.
const UNKNOWN_USER: &str = r#"{"device_keys":{},"failures":{},"master_keys":{},"self_signing_keys":{},"user_signing_keys":{}}"#;

/// Synapse 1.159.0's real answer, measured, when the server-name half of the
/// queried user id differs in case from its own configured `server_name`: it
/// treats the account as remote, federates, and fails. The account is named
/// nowhere. Reproduced here with this crate's example server name in place
/// of the container's.
const FEDERATION_FAILED: &str = r#"{"device_keys":{},"failures":{"EXAMPLE.ORG":{"status":503,"message":"Failed to send request"}},"master_keys":{},"self_signing_keys":{},"user_signing_keys":{}}"#;

/// A real homeserver's real answer for an account it knows and holds no
/// identity for. Synapse 1.159.0 and Dendrite 0.15.2, byte for byte with the
/// account substituted.
const NO_IDENTITY: &str = r#"{"device_keys":{"@alice:example.org":{}},"failures":{},"master_keys":{},"self_signing_keys":{},"user_signing_keys":{}}"#;

/// How many rounds of the documented remedy to run before giving up on it.
///
/// Five, matching the measurement that found the loop. The number is not the
/// point -- the point is that the round after the first says exactly what the
/// first said, which is what makes it a loop rather than progress.
const ROUNDS: usize = 5;

#[test]
fn an_answer_that_settles_nothing_says_so_instead_of_looping_in_silence() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(in_runtime(async move {
        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: "DEVICE1".to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        // Before anything has been sent: the other shut-gate situation, and
        // the one whose documented remedy works. Asserted rather than
        // assumed, because the whole value of the new field is that it
        // separates these two, and a field that were simply always true
        // would separate nothing.
        let status = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(!status.account_keys_fetched);
        assert!(
            !status.account_keys_answer_unsettled,
            "nobody has asked anything yet, so there is no answer to have settled \
             nothing: {status:?}"
        );

        for body in [UNKNOWN_USER, FEDERATION_FAILED] {
            for round in 1..=ROUNDS {
                let query = fresh_account_key_query().await;

                mark_request_sent(&query.id, body)
                    .await
                    .unwrap_or_else(|error| {
                        panic!(
                            "round {round}: the answer must still be accepted. It is a \
                             well-formed 200 and upstream has to see it; refusing it here \
                             would make a retriable failure out of a request the server \
                             really did answer. Got {error:?}"
                        )
                    });

                let status = identity_status()
                    .await
                    .expect("reading the identity status must not fail");
                assert!(
                    !status.account_keys_fetched,
                    "round {round}: an answer that says nothing about this account must \
                     not be read as one that says the account has no identity: {status:?}"
                );
                assert!(
                    status.account_keys_answer_unsettled,
                    "round {round}: THIS is the assertion the file exists for. The send \
                     succeeded, the server answered, the answer was accepted, and the \
                     gate is still shut. Without this field the caller is told only \
                     `AccountKeysNotFetched`, whose documented remedy is the loop it is \
                     already in: {status:?}"
                );
                assert_eq!(
                    bootstrap_identity().await,
                    Err(MachineError::AccountKeysNotFetched),
                    "round {round}: and the refusal itself is unchanged, which is the \
                     safe direction and the one this library takes everywhere"
                );
                assert_eq!(
                    create_recovery(PASSPHRASE, &[]).await.err(),
                    Some(MachineError::AccountKeysNotFetched),
                    "round {round}: the same flag gates writing a recovery, so it is \
                     checked here rather than assumed to follow"
                );
                assert_eq!(
                    recover_identity(PASSPHRASE, &[]).await,
                    Err(MachineError::AccountKeysNotFetched),
                    "round {round}: and restoring from one"
                );
            }
        }

        // --- The control: an answer that does cover the account -----------
        //
        // The same account, the same machine, one round later. If this did
        // not lift the gate, every round above would be proving that this
        // file can break bootstrapping rather than that a shut gate is now
        // legible.
        let query = fresh_account_key_query().await;
        mark_request_sent(&query.id, NO_IDENTITY)
            .await
            .expect("a real homeserver's real answer must be accepted");

        let status = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            status.account_keys_fetched,
            "an answer that covers this account and reports no identity for it must lift \
             the gate: {status:?}"
        );
        assert!(
            !status.account_keys_answer_unsettled,
            "and the diagnosis must clear, or a product that met one omitting answer \
             would be told forever that its answers settle nothing: {status:?}"
        );
        bootstrap_identity()
            .await
            .expect("and the bootstrap that answer authorises must be served");
    }));
}

/// Refuses a bootstrap to have a fresh account key query queued, drains the
/// pump, and returns that query.
///
/// The refusal is what queues it, which is the property that makes
/// `AccountKeysNotFetched` recoverable at all -- and, against the bodies in
/// this file, the property that makes the remedy a loop.
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
