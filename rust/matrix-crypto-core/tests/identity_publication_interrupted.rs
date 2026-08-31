//! An identity this device minted and never managed to publish must be
//! finishable, and must not be mistaken for one the account already has.
//!
//! # The defect this file exists for
//!
//! `create_identity` writes the minted identity into the crypto store and
//! *then* hands the publication to the caller. Between those two moments the
//! store holds an identity the account does not have, and it holds it
//! durably, because the store is a file and the publication is in a
//! process-local pump. A killed process, an offline device, a timed-out
//! socket or a backgrounded app in that window leaves exactly that state on
//! disk.
//!
//! The gate's negative branch used to read `stored.is_none()` and treat any
//! held identity as proof that a "this account has no identity" answer was
//! stale. **Measured, on continuwuity and on Synapse**: after that
//! interruption the next process was refused permanently on
//! `bootstrap_identity`, `create_identity`, `create_recovery` and
//! `recover_identity`; five rounds of the documented remedy changed nothing;
//! the one diagnostic the library offered pointed at the account id, which
//! was correct; and the only escape was deleting the crypto store, which is
//! the user's decryptable message history. The account was healthy, the
//! server was honest, and the store was honest: the identity it held is the
//! one that account was supposed to get.
//!
//! *This store holds an identity* and *this account has an identity* are
//! different facts, and only the store can remember which is true, because a
//! server cannot be asked about a publication that never arrived.
//! `signing::identity_is_unpublished` is that record.
//!
//! # What this file drives
//!
//! One process, because the record and both of its clearing moments are
//! observable through `identity_status`. The cross-process half, which is
//! the shape a real interruption takes, is driven against two live
//! homeservers by the probes named in the eighth report; what is pinned here
//! is the state machine those probes exercise.

use matrix_crypto_core::{
    bootstrap_identity, create_identity, create_machine, identity_status, mark_request_sent,
    take_outgoing_requests, MachineConfig, MachineError, OutgoingRequest,
};
use serde_json::Value;

const ACCOUNT: &str = "@alice:example.org";

/// A real homeserver's real answer for an account it holds no identity for.
/// Synapse 1.159.0 and Dendrite 0.15.2 byte for byte, account substituted.
/// Note what it is: not an omission, but three explicit empty key maps
/// saying this account has no cross-signing identity.
const NO_IDENTITY: &str = r#"{"device_keys":{"@alice:example.org":{}},"failures":{},"master_keys":{},"self_signing_keys":{},"user_signing_keys":{}}"#;

#[test]
fn a_minted_identity_that_was_never_published_can_still_be_published() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(async move {
        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: "DEVICE1".to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        // ---- The ordinary sign-up flow, up to the mint -----------------
        let query = fresh_account_key_query().await;
        mark_request_sent(&query.id, NO_IDENTITY)
            .await
            .expect("a real homeserver's real answer must be accepted");

        let asked = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(asked.account_keys_fetched && !asked.identity_known);
        assert!(
            !asked.identity_publication_pending,
            "nothing has been minted, so nothing is awaiting publication: {asked:?}"
        );
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::IdentityNotKnown),
            "there is nothing to publish yet"
        );

        create_identity()
            .await
            .expect("the deliberate, documented, correct call must be served");

        // ---- Act one: the mint is recorded as unpublished --------------
        let minted = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            minted.identity_known && minted.private_keys_held,
            "the mint stored an identity: {minted:?}"
        );
        assert!(
            minted.identity_publication_pending,
            "THIS is the fact the round before this one had nowhere to keep. The store now \
             holds an identity the account does not have, and if this process dies here that \
             is what the next one reopens: {minted:?}"
        );

        // The publication the mint queued, which is what an interruption
        // loses. Drained, and deliberately not reported.
        let batch = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let publication = batch
            .iter()
            .find(|r| r.kind == "signing_keys_upload")
            .expect("the mint must queue the publication it authorises")
            .clone();
        let confirming = batch
            .iter()
            .find(|r| r.kind == "keys_query" && names_the_account(&r.body))
            .expect("the mint must queue its confirming query")
            .clone();

        // ---- Act two: an unpublished identity does not contradict ------
        //
        // The same answer as before, from the same honest server, and it is
        // still true: the account has no identity. Before the record
        // existed this settled nothing and every write refused forever.
        mark_request_sent(&confirming.id, NO_IDENTITY)
            .await
            .expect("the answer must be accepted");
        let after = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            after.account_keys_fetched,
            "an answer saying the account has no identity agrees with a store holding one \
             this device minted and never published. Refusing here is what bricked the \
             account: {after:?}"
        );
        assert!(
            !after.account_keys_answer_unsettled,
            "and the caller must not be told the answer settled nothing, which is the \
             diagnosis that pointed at the account id: {after:?}"
        );
        assert!(
            after.identity_publication_pending,
            "and the publication is still owed: {after:?}"
        );

        // ---- Act three: the remedy is the deliberate call --------------
        //
        // **It was the every-launch call for one round, and that was the
        // defect.** Measured on continuwuity and on Synapse: a device in
        // exactly this state, answered honestly that the account has no
        // identity, republished over an identity a second device of the same
        // account had legitimately published in the gap before that answer
        // was reported. `create_identity` refused correctly throughout. The
        // careful call did the damage, which is why finishing is now a
        // decision too.
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::IdentityNotKnown),
            "the launch-time call may not publish an identity no homeserver has confirmed"
        );
        create_identity()
            .await
            .expect("and finishing it deliberately must be served, or this is a brick");

        let batch = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let again = batch
            .iter()
            .find(|r| r.kind == "signing_keys_upload")
            .expect("the republication must carry the same upload that was lost")
            .clone();
        assert_eq!(
            again.body, publication.body,
            "and it must be the same publication, byte for byte: this is finishing the act \
             that was interrupted, not starting a different one"
        );

        // ---- Act four: reporting the upload does NOT clear the record --
        //
        // **The second change of the ninth round.** This used to be a
        // clearing site, and it is not the moment a homeserver accepted the
        // publication: it is the moment the *caller* said so.
        // `refuse_a_non_response` names the two bodies it cannot tell from a
        // success, the empty body and the empty object, and those are what a
        // connection reset and a bodiless gateway error hand a product.
        // Measured: reporting either of them for an upload nothing ever sent
        // cleared the record and bricked the account permanently.
        mark_request_sent(&again.id, "{}")
            .await
            .expect("the report is still accepted, and upstream still sees it");
        let reported = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            reported.identity_publication_pending,
            "a caller's word that the upload succeeded is not the server's, and treating it \
             as the server's is what made one mistaken report unrecoverable: {reported:?}"
        );

        // ---- Act five: the server's own answer clears it ---------------
        //
        // The confirming query the creation queued, answered with the
        // identity a homeserver that accepted the publication would send
        // back. This is the only clearing site now.
        let confirming = batch
            .iter()
            .find(|r| r.kind == "keys_query" && names_the_account(&r.body))
            .expect("the creation queues its confirming query")
            .clone();
        mark_request_sent(&confirming.id, &answer_carrying(&again.body))
            .await
            .expect("the answer must be accepted");
        let published = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            !published.identity_publication_pending,
            "the server has told us it has this identity, so the record must go: left \
             standing, the launch-time call could never publish again: {published:?}"
        );
        bootstrap_identity()
            .await
            .expect("and the every-launch call is served again once it is confirmed");
    });
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
        .unwrap_or_else(|| {
            panic!(
                "no key query naming this account in the batch; got {:?}",
                batch.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>()
            )
        })
        .clone()
}

/// Turns the publication into the `/keys/query` answer a homeserver that
/// accepted it would send back.
fn answer_carrying(publication: &str) -> String {
    let up: Value = serde_json::from_str(publication).expect("JSON");
    serde_json::json!({
        "device_keys": { ACCOUNT: {} },
        "failures": {},
        "master_keys": { ACCOUNT: up["master_key"] },
        "self_signing_keys": { ACCOUNT: up["self_signing_key"] },
        "user_signing_keys": { ACCOUNT: up["user_signing_key"] },
    })
    .to_string()
}

/// Whether a `/keys/query` body's `device_keys` map names this account.
fn names_the_account(body: &str) -> bool {
    let parsed: Value = serde_json::from_str(body).expect("a pump body must be JSON");
    parsed
        .get("device_keys")
        .and_then(|users| users.get(ACCOUNT))
        .is_some()
}
