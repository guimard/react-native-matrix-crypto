//! A creation decides on an answer it asked for, so being thorough stops
//! making things worse.
//!
//! # The sequence this file exists for, and why it is the diligent product
//!
//! Measured on continuwuity and on Synapse, against the round before this
//! one. A product did everything this library's documentation asks of it:
//!
//! 1. It drained the outbound pump until it was **empty** and reported every
//!    answer honestly, so the library knew everything a homeserver had told
//!    it.
//! 2. It called the launch-time publishing call, which refused
//!    `IdentityNotKnown` because the account had no identity, and whose own
//!    documentation names the creating call as the remedy.
//! 3. Another device of the same account finished signing up in the gap, over
//!    real HTTP, answering the homeserver's real authentication challenge.
//! 4. It followed the documented remedy exactly.
//!
//! The creating call was served, and it **replaced the identity the other
//! device had just published** -- resetting the trust of every device and
//! every person who had ever verified that account, permanently and with no
//! signal.
//!
//! # Why it was not a race, and why care made it worse
//!
//! The precondition the creating call read was **as old as the last answer**,
//! and nothing shortened it:
//!
//! * the "we have been answered" flag is sticky for the process, so the
//!   library never asks again of its own accord;
//! * upstream volunteers an own-account key query only while the account is
//!   not yet tracked, which after the first sync it always is;
//! * and the `IdentityNotKnown` refusal in step 2 **queues nothing** -- act
//!   two below is what holds that.
//!
//! So a product with an unreported leftover query still in its pump survived
//! this sequence by accident: draining it refreshed the fact and the creation
//! refused correctly. The product that had drained to empty had nothing left
//! to send, and destroyed the account. **The safer-looking behaviour was the
//! fatal one**, which is the wrong way round for a safety property and is
//! what this file's act three changes.
//!
//! # What is driven here, in one process, in this order
//!
//! * **Act one and two** set up exactly the state above: answered, drained to
//!   empty, and a launch-time refusal that queues nothing.
//! * **Act three** is the change: the creation refuses
//!   `AccountKeysStale` and queues its own key query.
//! * **Act three and a half** is the count's one exclusion: a reply that
//!   leaves the library no better informed is not the answer this call asked
//!   for, so it does not launder the older one as fresh.
//! * **Act four** is the other direction, and it matters as much: answered
//!   that the account really has no identity, the creation is served and
//!   hands over the publication. A gate that refused here would brick every
//!   honest sign-up, which two earlier rounds did with the whole suite green.
//! * **Act five** is single-use. A second creation asks again rather than
//!   riding act four's answer, because one fresh answer authorises one
//!   publication and the next call can be arbitrarily far from it.
//! * **Act six** is the sequence at the top, with the interrupted publication
//!   that makes it the documented remedy: the fresh answer carries the other
//!   device's identity, and the creation refuses instead of publishing.
//!
//! Acts four and five are why this is not simply a stricter gate. The one
//! this replaces refused nothing it should have refused; this one must still
//! serve everything it served.

use matrix_crypto_core::{
    bootstrap_identity, create_identity, create_machine, identity_status, in_runtime,
    mark_request_sent, take_outgoing_requests, MachineConfig, MachineError, OutgoingRequest,
};
use matrix_sdk_common::ruma::{DeviceId, OwnedUserId};
use matrix_sdk_crypto::OlmMachine;
use serde_json::{json, Value};

const ACCOUNT: &str = "@alice:example.org";

/// A real homeserver's real answer for an account it holds no identity for.
/// Continuwuity, Synapse and Dendrite byte for byte, account substituted.
const NO_IDENTITY: &str = r#"{"device_keys":{"@alice:example.org":{}},"failures":{},"master_keys":{},"self_signing_keys":{},"user_signing_keys":{}}"#;

#[test]
fn a_creation_decides_on_an_answer_it_asked_for_and_serves_on_nothing_older() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(async move {
        // The identity the account's other device publishes while this one is
        // deciding. Minted by a bare upstream machine, so its keys and
        // signatures are real and upstream stores it when it finally sees it.
        let published_elsewhere = in_runtime(real_identity_answer()).await;

        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: "DEVICE1".to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        // ---- Act one: the diligent product, drained to empty -----------
        //
        // **Nothing here calls the creating call first, and that is the
        // fidelity of the reproduction rather than a shortcut.** The product
        // in the sequence at the top of this file had never called it: its
        // answer came from the key query *upstream* volunteers for an account
        // it is not yet tracking, drained and reported like every other
        // request. Answering it through this loop is what makes the state
        // below the one that was measured, and getting this wrong is easy --
        // a first refusal from the creating call would leave that call's own
        // question outstanding and act three would be served for a reason
        // that has nothing to do with the sequence.
        drain_until_empty().await;

        let answered = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            answered.account_keys_fetched && !answered.identity_known,
            "the state the sequence starts from: asked, answered, and the account has \
             nothing: {answered:?}"
        );

        // ---- Act two: the launch-time refusal queues nothing -----------
        //
        // The premise that makes the window unbounded rather than a race, and
        // it is asserted rather than reasoned about. If this ever queues a
        // query, the window shrinks for a reason nothing here would notice,
        // and act three would start passing for the wrong reason.
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::IdentityNotKnown),
            "there is nothing to publish, and its documentation sends a product to the \
             creating call"
        );
        let after_refusal = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert!(
            after_refusal.is_empty(),
            "THE PREMISE: the refusal that routes a product into the destructive call \
             queues nothing, so nothing in the library will ever refresh the fact that \
             call reads. A product with something left in its pump survived this sequence \
             by accident; this one has nothing. Got {:?}",
            kinds(&after_refusal)
        );

        // ---- Act three: the creation asks for itself -------------------
        //
        // **This is the change.** Before it, the call below was served on the
        // answer from act one -- true when the server sent it, and older than
        // this decision by however long the product took to decide.
        assert_eq!(
            create_identity().await,
            Err(MachineError::AccountKeysStale),
            "THIS is the assertion the file exists for. Served here, a product that \
             followed this library's own documented remedy replaces whatever identity the \
             account gained since act one, undetectably and permanently"
        );
        let asked = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert!(
            !asked.iter().any(|r| r.kind == "signing_keys_upload"),
            "and it must refuse without having queued the publication: a call that queued \
             it and then reported a refusal would have handed over the destructive request \
             already. Got {:?}",
            kinds(&asked)
        );
        let refresh = account_query_in(&asked);

        // ---- Act three and a half: an answer that settles nothing -----
        //
        // **A reply is not an answer, and the count must not treat it as
        // one.** This body is what the Matrix specification prescribes for a
        // user a reachable server does not know, and what a real Synapse
        // sends when the server-name half of the account id differs in case
        // from its own: accepted, carrying nothing about this account, and
        // leaving the library exactly as ignorant as before. Counting it
        // would launder the older answer as fresh, which is the staleness
        // this whole file is about, arrived at through the front door.
        mark_request_sent(&refresh.id, r#"{"device_keys":{},"failures":{}}"#)
            .await
            .expect("the body is accepted: upstream still has to see it");
        assert_eq!(
            create_identity().await,
            Err(MachineError::AccountKeysStale),
            "an answer that left this library no better informed is not the answer this              call asked for"
        );
        let asked_once_more = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let refresh = account_query_in(&asked_once_more);

        // ---- Act four: and it serves on the answer to that -------------
        //
        // The other direction, and the one two earlier rounds got wrong: a
        // gate that refuses an honest sign-up bricks every account it
        // protects. The account really has no identity, so the creation is
        // served and hands over the publication it authorises.
        mark_request_sent(&refresh.id, NO_IDENTITY)
            .await
            .expect("the query the refusal queued must be answerable");
        create_identity().await.expect(
            "an account the server has just said has no identity must still be \
                     able to get one, or this gate is a brick",
        );
        let publication = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert!(
            publication.iter().any(|r| r.kind == "signing_keys_upload"),
            "and the publication must reach the caller: {:?}",
            kinds(&publication)
        );
        let minted = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            minted.identity_publication_pending,
            "the publication is owed and no homeserver has confirmed it: {minted:?}"
        );

        // ---- Act five: one fresh answer authorises one publication -----
        //
        // The half that is easy to leave out. Without it the answer from act
        // four would authorise every later creation in this process, and the
        // next one could be arbitrarily far from it -- which is the unbounded
        // window again, one call along.
        assert_eq!(
            create_identity().await,
            Err(MachineError::AccountKeysStale),
            "the answer act four spent is spent: a second creation asks again rather than \
             riding the first one's"
        );
        let asked_again = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let refresh_again = account_query_in(&asked_again);

        // ---- Act six: the sequence at the top of this file -------------
        //
        // A device with an interrupted publication, following the documented
        // remedy, while another of the account's devices published in the
        // gap. The answer this creation asked for is what carries that back.
        mark_request_sent(&refresh_again.id, &published_elsewhere)
            .await
            .expect("the answer must be accepted");

        let healed = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            healed.identity_known,
            "upstream must now hold the identity the account really has: {healed:?}"
        );
        assert!(
            !healed.private_keys_held,
            "and must have dropped the private keys that disagree with it: {healed:?}"
        );
        assert!(
            !healed.identity_publication_pending,
            "AND THIS IS THE ONE A PRODUCT READS. `identity_publication_pending` says \
             *finish your own publication* and *you are about to overwrite the identity \
             your other phone just made* in the same word. The round this answer forces is \
             what tells them apart, and here it has: the flag that was true in act four is \
             false now, without anything having been published: {healed:?}"
        );

        assert_eq!(
            create_identity().await,
            Err(MachineError::IdentityAlreadyExists),
            "THE STAKE. Served here, this device replaces the identity the account really \
             has and every verification of this account ever made is silently reset"
        );
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::IdentityAlreadyExists),
            "and the launch-time call is told to join rather than to publish"
        );
        let nothing = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert!(
            !nothing.iter().any(|r| r.kind == "signing_keys_upload"),
            "and no publication reached the caller at all: a refusal that queued the \
             request first would have handed over the destructive act. Got {:?}",
            kinds(&nothing)
        );
    });
}

/// Drains and reports until the pump hands nothing back, which is what the
/// product in this file's opening paragraph did.
///
/// Bounded rather than a `loop`: a pump that never empties is a defect this
/// helper must report as one instead of hanging a test runner.
async fn drain_until_empty() {
    for _ in 0..8 {
        let batch = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        if batch.is_empty() {
            return;
        }
        for request in &batch {
            // Reported with the answer that endpoint's success carries. Only
            // the account key query matters to this file; the rest are here
            // because a diligent product resolves everything it drains, and
            // an unresolved entry is exactly the leftover this file is about.
            let body = match request.kind.as_str() {
                "keys_upload" => r#"{"one_time_key_counts":{}}"#.to_string(),
                "keys_query" if names_the_account(&request.body) => NO_IDENTITY.to_string(),
                // Any other key query is about somebody else. Answered
                // truthfully-shaped rather than with a bare `{}`, which
                // upstream accepts while marking nobody up to date, so it
                // re-offers the query and the pump never empties -- a
                // leftover of exactly the kind this file is about, and one
                // that would make the sequence below the *lucky* one.
                "keys_query" => r#"{"device_keys":{},"failures":{}}"#.to_string(),
                _ => "{}".to_string(),
            };
            let _ = mark_request_sent(&request.id, &body).await;
        }
    }
    panic!("the pump never emptied, which is a defect rather than a slow test");
}

/// The `/keys/query` in `batch` that names this account, or a failure saying
/// what was there instead.
fn account_query_in(batch: &[OutgoingRequest]) -> OutgoingRequest {
    batch
        .iter()
        .find(|request| request.kind == "keys_query" && names_the_account(&request.body))
        .unwrap_or_else(|| {
            panic!(
                "no key query naming this account in the batch; got {:?}",
                kinds(batch)
            )
        })
        .clone()
}

fn kinds(batch: &[OutgoingRequest]) -> Vec<&str> {
    batch.iter().map(|r| r.kind.as_str()).collect()
}

/// Whether a `/keys/query` body's `device_keys` map names this account.
fn names_the_account(body: &str) -> bool {
    let parsed: Value = serde_json::from_str(body).expect("a pump body must be JSON");
    parsed
        .get("device_keys")
        .and_then(|users| users.get(ACCOUNT))
        .is_some()
}

/// A complete `/keys/query` answer carrying an identity a bare upstream
/// machine really minted for this account, in the shape a homeserver sends
/// it.
async fn real_identity_answer() -> String {
    let user: OwnedUserId = ACCOUNT.parse().expect("well-formed");
    let machine = OlmMachine::new(&user, <&DeviceId>::from("OTHERDEV")).await;
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
    .to_string()
}
