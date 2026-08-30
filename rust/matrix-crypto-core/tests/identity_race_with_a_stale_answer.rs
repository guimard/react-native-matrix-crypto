//! The launch-time call cannot mint, so an answer that was true when the
//! server sent it cannot become a mint over an identity published since.
//!
//! # The race, which needs no misbehaving server
//!
//! Measured against a live continuwuity, with every party behaving
//! correctly. A device asked `/keys/query` about its own fresh account. The
//! server answered "no identity", which was true at that instant. In the
//! window before that answer was reported, another device of the same
//! account published an identity. The answer was then reported, the gate
//! lifted with `identity_known == false` because the answer was a truthful
//! negative, and `bootstrap_identity` minted a second identity over the
//! published one.
//!
//! No rule that reads one answer can prevent this. An answer describes the
//! instant the server sent it and nothing later. The gate was doing its job
//! correctly and the outcome was still the destruction the gate exists to
//! prevent.
//!
//! # What was actually wrong, which is not the gate
//!
//! `bootstrap_identity` is the call this library tells a product to make on
//! **every launch**, and it was also the call that created the account's
//! first identity. So the destructive act was reachable from the ordinary
//! launch path of every device, and a product that followed the
//! documentation exactly could lose this race without any human ever
//! deciding to create an identity.
//!
//! It is now two calls. `bootstrap_identity` publishes the identity this
//! device already holds and can create nothing; `create_identity` creates,
//! and a product arrives there only by deciding to. The window is unchanged
//! and this file does not claim otherwise. What changed is who can walk into
//! it.
//!
//! # What was measured about the aftermath, because it decided the rest
//!
//! Two things, both on a live homeserver, both before this change:
//!
//! * **The server's authentication challenge is not a second line of
//!   defence.** Continuwuity refused the replacement upload with a 401 and a
//!   password challenge. The product answered it with the password it
//!   already had, which is exactly what this library's own README tells it
//!   to do for an ordinary first publication, and the upload then returned
//!   200. The account's published master key changed from the one the other
//!   device had published to the raced one. The overwrite completed.
//! * **When the challenge was left unanswered, the machine did not recover
//!   on its own.** It held a private identity the account did not have,
//!   reported `identity_known` and `private_keys_held` like a healthy
//!   device, and **asked the server nothing further**: a served publication
//!   queued no query, and upstream volunteers none for an account it already
//!   tracks. Only an unrelated device-list change on a later sync forced
//!   another query, and when one arrived the machine did correct itself.
//!
//! That second measurement is why `create_identity` queues a confirming key
//! query alongside the publication. It is detection and not prevention, and
//! act four is what holds it to that.

use matrix_crypto_core::{
    bootstrap_identity, create_identity, create_machine, identity_status, in_runtime,
    mark_request_sent, share_scope_key, take_outgoing_requests, MachineConfig, MachineError,
    OutgoingRequest,
};
use matrix_sdk_common::ruma::{DeviceId, OwnedUserId};
use matrix_sdk_crypto::OlmMachine;
use serde_json::{json, Value};

const ACCOUNT: &str = "@alice:example.org";
const SOMEBODY_ELSE: &str = "@bob:example.org";

/// A real homeserver's real answer for an account it holds no identity for.
/// True when the server sends it, and only then.
const NO_IDENTITY: &str = r#"{"device_keys":{"@alice:example.org":{}},"failures":{},"master_keys":{},"self_signing_keys":{},"user_signing_keys":{}}"#;

#[test]
fn a_launch_time_bootstrap_cannot_mint_over_what_was_published_in_the_window() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(async move {
        // The identity another device of this account publishes in the
        // window. Minted by a bare upstream machine, so its keys and
        // signatures are real and upstream will accept it when it is
        // eventually seen.
        let published_elsewhere = in_runtime(real_identity_answer()).await;

        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: "DEVICE1".to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        // Give upstream another user to ask about, so its own-account
        // fallback stops firing and every account key query below can only
        // have come from this library. The same construction, and the same
        // reason, as `tests/identity_bootstrap_recovery.rs`; without it act
        // four counts upstream's volunteered query as well as the one under
        // test and cannot tell them apart.
        share_scope_key("!s:example.org", &[SOMEBODY_ELSE.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let before = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert_eq!(
            before
                .iter()
                .filter(|r| r.kind == "keys_query" && names_the_account(&r.body))
                .count(),
            0,
            "premise broken: upstream volunteered an own-account key query anyway, so act \
             four can no longer tell the creation's own query apart from upstream's. Got {:?}",
            before.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>()
        );

        // ---- Act one: the stale answer, reported ----------------------
        //
        // This is the whole race, compressed. The answer is a real server's
        // real answer and it was true when it was sent; the identity above
        // exists by the time it is reported. Nothing here can tell.
        let query = fresh_account_key_query().await;
        mark_request_sent(&query.id, NO_IDENTITY)
            .await
            .expect("a real homeserver's real answer must be accepted");

        let status = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            status.account_keys_fetched,
            "the answer is a truthful negative and the gate is right to lift on it. This \
             file is not about the gate: {status:?}"
        );
        assert!(
            !status.identity_known,
            "and this machine knows of no identity"
        );

        // ---- Act two: the launch-time call refuses --------------------
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::IdentityNotKnown),
            "THIS is the assertion the file exists for. Served here, the call this library \
             tells a product to make on every launch mints a second identity over one that \
             was published while the answer was in flight, and resets the trust of every \
             device and every person who ever verified it"
        );
        let after_refusal = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert_eq!(
            after_refusal, status,
            "and it must refuse without having minted anything, which is a separate claim: \
             a call that minted and then reported a refusal would have done the damage \
             already"
        );

        // ---- Act three: creating is a deliberate, separate act --------
        //
        // The product decides. Nothing about the library's state changed
        // between act two and here; what changed is that a caller said which
        // of the two acts it meant.
        create_identity().await.expect(
            "a product that has decided this account is getting its first identity \
                     must be able to say so",
        );

        let batch = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let kinds: Vec<&str> = batch.iter().map(|r| r.kind.as_str()).collect();
        assert!(
            kinds.contains(&"signing_keys_upload"),
            "the creation must queue the publication it authorises; got {kinds:?}"
        );

        // ---- Act four: the confirming query, and what it is for -------
        //
        // Queued by the creation, after the publication. A served
        // publication used to queue nothing and upstream volunteers nothing
        // for an account it already tracks, so a device that lost the race
        // asked the server nothing ever again and sat holding an identity
        // the account did not have. Measured, on a live homeserver.
        let confirming = batch
            .iter()
            .filter(|r| r.kind == "keys_query" && names_the_account(&r.body))
            .count();
        assert_eq!(
            confirming, 1,
            "the creation must queue a confirming key query alongside the publication, or a \
             device that lost the race never learns it: {kinds:?}"
        );
        let confirming = batch
            .iter()
            .find(|r| r.kind == "keys_query" && names_the_account(&r.body))
            .expect("just counted one");

        // The product sends it, and the answer carries what the account
        // really has: the identity the other device published.
        mark_request_sent(&confirming.id, &published_elsewhere)
            .await
            .expect("the confirming answer must be accepted");

        let healed = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            healed.identity_known,
            "upstream must now hold the identity the account really has: {healed:?}"
        );
        assert!(
            !healed.private_keys_held,
            "and must have dropped the private keys that disagree with it, which is \
             upstream's `check_private_identity` doing the one thing this device could not \
             do for itself: {healed:?}"
        );
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::IdentityAlreadyExists),
            "so the device that lost the race is told to join rather than left believing it \
             holds the account's identity. This is detection, not prevention: a product that \
             sent the publication before this answer arrived has already sent it"
        );
        assert_eq!(
            create_identity().await,
            Err(MachineError::IdentityAlreadyExists),
            "and creating is refused too, whether or not this device holds private keys"
        );
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
