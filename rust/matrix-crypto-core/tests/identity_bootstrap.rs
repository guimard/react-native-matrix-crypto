//! The legitimate bootstrap: the gate lifted, the identity minted once, and
//! the third request class reaching the pump.
//!
//! Three claims, driven end to end through the shipped surface and nothing
//! else:
//!
//! 1. Answering an account key query with "this account has no identity"
//!    lifts the gate `tests/identity_bootstrap_ordering.rs` drives.
//! 2. The signing-keys upload reaches the caller through the pump, with the
//!    real wire body of `POST /_matrix/client/v3/keys/device_signing/upload`
//!    and nothing else, and its response resolves through `mark_request_sent`
//!    like any other. It is the one request upstream cannot carry:
//!    `AnyOutgoingRequest` has six variants and none for that endpoint, and
//!    `outgoing_requests()` after a bootstrap returns only `keys_upload` and
//!    `keys_query`. So this crate hand-serialises it, and if it ever stopped
//!    doing so the identity would simply never be published -- silently,
//!    with every call still returning `Ok`.
//! 3. A second bootstrap republishes the identity this device already holds
//!    rather than minting a second one. Asserted on the **master key on the
//!    wire**, not on a status flag: a status flag would read the same either
//!    way, and the master key is the thing whose change is the damage.
//! 4. Repeating that does not leak pending ids. Each bootstrap mints a fresh
//!    transaction id for a publication of the *same* identity, so without an
//!    eviction rule the pump's `pending` map grows by one entry per
//!    bootstrap-and-drain cycle for the life of the process. M2 and M3 both
//!    had to prove this bound for their own request kinds; this is the same
//!    obligation for the kind M4 adds.
//!
//! Its own process, for the reason `tests/pump_eviction.rs` gives: the
//! machine registry and the pump's bookkeeping are process-wide.

use matrix_crypto_core::{
    bootstrap_identity, create_identity, create_machine, identity_status, mark_request_sent,
    take_outgoing_requests, MachineConfig, MachineError, OutgoingRequest,
};

const ACCOUNT: &str = "@alice:example.org";

/// Turns the publication into the `/keys/query` answer a homeserver that
/// accepted it would send back.
fn answer_carrying(publication: &str) -> String {
    let up: serde_json::Value = serde_json::from_str(publication).expect("JSON");
    serde_json::json!({
        "device_keys": { ACCOUNT: {} },
        "failures": {},
        "master_keys": { ACCOUNT: up["master_key"] },
        "self_signing_keys": { ACCOUNT: up["self_signing_key"] },
        "user_signing_keys": { ACCOUNT: up["user_signing_key"] },
    })
    .to_string()
}

/// A `/keys/query` answer naming no identity for this account: the server
/// has been asked, it has answered **about this account**, and what it holds
/// for it is nothing.
///
/// Continuwuity v26.7.2's real answer for such an account, measured directly
/// over HTTP; Synapse 1.159.0 and Dendrite 0.15.2 answer the same thing with
/// `"failures":{}` and the three empty cross-signing maps beside it. The
/// account is **named**, which the `{"device_keys":{}}` this constant used to
/// hold was not, and which no measured homeserver omits. A body that names
/// nobody is silent about this account, and `session::answer_about_this_account`
/// has why silence does not lift the gate.
const NO_IDENTITY: &str = r#"{"device_keys":{"@alice:example.org":{}}}"#;

#[test]
fn a_bootstrap_publishes_one_identity_and_republishes_the_same_one() {
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

        // Claim 1. Upstream volunteers an own-account key query on a machine
        // that is not yet tracking itself ("We always want to track our own
        // user", `identities/manager.rs:836-852`), so the ordinary pump loop
        // is enough here and no out-of-band query is needed.
        let batch = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let account_query = batch
            .iter()
            .find(|request| request.kind == "keys_query" && names_the_account(&request.body))
            .unwrap_or_else(|| {
                panic!(
                    "a fresh machine must owe a key query for its own account; got {:?}",
                    kinds(&batch)
                )
            });
        mark_request_sent(&account_query.id, NO_IDENTITY)
            .await
            .expect("answering the account key query must not fail");

        let asked = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            asked.account_keys_fetched,
            "an answered account key query is what `account_keys_fetched` reports: {asked:?}"
        );
        assert!(
            !asked.identity_known,
            "the answer named no identity, so none is known: {asked:?}"
        );
        assert!(
            !asked.private_keys_held,
            "asking a question mints nothing: {asked:?}"
        );

        let refresh = the_query_the_creation_asked_for().await;
        mark_request_sent(&refresh.id, NO_IDENTITY)
            .await
            .expect("the query that refusal queued must be answerable");

        create_identity().await.expect(
            "creating the account's first identity after the keys have been fetched \
                     must be served",
        );

        let minted = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            minted.private_keys_held,
            "a served bootstrap must leave this device holding the private keys: {minted:?}"
        );
        assert!(
            minted.identity_known,
            "a served bootstrap must leave a public identity known for this account: {minted:?}"
        );

        // The two calls are different acts, and this is the state that says
        // so at integration level rather than only in `signing.rs`'s unit
        // tests. What changed in the ninth round is *which* of them is
        // served here, and it is worth saying rather than quietly editing.
        //
        // The identity has been minted and no homeserver has confirmed it
        // yet, so it is a candidate rather than the account's identity.
        // Publishing a candidate is not the launch-time call's to do:
        // measured on two live homeservers, doing that destroyed an
        // account's real identity when a second device signed up in the gap
        // before this device's answer was reported. So `bootstrap_identity`
        // refuses here, and finishing the publication is the deliberate
        // call, which is exactly what the caller asked for a moment ago.
        assert!(
            minted.identity_publication_pending,
            "the mint is not confirmed by anybody yet: {minted:?}"
        );
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::IdentityNotKnown),
            "the launch-time call may not publish an identity nothing has confirmed: \
             {minted:?}"
        );
        let refresh = the_query_the_creation_asked_for().await;
        mark_request_sent(&refresh.id, NO_IDENTITY)
            .await
            .expect("the query that refusal queued must be answerable");

        create_identity()
            .await
            .expect("and finishing it is the same decision that was just made");

        // Claim 2.
        let published = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        let signing_keys: Vec<&OutgoingRequest> = published
            .iter()
            .filter(|request| request.kind == "signing_keys_upload")
            .collect();
        assert_eq!(
            signing_keys.len(),
            1,
            "exactly one signing-keys upload must reach the caller; got {:?}",
            kinds(&published)
        );

        let body: serde_json::Value =
            serde_json::from_str(&signing_keys[0].body).expect("a pump body must be JSON");
        let mut fields: Vec<&str> = body
            .as_object()
            .expect("the signing-keys upload body is a JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            vec!["master_key", "self_signing_key", "user_signing_key"],
            "the body must be that endpoint's real wire body and nothing else -- in \
             particular no `auth`, which the product merges in itself after the server \
             has said what it wants"
        );

        // Order matters and upstream states it: the device keys first if
        // present, then the signing keys, then the signatures, because a
        // signature may reference a key that is not published yet. Both
        // halves are asserted; only the second used to be, and a device-key
        // upload sorting after the signing keys would have gone unnoticed.
        let device_keys_at = position(&published, "keys_upload");
        let signing_at = position(&published, "signing_keys_upload");
        let signatures_at = position(&published, "signature_upload");
        assert!(
            device_keys_at < signing_at,
            "the device-key upload must be handed out before the signing-keys upload: {:?}",
            kinds(&published)
        );
        assert!(
            signing_at < signatures_at,
            "the signing-keys upload must be handed out before the signature upload: {:?}",
            kinds(&published)
        );

        // The response side is the asymmetric half: upstream has no
        // `From<&SigningKeysUploadResponse>` impl and ignores the request id
        // for this one kind, so the call site has to name the incoming
        // variant explicitly. If it named the wrong one, the identity would
        // never be marked as published and this call would fail or lie.
        mark_request_sent(&signing_keys[0].id, "{}")
            .await
            .expect("resolving the signing-keys upload must not fail");

        // **And the report alone does not confirm it.** Reporting the upload
        // is the caller's word, not the server's, and the two bodies this
        // library cannot tell from a success are exactly what a dropped
        // connection produces. So the record survives it, and the
        // launch-time call stays refused until a homeserver's own answer
        // carries the identity back.
        assert!(
            identity_status()
                .await
                .expect("reading the identity status must not fail")
                .identity_publication_pending,
            "a caller's report is not a homeserver's answer"
        );
        assert_eq!(
            bootstrap_identity().await,
            Err(MachineError::IdentityNotKnown),
            "so the launch-time call is still refused"
        );

        let confirming = published
            .iter()
            .find(|request| request.kind == "keys_query" && names_the_account(&request.body))
            .expect("the creation queues a confirming query alongside the publication");
        mark_request_sent(&confirming.id, &answer_carrying(&signing_keys[0].body))
            .await
            .expect("the homeserver's own answer must be accepted");
        let confirmed = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            !confirmed.identity_publication_pending,
            "and the server's answer is what confirms it"
        );

        // Claim 3, **and it is the opposite of what it used to be.**
        //
        // This asserted that a second bootstrap republishes the same master
        // key, on the reasoning that publishing the same one is harmless and
        // publishing a different one is the failure mode. The first half is
        // false whenever the account's identity has moved since this device
        // last looked, and that is not exotic: resetting cross-signing is a
        // first-class action in every mainstream client.
        //
        // Measured on continuwuity three times and on Synapse: a device that
        // signed up entirely correctly, restarted, refused, queued the key
        // query as documented and had the homeserver answer it honestly, had
        // another client of the account reset the identity in the gap before
        // that answer was reported, and then republished the old identity
        // over the new one through this very call. Nothing in that sequence
        // is stale, interrupted or misbehaving.
        //
        // So the launch-time call no longer hands over the one request that
        // can replace an identity. It still republishes this device's keys
        // and its signature into the account's identity, because those are
        // idempotent and repair a publication whose signature upload was the
        // part that failed.
        bootstrap_identity()
            .await
            .expect("a second bootstrap must still be served, and do the harmless half");
        let again = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert!(
            !again
                .iter()
                .any(|request| request.kind == "signing_keys_upload"),
            "THIS is the assertion the claim became: the every-launch call must never hand \
             over the request that replaces an account's cross-signing identity. It cannot \
             be needed here, because the identity is confirmed, which means a homeserver's \
             own answer carried it back and the server demonstrably has it. Got {:?}",
            kinds(&again)
        );
        assert!(
            again
                .iter()
                .any(|request| request.kind == "signature_upload"),
            "and the harmless half must still happen, or a device whose signature upload \
             was the part that failed has no way to repair it. Got {:?}",
            kinds(&again)
        );
        assert_eq!(
            identity_status()
                .await
                .expect("reading the identity status must not fail"),
            confirmed,
            "and nothing about what this library knows may have moved"
        );
    });
}

/// The account key query **the creation itself asked for**, drained and
/// returned.
///
/// `create_identity` serves only on an answer that settled after it asked, so
/// a first call refuses [`MachineError::AccountKeysStale`] with the query
/// already queued, and this is that one round. It is the cost the eleventh
/// round added, and it is a round rather than a wall: everything this file
/// asserts still completes.
///
/// **Why it cannot be skipped**: the answer that lifted the gate above was
/// asked for by something else, at a moment that can be arbitrarily earlier,
/// and another device of this account can have published an identity since.
/// This round is where that comes back. See `signing::PUBLICATION_ASKED_AFTER`.
async fn the_query_the_creation_asked_for() -> OutgoingRequest {
    assert_eq!(
        create_identity().await,
        Err(MachineError::AccountKeysStale),
        "a creation may not decide on an answer it did not ask for"
    );
    let batch = take_outgoing_requests()
        .await
        .expect("draining the pump must not fail");
    batch
        .iter()
        .find(|request| request.kind == "keys_query" && names_the_account(&request.body))
        .unwrap_or_else(|| {
            panic!(
                "the refusal must queue the query that lifts it; got {:?}",
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

fn kinds(batch: &[OutgoingRequest]) -> Vec<&str> {
    batch.iter().map(|request| request.kind.as_str()).collect()
}

/// The index of the first request of `kind`, or a failure naming what was
/// there instead -- never a silent `usize::MAX` that would make the ordering
/// assertion above pass by accident.
fn position(batch: &[OutgoingRequest], kind: &str) -> usize {
    batch
        .iter()
        .position(|request| request.kind == kind)
        .unwrap_or_else(|| panic!("no {kind} in the batch; got {:?}", kinds(batch)))
}
