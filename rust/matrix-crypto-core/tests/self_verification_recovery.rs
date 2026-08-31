//! The other call's refusal has to queue the query that lifts it too, and in
//! the one case where nothing else will.
//!
//! `request_self_flow` refuses with `AccountKeysNotFetched` until this process
//! has asked the server about this account. That refusal is only a refusal,
//! rather than a permanent deadlock, because it queues the question itself.
//!
//! # Why a fresh machine cannot test this, and why that mattered here
//!
//! On a fresh machine upstream volunteers exactly that query, so the batch
//! after a refusal contains one whether or not the refusal contributed
//! anything. `tests/self_verification_unasked.rs` runs on such a machine and
//! is the wrong place to assert a remedy for that reason; it asserts the
//! refusal and nothing about recovery.
//!
//! Upstream will not ask for us in general. `users_for_key_query` volunteers
//! an own-account query only when it has nothing else to ask *and* the account
//! is not yet tracked (`identities/manager.rs:836-852`), and
//! `update_tracked_users` re-flags only accounts it did not already know
//! (`store/mod.rs:258-273`), so an account that is already tracked is never
//! asked about again on its own. That covers **every relaunch of an existing
//! store**, because `account_keys_answered` is not persisted.
//!
//! So this file constructs the case the mechanism exists for, using nothing
//! but the shipped surface, exactly as `tests/identity_bootstrap_recovery.rs`
//! does for the other call: share a key with somebody else first, so
//! `users_for_key_query` always has something to ask and its own-account
//! fallback never fires. The only possible source of a query naming this
//! account is then the refusal itself.
//!
//! # The act this file has that its sibling does not
//!
//! It calls `request_self_flow` a **second** time after answering, and
//! requires a **different** refusal. A remedy that merely queues something is
//! not a remedy: what has to be true is that the loop terminates, and the
//! proof of that is the gate moving off `AccountKeysNotFetched` onto the
//! refusal that belongs to an account with no identity. Without that act, an
//! implementation that queued the query and never read the answer would pass.

use matrix_crypto_core::{
    create_machine, identity_status, mark_request_sent, request_self_flow, share_scope_key,
    take_outgoing_requests, MachineConfig, MachineError, OutgoingRequest,
};

const ACCOUNT: &str = "@alice:example.org";
const SOMEBODY_ELSE: &str = "@bob:example.org";

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
fn the_refusal_queues_the_query_that_lifts_it_when_upstream_never_would() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(async move {
        create_machine(MachineConfig {
            user_id: ACCOUNT.to_string(),
            device_id: "NEWLOGIN".to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        // Give upstream something else to ask about, so its own-account
        // fallback stops firing. This delivers nothing, because Bob has no
        // known device, and that is fine: what it does is mark him as needing
        // a key query, which is all this test needs from it.
        share_scope_key("!s:example.org", &[SOMEBODY_ELSE.to_string()])
            .await
            .expect("sharing a scope key must not fail");

        // The premise, asserted rather than assumed. If upstream volunteers an
        // own-account query here after all, every assertion below would pass
        // without the mechanism under test and this file would be worthless.
        let before = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert_eq!(
            account_queries(&before),
            0,
            "premise broken: upstream volunteered an own-account key query on a machine that \
             already has another user to ask about, so this test can no longer tell the \
             refusal's own query apart from upstream's. Got {:?}",
            kinds(&before)
        );
        assert!(
            before.iter().any(|r| r.kind == "keys_query"),
            "upstream must still owe a key query for the other user, or nothing below is \
             exercising the case where ordinary key queries keep arriving: {:?}",
            kinds(&before)
        );

        assert_eq!(
            request_self_flow().await.err(),
            Some(MachineError::AccountKeysNotFetched),
            "this process has asked the server nothing about this account, so it cannot know \
             whether there is an identity to join"
        );

        // The assertion this file exists for. Nothing but the refusal can have
        // put an account key query in this batch.
        let after = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert_eq!(
            account_queries(&after),
            1,
            "the refusal must queue the key query that lifts it. Nothing else can: upstream \
             has another user to ask about, so its own-account fallback never fires, and \
             without this the remedy the facade documents first -- drain, send, report sent, \
             call again -- is a no-op and this refusal is permanent on this call. Got {:?}",
            kinds(&after)
        );
        let recovery_id = after
            .iter()
            .find(|r| r.kind == "keys_query" && names_the_account(&r.body))
            .expect("just counted one")
            .id
            .clone();

        mark_request_sent(&recovery_id, NO_IDENTITY)
            .await
            .expect("answering the recovery query must not fail");

        let status = identity_status()
            .await
            .expect("reading the identity status must not fail");
        assert!(
            status.account_keys_fetched,
            "the answer was accepted, which is the fact the gate reads: {status:?}"
        );

        // The act that makes the assertion above a remedy rather than an
        // emission. The same call, in the same process, must now refuse for
        // the *other* reason: the server has answered and named no identity.
        // An implementation that queued the query and ignored the answer
        // returns `AccountKeysNotFetched` here forever and fails this.
        assert_eq!(
            request_self_flow().await.err(),
            Some(MachineError::IdentityNotKnown),
            "the loop must terminate: the answered query moves this call off the refusal it \
             queued the query for, onto the one that belongs to an account with no identity"
        );
    });
}

/// How many `/keys/query` requests in this batch name this account.
fn account_queries(batch: &[OutgoingRequest]) -> usize {
    batch
        .iter()
        .filter(|r| r.kind == "keys_query" && names_the_account(&r.body))
        .count()
}

fn kinds(batch: &[OutgoingRequest]) -> Vec<&str> {
    batch.iter().map(|r| r.kind.as_str()).collect()
}

/// Whether a `/keys/query` body's `device_keys` map names this account.
fn names_the_account(body: &str) -> bool {
    let parsed: serde_json::Value = serde_json::from_str(body).expect("a pump body must be JSON");
    parsed
        .get("device_keys")
        .and_then(|users| users.get(ACCOUNT))
        .is_some()
}
