//! The refusal has to queue the key query that lifts it, in the one case
//! where nothing else will.
//!
//! `bootstrap_identity` refuses until this process has asked the server about
//! this account. That refusal is only a refusal, rather than a permanent
//! deadlock, because it queues the question itself. Upstream will not do it
//! for us in general: `users_for_key_query` volunteers an own-account query
//! only when it has nothing else to ask *and* the account is not yet tracked
//! (`identities/manager.rs:836-852`), and `update_tracked_users` re-flags
//! only accounts it did not already know (`store/mod.rs:258-273`), so an
//! account that is already tracked is never asked about again on its own.
//!
//! **A fresh machine cannot test this.** On a fresh machine upstream
//! volunteers exactly that query, so the batch after a refusal contains one
//! whether or not the refusal contributed anything. An assertion there that
//! merely finds an account key query passes with the mechanism deleted --
//! it did, for the whole first round of this task.
//!
//! So this file constructs the case the mechanism exists for, using nothing
//! but the shipped surface: share a key with somebody else first. That marks
//! another user as needing a key query, `users_for_key_query` then always has
//! something to ask, its own-account fallback never fires, and the only
//! possible source of a query naming this account is the refusal itself.
//! This is not a contrived arrangement; it is what any product that
//! encrypted anything before bootstrapping looks like.
//!
//! The last act covers the other half. The out-of-band query must also
//! *survive* the ordinary key queries that keep arriving beside it. It is
//! deliberately not in their eviction group, because upstream's
//! `build_key_query_for_users` does not forget it the way `users_for_key_query`
//! forgets its own ("does not store the details",
//! `identities/manager.rs:804-816`). Grouped with them, the next batch's
//! ordinary key query would evict the recovery query while it was still in
//! flight, and the path this file is about would be broken by the very
//! situation it exists for.

use matrix_crypto_core::{
    bootstrap_identity, create_machine, mark_request_sent, share_scope_key, take_outgoing_requests,
    MachineConfig, MachineError, OutgoingRequest, SessionError,
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
/// account is **named**, which the `{"device_keys":{}}` written here before
/// was not, and which no measured homeserver omits. A body that names nobody
/// is silent about this account, and `session::answer_about_this_account` has why
/// silence does not lift the gate.
const NO_IDENTITY: &str = r#"{"device_keys":{"@alice:example.org":{}}}"#;

#[test]
fn the_refusal_queues_the_query_that_lifts_it_when_upstream_never_would() {
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

        // Give upstream something else to ask about, so its own-account
        // fallback stops firing. This delivers nothing -- Bob has no known
        // device -- and that is fine: what it does is mark him as needing a
        // key query, which is all this test needs from it.
        share_scope_key("!s:example.org", &[SOMEBODY_ELSE.to_string()])
            .await
            .expect("sharing a scope key must not fail");

        // The premise, asserted rather than assumed. If upstream volunteers
        // an own-account query here after all, every assertion below would
        // pass without the mechanism under test and this file would be
        // worthless. Better to fail loudly at the premise.
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
            bootstrap_identity().await,
            Err(MachineError::AccountKeysNotFetched),
            "this process has asked the server nothing about this account"
        );

        // The assertion this file exists for. Nothing but the refusal can
        // have put an account key query in this batch.
        let after = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert_eq!(
            account_queries(&after),
            1,
            "the refusal must queue the key query that lifts it. Nothing else can: upstream \
             has another user to ask about, so its own-account fallback never fires, and \
             without this the refusal is permanent for every process that encrypted anything \
             before bootstrapping. Got {:?}",
            kinds(&after)
        );
        let recovery_query = after
            .iter()
            .find(|r| r.kind == "keys_query" && names_the_account(&r.body))
            .expect("just counted one");
        let recovery_id = recovery_query.id.clone();

        // It must survive the ordinary key queries that keep arriving. Bob's
        // query was never reported sent, so upstream re-derives it and hands
        // out a fresh one here, which supersedes its own predecessor and must
        // not touch this.
        let later = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert!(
            later.iter().any(|r| r.kind == "keys_query"),
            "upstream must still be offering its own key query, or this act asserts nothing: \
             {:?}",
            kinds(&later)
        );
        assert_eq!(
            account_queries(&later),
            0,
            "the recovery query is a single slot and was drained; it must not be re-offered: \
             {:?}",
            kinds(&later)
        );

        assert_ne!(
            mark_request_sent(&recovery_id, NO_IDENTITY).await,
            Err(SessionError::UnknownRequest),
            "a later ordinary key query must not evict the recovery query. Upstream does not \
             forget an out-of-band query the way it forgets the ones it volunteers, so \
             grouping the two for eviction makes the recovery path unusable in exactly the \
             case it exists for"
        );

        bootstrap_identity()
            .await
            .expect("the answered recovery query must lift the gate");
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
