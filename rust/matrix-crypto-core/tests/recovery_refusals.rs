//! The refusals a recovery makes about the machine rather than about the
//! account data, including the one that has to queue the question that
//! lifts it.
//!
//! # Why these are not in `src/recovery.rs`'s own tests
//!
//! Two of them turn on `account_keys_fetched`, which is process-wide and
//! has no reset: once anything in a test binary has reported a key query
//! answered, everything later in that binary sees it as answered forever.
//! Every unit test in `src/recovery.rs` answers one, so a refusal that only
//! occurs before the first answer cannot be constructed there at all. Cargo
//! gives each file under `tests/` its own process, which is the only place
//! this sequence exists. The same reason
//! `tests/self_verification_unasked.rs` is its own file.
//!
//! # Why `PrivateKeysNotHeld` is not the first thing asserted
//!
//! It was, and it moved. `create_recovery` now carries the same
//! `account_keys_fetched` gate `bootstrap_identity` and `recover_identity`
//! do, and that gate comes first, so a fresh machine that has asked nothing
//! meets it rather than the one about the keys. Holding no private keys is
//! still what `create_recovery` reports once the query has been answered,
//! which is where act four asserts it.
//!
//! # A fresh machine cannot test the second act, and this file says why
//!
//! `recover_identity` refuses until this process has asked the server about
//! this account, and that refusal is a refusal rather than a deadlock only
//! because it queues the question itself. On a *fresh* machine upstream
//! volunteers exactly that query anyway
//! (`identities/manager.rs`: "We always want to track our own user"), so a
//! batch drained after the refusal contains one whether or not the refusal
//! contributed anything. **An assertion there passes with the mechanism
//! deleted, and this one did**: the first version of this file found the
//! query, reported the branch covered, and went on passing after the two
//! lines that queue it were removed.
//!
//! So the second act constructs the case the mechanism exists for, using
//! nothing but the shipped surface: share a key with somebody else first.
//! That marks another user as needing a key query, upstream's own-account
//! fallback then never fires, and the only possible source of a query
//! naming this account is the refusal. `tests/identity_bootstrap_recovery.rs`
//! does the same for `bootstrap_identity` and explains the upstream
//! mechanics at length; this file exercises the other call that depends on
//! them.
//!
//! # The account data is empty in most of what follows, on purpose
//!
//! If a refusal about the machine were ever replaced by one about the
//! *argument*, an empty list is exactly what `RecoveryNotSetUp` reports, and
//! none of these assertions accepts it. So the order these checks run in is
//! asserted by the assertions themselves rather than by a comment. The one
//! act that does pass account data is act five, which is about the opposite
//! ordering and says so.

use matrix_crypto_core::{
    create_machine, create_recovery, in_runtime, mark_request_sent, recover_identity,
    share_scope_key, take_outgoing_requests, AccountDataEntry, MachineConfig, MachineError,
    OutgoingRequest,
};

const ACCOUNT: &str = "@alice:example.org";
const SOMEBODY_ELSE: &str = "@bob:example.org";

/// A `/keys/query` answer naming no identity for this account: the server
/// has been asked and has said there is none. Every field of ruma's own
/// response type is `#[serde(default)]`, so an empty object says exactly
/// that.
const NO_IDENTITY: &str = r#"{"device_keys":{}}"#;

/// A literal with no account behind it, like the `store_passphrase` every
/// other test in this crate hands to `MachineConfig`.
const PASSPHRASE: &str = "recovery-test-passphrase";

/// One `#[test]` fn, because the machine registry and the pump are
/// process-wide and an integration test has no access to the `#[cfg(test)]`
/// reset helpers. The five acts are one sequence and have to be.
#[test]
fn a_recovery_refuses_before_it_can_know_what_identity_this_account_has() {
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

        // ---- Act one: nothing to restore into, and nobody has asked ----
        //
        // Give upstream something else to ask about first, so its
        // own-account fallback stops firing. This delivers nothing, since
        // the other user has no known device, and that is fine: what it
        // does is mark him as needing a key query, which is all this needs
        // from it.
        share_scope_key("!s:example.org", &[SOMEBODY_ELSE.to_string()])
            .await
            .expect("sharing a scope key must not fail");

        // The premise, asserted rather than assumed. If upstream
        // volunteers an own-account query here after all, act three would
        // pass without the mechanism under test.
        let before = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert_eq!(
            account_queries(&before),
            0,
            "premise broken: upstream volunteered an own-account key query on \
             a machine that already has another user to ask about, so this \
             test can no longer tell the refusal's own query apart from \
             upstream's. Got {:?}",
            kinds(&before)
        );

        assert_eq!(
            recover_identity(PASSPHRASE, &[]).await,
            Err(MachineError::AccountKeysNotFetched),
            "importing a private signing key checks it against the account's \
             published identity, which is only in the store once a key query \
             has been answered. Note the account data is empty here: a call \
             that looked at its argument first would answer `RecoveryNotSetUp`"
        );

        // ---- Act two: the refusal queued the question ------------------
        //
        // Nothing else can have put an account key query in this batch.
        let after = take_outgoing_requests()
            .await
            .expect("draining the pump must not fail");
        assert_eq!(
            account_queries(&after),
            1,
            "the refusal must queue the key query that lifts it. Nothing else \
             can here: upstream has another user to ask about, so its \
             own-account fallback never fires, and without this the refusal \
             is permanent for every process that encrypted anything before \
             recovering. Got {:?}",
            kinds(&after)
        );
        let account_query = after
            .iter()
            .find(|request| request.kind == "keys_query" && names_the_account(&request.body))
            .expect("just counted one");
        mark_request_sent(&account_query.id, NO_IDENTITY)
            .await
            .expect("answering the account key query must not fail");

        // ---- Act three: asked, and the answer named no identity --------
        //
        // A different refusal with a different remedy: create an identity,
        // do not ask again.
        assert_eq!(
            recover_identity(PASSPHRASE, &[]).await,
            Err(MachineError::IdentityNotKnown),
            "an account the server says has no signing identity has nothing \
             for a recovery to restore into, and that is not the same answer \
             as `nobody has asked`"
        );

        // ---- Act four: nothing to write --------------------------------
        //
        // Reached only now, because the gate above had to be lifted first.
        // This machine holds no private signing keys, so there is no copy
        // of them to put anywhere.
        assert_eq!(
            create_recovery(PASSPHRASE, &[]).await.err(),
            Some(MachineError::PrivateKeysNotHeld),
            "a device that does not hold the account's private signing keys \
             cannot write them into server-side storage, and must say so \
             rather than write a recovery that opens onto nothing"
        );

        // ---- Act five: the argument is checked before the machine ------
        //
        // The mirror of the section above, and the one act that passes
        // account data. This machine holds no private keys, so a
        // `create_recovery` that looked at the machine first would answer
        // `PrivateKeysNotHeld` here. It answers about the argument instead,
        // because the refusal that protects something a user already has
        // should arrive whatever else is true of this device.
        let existing = [AccountDataEntry {
            event_type: "m.secret_storage.default_key".to_string(),
            content: r#"{"key":"AKEYIDFROMANOTHERCLIENT"}"#.to_string(),
        }];
        assert_eq!(
            create_recovery(PASSPHRASE, &existing).await.err(),
            Some(MachineError::RecoveryAlreadyExists),
            "account data naming a recovery must be refused before anything \
             about this device is considered, or a product on a device that \
             happens to hold no keys is told the wrong thing about an account \
             whose recovery it was about to invalidate"
        );
    }));
}

/// How many `/keys/query` requests in this batch name this account.
fn account_queries(batch: &[OutgoingRequest]) -> usize {
    batch
        .iter()
        .filter(|request| request.kind == "keys_query" && names_the_account(&request.body))
        .count()
}

fn kinds(batch: &[OutgoingRequest]) -> Vec<&str> {
    batch.iter().map(|request| request.kind.as_str()).collect()
}

/// Whether a `/keys/query` body's `device_keys` map names this account.
fn names_the_account(body: &str) -> bool {
    let parsed: serde_json::Value = serde_json::from_str(body).expect("a pump body must be JSON");
    parsed
        .get("device_keys")
        .and_then(|users| users.get(ACCOUNT))
        .is_some()
}
