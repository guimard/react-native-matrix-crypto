//! The pump's stale-entry eviction, and the one property it must not break.
//!
//! `take_outgoing_requests` evicts previously handed-out, still-unresolved
//! ids of the three kinds `PendingKind::superseded_by_a_fresh_request`
//! names, because upstream mints a fresh, uncorrelated id for the same
//! standing need on every call and forgets the one it handed out last. That
//! much `session.rs`'s own
//! `a_stale_keys_upload_id_does_not_accumulate_across_repeated_calls`
//! already covers.
//!
//! What nothing covered until this file is **when** the eviction runs.
//! It runs once per call, over the whole batch, rather than once per item --
//! deliberately, because upstream splits a large user list across several
//! `/keys/query` requests handed out in the *same* batch
//! (`identities/manager.rs`'s own "convert the set of users into multiple
//! /keys/query requests", capped at 250 users per request). Under a
//! per-item eviction, inserting the second sibling would discard the first,
//! and the caller who dutifully sent both would be told `UnknownRequest`
//! for the one it sent first -- a request it can then never resolve, for a
//! device list that is then never marked up to date.
//!
//! The whole suite passes under that mutation; only an ad-hoc probe caught
//! it. This test fails under it, at the line marked below.
//!
//! Its own file, not a second `#[test]` in `two_parties.rs`: the machine
//! registry and the pump's bookkeeping are process-wide, cargo gives each
//! file under `tests/` its own process, and an integration test has no
//! access to the `#[cfg(test)]` reset helpers the unit tests use.

use matrix_crypto_core::{
    create_machine, in_runtime, mark_request_sent, take_outgoing_requests, with_machine,
    MachineConfig,
};
use matrix_sdk_common::ruma::OwnedUserId;

/// Comfortably over upstream's own 250-users-per-request cap, so the split
/// is not sitting on the boundary, and small enough to stay fast.
const TRACKED_USERS: usize = 300;

#[test]
fn every_keys_query_sibling_handed_out_in_one_batch_stays_resolvable() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    // `futures::executor::block_on`, not `#[tokio::test]`: an ambient
    // runtime would make the library look like it supplies its own even
    // where it supplies none -- the mistake `machine.rs`'s
    // `with_machine_supplies_a_runtime_for_store_touching_calls` exists to
    // catch, and one this milestone has already made twice.
    futures::executor::block_on(in_runtime(async move {
        create_machine(MachineConfig {
            user_id: "@alice:example.org".to_string(),
            device_id: "DEVICE1".to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        // Enough tracked users to force upstream to split its key query.
        // Reached through `with_machine`, this crate's own public accessor
        // for the live machine: M2's public surface has no "track these
        // users" call of its own (that is the product's `/sync` room-member
        // handling, which this bridge deliberately does not do), and
        // `receive_sync_changes`'s changed-device list only re-flags users
        // that are *already* tracked -- upstream's own
        // `mark_tracked_users_as_changed` skips every user it has never
        // seen. So there is no way to set this precondition up through the
        // narrower surface, and faking it by hand would not produce the
        // sibling requests this test is about.
        let users: Vec<OwnedUserId> = (0..TRACKED_USERS)
            .map(|i| {
                format!("@u{i}:example.org")
                    .parse()
                    .expect("a generated user id parses")
            })
            .collect();
        with_machine(move |machine| {
            Box::pin(async move {
                machine
                    .update_tracked_users(users.iter().map(AsRef::as_ref))
                    .await
            })
        })
        .await
        .expect("the machine must be live")
        .expect("tracking users must not fail");

        let batch = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let query_ids: Vec<String> = batch
            .iter()
            .filter(|r| r.kind == "keys_query")
            .map(|r| r.id.clone())
            .collect();
        assert!(
            query_ids.len() >= 2,
            "this test needs upstream to split its key query across several \
             requests in one batch; it handed out {} instead, so the property \
             below is not actually being exercised",
            query_ids.len()
        );

        // The decisive loop. Every sibling was handed to the caller in the
        // same batch, so every sibling must still be resolvable -- in the
        // order they were handed out, which is the order a caller sends
        // them in. Under a per-item eviction the first sibling is already
        // gone from the pending set by the time the second is inserted, and
        // this fails on the first iteration with `UnknownRequest`.
        for id in &query_ids {
            mark_request_sent(id, r#"{"device_keys":{}}"#).await.expect(
                "every keys-query request handed out in one batch must still be \
                     resolvable -- a sibling handed out alongside it must not evict it",
            );
        }
    }));
}
