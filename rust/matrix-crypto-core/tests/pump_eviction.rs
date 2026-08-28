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
    create_machine, mark_request_sent, share_scope_key, take_outgoing_requests, MachineConfig,
};

/// Upstream's own per-request cap, `IdentityManager::MAX_KEY_QUERY_USERS`
/// (`matrix-sdk-crypto-0.18.0/src/identities/manager.rs:102`), applied by
/// `users_for_key_query`'s `.chunks(...)` at `:871`. Restated here rather
/// than imported because it is a private associated constant; if upstream
/// changes it, the guard below says so by name and by value instead of
/// leaving a maintainer to find out.
const UPSTREAM_CHUNK_CAP: usize = 250;

/// Comfortably over the cap, so the split is not sitting on the boundary,
/// and small enough to stay fast. Derived from the cap rather than written
/// as a literal, so raising one raises the other.
const TRACKED_USERS: usize = UPSTREAM_CHUNK_CAP + 50;

#[test]
fn every_keys_query_sibling_handed_out_in_one_batch_stays_resolvable() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    // A bare `futures::executor::block_on`: no `#[tokio::test]`, and no
    // `in_runtime` wrapper of its own either. Every call below is a library
    // call, and each is responsible for reaching for the runtime it needs --
    // so this test enters with genuinely no runtime context anywhere, and a
    // library function that forgot its own `in_runtime` would panic here
    // rather than be carried by a context this test supplied. That is the
    // mistake `machine.rs`'s
    // `with_machine_supplies_a_runtime_for_store_touching_calls` exists to
    // catch, made twice already in this milestone with a green suite both
    // times. `tests/two_parties.rs` cannot hold this property -- it drives a
    // bare upstream `OlmMachine`, whose own `share_room_key` reaches
    // `tokio::task::spawn` and needs a context this crate does not supply
    // for it -- so it lives here instead.
    futures::executor::block_on(async move {
        create_machine(MachineConfig {
            user_id: "@alice:example.org".to_string(),
            device_id: "DEVICE1".to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        // Enough tracked users to force upstream to split its key query,
        // set up through the shipped surface: `share_scope_key` tracks the
        // users it is given, so naming this many is what makes the pump
        // owe a query for each of them. (An earlier version of this test
        // reached `update_tracked_users` through `with_machine`, because
        // nothing on the surface could do it -- that gap is closed, and
        // this test no longer needs the back door.) This first share
        // delivers nothing: not one of these users has a known device.
        let users: Vec<String> = (0..TRACKED_USERS)
            .map(|i| format!("@u{i}:example.org"))
            .collect();
        share_scope_key("!s:example.org", &users)
            .await
            .expect("sharing a scope key must not fail");

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
             requests in one batch, and it handed out {} instead, so the \
             property below is not being exercised. It tracked {} users \
             against upstream's MAX_KEY_QUERY_USERS, which was {} when this \
             was written (matrix-sdk-crypto identities/manager.rs). If that \
             cap has risen, raise UPSTREAM_CHUNK_CAP in this file to match \
             it; TRACKED_USERS follows from it.",
            query_ids.len(),
            TRACKED_USERS,
            UPSTREAM_CHUNK_CAP
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
    });
}
