// The FFI crate must expose the core's probe unchanged. This test does not
// cross the FFI boundary; it only proves the re-export compiles and delegates.
#[tokio::test]
async fn ffi_probe_delegates_to_core() {
    let report = matrix_crypto_ffi::probe("hi".to_string(), vec![9, 8])
        .await
        .unwrap();
    assert_eq!(report.echoed, "hi");
    assert_eq!(report.payload, vec![8, 9]);
}

#[tokio::test]
async fn ffi_probe_propagates_typed_error() {
    let err = matrix_crypto_ffi::probe(String::new(), vec![])
        .await
        .unwrap_err();
    assert!(
        matches!(err, matrix_crypto_ffi::ProbeFfiError::Rejected { reason } if reason == "input must not be empty")
    );
}

/// The signing identity's two calls exist on this crate's surface and reach
/// the core, which is the whole content of the bridge: both are one-line
/// delegations, so what can go wrong is that they are absent, or wired to
/// the wrong core function, or swallow the core's error.
///
/// No machine is created in this test binary, so the core answers
/// `NotInitialised` for both, and asserting on that particular variant is
/// what separates a real delegation from a stub that succeeds: a function
/// returning `Ok(())` or a default record passes a test that only checks it
/// can be called, and fails this one.
///
/// **It does not separate it from a stub that fails the same way.** A body
/// of `Err(MachineFfiError::NotInitialised)` passes this, and no test
/// reachable from here can tell it apart, because reaching the core's other
/// answers means creating a machine and this binary deliberately creates
/// none. The stronger check lives where a machine exists: the core's own
/// `tests/identity_bootstrap*.rs` drive both refusals and the served path
/// against a real store. Said rather than left implied, because a comment
/// claiming more than its assertion is the defect this milestone keeps
/// finding.
#[tokio::test]
async fn the_signing_identity_calls_reach_the_core() {
    let err = matrix_crypto_ffi::identity_status().await.unwrap_err();
    assert!(matches!(
        err,
        matrix_crypto_ffi::MachineFfiError::NotInitialised
    ));

    let err = matrix_crypto_ffi::bootstrap_identity().await.unwrap_err();
    assert!(matches!(
        err,
        matrix_crypto_ffi::MachineFfiError::NotInitialised
    ));
}

/// The call a device joins an identity with reaches the core too, and is the
/// same one-line delegation with the same three ways of going wrong.
///
/// Separate from the test above rather than a third line inside it, because
/// it belongs to a different call on the product's surface: joining is a
/// verification, not a bootstrap, and the two must never be reached for
/// interchangeably. The same limit applies as above -- a body of
/// `Err(MachineFfiError::NotInitialised)` would pass this, and the core's own
/// `tests/self_verification*.rs` are what drive the served path and both
/// refusals against a real store.
#[tokio::test]
async fn the_self_verification_call_reaches_the_core() {
    let err = matrix_crypto_ffi::request_self_verification()
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        matrix_crypto_ffi::MachineFfiError::NotInitialised
    ));
}

/// The two server-side recovery calls reach the core, with the same three
/// ways of going wrong as the calls above: absent, wired to the wrong core
/// function, or swallowing the core's error.
///
/// The same limit applies as above, and is worth restating because these two
/// have four refusals between them: a body of
/// `Err(MachineFfiError::NotInitialised)` would pass this, and no test
/// reachable from here can tell it apart. What drives the served path and
/// every refusal against a real store is the core's own
/// `src/recovery.rs` tests and `tests/recovery_refusals.rs`.
#[tokio::test]
async fn the_recovery_calls_reach_the_core() {
    // `unwrap_err` is unavailable here: `RecoverySetup` has no `Debug`
    // derive on purpose, because it carries the recovery key. Matched
    // instead, which asserts the same thing.
    assert!(matches!(
        matrix_crypto_ffi::create_recovery("passphrase".to_string(), Vec::new()).await,
        Err(matrix_crypto_ffi::MachineFfiError::NotInitialised)
    ));

    let err = matrix_crypto_ffi::recover_identity("passphrase".to_string(), Vec::new())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        matrix_crypto_ffi::MachineFfiError::NotInitialised
    ));
}
